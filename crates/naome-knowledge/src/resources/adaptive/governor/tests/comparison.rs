//! Deterministic replay, not a native performance benchmark. Both policies see
//! identical arrivals, CPU capacity, worker ceilings, memory and absolute job
//! deadlines. The baseline omits only the newly available provider costs.
use super::*;
use crate::resources::{feedback::Role, operating};
use std::collections::VecDeque;

const STEP_MS: u64 = 10;
const HORIZON_MS: u64 = 5_000;
const WORK_UNITS: u32 = 64;
const WORKER_RSS: u64 = 4 * MIB;

#[derive(Clone)]
struct Job {
    id: u64,
    role: usize,
    created: u64,
    expires: u64,
    allowance: u32,
    io_us: u64,
    cpu_us: u64,
}

#[derive(Debug, serde::Serialize)]
struct Result {
    completed: usize,
    expired: usize,
    p95_latency_ms: u64,
    peak_running: usize,
    completed_ids: u64,
}

fn selection(profile: Profile) -> Selection {
    Selection {
        profile,
        custom: (profile == Profile::Custom).then_some(Custom {
            memory_bytes: 128 * MIB,
            concurrency: 2,
            cache_bytes: MIB,
            batch_steps: 4,
            network_requests: 2,
        }),
    }
}

// A frozen calibration prefix: one complete 200 ms attempt per role. The
// independent replay below schedules CPU work and I/O waits, rather than
// assuming that every extra worker provides extra processing capacity.
fn calibrated(cpu_percent: u64) -> Statistics {
    let mut stats = Statistics::default();
    for provider in [
        &mut stats.providers.finding,
        &mut stats.providers.solving,
        &mut stats.providers.local_interest,
        &mut stats.providers.peer_interest,
    ] {
        provider.completed = 1;
        provider.service_nanos = 200_000_000;
        provider.active_nanos = 200_000_000;
        provider.cpu_nanos = Some(200_000_000 * cpu_percent / 100);
        for (cost, millis) in [
            (&mut provider.setup, 10),
            (&mut provider.work, 180),
            (&mut provider.finalization, 10),
        ] {
            cost.samples = 1;
            cost.cpu_samples = 1;
            cost.elapsed_nanos = millis * 1_000_000;
            cost.cpu_nanos = cost.elapsed_nanos * cpu_percent / 100;
            cost.peak_rss_bytes = WORKER_RSS;
        }
    }
    stats
}

fn replay(profile: Profile, cpu_millis: u64, cpu_percent: u64, feedback: bool) -> Result {
    let limits = crate::resources::limits();
    let start = Instant::now();
    let mut governor = Governor::default();
    let mut observed = hardware();
    observed.cpu_millis = cpu_millis;
    let mut queued: VecDeque<Job> = VecDeque::new();
    let mut running: Vec<Job> = Vec::new();
    let mut next = [0; 4];
    let mut latencies = Vec::new();
    let mut expired = 0;
    let mut peak_running = 0;
    let mut completed_ids = 0;
    let arrival_ms = if cpu_percent == 100 { 250 } else { 50 };
    for now in (0..400 * arrival_ms + 10_000).step_by(STEP_MS as usize) {
        if now < 400 * arrival_ms && now % arrival_ms == 0 {
            let id = now / arrival_ms;
            queued.push_back(Job {
                id,
                role: id as usize % Role::ALL.len(),
                created: now,
                expires: now + HORIZON_MS,
                allowance: WORK_UNITS,
                io_us: 200_000 * (100 - cpu_percent) / 100,
                cpu_us: 200_000 * cpu_percent / 100,
            });
        }
        queued.retain(|job| {
            let keep = job.expires > now;
            expired += usize::from(!keep);
            keep
        });
        running.retain(|job| {
            assert_eq!(job.expires, job.created + HORIZON_MS);
            assert_eq!(job.allowance, WORK_UNITS);
            if job.cpu_us == 0 && job.io_us == 0 {
                assert!(now <= job.expires);
                latencies.push(now - job.created);
                completed_ids ^= job.id;
                false
            } else if job.expires <= now {
                expired += 1;
                false
            } else {
                true
            }
        });
        let mut stats = if feedback {
            calibrated(cpu_percent)
        } else {
            Statistics::default()
        };
        let mut queued_roles = [0; 4];
        let mut running_roles = [0; 4];
        for job in &queued {
            queued_roles[job.role] += 1;
        }
        for job in &running {
            running_roles[job.role] += 1;
        }
        for (role, provider) in [
            &mut stats.providers.finding,
            &mut stats.providers.solving,
            &mut stats.providers.local_interest,
            &mut stats.providers.peer_interest,
        ]
        .into_iter()
        .enumerate()
        {
            provider.queued = queued_roles[role];
            provider.running = running_roles[role];
        }
        stats.queued_jobs = queued.len() as u64;
        stats.running_jobs = running.len() as u64;
        stats.descendant_rss = running.len() as u64 * WORKER_RSS;
        let snapshot = governor
            .update(
                selection(profile),
                observed.clone(),
                512 * MIB,
                stats,
                Pressure::default(),
                start + Duration::from_millis(now),
            )
            .unwrap();
        assert!(snapshot.budget.paused.is_none());
        let budget = &snapshot.budget;
        assert!(budget.concurrency <= limits.workers.iter().sum());
        if profile == Profile::Light {
            assert_eq!(budget.concurrency, 1);
        }
        if profile == Profile::Custom {
            assert!(budget.concurrency <= 2);
        }
        let work = operating::derive_with_statistics(limits, budget, stats);
        assert_eq!(work.job_work_units, limits.job_work_units);
        assert_eq!(work.job_horizon, limits.job_horizon);
        assert_eq!(work.proof_bytes, limits.proof_bytes);
        assert_eq!(work.request_burst, limits.request_burst);
        assert_eq!(work.replay_guard_bytes, limits.replay_guard_bytes);
        while running.len() < budget.concurrency {
            let Some(index) = queued.iter().position(|job| {
                now >= next[job.role] && running_roles[job.role] < limits.workers[job.role] as u64
            }) else {
                break;
            };
            let job = queued.remove(index).unwrap();
            next[job.role] = now
                + match job.role {
                    0 => work.finding_interval,
                    1 => work.solving_interval,
                    _ => limits.transport_busy_grace,
                }
                .as_millis() as u64;
            running_roles[job.role] += 1;
            running.push(job);
        }
        peak_running = peak_running.max(running.len());
        assert!(running.len() as u64 * WORKER_RSS + observed.process_rss <= 512 * MIB);
        // Processor sharing is an independent capacity oracle: oversubscribing
        // CPU workers cannot manufacture additional CPU time.
        let cpu_jobs = running.iter().filter(|job| job.io_us == 0).count() as u64;
        let cpu_share = (cpu_millis * STEP_MS / cpu_jobs.max(1)).min(STEP_MS * 1000);
        for job in &mut running {
            if job.io_us > 0 {
                job.io_us = job.io_us.saturating_sub(STEP_MS * 1000);
            } else {
                job.cpu_us = job.cpu_us.saturating_sub(cpu_share);
            }
        }
    }
    assert!(queued.is_empty() && running.is_empty());
    assert_eq!(latencies.len() + expired, 400);
    latencies.sort_unstable();
    Result {
        completed: latencies.len(),
        expired,
        peak_running,
        completed_ids,
        p95_latency_ms: latencies[(latencies.len() * 95 / 100).min(latencies.len() - 1)],
    }
}

#[test]
fn matched_replays_compare_configured_cadence_with_provider_feedback() {
    for profile in [
        Profile::Light,
        Profile::Dynamic,
        Profile::Heavy,
        Profile::Custom,
    ] {
        for cpu_millis in [1000, 4000] {
            for cpu_percent in [10, 100] {
                let baseline = replay(profile, cpu_millis, cpu_percent, false);
                let adaptive = replay(profile, cpu_millis, cpu_percent, true);
                println!(
                    "{}",
                    serde_json::json!({
                        "workload": "provider-feedback-replay-v1", "profile": profile,
                        "cpu_millis": cpu_millis, "cpu_percent": cpu_percent,
                        "arrivals": 400, "arrival_interval_ms": if cpu_percent == 100 { 250 } else { 50 },
                        "service_ms": 200, "original_horizon_ms": HORIZON_MS,
                        "original_work_units": WORK_UNITS,
                        "baseline": baseline, "feedback": adaptive,
                    })
                );
                if cpu_percent == 10 && matches!(profile, Profile::Dynamic | Profile::Heavy) {
                    assert!(adaptive.completed > baseline.completed);
                    assert!(adaptive.p95_latency_ms < baseline.p95_latency_ms);
                }
                if cpu_percent == 100 {
                    assert!(adaptive.peak_running <= cpu_millis.div_ceil(1000) as usize);
                    assert!(adaptive.completed >= baseline.completed);
                }
            }
        }
    }
}

#[test]
fn role_costs_cannot_override_pressure_memory_or_owner_modes() {
    let start = Instant::now();
    for profile in [
        Profile::Light,
        Profile::Dynamic,
        Profile::Heavy,
        Profile::Custom,
    ] {
        let mut governor = Governor::default();
        let mut stats = calibrated(10);
        stats.queued_jobs = 100;
        stats.providers.finding.queued = 100;
        for second in 0..10 {
            let next = governor
                .update(
                    selection(profile),
                    hardware(),
                    512 * MIB,
                    stats,
                    Pressure::default(),
                    start + Duration::from_secs(second),
                )
                .unwrap();
            if profile == Profile::Light {
                assert_eq!(next.budget.concurrency, 1);
            }
            if profile == Profile::Custom {
                assert_eq!(next.budget.concurrency, 2);
            }
        }
        let pressure = governor
            .update(
                selection(profile),
                hardware(),
                512 * MIB,
                stats,
                Pressure {
                    memory: Some(true),
                    ..Pressure::default()
                },
                start + Duration::from_secs(10),
            )
            .unwrap();
        assert_eq!(pressure.budget.concurrency, 0);
        assert_eq!(pressure.budget.batch_steps, 0);
        assert_eq!(pressure.budget.network_requests, 1);
        for second in [11, 40, 41] {
            let next = governor
                .update(
                    selection(profile),
                    hardware(),
                    512 * MIB,
                    stats,
                    Pressure {
                        memory: Some(false),
                        ..Pressure::default()
                    },
                    start + Duration::from_secs(second),
                )
                .unwrap();
            assert_eq!(next.budget.paused.is_some(), second < 41);
            if second < 41 {
                assert_eq!(next.budget.concurrency, 0);
            }
        }
        stats.providers.finding.work.peak_rss_bytes = 256 * MIB;
        let memory = governor
            .update(
                selection(Profile::Heavy),
                hardware(),
                512 * MIB,
                stats,
                Pressure::default(),
                start + Duration::from_secs(42),
            )
            .unwrap();
        assert!(memory.budget.concurrency <= 1);
    }
}
