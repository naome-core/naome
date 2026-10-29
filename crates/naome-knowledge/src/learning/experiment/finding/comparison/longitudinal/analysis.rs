//! Paired whole-family inference with initialization seeds kept explicit.
use super::*;
const CELLS: usize = 3 * 3 * 6 * 3 * 3 * 2 * 6;
fn index(
    seed: usize,
    arm: usize,
    phase: usize,
    track: usize,
    band: usize,
    half: usize,
    family: usize,
) -> usize {
    (((((seed * 3 + arm) * 6 + phase) * 3 + track) * 3 + band) * 2 + half) * 6 + family
}
#[derive(Clone, Copy)]
struct Contrast {
    phase: usize,
    control: Option<usize>,
    track: usize,
    band: usize,
    half: usize,
}
fn contrasts() -> Vec<Contrast> {
    let mut output = Vec::new();
    for phase in 1..=PHASES {
        for track in 0..3 {
            for band in 0..3 {
                for half in 0..2 {
                    output.push(Contrast {
                        phase,
                        control: None,
                        track,
                        band,
                        half,
                    });
                }
            }
        }
    }
    for control in 1..3 {
        for track in 0..3 {
            for band in 0..3 {
                for half in 0..2 {
                    output.push(Contrast {
                        phase: PHASES,
                        control: Some(control),
                        track,
                        band,
                        half,
                    });
                }
            }
        }
    }
    output
}
fn net(data: &[u8], c: Contrast, seeds: &[usize; 3], families: &[usize; 6]) -> i32 {
    let (arm, phase) = c.control.map_or((0, c.phase - 1), |arm| (arm, PHASES));
    seeds
        .iter()
        .flat_map(|s| families.iter().map(move |f| (*s, *f)))
        .map(|(s, f)| {
            i32::from(data[index(s, 0, c.phase, c.track, c.band, c.half, f)])
                - i32::from(data[index(s, arm, phase, c.track, c.band, c.half, f)])
        })
        .sum()
}
struct Random(u64);
impl Random {
    fn sample(&mut self, n: usize) -> usize {
        loop {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            let ceiling = u64::MAX - u64::MAX % (n as u64);
            if self.0 < ceiling {
                return (self.0 % n as u64) as usize;
            }
        }
    }
}
fn critical(data: &[u8], contrasts: &[Contrast], observed: &[i32]) -> i32 {
    let mut rng = Random(2_901_029);
    let mut deviations = Vec::with_capacity(20_000);
    for _ in 0..20_000 {
        let seeds = std::array::from_fn(|_| rng.sample(3));
        let families: [[[[usize; 6]; 2]; 3]; 3] = std::array::from_fn(|_| {
            std::array::from_fn(|_| std::array::from_fn(|_| std::array::from_fn(|_| rng.sample(6))))
        });
        deviations.push(
            contrasts
                .iter()
                .zip(observed)
                .map(|(c, point)| {
                    (net(data, *c, &seeds, &families[c.track][c.band][c.half]) - point).abs()
                })
                .max()
                .unwrap(),
        );
    }
    deviations.sort_unstable();
    deviations[18_999]
}
fn frontier(data: &[u8], seed: usize, arm: usize, phase: usize, track: usize) -> usize {
    (0..3)
        .take_while(|band| {
            (0..2).all(|half| {
                (0..6)
                    .map(|f| u32::from(data[index(seed, arm, phase, track, *band, half, f)]))
                    .sum::<u32>()
                    >= 9
            })
        })
        .count()
}
pub(super) fn summarize(rows: &[Value]) -> Result<Value, String> {
    if rows.len() != 9 {
        return Err("analysis requires three independent seeds and all controls".into());
    }
    let mut data = vec![0; CELLS];
    let mut seen = BTreeMap::new();
    let mut family_binding = BTreeMap::new();
    for result in rows {
        let seed = SEEDS
            .iter()
            .position(|s| result["seed"] == *s)
            .ok_or("unknown analysis seed")?;
        let arm = match Arm::read(result["arm"].as_str().ok_or("analysis arm absent")?)? {
            Arm::Adaptive => 0,
            Arm::FrozenWeights => 1,
            Arm::FixedChoices => 2,
        };
        if result["complete"] != true
            || result["optimizer_updates"] != 0
            || result["feedback_events"] != 0
        {
            return Err("assessment is incomplete or fed back outcomes".into());
        }
        for p in result["phases"]
            .as_array()
            .ok_or("assessment phases absent")?
        {
            let phase = p["phase"].as_u64().ok_or("phase absent")? as usize;
            if phase > PHASES {
                return Err("assessment phase out of range".into());
            }
            for row in p["rows"].as_array().ok_or("assessment rows absent")? {
                let cell = &row["cell"];
                let get = |v: &Value, k: &str| {
                    v[k].as_u64()
                        .map(|n| n as usize)
                        .ok_or_else(|| format!("analysis cell {k} absent"))
                };
                let t = get(&cell["case"], "track")?;
                let b = get(cell, "band")?;
                let h = get(cell, "half")?;
                let f = get(cell, "family_index")?;
                let v = get(&cell["case"], "variant")?;
                if t >= 3
                    || b >= 3
                    || h >= 2
                    || f >= 6
                    || v >= 2
                    || seen
                        .insert(
                            (seed, arm, phase, t, b, h, f, v),
                            row["solved"].as_bool().ok_or("assessment outcome absent")?,
                        )
                        .is_some()
                {
                    return Err("assessment duplicate or invalid family cell".into());
                }
                let identity = json!([cell["case"]["construction"], cell["case"]["resolution"]]);
                if identity.as_array().unwrap().iter().any(Value::is_null) {
                    return Err("assessment family identity absent".into());
                }
                if let Some(prior) = family_binding.insert((t, b, h, f, v), identity.clone())
                    && prior != identity
                {
                    return Err("assessment panel changed across seeds, arms or phases".into());
                }
                data[index(seed, arm, phase, t, b, h, f)] +=
                    u8::from(row["solved"].as_bool().ok_or("assessment outcome absent")?);
            }
        }
    }
    if seen.len() != CELLS * 2 {
        return Err("assessment matrix lacks complete paired whole-family coverage".into());
    }
    let comparisons = contrasts();
    let observed = comparisons
        .iter()
        .map(|c| net(&data, *c, &[0, 1, 2], &[0, 1, 2, 3, 4, 5]))
        .collect::<Vec<_>>();
    let radius = critical(&data, &comparisons, &observed);
    let intervals=comparisons.iter().zip(&observed).map(|(c,point)|json!({"phase":c.phase,"control":c.control,"track":c.track,"band":c.band,"half":c.half,"net_observations":point,"denominator":36,"simultaneous_lower_net":point-radius,"simultaneous_upper_net":point+radius})).collect::<Vec<_>>();
    let mut profiles = Vec::new();
    for (seed, seed_id) in SEEDS.iter().enumerate() {
        for arm in 0..3 {
            for phase in 0..=PHASES {
                profiles.push(json!({"seed":seed_id,"arm":arm,"phase":phase,"frontier":(0..3).map(|t|frontier(&data,seed,arm,phase,t)).collect::<Vec<_>>() }));
            }
        }
    }
    let mut retention = Vec::new();
    for (seed, seed_id) in SEEDS.iter().enumerate() {
        for arm in 0..3 {
            for phase in 1..=PHASES {
                let mut initial_lost = 0;
                let mut previous_lost = 0;
                let mut recovered = 0;
                for t in 0..3 {
                    for b in 0..3 {
                        for h in 0..2 {
                            for f in 0..6 {
                                for v in 0..2 {
                                    let now = seen[&(seed, arm, phase, t, b, h, f, v)];
                                    let before = seen[&(seed, arm, phase - 1, t, b, h, f, v)];
                                    initial_lost +=
                                        usize::from(seen[&(seed, arm, 0, t, b, h, f, v)] && !now);
                                    previous_lost += usize::from(before && !now);
                                    recovered += usize::from(
                                        now && !before
                                            && (0..phase - 1)
                                                .any(|p| seen[&(seed, arm, p, t, b, h, f, v)]),
                                    );
                                }
                            }
                        }
                    }
                }
                retention.push(json!({"seed":seed_id,"arm":arm,"phase":phase,"initial_successes_lost":initial_lost,"previous_phase_successes_lost":previous_lost,"earlier_successes_recovered":recovered,
                "recovery_cost":"Whole phase acquisition/training/checkpoint costs are recorded separately; no family-specific recovery-cost attribution is measured."}));
            }
        }
    }
    let mut confirmed = Vec::new();
    for phase in 1..=PHASES {
        for t in 0..3 {
            for b in 0..3 {
                let replicated = (0..3).all(|s| {
                    frontier(&data, s, 0, phase - 1, t) <= b
                        && frontier(&data, s, 0, phase, t) > b
                        && frontier(&data, s, 0, PHASES, t) > b
                });
                let positive = (0..2).all(|h| {
                    observed[comparisons
                        .iter()
                        .position(|c| {
                            c.control.is_none()
                                && c.phase == phase
                                && c.track == t
                                && c.band == b
                                && c.half == h
                        })
                        .unwrap()]
                        > radius
                });
                if replicated && positive {
                    confirmed.push(json!({"phase":phase,"track":t,"band":b}));
                }
            }
        }
    }
    let boundaries = confirmed
        .iter()
        .map(|c| c["phase"].as_u64().unwrap())
        .collect::<BTreeSet<_>>();
    let controls=(1..3).map(|control| {
        let differences=(0..3).map(|s|(0..3).map(|t|frontier(&data,s,0,PHASES,t) as i32-frontier(&data,s,control,PHASES,t) as i32).sum::<i32>()).collect::<Vec<_>>();
        // A band advantage must also have positive simultaneous solve-rate
        // evidence in each half; ceiling cells cannot manufacture significance.
        let supported=(0..3).any(|t|(0..3).any(|b|(0..3).all(|s|frontier(&data,s,0,PHASES,t)>b && frontier(&data,s,control,PHASES,t)<=b) && (0..2).all(|h|observed[comparisons.iter().position(|c|c.control==Some(control)&&c.track==t&&c.band==b&&c.half==h).unwrap()]>radius)));
        json!({"control":control,"per_seed_track_band_difference":differences,"qualifies":differences.iter().all(|d|*d>=0)&&differences.iter().sum::<i32>()>=3&&supported})
    }).collect::<Vec<_>>();
    Ok(
        json!({"raw_solved_variants_by_seed_arm_phase_track_band_half_family":data,
        "simultaneous_comparisons":intervals,"integer_critical_net":radius,"fixed_denominator":36,
        "frontier_profiles":profiles,"retention_loss_recovery":retention,"confirmed_advances":confirmed,"confirmed_distinct_phase_boundaries":boundaries.len(),
        "frontier_criterion_met":boundaries.len()>=3,"control_comparisons":controls,
        "limitations":"Only three initialization seeds; operational calibrated demands and finite bounded evidence. Retention/loss/recovery and causal probes remain separate outcomes. Efficiency is not qualified by this analysis."}),
    )
}

#[test]
fn zero_net_remains_exactly_zero_and_a_ceiling_cannot_confirm_an_advance() {
    let data = vec![2; CELLS];
    let comparisons = contrasts();
    assert_eq!(comparisons.len(), 126);
    let observed = comparisons
        .iter()
        .map(|c| net(&data, *c, &[0, 1, 2], &[0, 1, 2, 3, 4, 5]))
        .collect::<Vec<_>>();
    assert!(observed.iter().all(|n| *n == 0));
    assert_eq!(critical(&data, &comparisons, &observed), 0);
    assert_eq!(frontier(&data, 0, 0, 0, 0), 3);
}
