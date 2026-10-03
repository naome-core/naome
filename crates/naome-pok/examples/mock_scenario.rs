//! Signed research inputs and real proof checking; publication and rewards are mocks.

mod support;

use std::collections::BTreeMap;
use std::io;
use std::sync::mpsc;

use naome_pok::{adapters::ResearchImport, *};
use naome_proof::ProofCertificate;

const CITATION_REWARD_NAO: u64 = 2;

#[derive(Default)]
struct Mocks {
    accepted: BTreeMap<EffectId, Effect>,
    verifications: usize,
    publications: usize,
    rewards: usize,
    balances: BTreeMap<ParticipantId, u64>,
}

impl EffectSink for Mocks {
    type Error = &'static str;
    fn deliver(&mut self, effect: Effect) -> Result<(), Self::Error> {
        if let Some(existing) = self.accepted.get(&effect.id) {
            return if *existing == effect {
                Ok(())
            } else {
                Err("effect identity conflict")
            };
        }
        match effect.kind {
            EffectKind::Verify(_) => self.verifications += 1,
            EffectKind::Publish { .. } => self.publications += 1,
            EffectKind::Reward(reward) => {
                let old = self.balances.get(&reward.beneficiary).copied().unwrap_or(0);
                let new = old
                    .checked_add(reward.amount_nao)
                    .ok_or("mock balance overflow")?;
                self.balances.insert(reward.beneficiary, new);
                self.rewards += 1;
            }
        }
        self.accepted.insert(effect.id, effect);
        Ok(())
    }
}

fn apply(import: &mut ResearchImport, mocks: &mut Mocks, input: Input) -> Applied {
    let outcome = import
        .core
        .apply(Event {
            id: import.next_event,
            input,
        })
        .unwrap();
    import.next_event.0 += 1;
    let effects: Vec<_> = import.core.pending_effects().copied().collect();
    for effect in effects {
        mocks.deliver(effect).unwrap();
        import.core.acknowledge(effect.id);
    }
    outcome
}

fn solve(
    import: &mut ResearchImport,
    mocks: &mut Mocks,
    question: QuestionId,
    solver: ParticipantId,
    submission: u64,
    certificate: ProofCertificate,
) -> Candidate {
    // Content addresses come from the actual checker, not fixture numbers.
    let checked = naome_checker::normalize_and_check(certificate).unwrap();
    let request = Candidate {
        submission: SubmissionId(submission),
        question,
        result: checked.statement_id(),
        proof: checked.proof_id(),
        solver,
    };
    apply(import, mocks, Input::Submit(request));
    let verified = import
        .verifier
        .verify(request, checked.normal_form().canonical_bytes())
        .unwrap();
    assert_eq!(
        apply(import, mocks, Input::Verified(verified.receipt())),
        Applied::Selected
    );
    import
        .verifier
        .admit_selected(&import.core, verified)
        .unwrap();
    request
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert!(
        args.is_empty() || args == ["--loop"],
        "usage: mock_scenario [--loop]"
    );
    let (source, question, keys) = support::research();
    let mut import = ResearchImport::new(
        &source,
        Config {
            top_k: 2.try_into().unwrap(),
            citation_reward_nao: CITATION_REWARD_NAO.try_into().unwrap(),
        },
    )
    .unwrap();
    let p1 = ParticipantId::for_key(keys[0].verifying_key().as_bytes());
    let p2 = ParticipantId::for_key(keys[1].verifying_key().as_bytes());
    let mut mocks = Mocks::default();
    assert_eq!(import.core.top_questions()[0], question);
    let first = solve(&mut import, &mut mocks, question, p1, 1, support::detour());
    println!(
        "P1 selected: actual canonical steps=5; research_head={:02x?}",
        import.research_head
    );
    for depth in 1..=23 {
        if depth == 4 {
            let improved = solve(&mut import, &mut mocks, question, p2, 2, support::direct());
            assert_eq!(improved.result, first.result);
            println!("P2 selected: actual canonical steps=2; future citation beneficiary=P2");
        }
        // Historical P1 references remain resolvable and pay the current solver.
        let verified = import
            .verifier
            .verify_citation(&support::citing(first.proof, depth).to_canonical_bytes())
            .unwrap();
        assert_eq!(verified.citations().len(), 1);
        assert_eq!(verified.verified_steps().get(), u64::from(depth) + 1);
        for citation in import.verifier.admit_citation(verified).unwrap() {
            apply(&mut import, &mut mocks, Input::Cite(citation));
        }
    }
    assert_eq!(mocks.balances.get(&p1), Some(&7));
    assert_eq!(mocks.balances.get(&p2), Some(&40));
    assert_eq!(
        (mocks.verifications, mocks.publications, mocks.rewards),
        (2, 2, 24)
    );
    println!("mock outcome: P1=7 NAO (1 first + 3*2 citations); P2=40 NAO (20*2 citations)");
    println!("real checker/reference inputs; mock publications=2 rewards=24; no ledger settlement");

    let (tx, rx) = mpsc::channel();
    if args.is_empty() {
        tx.send(Command::Cancel).unwrap();
    } else {
        println!("loop: cancel stops, retry retries pending effects; EOF cancels");
        std::thread::spawn(move || {
            for line in io::stdin().lines() {
                match line.as_deref() {
                    Ok("retry") => {
                        if tx.send(Command::RetryEffects).is_err() {
                            return;
                        }
                    }
                    Ok("cancel") | Err(_) => break,
                    _ => println!("commands: cancel, retry"),
                }
            }
            let _ = tx.send(Command::Cancel);
        });
    }
    let report = run(&mut import.core, &rx, &mut mocks);
    assert_eq!(report.stop, StopReason::Cancelled);
    assert!(report.rejected_inputs.is_empty());
    assert_eq!(report.failed_delivery_attempts, 0);
    assert_eq!(import.core.pending_effects().count(), 0);
    println!("stop={:?}; pending_effects=0", report.stop);
}
