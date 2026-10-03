//! Fixed P1/P2 experiment. All checking, blocks and accounts below are mocks.

use std::collections::BTreeMap;
use std::io;
use std::sync::mpsc;

use naome_pok::*;

const Q1: QuestionId = QuestionId(1);
const R1: ResultId = ResultId(101);
const P1: ParticipantId = ParticipantId(1);
const P2: ParticipantId = ParticipantId(2);
const CITATION_REWARD_NAO: u64 = 2;
const FIRST: Candidate = Candidate {
    submission: SubmissionId(1),
    question: Q1,
    result: R1,
    proof: ProofId(1),
    solver: P1,
};
const IMPROVED: Candidate = Candidate {
    submission: SubmissionId(2),
    question: Q1,
    result: R1,
    proof: ProofId(2),
    solver: P2,
};

#[derive(Default)]
struct Mocks {
    accepted: BTreeMap<EffectId, Effect>,
    verification_requests: Vec<Candidate>,
    publications: Vec<(CurrentProof, Option<ProofId>)>,
    rewards: Vec<RewardIntent>,
    balances: BTreeMap<ParticipantId, u64>,
}

impl Mocks {
    fn receipt(request: Candidate) -> VerificationReceipt {
        let steps = match request {
            FIRST => 12,
            IMPROVED => 7,
            _ => panic!("not a fixed mock verification input"),
        };
        VerificationReceipt {
            request,
            verdict: Verdict::Valid {
                verified_steps: steps.try_into().unwrap(),
            },
        }
    }
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
            EffectKind::Verify(request) => {
                Self::receipt(request);
                self.verification_requests.push(request);
                println!("verify {:?}: {:?}", effect.id, request);
            }
            EffectKind::Publish { current, replaces } => {
                self.publications.push((current, replaces));
                println!(
                    "publish {:?}: {:?}, replaces={replaces:?}",
                    effect.id, current
                );
            }
            EffectKind::Reward(reward) => {
                let old = self.balances.get(&reward.beneficiary).copied().unwrap_or(0);
                let new = old
                    .checked_add(reward.amount_nao)
                    .ok_or("mock balance overflow")?;
                self.balances.insert(reward.beneficiary, new);
                self.rewards.push(reward);
                println!("reward {:?}: {:?}", effect.id, reward);
            }
        }
        self.accepted.insert(effect.id, effect);
        Ok(())
    }
}

fn fixed_inputs() -> Vec<Input> {
    let mut inputs = vec![
        Input::RegisterQuestion(Q1),
        Input::RegisterQuestion(QuestionId(2)),
        Input::RegisterQuestion(QuestionId(3)),
    ];
    for (question, participant) in [(Q1, P1), (Q1, P2), (QuestionId(2), P1), (QuestionId(3), P1)] {
        inputs.push(Input::Approval {
            question,
            participant,
            approved: true,
        });
    }
    inputs.extend([Input::Submit(FIRST), Input::Verified(Mocks::receipt(FIRST))]);
    for citation in 1..=3 {
        inputs.push(Input::Cite(Citation {
            citation: CitationId(citation),
            question: Q1,
            result: R1,
        }));
    }
    inputs.extend([
        Input::Submit(IMPROVED),
        Input::Verified(Mocks::receipt(IMPROVED)),
    ]);
    for citation in 4..=23 {
        inputs.push(Input::Cite(Citation {
            citation: CitationId(citation),
            question: Q1,
            result: R1,
        }));
    }
    inputs
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert!(
        args.is_empty() || args == ["--loop"],
        "usage: mock_scenario [--loop]"
    );
    let interactive = !args.is_empty();
    let (tx, rx) = mpsc::channel();
    let inputs = fixed_inputs();
    println!(
        "mock scenario: top_k=2 citation_reward_nao={CITATION_REWARD_NAO} inputs={}",
        inputs.len()
    );
    for (i, input) in inputs.into_iter().enumerate() {
        tx.send(Command::Event(Event {
            id: EventId(i as u64 + 1),
            input,
        }))
        .unwrap();
    }
    if interactive {
        println!("loop: type cancel to stop cleanly, retry to retry pending effects; EOF cancels");
        std::thread::spawn(move || {
            for line in io::stdin().lines() {
                match line.as_deref() {
                    Ok("retry") => {
                        if tx.send(Command::RetryEffects).is_err() {
                            return;
                        }
                    }
                    Ok("cancel") | Err(_) => break,
                    _ => eprintln!("expected cancel or retry"),
                }
            }
            let _ = tx.send(Command::Cancel);
        });
    } else {
        tx.send(Command::Cancel).unwrap();
    }
    let mut core = Orchestrator::new(Config {
        top_k: 2.try_into().unwrap(),
        citation_reward_nao: CITATION_REWARD_NAO.try_into().unwrap(),
    });
    let mut mocks = Mocks::default();
    let report = run(&mut core, &rx, &mut mocks);
    assert_eq!(report.stop, StopReason::Cancelled);
    assert!(report.rejected_inputs.is_empty());
    assert_eq!(report.failed_delivery_attempts, 0);
    assert_eq!(core.pending_effects().count(), 0);
    assert_eq!(core.current(Q1).unwrap().candidate, IMPROVED);
    assert_eq!(mocks.verification_requests, [FIRST, IMPROVED]);
    assert_eq!(mocks.publications.len(), 2);
    assert_eq!(mocks.publications[0].1, None);
    assert_eq!(mocks.publications[1].1, Some(FIRST.proof));
    assert_eq!(mocks.rewards.len(), 24);
    assert_eq!(
        mocks.rewards[0],
        RewardIntent {
            beneficiary: P1,
            amount_nao: 1,
            reason: RewardReason::FirstSolution(Q1)
        }
    );
    for (i, reward) in mocks.rewards.iter().skip(1).enumerate() {
        assert_eq!(
            reward.reason,
            RewardReason::Citation(CitationId(i as u64 + 1))
        );
        assert_eq!(reward.beneficiary, if i < 3 { P1 } else { P2 });
        assert_eq!(reward.amount_nao, CITATION_REWARD_NAO);
    }
    assert_eq!(mocks.balances.get(&P1), Some(&7));
    assert_eq!(mocks.balances.get(&P2), Some(&40));
    println!(
        "PASS: initial_awards=1 P1_citations=3 P2_citations=20 publications=2 P1_mock_nao=7 P2_mock_nao=40 stop={:?}",
        report.stop
    );
}
