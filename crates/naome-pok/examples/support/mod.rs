use ed25519_dalek::SigningKey;
use naome_foundation::{Formula, FreeVariable};
use naome_pok::QuestionId;
use naome_proof::{ProofCertificate, ProofId, ProofStep};
use naome_research::{
    formal::FormulaInput,
    state::{Action, Genesis, PoolConfig, Question, ResearchState, SignedAction, SignedGenesis},
};

pub fn research() -> (ResearchState, QuestionId, [SigningKey; 2]) {
    let coordinator = SigningKey::from_bytes(&[99; 32]);
    let participants = [
        SigningKey::from_bytes(&[1; 32]),
        SigningKey::from_bytes(&[2; 32]),
    ];
    let genesis = Genesis::new(
        "pok-integration-fixture".into(),
        coordinator.verifying_key().to_bytes(),
        participants
            .iter()
            .map(|key| key.verifying_key().to_bytes())
            .collect(),
        PoolConfig::default(),
    )
    .unwrap();
    let mut state =
        ResearchState::new(SignedGenesis::sign(genesis, &coordinator).unwrap()).unwrap();
    let mut first = None;
    for depth in 1..=3 {
        let mut formula = FormulaInput::Equal { left: 0, right: 0 };
        for variable in 0..depth {
            formula = FormulaInput::Forall {
                variable,
                body: Box::new(formula),
            };
        }
        let question = Question {
            title: format!("Identity at depth {depth}"),
            context: "Signed local integration fixture".into(),
            formula,
            definitions: Vec::new(),
        };
        let id = question.id().unwrap();
        if depth == 1 {
            first = Some(QuestionId(id));
        }
        confirm(
            &mut state,
            &coordinator,
            &participants[0],
            Action::Publish { question },
        );
        confirm(
            &mut state,
            &coordinator,
            &participants[0],
            Action::Vote {
                question: id,
                yes: true,
            },
        );
        if depth == 1 {
            confirm(
                &mut state,
                &coordinator,
                &participants[1],
                Action::Vote {
                    question: id,
                    yes: true,
                },
            );
        }
    }
    (state, first.unwrap(), participants)
}

pub fn confirm(
    state: &mut ResearchState,
    coordinator: &SigningKey,
    key: &SigningKey,
    action: Action,
) {
    let signed = SignedAction::sign(
        state.genesis().genesis.id(),
        state.next_nonce(key.verifying_key().to_bytes()),
        action,
        key,
    );
    state.confirm(signed, coordinator).unwrap();
}

pub fn direct() -> ProofCertificate {
    ProofCertificate::new(vec![
        ProofStep::EqualityReflexivity {
            variable: FreeVariable::new(0),
        },
        ProofStep::Generalization {
            premise: 0,
            variable: FreeVariable::new(0),
        },
    ])
    .unwrap()
}

pub fn detour() -> ProofCertificate {
    let variable = FreeVariable::new(0);
    let formula = Formula::equal(variable, variable);
    ProofCertificate::new(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Simplification {
            antecedent: formula.clone().into(),
            consequent: formula.into(),
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 2,
        },
        ProofStep::Generalization {
            premise: 3,
            variable,
        },
    ])
    .unwrap()
}

pub fn citing(proof_id: ProofId, depth: u32) -> ProofCertificate {
    let mut steps = vec![ProofStep::ProofReference { proof_id }];
    for n in 0..depth {
        steps.push(ProofStep::Generalization {
            premise: n,
            variable: FreeVariable::new(100 + n),
        });
    }
    ProofCertificate::new(steps).unwrap()
}
