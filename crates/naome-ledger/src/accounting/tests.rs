use super::*;
use crate::test_support::{account, genesis};

fn author(i: u8) -> AccountId {
    AccountId::for_key(account(i).verifying_key().as_bytes())
}

#[test]
fn no_citations_preserves_exact_supply() {
    let genesis = genesis();
    let plan = RewardPlan::new(&genesis, author(4), vec![]).unwrap();
    assert_eq!(plan.credits()[&author(4)], 700_000_000);
    for i in 0..4 {
        assert_eq!(plan.credits()[&author(i)], 50_000_000);
    }
    assert_eq!(plan.reserve(), 100_000_000);
    let mut balances = Balances::new(&genesis);
    for count in 1..=12 {
        balances.apply(&plan, &genesis).unwrap();
        assert_eq!(balances.paid_completions(), count);
        balances.verify_conservation(&genesis).unwrap();
    }
}

#[test]
fn division_precedes_shared_recipient_aggregation() {
    let genesis = genesis();
    let citations = vec![
        CitationRecipient {
            proof: ProofId::from_bytes([3; 32]),
            recipient: author(5),
        },
        CitationRecipient {
            proof: ProofId::from_bytes([1; 32]),
            recipient: author(5),
        },
        CitationRecipient {
            proof: ProofId::from_bytes([2; 32]),
            recipient: author(4),
        },
    ];
    let plan = RewardPlan::new(&genesis, author(4), citations).unwrap();
    assert_eq!(
        plan.citations().iter().map(|x| x.2).collect::<Vec<_>>(),
        vec![33_333_334, 33_333_333, 33_333_333]
    );
    assert_eq!(plan.credits()[&author(4)], 633_333_333);
    assert_eq!(plan.credits()[&author(5)], 66_666_667);
    let mut balances = Balances::new(&genesis);
    balances.apply(&plan, &genesis).unwrap();
    balances.verify_conservation(&genesis).unwrap();
}

#[test]
fn duplicate_or_unknown_recipients_cannot_gain_payments() {
    let genesis = genesis();
    let citation = CitationRecipient {
        proof: ProofId::from_bytes([1; 32]),
        recipient: author(4),
    };
    assert!(RewardPlan::new(&genesis, author(4), vec![citation, citation]).is_err());
    assert!(RewardPlan::new(&genesis, author(9), vec![]).is_err());
    assert!(
        RewardPlan::new(
            &genesis,
            author(4),
            vec![CitationRecipient {
                recipient: author(9),
                ..citation
            }]
        )
        .is_err()
    );
}

#[test]
fn arithmetic_failure_keeps_all_balances_unchanged() {
    let genesis = genesis();
    let plan = RewardPlan::new(&genesis, author(4), vec![]).unwrap();
    let mut balances = Balances::new(&genesis);
    balances.accounts.insert(author(4), u128::MAX);
    let before = balances.clone();
    assert!(balances.apply(&plan, &genesis).is_err());
    assert_eq!(balances, before);
    let mut balances = Balances::new(&genesis);
    balances.paid_completions = u64::MAX;
    let before = balances.clone();
    assert!(balances.apply(&plan, &genesis).is_err());
    assert_eq!(balances, before);
}
