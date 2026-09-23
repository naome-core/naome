use super::*;
use crate::test_support::{account, genesis};

fn genesis_rewards(
    genesis: &Genesis,
    author: AccountId,
    citations: Vec<CitationRecipient>,
) -> Result<RewardPlan, LedgerError> {
    let authority = AuthoritySnapshot::from_genesis(genesis)?;
    RewardPlan::new(genesis, &authority, author, citations)
}

fn author(i: u8) -> AccountId {
    AccountId::for_key(account(i).verifying_key().as_bytes())
}

fn registry(genesis: &Genesis) -> BTreeMap<AccountId, [u8; 32]> {
    genesis
        .accounts()
        .iter()
        .map(|a| (a.id(), *a.key()))
        .collect()
}

#[test]
fn no_citations_preserves_exact_supply() {
    let genesis = genesis();
    let registry = registry(&genesis);
    let plan = genesis_rewards(&genesis, author(4), vec![]).unwrap();
    assert_eq!(plan.credits()[&author(4)], 700_000_000);
    for i in 0..4 {
        assert_eq!(plan.credits()[&author(i)], 50_000_000);
    }
    assert_eq!(plan.reserve(), 100_000_000);
    let mut balances = Balances::new(&genesis);
    for count in 1..=12 {
        balances.apply(&plan, &genesis, &registry).unwrap();
        assert_eq!(balances.paid_completions(), count);
        balances.verify_conservation(&genesis, &registry).unwrap();
    }
}

#[test]
fn division_precedes_shared_recipient_aggregation() {
    let genesis = genesis();
    let registry = registry(&genesis);
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
    let plan = genesis_rewards(&genesis, author(4), citations).unwrap();
    assert_eq!(
        plan.citations().iter().map(|x| x.2).collect::<Vec<_>>(),
        vec![33_333_334, 33_333_333, 33_333_333]
    );
    assert_eq!(plan.credits()[&author(4)], 633_333_333);
    assert_eq!(plan.credits()[&author(5)], 66_666_667);
    let mut balances = Balances::new(&genesis);
    balances.apply(&plan, &genesis, &registry).unwrap();
    balances.verify_conservation(&genesis, &registry).unwrap();
}

#[test]
fn duplicate_or_unknown_recipients_cannot_gain_payments() {
    let genesis = genesis();
    let registry = registry(&genesis);
    let citation = CitationRecipient {
        proof: ProofId::from_bytes([1; 32]),
        recipient: author(4),
    };
    assert!(genesis_rewards(&genesis, author(4), vec![citation, citation]).is_err());
    let plans = [
        genesis_rewards(&genesis, author(9), vec![]).unwrap(),
        genesis_rewards(
            &genesis,
            author(4),
            vec![CitationRecipient {
                recipient: author(9),
                ..citation
            }],
        )
        .unwrap(),
    ];
    for plan in plans {
        let mut balances = Balances::new(&genesis);
        let before = balances.clone();
        assert!(balances.apply(&plan, &genesis, &registry).is_err());
        assert_eq!(balances, before);
    }
}

#[test]
fn arithmetic_failure_keeps_all_balances_unchanged() {
    let genesis = genesis();
    let registry = registry(&genesis);
    let plan = genesis_rewards(&genesis, author(4), vec![]).unwrap();
    let mut balances = Balances::new(&genesis);
    balances.accounts.insert(author(4), u128::MAX);
    let before = balances.clone();
    assert!(balances.apply(&plan, &genesis, &registry).is_err());
    assert_eq!(balances, before);
    let mut balances = Balances::new(&genesis);
    balances.paid_completions = u64::MAX;
    let before = balances.clone();
    assert!(balances.apply(&plan, &genesis, &registry).is_err());
    assert_eq!(balances, before);
}

#[test]
fn new_registered_accounts_start_empty_and_receive_author_and_citation_rewards() {
    let genesis = genesis();
    let mut registry = registry(&genesis);
    let mut balances = Balances::new(&genesis);
    for index in [8, 9] {
        balances.register(author(index)).unwrap();
        registry.insert(author(index), account(index).verifying_key().to_bytes());
        assert_eq!(balances.account(author(index)), Some(0));
    }
    balances.verify_conservation(&genesis, &registry).unwrap();
    assert_eq!(balances.paid_completions(), 0);
    assert_eq!(balances.reserve(), 0);
    let first = genesis_rewards(&genesis, author(8), vec![]).unwrap();
    balances.apply(&first, &genesis, &registry).unwrap();
    let second = genesis_rewards(
        &genesis,
        author(9),
        vec![CitationRecipient {
            proof: ProofId::from_bytes([1; 32]),
            recipient: author(8),
        }],
    )
    .unwrap();
    balances.apply(&second, &genesis, &registry).unwrap();
    assert_eq!(balances.account(author(8)), Some(800_000_000));
    assert_eq!(balances.account(author(9)), Some(600_000_000));
    balances.verify_conservation(&genesis, &registry).unwrap();
    let before = balances.clone();
    assert!(balances.register(author(8)).is_err());
    assert_eq!(balances, before);
}

#[test]
fn exact_registry_membership_is_required_even_for_zero_balances() {
    let genesis = genesis();
    let mut registry = registry(&genesis);
    let mut balances = Balances::new(&genesis);
    balances.register(author(9)).unwrap();
    assert!(balances.verify_conservation(&genesis, &registry).is_err());
    let plan = genesis_rewards(&genesis, author(9), vec![]).unwrap();
    let before = balances.clone();
    assert!(balances.apply(&plan, &genesis, &registry).is_err());
    assert_eq!(balances, before);
    registry.insert(author(9), account(9).verifying_key().to_bytes());
    balances.verify_conservation(&genesis, &registry).unwrap();
    registry.insert(author(8), account(8).verifying_key().to_bytes());
    assert!(balances.verify_conservation(&genesis, &registry).is_err());
    assert!(balances.register(author(4)).is_err());
    assert_eq!(balances, before);
}
