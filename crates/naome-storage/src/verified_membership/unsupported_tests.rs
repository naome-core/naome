use super::*;
use naome_chain::{ArtifactChainDefinition, ArtifactChainState};

#[test]
fn unsupported_membership_owner_refuses_before_creating_or_locking_any_file() {
    let root = std::env::temp_dir().join(format!("membership-unsupported-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let journal = root.join("journal");
    let anchor = root.join("anchor");
    fs::create_dir(&journal).unwrap();
    fs::create_dir(&anchor).unwrap();
    let members = (1..=4)
        .map(|id| {
            let keys: [SigningKey; 3] = std::array::from_fn(|role| {
                let mut seed = [id; 32];
                seed[0] = role as u8;
                SigningKey::from_bytes(&seed)
            });
            Member {
                organization: [id; 32],
                consensus_key: keys[0].verifying_key().to_bytes(),
                approval_key: keys[1].verifying_key().to_bytes(),
                network_key: keys[2].verifying_key().to_bytes(),
            }
        })
        .collect();
    let genesis = MembershipBranch::genesis(
        ArtifactChainState::new(ArtifactChainDefinition::new([67; 32])).branch_snapshot(),
        members,
    )
    .unwrap();
    let limits = MembershipJournalLimits {
        maximum_round: 64,
        maximum_records: 1000,
        maximum_bytes: 100_000_000,
    };
    let mut seed = [1; 32];
    seed[0] = 0;
    for key in [None, Some(SigningKey::from_bytes(&seed))] {
        for open in [
            MembershipJournal::create,
            MembershipJournal::open,
            MembershipJournal::recover_pair,
        ] {
            assert!(matches!(
                open(&journal, &anchor, genesis.clone(), key.clone(), limits),
                Err(MembershipJournalError::UnsupportedDurableDirectorySync)
            ));
            assert_eq!(fs::read_dir(&journal).unwrap().count(), 0);
            assert_eq!(fs::read_dir(&anchor).unwrap().count(), 0);
        }
    }
    fs::remove_dir_all(root).unwrap();
}
