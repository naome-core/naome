use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use naome_chain::ArtifactChainDefinition;
use naome_consensus::{
    ActiveAgreementEntry, AgreementWeight, ConsensusContextV0, ConsensusGenesisId, ConsensusKey,
    ConsensusProtocolVersion,
};
use naome_storage::{
    FixedValidatorAnchorErrorV0, FixedValidatorAnchoredFinalityJournalErrorV0,
    FixedValidatorFinalityReplayLimitV0, FixedValidatorSignerRecoveryRoundLimitV0,
    FixedValidatorVoteSafetyReplayLimitV0,
};

use super::*;

#[test]
fn non_unix_anchor_startup_is_typed_unsupported_and_never_ready() {
    let sequence = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = env::temp_dir().join(format!(
        "naome-node-unsupported-{}-{sequence}",
        std::process::id()
    ));
    let finality_journal = root.join("finality-journal");
    let finality_anchor = root.join("finality-anchor");
    let vote_journal = root.join("vote-journal");
    let vote_anchor = root.join("vote-anchor");
    for directory in [
        &finality_journal,
        &finality_anchor,
        &vote_journal,
        &vote_anchor,
    ] {
        fs::create_dir_all(directory).unwrap();
    }

    let definition = ArtifactChainDefinition::new([0x51; 32]);
    let context = ConsensusContextV0::new(
        definition.id(),
        ConsensusGenesisId::from_bytes([0x52; 32]),
        ConsensusProtocolVersion::new(7),
    );
    let signing_key = SigningKey::from_bytes(&[0x53; 32]);
    let entries = [ActiveAgreementEntry::new(
        ConsensusKey::from_bytes(signing_key.verifying_key().to_bytes()),
        AgreementWeight::new(1),
    )];
    let provision = FixedValidatorNodeProvisionV0::new(
        definition,
        context,
        &entries,
        FixedValidatorNodeDirectoriesV0::new(
            &finality_journal,
            &finality_anchor,
            &vote_journal,
            &vote_anchor,
        ),
        FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        FixedValidatorVoteSafetyReplayLimitV0::new(8).unwrap(),
        FixedValidatorSignerRecoveryRoundLimitV0::new(8),
        FixedValidatorSignerCatchUpHeightLimitV0::new(8),
    );
    assert!(matches!(
        provision.create(signing_key),
        Err(FixedValidatorNodeStartupErrorV0::FinalityPair(source))
            if matches!(
                source.as_ref(),
                FixedValidatorAnchoredFinalityJournalErrorV0::Anchor(
                    FixedValidatorAnchorErrorV0::UnsupportedDurableDirectorySync
                )
            )
    ));
    fs::remove_dir_all(root).unwrap();
}
