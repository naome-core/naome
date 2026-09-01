use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::SigningKey;
use naome_chain::{ArtifactChainDefinition, ArtifactChainState};
use naome_consensus::{
    ActiveAgreementEntry, AgreementWeight, ConsensusContextV0, ConsensusGenesisId, ConsensusKey,
    ConsensusProtocolVersion, FixedConsensusBranchV0,
};
use sha2::{Digest as _, Sha256 as IndependentSha256};

use super::*;

static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        loop {
            let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "naome-fixed-anchor-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("temporary directory failed: {error}"),
            }
        }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn fixture() -> (ConsensusContextV0, FixedAgreementSetId, ConsensusKey) {
    let definition = ArtifactChainDefinition::new([0x31; 32]);
    let context = ConsensusContextV0::new(
        definition.id(),
        ConsensusGenesisId::from_bytes([0x42; 32]),
        ConsensusProtocolVersion::new(7),
    );
    let signing_key = SigningKey::from_bytes(&[0x53; 32]);
    let signer = ConsensusKey::from_bytes(signing_key.verifying_key().to_bytes());
    let fixed_set_id = derive_fixed_set_id(context, definition, signer);
    (context, fixed_set_id, signer)
}

fn derive_fixed_set_id(
    context: ConsensusContextV0,
    definition: ArtifactChainDefinition,
    signer: ConsensusKey,
) -> FixedAgreementSetId {
    let entries = [ActiveAgreementEntry::new(signer, AgreementWeight::new(5))];
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        context,
        &entries,
        ArtifactChainState::new(definition).branch_snapshot(),
    )
    .unwrap();
    branch.fixed_agreement_set_id()
}

#[cfg(unix)]
#[test]
fn exact_finality_anchor_roundtrips_and_advances_one_issued_transition() {
    let directory = TestDirectory::new("finality-roundtrip");
    let (context, fixed_set_id, _) = fixture();
    let mut anchor = FixedValidatorAnchorFileV0::create_finality(
        &directory.0,
        context,
        fixed_set_id,
        8,
        [0x61; 32],
    )
    .unwrap();
    let bytes = fs::read(directory.0.join(FINALITY_FILE_NAME)).unwrap();
    assert_eq!(bytes.len(), 221);
    assert_eq!(&bytes[..41], FINALITY_HEADER);
    assert_eq!(&bytes[41..73], context.chain_id().as_bytes());
    assert_eq!(&bytes[73..105], context.genesis_id().as_bytes());
    assert_eq!(&bytes[105..109], &7_u32.to_be_bytes());
    assert_eq!(&bytes[109..141], fixed_set_id.as_bytes());
    assert_eq!(&bytes[141..149], &8_u64.to_be_bytes());
    assert_eq!(&bytes[149..157], &0_u64.to_be_bytes());
    assert_eq!(&bytes[157..189], &[0x61; 32]);
    let mut expected_checksum = IndependentSha256::new();
    expected_checksum.update(b"naome:fixed-validator-finality-anchor-checksum:v0\0");
    expected_checksum.update(&bytes[..189]);
    assert_eq!(&bytes[189..221], expected_checksum.finalize().as_slice());

    let transition =
        JournalAnchorTransitionV0::new(anchor.pairing_seal(), anchor.position(), [0x71; 32])
            .unwrap();
    anchor.advance(transition).unwrap();
    assert_eq!(anchor.position().sequence, 1);
    assert_eq!(anchor.position().state_id, [0x71; 32]);

    drop(anchor);
    let reopened =
        FixedValidatorAnchorFileV0::open_finality(&directory.0, context, fixed_set_id, 8).unwrap();
    assert_eq!(reopened.position().sequence, 1);
    assert_eq!(reopened.position().state_id, [0x71; 32]);
}

#[cfg(unix)]
#[test]
fn exact_vote_anchor_is_key_bound_and_corruption_fails_strictly() {
    let directory = TestDirectory::new("vote-roundtrip");
    let (context, fixed_set_id, signer) = fixture();
    let anchor = FixedValidatorAnchorFileV0::create_vote(
        &directory.0,
        context,
        fixed_set_id,
        signer,
        16,
        [0x81; 32],
    )
    .unwrap();
    let path = directory.0.join(&anchor.file_name);
    let mut bytes = fs::read(&path).unwrap();
    assert_eq!(bytes.len(), 256);
    assert_eq!(&bytes[..44], VOTE_HEADER);
    assert_eq!(&bytes[44..76], context.chain_id().as_bytes());
    assert_eq!(&bytes[76..108], context.genesis_id().as_bytes());
    assert_eq!(&bytes[108..112], &7_u32.to_be_bytes());
    assert_eq!(&bytes[112..144], fixed_set_id.as_bytes());
    assert_eq!(&bytes[144..176], signer.as_bytes());
    assert_eq!(&bytes[176..184], &16_u64.to_be_bytes());
    assert_eq!(&bytes[184..192], &0_u64.to_be_bytes());
    assert_eq!(&bytes[192..224], &[0x81; 32]);
    let mut expected_checksum = IndependentSha256::new();
    expected_checksum.update(b"naome:fixed-validator-vote-safety-anchor-checksum:v0\0");
    expected_checksum.update(&bytes[..224]);
    assert_eq!(&bytes[224..256], expected_checksum.finalize().as_slice());
    drop(anchor);

    bytes[224] ^= 1;
    fs::write(&path, bytes).unwrap();
    assert!(matches!(
        FixedValidatorAnchorFileV0::open_vote(&directory.0, context, fixed_set_id, signer, 16,),
        Err(FixedValidatorAnchorErrorV0::ChecksumMismatch)
    ));
}

#[cfg(unix)]
#[test]
fn strict_anchor_load_rejects_missing_duplicate_wrong_binding_and_width() {
    let directory = TestDirectory::new("strict");
    let (context, fixed_set_id, signer) = fixture();
    assert!(matches!(
        FixedValidatorAnchorFileV0::open_finality(&directory.0, context, fixed_set_id, 8),
        Err(FixedValidatorAnchorErrorV0::Missing { .. })
    ));
    let anchor = FixedValidatorAnchorFileV0::create_finality(
        &directory.0,
        context,
        fixed_set_id,
        8,
        [0x91; 32],
    )
    .unwrap();
    drop(anchor);
    assert!(matches!(
        FixedValidatorAnchorFileV0::create_finality(
            &directory.0,
            context,
            fixed_set_id,
            8,
            [0x91; 32],
        ),
        Err(FixedValidatorAnchorErrorV0::AlreadyExists { .. })
    ));
    assert!(matches!(
        FixedValidatorAnchorFileV0::open_finality(&directory.0, context, fixed_set_id, 9),
        Err(FixedValidatorAnchorErrorV0::BindingMismatch)
    ));

    let path = directory.0.join(FINALITY_FILE_NAME);
    let mut bytes = fs::read(&path).unwrap();
    let position = AnchorPositionV0 {
        sequence: 0,
        state_id: [0x91; 32],
    };
    let wrong_chain_context = ConsensusContextV0::new(
        ArtifactChainDefinition::new([0x32; 32]).id(),
        context.genesis_id(),
        context.protocol_version(),
    );
    let wrong_genesis_context = ConsensusContextV0::new(
        context.chain_id(),
        ConsensusGenesisId::from_bytes([0x43; 32]),
        context.protocol_version(),
    );
    let wrong_version_context = ConsensusContextV0::new(
        context.chain_id(),
        context.genesis_id(),
        ConsensusProtocolVersion::new(8),
    );
    for wrong_context in [
        wrong_chain_context,
        wrong_genesis_context,
        wrong_version_context,
    ] {
        assert!(matches!(
            decode_bytes(
                &bytes,
                wrong_context,
                fixed_set_id,
                8,
                AnchorKindV0::Finality,
            ),
            Err(FixedValidatorAnchorErrorV0::BindingMismatch)
        ));
    }
    let other_signer = ConsensusKey::from_bytes(
        SigningKey::from_bytes(&[0x54; 32])
            .verifying_key()
            .to_bytes(),
    );
    let other_fixed_set_id = derive_fixed_set_id(
        context,
        ArtifactChainDefinition::new([0x31; 32]),
        other_signer,
    );
    assert_ne!(other_fixed_set_id, fixed_set_id);
    assert!(matches!(
        decode_bytes(
            &bytes,
            context,
            other_fixed_set_id,
            8,
            AnchorKindV0::Finality,
        ),
        Err(FixedValidatorAnchorErrorV0::BindingMismatch)
    ));

    let vote_bytes = canonical_bytes(
        context,
        fixed_set_id,
        16,
        AnchorKindV0::Vote { signer },
        position,
    );
    assert!(matches!(
        decode_bytes(
            &vote_bytes,
            wrong_chain_context,
            fixed_set_id,
            16,
            AnchorKindV0::Vote { signer },
        ),
        Err(FixedValidatorAnchorErrorV0::BindingMismatch)
    ));
    assert!(matches!(
        decode_bytes(
            &vote_bytes,
            context,
            other_fixed_set_id,
            16,
            AnchorKindV0::Vote { signer },
        ),
        Err(FixedValidatorAnchorErrorV0::BindingMismatch)
    ));
    assert!(matches!(
        decode_bytes(
            &vote_bytes,
            context,
            fixed_set_id,
            16,
            AnchorKindV0::Vote {
                signer: other_signer,
            },
        ),
        Err(FixedValidatorAnchorErrorV0::BindingMismatch)
    ));
    assert!(matches!(
        decode_bytes(
            &vote_bytes,
            context,
            fixed_set_id,
            17,
            AnchorKindV0::Vote { signer },
        ),
        Err(FixedValidatorAnchorErrorV0::BindingMismatch)
    ));

    bytes.push(0);
    fs::write(&path, bytes).unwrap();
    assert!(matches!(
        FixedValidatorAnchorFileV0::open_finality(&directory.0, context, fixed_set_id, 8),
        Err(FixedValidatorAnchorErrorV0::InvalidLength {
            expected: 221,
            actual: 222
        })
    ));

    assert!(matches!(
        FixedValidatorAnchorFileV0::open_vote(&directory.0, context, fixed_set_id, signer, 8,),
        Err(FixedValidatorAnchorErrorV0::Missing { .. })
    ));
}

#[cfg(unix)]
#[test]
fn live_anchor_locks_are_independent_by_kind_and_vote_signer() {
    let directory = TestDirectory::new("locks");
    let (context, fixed_set_id, signer) = fixture();
    let finality = FixedValidatorAnchorFileV0::create_finality(
        &directory.0,
        context,
        fixed_set_id,
        8,
        [0xa1; 32],
    )
    .unwrap();
    assert!(matches!(
        FixedValidatorAnchorFileV0::open_finality(&directory.0, context, fixed_set_id, 8),
        Err(FixedValidatorAnchorErrorV0::Locked { .. })
    ));

    let vote = FixedValidatorAnchorFileV0::create_vote(
        &directory.0,
        context,
        fixed_set_id,
        signer,
        16,
        [0xb1; 32],
    )
    .unwrap();
    let other_signer = ConsensusKey::from_bytes(
        SigningKey::from_bytes(&[0x54; 32])
            .verifying_key()
            .to_bytes(),
    );
    let other_vote = FixedValidatorAnchorFileV0::create_vote(
        &directory.0,
        context,
        fixed_set_id,
        other_signer,
        16,
        [0xc1; 32],
    )
    .unwrap();
    assert!(matches!(
        FixedValidatorAnchorFileV0::open_vote(&directory.0, context, fixed_set_id, signer, 16,),
        Err(FixedValidatorAnchorErrorV0::Locked { .. })
    ));

    drop(finality);
    drop(vote);
    drop(other_vote);
    FixedValidatorAnchorFileV0::open_finality(&directory.0, context, fixed_set_id, 8).unwrap();
    FixedValidatorAnchorFileV0::open_vote(&directory.0, context, fixed_set_id, signer, 16).unwrap();
}
