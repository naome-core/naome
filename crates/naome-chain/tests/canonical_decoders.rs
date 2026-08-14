use naome_chain::{
    ArtifactBlock, ArtifactBlockId, ArtifactChainDefinition, ArtifactDag, ArtifactSetProof,
    ArtifactSetRoot,
};
use naome_foundation::{Formula, FreeVariable};
use naome_proof::{
    ArtifactId, ArtifactPayload, DefinedFormula, DefinitionCertificate, ProofCertificate, ProofStep,
};

const RANDOM_CASES: usize = 2_048;
const RANDOM_MAX_BYTES: usize = 4_096;

#[test]
fn canonical_decoders_round_trip_deterministic_malformed_inputs() {
    for seed in canonical_seeds() {
        assert_accepted_values_reencode_exactly(&seed);

        for end in 0..seed.len() {
            assert_accepted_values_reencode_exactly(&seed[..end]);
        }

        for index in 0..seed.len() {
            let mut removed = seed.clone();
            removed.remove(index);
            assert_accepted_values_reencode_exactly(&removed);

            for bit in 0..u8::BITS {
                let mut flipped = seed.clone();
                flipped[index] ^= 1 << bit;
                assert_accepted_values_reencode_exactly(&flipped);
            }
        }

        for byte in [0x00, 0xff] {
            let mut extended = seed.clone();
            extended.push(byte);
            assert_accepted_values_reencode_exactly(&extended);
        }
    }

    let mut state = 0x006e_616f_6d65_u64;
    for case in 0..RANDOM_CASES {
        let length = case * RANDOM_MAX_BYTES / (RANDOM_CASES - 1);
        let mut bytes = vec![0; length];
        for byte in &mut bytes {
            state = xorshift64(state);
            *byte = state as u8;
        }
        assert_accepted_values_reencode_exactly(&bytes);
    }
}

fn canonical_seeds() -> [Vec<u8>; 7] {
    let formula = Formula::equal(FreeVariable::new(0), FreeVariable::new(1));
    let certificate = ProofCertificate::new(vec![ProofStep::EqualityReflexivity {
        variable: FreeVariable::new(1),
    }])
    .unwrap();
    let block = ArtifactBlock::new(
        ArtifactBlockId::from_bytes([0x44; 32]),
        ArtifactSetRoot::from_bytes([0x11; 32]),
        ArtifactSetRoot::from_bytes([0x22; 32]),
        ArtifactId::from_bytes([0x33; 32]),
    );
    let artifact_set = ArtifactDag::new().artifact_set_proof(ArtifactId::from_bytes([0x55; 32]));
    let chain_definition = ArtifactChainDefinition::new([0x66; 32]);
    let proof_payload = ArtifactPayload::Proof(certificate.clone());
    let relation = DefinitionCertificate::relation(
        1,
        DefinedFormula::equal(FreeVariable::new(0), FreeVariable::new(0)),
    )
    .unwrap();
    let definition_payload = ArtifactPayload::Definition(relation);

    [
        formula.encode_canonical().unwrap(),
        certificate.to_canonical_bytes(),
        proof_payload.to_canonical_bytes(),
        definition_payload.to_canonical_bytes(),
        block.to_canonical_bytes().to_vec(),
        artifact_set.to_canonical_bytes(),
        chain_definition.to_canonical_bytes().to_vec(),
    ]
}

fn assert_accepted_values_reencode_exactly(bytes: &[u8]) {
    if let Ok(formula) = Formula::decode_canonical(bytes) {
        assert_eq!(formula.encode_canonical().as_deref(), Ok(bytes));
    }
    if let Ok(certificate) = ProofCertificate::from_canonical_bytes(bytes) {
        assert_eq!(certificate.to_canonical_bytes(), bytes);
    }
    if let Ok(payload) = ArtifactPayload::from_canonical_bytes(bytes) {
        assert_eq!(payload.to_canonical_bytes(), bytes);
    }
    if let Ok(block) = ArtifactBlock::from_canonical_bytes(bytes) {
        assert_eq!(block.to_canonical_bytes().as_slice(), bytes);
    }
    if let Ok(proof) = ArtifactSetProof::from_canonical_bytes(bytes) {
        assert_eq!(proof.to_canonical_bytes(), bytes);
    }
    if let Ok(definition) = ArtifactChainDefinition::from_canonical_bytes(bytes) {
        assert_eq!(definition.to_canonical_bytes().as_slice(), bytes);
    }
}

const fn xorshift64(mut state: u64) -> u64 {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    state
}
