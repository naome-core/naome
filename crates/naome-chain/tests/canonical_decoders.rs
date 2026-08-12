use naome_chain::{
    ProofBlock, ProofBlockId, ProofChainDefinition, ProofDag, ProofSetProof, ProofSetRoot,
    ProofTransition,
};
use naome_foundation::{Formula, FreeVariable};
use naome_proof::{ProofCertificate, ProofId, ProofStep};

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

fn canonical_seeds() -> [Vec<u8>; 6] {
    let formula = Formula::equal(FreeVariable::new(0), FreeVariable::new(1));
    let certificate = ProofCertificate::new(vec![ProofStep::EqualityReflexivity {
        variable: FreeVariable::new(1),
    }])
    .unwrap();
    let transition = ProofTransition::new(
        ProofSetRoot::from_bytes([0x11; 32]),
        ProofSetRoot::from_bytes([0x22; 32]),
        vec![ProofId::from_bytes([0x33; 32])],
    )
    .unwrap();
    let block = ProofBlock::new(ProofBlockId::from_bytes([0x44; 32]), transition.clone());
    let proof_set = ProofDag::new().proof_set_proof(ProofId::from_bytes([0x55; 32]));
    let definition = ProofChainDefinition::new([0x66; 32]);

    [
        formula.encode_canonical().unwrap(),
        certificate.to_canonical_bytes(),
        transition.to_canonical_bytes(),
        block.to_canonical_bytes(),
        proof_set.to_canonical_bytes(),
        definition.to_canonical_bytes().to_vec(),
    ]
}

fn assert_accepted_values_reencode_exactly(bytes: &[u8]) {
    if let Ok(formula) = Formula::decode_canonical(bytes) {
        assert_eq!(formula.encode_canonical().as_deref(), Ok(bytes));
    }
    if let Ok(certificate) = ProofCertificate::from_canonical_bytes(bytes) {
        assert_eq!(certificate.to_canonical_bytes(), bytes);
    }
    if let Ok(transition) = ProofTransition::from_canonical_bytes(bytes) {
        assert_eq!(transition.to_canonical_bytes(), bytes);
    }
    if let Ok(block) = ProofBlock::from_canonical_bytes(bytes) {
        assert_eq!(block.to_canonical_bytes(), bytes);
    }
    if let Ok(proof) = ProofSetProof::from_canonical_bytes(bytes) {
        assert_eq!(proof.to_canonical_bytes(), bytes);
    }
    if let Ok(definition) = ProofChainDefinition::from_canonical_bytes(bytes) {
        assert_eq!(definition.to_canonical_bytes().as_slice(), bytes);
    }
}

const fn xorshift64(mut state: u64) -> u64 {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    state
}
