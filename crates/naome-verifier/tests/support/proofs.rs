use ed25519_dalek::{Signer, SigningKey};
use naome_chain::ArtifactChainState;
use naome_consensus::{ConsensusPosition, ConsensusValueV0};
use naome_proof::{ArtifactPayload, ProofCertificate};
use serde_json::{Value, json};

use super::{Fixture, Layout, consensus_key};

#[derive(Clone)]
pub struct Proof {
    pub value: ConsensusValueV0,
    pub position: ConsensusPosition,
    pub proposer: usize,
    pub envelope: Vec<u8>,
    pub payload: Vec<u8>,
}

impl Fixture {
    pub fn proof(&self, prefix: &[&Proof], round: u64, axiom: u8) -> Proof {
        let payload = ArtifactPayload::Proof(
            ProofCertificate::from_canonical_bytes(&[0, 0, 0, 1, 0x10, axiom]).unwrap(),
        )
        .to_canonical_bytes();
        self.proof_with_payload(prefix, round, payload)
    }

    pub fn proof_with_payload(&self, prefix: &[&Proof], round: u64, payload: Vec<u8>) -> Proof {
        let mut branch = self.genesis();
        let mut artifacts = ArtifactChainState::new(self.definition);
        for proof in prefix {
            branch = branch
                .decode_and_verify_envelope_with_round_limit(
                    &proof.envelope,
                    proof.payload.clone(),
                    proof.position.round(),
                )
                .unwrap()
                .into_branch();
            artifacts
                .apply_block(&proof.value.artifact_block(), proof.payload.clone())
                .unwrap();
        }
        let mut cursor = branch.begin_round_zero().unwrap();
        for _ in 0..round {
            cursor = cursor.advance_round().unwrap();
        }
        let proposer = self
            .keys
            .iter()
            .position(|key| consensus_key(key) == cursor.proposer())
            .unwrap();
        let artifact_id = artifacts
            .artifact_dag()
            .clone()
            .apply_canonical_artifact_bytes(payload.clone())
            .unwrap()
            .artifact_id();
        let value = cursor.value_for_artifact_block(artifacts.prepare_block(artifact_id).unwrap());
        let mut proof = Proof {
            value,
            position: cursor.position(),
            proposer,
            envelope: Vec::new(),
            payload,
        };
        proof.envelope = envelope(
            &proof,
            &self.keys[proposer],
            &[&self.keys[0], &self.keys[1], &self.keys[2]],
            2,
        );
        let _ = cursor
            .decode_and_verify(&proof.envelope, proof.payload.clone())
            .unwrap();
        proof
    }
}

impl Proof {
    pub fn write(&self, layout: &Layout, name: &str) {
        layout.write(&format!("{name}.envelope"), &self.envelope);
        layout.write(&format!("{name}.payload"), &self.payload);
    }

    pub fn command(id: u64, name: &str) -> Value {
        json!({"command": "import", "id": id, "envelope_file": format!("{name}.envelope"), "payload_file": format!("{name}.payload")})
    }
}

/// Independent test encoding with real Ed25519 signatures, including malicious
/// producer/quorum fixtures. Keys exist only in this test process; target
/// layouts contain no private keys, signer journals, or signer API owners.
pub fn envelope(
    proof: &Proof,
    proposer: &SigningKey,
    signers: &[&SigningKey],
    role: u8,
) -> Vec<u8> {
    let context = proof.value.context();
    let mut authorization = Vec::new();
    authorization.extend_from_slice(context.chain_id().as_bytes());
    authorization.extend_from_slice(context.genesis_id().as_bytes());
    authorization.extend_from_slice(&context.protocol_version().value().to_be_bytes());
    authorization.extend_from_slice(&proof.position.height().value().to_be_bytes());
    authorization.extend_from_slice(&proof.position.round().value().to_be_bytes());
    authorization.extend_from_slice(proof.value.proposal_signing_root().as_bytes());
    assert_eq!(authorization.len(), 116);
    authorization.extend_from_slice(consensus_key(proposer).as_bytes());
    let mut transcript = b"naome:consensus-producer-authorization:v0\0".to_vec();
    transcript.extend_from_slice(&authorization);
    authorization.extend_from_slice(&proposer.sign(&transcript).to_bytes());

    let mut body = vec![role];
    body.extend_from_slice(context.chain_id().as_bytes());
    body.extend_from_slice(context.genesis_id().as_bytes());
    body.extend_from_slice(&context.protocol_version().value().to_be_bytes());
    body.extend_from_slice(&proof.position.height().value().to_be_bytes());
    body.extend_from_slice(&proof.position.round().value().to_be_bytes());
    body.push(1);
    body.extend_from_slice(proof.value.proposal_signing_root().as_bytes());
    assert_eq!(body.len(), 118);
    let mut certificate = body.clone();
    certificate.extend_from_slice(&u16::try_from(signers.len()).unwrap().to_be_bytes());
    let mut signers = signers.to_vec();
    signers.sort_unstable_by_key(|key| consensus_key(key));
    for key in signers {
        let mut transcript = match role {
            1 => b"naome:consensus-prevote-signing:v0\0".to_vec(),
            2 => b"naome:consensus-precommit-signing:v0\0".to_vec(),
            _ => panic!("fixture role"),
        };
        transcript.extend_from_slice(&body);
        transcript.extend_from_slice(consensus_key(key).as_bytes());
        certificate.extend_from_slice(consensus_key(key).as_bytes());
        certificate.extend_from_slice(&key.sign(&transcript).to_bytes());
    }
    let mut envelope = proof.value.to_canonical_bytes().to_vec();
    envelope.extend_from_slice(&authorization);
    envelope.extend_from_slice(&certificate);
    envelope
}
