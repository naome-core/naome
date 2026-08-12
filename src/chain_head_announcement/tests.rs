use naome_chain::{ProofBlockId, ProofChainId};

use super::{
    PROOF_CHAIN_HEAD_ANNOUNCEMENT_BYTES, ProofChainHeadAnnouncement,
    ProofChainHeadAnnouncementWireError,
};

#[test]
fn announcement_is_one_exact_chain_and_head_pair() {
    let chain_id = ProofChainId::from_bytes([0x11; 32]);
    let head_block_id = ProofBlockId::from_bytes([0x22; 32]);
    let announcement = ProofChainHeadAnnouncement::new(chain_id, head_block_id);
    let mut expected = [0_u8; PROOF_CHAIN_HEAD_ANNOUNCEMENT_BYTES];
    expected[..32].fill(0x11);
    expected[32..].fill(0x22);

    assert_eq!(announcement.chain_id(), chain_id);
    assert_eq!(announcement.head_block_id(), head_block_id);
    assert_eq!(announcement.to_wire_bytes(), expected);
    assert_eq!(
        ProofChainHeadAnnouncement::from_wire_bytes(&expected).unwrap(),
        announcement
    );
}

#[test]
fn announcement_rejects_every_non_exact_length() {
    let bytes = [0xa5; PROOF_CHAIN_HEAD_ANNOUNCEMENT_BYTES + 1];
    for actual in 0..=bytes.len() {
        if actual == PROOF_CHAIN_HEAD_ANNOUNCEMENT_BYTES {
            continue;
        }
        assert_eq!(
            ProofChainHeadAnnouncement::from_wire_bytes(&bytes[..actual]),
            Err(ProofChainHeadAnnouncementWireError::InvalidLength {
                actual,
                expected: PROOF_CHAIN_HEAD_ANNOUNCEMENT_BYTES,
            })
        );
    }
}
