use naome_chain::{ArtifactBlockId, ArtifactChainId};
use naome_proof::ArtifactId;

#[test]
fn root_wire_paths_reexport_the_protocol_types_and_exact_bytes() {
    let artifact: naome_protocol::artifact_exchange::ArtifactRequest =
        naome::artifact_exchange::ArtifactRequest::new(ArtifactId::from_bytes([0x11; 32]));
    assert_eq!(artifact.to_wire_bytes(), [0x11; 32]);
    let block: naome_protocol::block_exchange::ArtifactBlockRequest =
        naome::block_exchange::ArtifactBlockRequest::new(ArtifactBlockId::from_bytes([0x22; 32]));
    assert_eq!(block.to_wire_bytes(), [0x22; 32]);
    let head: naome_protocol::chain_head_exchange::ArtifactChainHeadRequest =
        naome::chain_head_exchange::ArtifactChainHeadRequest::new(ArtifactChainId::from_bytes(
            [0x33; 32],
        ));
    assert_eq!(head.to_wire_bytes(), [0x33; 32]);
    let announcement: naome_protocol::chain_head_announcement::ArtifactChainHeadAnnouncement =
        naome::chain_head_announcement::ArtifactChainHeadAnnouncement::new(
            ArtifactChainId::from_bytes([0x33; 32]),
            ArtifactBlockId::from_bytes([0x22; 32]),
        );
    let mut expected = [0x33; 64];
    expected[32..].fill(0x22);
    assert_eq!(announcement.to_wire_bytes(), expected);
}
