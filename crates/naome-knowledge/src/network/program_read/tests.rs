use super::*;
use naome_proof::program::{Chunk, Command};

#[test]
fn program_reply_keeps_the_original_record_admission_and_scope() {
    let read = ProgramRead {
        root: ArtifactId::from_bytes([1; 32]),
        id: ArtifactId::from_bytes([2; 32]),
        start: 7,
        limit: 3,
    };
    let mut chunk = Chunk {
        start: 7,
        previous: [0; 32],
        next: [0; 32],
        records: vec![Command::Reflexivity { variable: 0 }; 3],
    };
    let root = *read.root.as_bytes();
    let id = *read.id.as_bytes();
    assert!(read.matches_reply(root, id, &chunk));
    let reduced = ProgramRead { limit: 1, ..read };
    assert!(
        !reduced.matches_reply(root, id, &chunk),
        "a format-valid reply cannot exceed its requested portion"
    );
    assert!(
        read.matches_reply(root, id, &chunk),
        "a later reduction cannot revoke the earlier admitted portion"
    );
    assert!(!read.matches_reply(id, root, &chunk));
    chunk.start += 1;
    assert!(!read.matches_reply(root, id, &chunk));
    chunk.start -= 1;
    chunk.records.clear();
    assert!(
        !read.matches_reply(root, id, &chunk),
        "an empty reply cannot advance a program read"
    );
}
