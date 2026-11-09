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
    assert_eq!(read.check_reply(root, id, &chunk), Ok(()));
    let reduced = ProgramRead { limit: 1, ..read };
    assert!(
        reduced.check_reply(root, id, &chunk) == Err(crate::InputFault::ProgramReplyLimit),
        "a format-valid reply cannot exceed its requested portion"
    );
    assert!(
        read.check_reply(root, id, &chunk).is_ok(),
        "a later reduction cannot revoke the earlier admitted portion"
    );
    assert_eq!(
        read.check_reply(id, root, &chunk),
        Err(crate::InputFault::ProgramReplyRoot)
    );
    assert_eq!(
        read.check_reply(root, root, &chunk),
        Err(crate::InputFault::ProgramReplyId)
    );
    chunk.start += 1;
    assert_eq!(
        read.check_reply(root, id, &chunk),
        Err(crate::InputFault::ProgramReplyStart)
    );
    chunk.start -= 1;
    chunk.records.clear();
    assert!(
        read.check_reply(root, id, &chunk) == Err(crate::InputFault::ProgramReplyEmpty),
        "an empty reply cannot advance a program read"
    );
}
