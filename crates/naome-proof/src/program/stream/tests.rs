use super::*;

use naome_foundation::graph::{Node, Variable};

const RECORDS: [&[u8]; 3] = [&[0x14, 0], &[0x1b, 0, 0], &[0x1d, 1]];
fn digest(hex: &str) -> [u8; 32] {
    std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
}
fn fixture() -> (Manifest, Chunk, Progress) {
    // Literal commitments were calculated independently from the fixed bytes.
    let manifest = Manifest {
        commands: 3,
        input_bytes: 7,
        program_hash: digest("50d2cc31a3edcd7a82d191d2b0a3822f76976dc98dff361451376f3258d1606b"),
        stream_root: digest("d4a07589151f201e4469fd3f65c278f93a8336bcdaa22e77bbd7070d58bcd1d7"),
        conclusion: [17; 32],
        statement: [23; 32],
    };
    let progress = Progress {
        commands: 0,
        input_bytes: 0,
        hash: [0; 32],
        remaining: manifest.stream_root,
    };
    let chunk = Chunk {
        start: 0,
        previous: [0; 32],
        next: [0; 32],
        records: RECORDS
            .iter()
            .map(|bytes| decode_command(bytes).unwrap())
            .collect(),
    };
    (manifest, chunk, progress)
}

#[test]
fn manifest_length_matches_the_codec_at_integer_boundaries() {
    let (mut manifest, _, _) = fixture();
    for shift in (7..64).step_by(7) {
        let boundary = 1u64 << shift;
        for (commands, input_bytes) in [(boundary - 1, boundary), (boundary, boundary - 1)] {
            manifest.commands = commands;
            manifest.input_bytes = input_bytes;
            assert_eq!(
                manifest.encoded_length().unwrap(),
                manifest.canonical_bytes().unwrap().len()
            );
        }
    }
    manifest.commands = u64::MAX;
    manifest.input_bytes = u64::MAX;
    assert_eq!(manifest.encoded_length(), Ok(MANIFEST_BYTES));
    assert_eq!(manifest.canonical_bytes().unwrap().len(), MANIFEST_BYTES);

    for (commands, input_bytes) in [(0, 1), (1, 0)] {
        manifest.commands = commands;
        manifest.input_bytes = input_bytes;
        assert_eq!(
            manifest.encoded_length(),
            Err(CodecFailure::InvalidManifest)
        );
        assert_eq!(
            manifest.canonical_bytes(),
            Err(CodecFailure::InvalidManifest)
        );
    }
}

#[test]
fn fixed_command_bytes_and_both_commitments_remain_exact() {
    let (manifest, chunk, initial) = fixture();
    assert_eq!(
        encode_command(&Command::Reflexivity { variable: 0 }).unwrap(),
        RECORDS[0]
    );
    let (progress, records) = initial.prepare_append(&manifest, &chunk).unwrap();
    progress.require_complete(&manifest).unwrap();
    assert_eq!(progress.hash, manifest.program_hash);
    assert_eq!(progress.input_bytes, 7);
    assert_eq!(
        records
            .iter()
            .map(|record| record.bytes.as_slice())
            .collect::<Vec<_>>(),
        RECORDS
    );
    assert_eq!(
        records[0].hash,
        digest("8090bc6bf587b9632264bc376ef881bd809e0e1ceeafaf9918f2b13177dbb538")
    );
    assert_eq!(
        records[1].suffix,
        digest("453b06c40c0d3543c10077ce6a32ecda5d2a62a25c92b4fc27e2791fc2abd3b6")
    );
}

#[test]
fn chunk_boundaries_resume_the_exact_authenticated_prefix() {
    let (manifest, mut chunk, initial) = fixture();
    chunk.records.truncate(1);
    chunk.next = digest("453b06c40c0d3543c10077ce6a32ecda5d2a62a25c92b4fc27e2791fc2abd3b6");
    let (progress, first) = initial.prepare_append(&manifest, &chunk).unwrap();
    assert!(progress.require_complete(&manifest).is_err());
    let mut reader = ChunkReader::new(0, [0; 32], CHUNK_RECORDS, 2).unwrap();
    assert!(reader.push(0, RECORDS[0], first[0].hash).unwrap());
    assert!(!reader.push(1, RECORDS[1], [0; 32]).unwrap());
    assert_eq!(reader.finish(1, chunk.next).unwrap(), chunk);
    let tail = Chunk {
        start: 1,
        previous: progress.hash,
        next: [0; 32],
        records: RECORDS[1..]
            .iter()
            .map(|bytes| decode_command(bytes).unwrap())
            .collect(),
    };
    progress
        .prepare_append(&manifest, &tail)
        .unwrap()
        .0
        .require_complete(&manifest)
        .unwrap();
}

#[test]
fn noncanonical_records_manifests_and_corrupt_transitions_are_rejected() {
    for (bytes, reason) in [
        (
            [0x1d, 0x81, 0].as_slice(),
            CodecFailure::NoncanonicalInteger,
        ),
        (&[0x1d, 0x81], CodecFailure::Truncated),
        (&[0x1d, 1, 0], CodecFailure::TrailingCommandBytes),
        (&[0xff, 1], CodecFailure::Opcode),
    ] {
        assert_eq!(decode_command(bytes), Err(reason));
    }
    assert_eq!(
        decode_command(&vec![b' '; RECORD_BYTES + 1]),
        Err(CodecFailure::CommandBytes)
    );
    let (manifest, chunk, initial) = fixture();
    let bytes = manifest.canonical_bytes().unwrap();
    assert_eq!(Manifest::from_canonical_bytes(&bytes).unwrap(), manifest);
    assert!(Manifest::from_canonical_bytes(&[bytes.as_slice(), b" "].concat()).is_err());
    let mut invalid = manifest.clone();
    invalid.commands = 0;
    assert!(invalid.canonical_bytes().is_err());
    let mut mutations = Vec::new();
    let mut changed = chunk.clone();
    changed.start = 1;
    mutations.push(changed);
    let mut changed = chunk.clone();
    changed.previous[0] = 1;
    mutations.push(changed);
    let mut changed = chunk.clone();
    changed.next[0] = 1;
    mutations.push(changed);
    let mut changed = chunk.clone();
    changed.records.swap(0, 1);
    mutations.push(changed);
    for changed in mutations {
        assert!(initial.prepare_append(&manifest, &changed).is_err());
    }
    let mut invalid = manifest.clone();
    invalid.input_bytes += 1;
    assert!(initial.prepare_append(&invalid, &chunk).is_err());
    let mut reader = ChunkReader::new(0, [0; 32], 1, CHUNK_BYTES).unwrap();
    assert!(reader.push(1, RECORDS[0], [0; 32]).is_err());
    assert!(reader.push(0, RECORDS[0], [0; 32]).is_err());
    assert!(reader.finish(1, [0; 32]).is_err());
}

#[test]
fn prefix_overflow_leaves_the_previous_state_unchanged() {
    for mut prefix in [
        Prefix {
            commands: u64::MAX,
            ..Prefix::default()
        },
        Prefix {
            input_bytes: u64::MAX,
            ..Prefix::default()
        },
    ] {
        let before = prefix;
        assert!(prefix.append(RECORDS[0]).is_err());
        assert_eq!(prefix, before);
    }
}

#[test]
fn typed_instantiation_has_one_canonical_encoding() {
    let command = Command::Instantiate {
        premise: 258,
        replacement: 772,
    };
    let bytes = [0x13, 0x82, 0x02, 0x84, 0x06];
    assert_eq!(encode_command(&command).unwrap(), bytes);
    assert_eq!(decode_command(&bytes).unwrap(), command);
    assert!(decode_command(&bytes[..4]).is_err());
    let mut extra = bytes.to_vec();
    extra.push(0);
    assert!(decode_command(&extra).is_err());
}

#[test]
fn graph_record_preserves_bound_scope_and_rejects_malformed_terms() {
    let command = Command::Graph {
        node: Node::Member(Variable::Bound(1), Variable::Free(9)),
    };
    let bytes = [0x01, 3, 18];
    assert_eq!(encode_command(&command).unwrap(), bytes);
    assert_eq!(decode_command(&bytes).unwrap(), command);
    let mut wrong_width = vec![0x01, 3];
    put_integer(&mut wrong_width, 1 << 33);
    assert!(decode_command(&wrong_width).is_err());
    assert!(decode_command(&bytes[..2]).is_err());
}

#[test]
fn instructions_are_self_delimiting_and_accept_wide_references() {
    let mp = Command::ModusPonens {
        premise: 2,
        implication: 127,
    };
    let seal = Command::Seal { proof: u64::MAX };
    assert_eq!(encode_command(&mp).unwrap(), [0x1a, 2, 127]);
    let bytes = encode_records(&[mp.clone(), seal.clone()]).unwrap();
    assert_eq!(bytes.len(), 14);
    assert_eq!(decode_records(&bytes).unwrap(), [mp, seal]);
    assert!(decode_records(&bytes[..13]).is_err());
    let mut overflow = bytes;
    *overflow.last_mut().unwrap() = 2;
    assert!(decode_records(&overflow).is_err());
    assert!(decode_records(&[0x1d, 0].repeat(CHUNK_RECORDS + 1)).is_err());
}

#[test]
fn scoped_operand_counts_are_bounded_before_reading_operands() {
    use crate::program::{ACTION_PREMISES, SCOPE_ACTIONS, SCOPE_ASSUMPTIONS, ScopedAction};
    let command = Command::Deduce {
        assumptions: vec![0, 1],
        actions: vec![ScopedAction::Conjoin { left: 0, right: 1 }],
        result: 2,
    };
    let bytes = [0x12, 2, 0, 1, 1, 1, 0, 1, 2];
    assert_eq!(encode_command(&command).unwrap(), bytes);
    assert_eq!(decode_command(&bytes).unwrap(), command);
    for malformed in [
        vec![0x12, 0],
        vec![0x12, SCOPE_ASSUMPTIONS as u8 + 1],
        vec![0x12, 1, 0, SCOPE_ACTIONS as u8 + 1],
        vec![0x12, 1, 0, 1, 0, 0, 0, ACTION_PREMISES as u8 + 1],
        vec![0x12, 1, 0, 1, 2],
    ] {
        assert!(decode_command(&malformed).is_err());
    }
}
