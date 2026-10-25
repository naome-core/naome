use super::*;

const RECORDS: [&[u8]; 3] = [
    br#"{"op":"reflexivity","variable":0}"#,
    br#"{"op":"generalization","premise":0,"variable":0}"#,
    br#"{"op":"seal","proof":1}"#,
];
fn digest(hex: &str) -> [u8; 32] {
    std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
}
fn fixture() -> (Manifest, Chunk, Progress) {
    // Literal commitments were calculated independently from the fixed bytes.
    let manifest = Manifest {
        commands: 3,
        input_bytes: 104,
        program_hash: digest("137c0a5aafab51f5134401e5826da936a1fe9fa30e74ca5fd947ed897cd1be36"),
        stream_root: digest("8b162de23bf080af0034b43b5b4a223106a808f0445e6c86921652af15e6a62e"),
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
fn fixed_command_bytes_and_both_commitments_remain_exact() {
    let (manifest, chunk, initial) = fixture();
    assert_eq!(
        encode_command(&Command::Reflexivity { variable: 0 }).unwrap(),
        RECORDS[0]
    );
    let (progress, records) = initial.prepare_append(&manifest, &chunk).unwrap();
    progress.require_complete(&manifest).unwrap();
    assert_eq!(progress.hash, manifest.program_hash);
    assert_eq!(progress.input_bytes, 104);
    assert_eq!(
        records
            .iter()
            .map(|record| record.bytes.as_slice())
            .collect::<Vec<_>>(),
        RECORDS
    );
    assert_eq!(
        records[0].hash,
        digest("da09b39a0d6d09d7b2bab31388f2a734d4bf2cefb4c1c1011ba738b3590fa327")
    );
    assert_eq!(
        records[1].suffix,
        digest("3d94e6ee8db52b6caecf25a7e680b1a510232d99268927166062244d1a1e728d")
    );
}

#[test]
fn chunk_boundaries_resume_the_exact_authenticated_prefix() {
    let (manifest, mut chunk, initial) = fixture();
    chunk.records.truncate(1);
    chunk.next = digest("3d94e6ee8db52b6caecf25a7e680b1a510232d99268927166062244d1a1e728d");
    let (progress, first) = initial.prepare_append(&manifest, &chunk).unwrap();
    assert!(progress.require_complete(&manifest).is_err());
    let mut reader = ChunkReader::new(0, [0; 32], CHUNK_RECORDS, 33).unwrap();
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
    for bytes in [
        br#"{"op": "seal","proof":1}"#.as_slice(),
        br#"{"proof":1,"op":"seal"}"#,
        br#"{"op":"seal","proof":1,"extra":0}"#,
    ] {
        assert!(decode_command(bytes).is_err());
    }
    assert!(decode_command(&vec![b' '; RECORD_BYTES + 1]).is_err());
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
