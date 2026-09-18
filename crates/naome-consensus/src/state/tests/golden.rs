use super::*;

#[test]
fn signed_consensus_v1_golden_vectors() {
    use std::fmt::Write;
    let branch = branch();
    let proposal = proposal(
        &branch,
        record(&branch, "golden research proposal"),
        0,
        None,
    );
    let prevote = vote(&branch, 0, ConsensusVoteRole::Prevote, target(&proposal), 0);
    let nil = vote(
        &branch,
        1,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        1,
    );
    let qc = quorum(&branch, 0, ConsensusVoteRole::Precommit, target(&proposal));
    let finality = branch.verify_finality(&proposal, &qc, MAX_ROUND).unwrap();
    let entries = [
        ("proposal", proposal.encode().unwrap()),
        ("prevote", prevote.encode()),
        ("nil-precommit", nil.encode()),
        ("precommit-quorum", qc.encode()),
        ("finality", finality.encode().unwrap()),
        ("branch-commitment", finality.branch().commitment().to_vec()),
    ];
    let mut output = String::new();
    for (name, bytes) in entries {
        write!(output, "{name} {} ", bytes.len()).unwrap();
        for byte in bytes {
            write!(output, "{byte:02x}").unwrap();
        }
        output.push('\n');
    }
    if let Some(path) = std::env::var_os("NAOME_REGENERATE_CONSENSUS_VECTORS") {
        std::fs::write(path, &output).unwrap();
        return;
    }
    assert_eq!(output, include_str!("golden-v1.txt"));
}

#[test]
fn legacy_research_consensus_evidence_is_rejected() {
    let branch = branch();
    let candidate = proposal(
        &branch,
        record(&branch, "golden research proposal"),
        0,
        None,
    );
    let certificate = quorum(&branch, 0, ConsensusVoteRole::Precommit, target(&candidate));
    let current = branch
        .verify_finality(&candidate, &certificate, MAX_ROUND)
        .unwrap();
    for line in include_str!("legacy-research-v1.txt").lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let mut bytes: Vec<_> = fields[2]
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(bytes.len(), fields[1].parse::<usize>().unwrap());
        match fields[0] {
            "proposal" => {
                assert!(branch.verify_proposal(&bytes, MAX_ROUND).is_err());
                bytes[..5].copy_from_slice(b"NSCP1");
                assert!(branch.verify_proposal(&bytes, MAX_ROUND).is_err());
            }
            "finality" => {
                assert!(branch.decode_finality(&bytes, MAX_ROUND).is_err());
                bytes[..5].copy_from_slice(b"NSCF1");
                assert!(branch.decode_finality(&bytes, MAX_ROUND).is_err());
            }
            "prevote" | "nil-precommit" => {
                assert!(ResearchVote::decode(&bytes, branch.state().genesis()).is_err());
                bytes[..5].copy_from_slice(b"NSCV1");
                assert!(ResearchVote::decode(&bytes, branch.state().genesis()).is_err());
            }
            "precommit-quorum" => {
                assert!(ResearchQuorum::decode(&bytes, branch.state().genesis()).is_err())
            }
            "branch-commitment" => assert_ne!(bytes, current.branch().commitment()),
            name => panic!("unhandled legacy vector {name}"),
        }
    }
}
