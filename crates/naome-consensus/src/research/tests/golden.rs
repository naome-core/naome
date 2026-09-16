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
