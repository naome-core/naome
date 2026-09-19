//! Canonical finalized-state authority for source dependency resolution.
include!("support/finalized_history.rs");
use naome_authoring::{
    CompileError, SelectedHistoryCompileError, compile, compile_against_selected_history,
};
use naome_proof::ProofId;
use naome_storage::state::SelectedResearchHistory;

fn source_for(id: ProofId) -> String {
    let hex: String = id.as_bytes().iter().map(|v| format!("{v:02x}")).collect();
    format!(
        "foundation = \"naome:zfc\" statement = forall(y,forall(x,equal(x,x))) proof: p0 = cite(\"{hex}\") p1 = generalization(p0,y) return p1"
    )
}
fn image(path: &std::path::Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    fs::read_dir(path)
        .unwrap()
        .map(|v| {
            let path = v.unwrap().path();
            let bytes = fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect()
}
fn missing(source: &str, selected: &impl SelectedResearchHistory, id: ProofId) {
    assert!(matches!(compile_against_selected_history(source, selected),
        Err(SelectedHistoryCompileError::Compilation { source: CompileError::Check { source, .. } })
        if matches!(source.as_ref(), naome_checker::CheckError::UnknownProofReference { proof_id, .. } if *proof_id == id)));
}

#[test]
fn only_finalized_settlement_authorizes_helpers_and_replay_preserves_authoring() {
    let (dir, anchors, genesis, mut history, settlement) = pending_two_proof_settlement();
    let helper = compile(include_str!("../../../examples/research-mvp/helper-h.nao")).unwrap();
    let source = source_for(helper.proof_id());
    let before = image(&dir.0);
    let before_anchor = image(&anchors.0);
    missing(&source, &history, helper.proof_id());
    // Even a fully certified but unselected settlement is not an authoring input.
    let candidate = history
        .head()
        .unwrap()
        .decode_finality(&settlement, MAX_ROUND)
        .unwrap();
    assert!(
        candidate
            .branch()
            .state()
            .library()
            .lookup(helper.proof_id())
            .is_some()
    );
    missing(&source, &history, helper.proof_id());
    assert_eq!(image(&dir.0), before);
    assert_eq!(image(&anchors.0), before_anchor);
    assert_eq!(
        history.append_finality(&settlement).unwrap(),
        ResearchAppendOutcome::Finalized
    );
    let compiled = compile_against_selected_history(&source, &history).unwrap();
    let mono = compile("foundation = \"naome:zfc\" statement = forall(y,forall(x,equal(x,x))) proof: p0 = equality_reflexivity(x) p1 = generalization(p0,x) p2 = generalization(p1,y) return p2").unwrap();
    assert_eq!(compiled.statement_id(), mono.statement_id());
    assert_eq!(compiled.derivation_id(), mono.derivation_id());
    assert_ne!(compiled.proof_id(), mono.proof_id());
    let selected = history.head().unwrap().clone();
    let library_bytes = selected.state().library().encode().unwrap();
    let helper_record = selected
        .state()
        .library()
        .lookup(helper.proof_id())
        .unwrap()
        .clone();
    let before = image(&dir.0);
    let before_anchor = image(&anchors.0);
    for wrong in [mono.proof_id(), ProofId::from_bytes([0xff; 32])] {
        missing(&source_for(wrong), &history, wrong);
    }
    // A different valid authored conclusion remains unpublished.
    let unpublished = source
        .replace(
            "forall(y,forall(x,equal(x,x)))",
            "forall(z,forall(y,forall(x,equal(x,x))))",
        )
        .replace("return p1", "p2 = generalization(p1,z) return p2");
    let output = compile_against_selected_history(&unpublished, &history).unwrap();
    assert!(
        history
            .head()
            .unwrap()
            .state()
            .library()
            .lookup(output.proof_id())
            .is_none()
    );
    assert_eq!(
        history.head().unwrap().state().library().encode().unwrap(),
        library_bytes
    );
    assert_eq!(history.head().unwrap().commitment(), selected.commitment());
    assert_eq!(image(&dir.0), before);
    assert_eq!(image(&anchors.0), before_anchor);
    drop(history);
    let reopened = ResearchHistory::open(&dir.0, &anchors.0, genesis.clone(), MAX_ROUND).unwrap();
    assert_eq!(
        compile_against_selected_history(&source, &reopened).unwrap(),
        compiled
    );
    assert_eq!(
        reopened
            .head()
            .unwrap()
            .state()
            .library()
            .lookup(helper.proof_id()),
        Some(&helper_record)
    );
    let observer = ResearchObserver::open(&dir.0, &anchors.0, genesis, MAX_ROUND).unwrap();
    assert_eq!(
        compile_against_selected_history(&source, &observer).unwrap(),
        compiled
    );
    assert_eq!(observer.branch().commitment(), selected.commitment());
    assert_eq!(image(&dir.0), before);
    assert_eq!(image(&anchors.0), before_anchor);
}

#[test]
fn conflict_halt_precedes_source_parsing_for_writer_reopen_and_observer() {
    let dir = Directory::new();
    let anchors = Directory::new();
    let g = genesis();
    let mut history = ResearchHistory::create(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
    let sibling = first_finality(history.head().unwrap(), "conflicting question")
        .encode()
        .unwrap();
    let op = submission(history.head().unwrap().state(), "selected question");
    append(&mut history, 100, vec![op]);
    assert_eq!(
        history.report_conflict(1, &sibling).unwrap(),
        ResearchAppendOutcome::ConflictHalt
    );
    fn rejected(history: &impl SelectedResearchHistory) {
        assert!(history.selected_branch().is_ok()); // readable history is not operable history
        for source in [
            "malformed source",
            include_str!("../../../examples/self-equality.nao"),
        ] {
            assert!(matches!(
                compile_against_selected_history(source, history),
                Err(SelectedHistoryCompileError::SelectedState { .. })
            ));
        }
    }
    let before = image(&dir.0);
    let before_anchor = image(&anchors.0);
    rejected(&history);
    drop(history);
    let reopened = ResearchHistory::open(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
    rejected(&reopened);
    let observer = ResearchObserver::open(&dir.0, &anchors.0, g, MAX_ROUND).unwrap();
    rejected(&observer);
    assert_eq!(image(&dir.0), before);
    assert_eq!(image(&anchors.0), before_anchor);
}
