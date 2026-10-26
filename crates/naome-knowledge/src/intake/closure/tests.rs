use super::*;
use crate::object::id_bytes;

impl std::fmt::Debug for Closure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Closure")
            .field("needed", &self.needed)
            .field("programs", &self.items.len())
            .field("certificates", &self.certificates.len())
            .field("registered", &self.registered)
            .field("registration_pending", &self.registration.is_some())
            .field("budget", &self.budget)
            .finish()
    }
}

fn id(object: &Envelope) -> ProofId {
    ProofId::from_bytes(id_bytes(&object.proof_id).unwrap())
}
fn fixtures() -> (Envelope, Envelope, Envelope) {
    let mut producer = Graph::default();
    let helper = producer
        .produce("goal=all(x,eq(x,x)) proof: p0=refl(x) p1=gen(p0,x) return p1")
        .unwrap()
        .0;
    let parent = producer
        .produce(&format!(
            "goal=all(x,eq(x,x)) proof: p0=cite(\"{}\") return p0",
            helper.proof_id
        ))
        .unwrap()
        .0;
    let root = producer
        .author(&format!(
            "goal=all(x,eq(x,x)) proof: p0=cite(\"{}\") return p0",
            parent.proof_id
        ))
        .unwrap();
    (root, parent, helper)
}
fn isolated(case: &str) -> bool {
    if std::env::var("NAOME_CLOSURE_CASE").as_deref() == Ok(case) {
        return false;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", case, "--nocapture"])
        .env("NAOME_CLOSURE_CASE", case)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

#[test]
fn one_frontier_deduplicates_members_and_rejected_payloads_do_not_spend_budget() {
    let (root, parent, helper) = fixtures();
    let graph = Graph::default();
    let root_id = id(&root);
    let transfer = TransferGrant::new(PeerId::random(), root_id, None);
    let mut closure = Closure::new(
        root_id,
        Some(StatementId::from_bytes(
            id_bytes(&root.statement_id).unwrap(),
        )),
    );
    closure.require_root(&graph).unwrap();
    closure.require(id(&parent), &graph).unwrap();
    closure.require(id(&parent), &graph).unwrap();
    assert_eq!(closure.member_count(), 2);
    closure
        .certificate_payload(root_id, root.clone(), &graph, &transfer)
        .unwrap();
    assert_eq!(
        closure.member_count(),
        2,
        "the root's repeated citation shares the same dependency slot"
    );
    closure
        .certificate_payload(id(&parent), parent.clone(), &graph, &transfer)
        .unwrap();
    assert_eq!(closure.needed().collect::<Vec<_>>(), [id(&helper)]);
    let steps = closure.certificate_steps();
    assert!(
        closure
            .certificate_payload(id(&parent), parent, &graph, &transfer)
            .is_err()
    );
    let mut corrupt = helper.clone();
    corrupt.proof.pop();
    assert!(
        closure
            .certificate_payload(id(&helper), corrupt, &graph, &transfer)
            .is_err()
    );
    assert_eq!(closure.certificate_count(), 2);
    assert_eq!(closure.certificate_steps(), steps);
    assert_eq!(closure.needed().collect::<Vec<_>>(), [id(&helper)]);
    closure
        .certificate_payload(id(&helper), helper, &graph, &transfer)
        .unwrap();
    assert_eq!(closure.member_count(), 3);
    assert!(closure.certificate_ready());
    let question = CompiledQuestion::compile("goal=all(x,eq(x,x))").unwrap();
    let _batch = closure.prepare_certificates(&graph, &question).unwrap();
    assert_eq!(
        graph.accepted_count(),
        0,
        "closure completion cannot publish any helper"
    );
}

#[test]
fn root_and_helper_certificates_share_one_cumulative_step_limit() {
    const CASE: &str =
        "intake::closure::tests::root_and_helper_certificates_share_one_cumulative_step_limit";
    if isolated(CASE) {
        return;
    }
    let mut profile = crate::resources::ResourceProfile::default();
    profile.tuning.closure_steps = Some(3);
    crate::resources::configure(profile).unwrap();
    let (root, parent, helper) = fixtures();
    let graph = Graph::default();
    let transfer = TransferGrant::new(PeerId::random(), id(&root), None);
    let mut closure = Closure::new(id(&root), None);
    closure.require_root(&graph).unwrap();
    closure
        .certificate_payload(id(&root), root, &graph, &transfer)
        .unwrap();
    closure
        .certificate_payload(id(&parent), parent, &graph, &transfer)
        .unwrap();
    assert_eq!(closure.certificate_steps(), 2);
    assert!(matches!(
        closure.certificate_payload(id(&helper), helper.clone(), &graph, &transfer),
        Err(crate::Error::InputLimit("staged closure step work limit"))
    ));
    assert_eq!(closure.certificate_count(), 2);
    assert_eq!(closure.certificate_steps(), 2);
    assert_eq!(closure.needed().collect::<Vec<_>>(), [id(&helper)]);
    assert_eq!(graph.accepted_count(), 0);
}

#[test]
fn program_root_reserves_its_member_slot_before_dependencies_arrive() {
    const CASE: &str =
        "intake::closure::tests::program_root_reserves_its_member_slot_before_dependencies_arrive";
    if isolated(CASE) {
        return;
    }
    let mut profile = crate::resources::ResourceProfile::default();
    profile.tuning.closure_objects = Some(3);
    crate::resources::configure(profile).unwrap();
    let graph = Graph::default();
    let root = ProofId::from_bytes([1; 32]);
    let mut closure = Closure::new(root, None);
    assert_eq!(closure.member_count(), 1);
    closure
        .require(ProofId::from_bytes([2; 32]), &graph)
        .unwrap();
    closure
        .require(ProofId::from_bytes([3; 32]), &graph)
        .unwrap();
    closure
        .require(ProofId::from_bytes([2; 32]), &graph)
        .unwrap();
    assert!(
        closure
            .require(ProofId::from_bytes([4; 32]), &graph)
            .is_err()
    );
    assert_eq!(closure.member_count(), 3);
    assert_eq!(
        closure.needed().collect::<Vec<_>>(),
        [ProofId::from_bytes([2; 32]), ProofId::from_bytes([3; 32])]
    );
    assert!(
        closure.require(root, &graph).is_err(),
        "the root cannot become its own helper"
    );
}
