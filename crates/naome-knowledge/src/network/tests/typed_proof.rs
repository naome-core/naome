use super::*;
use crate::{
    object::BinaryArtifact,
    proof_work::{CheckedWork, Work},
    resources::adaptive::Budget,
    wire,
};
use naome_checker::{ContextView, check_normal_form_with_step_digests, program::FactShape};
use naome_proof::{
    ProofStep,
    program::{
        CHUNK_BYTES, CHUNK_RECORDS, Command, MANIFEST_MAGIC, Projection, StepResult,
        decode_records, encode_command,
    },
};
use serde_json::json;
use std::collections::BTreeSet;

const HELPERS: [&[u8]; 4] = [
    include_bytes!("../../../tests/fixtures/typed-membership/helper-01.proof"),
    include_bytes!("../../../tests/fixtures/typed-membership/helper-02.proof"),
    include_bytes!("../../../tests/fixtures/typed-membership/helper-03.proof"),
    include_bytes!("../../../tests/fixtures/typed-membership/helper-04.proof"),
];
const CERTIFICATE: &[u8] =
    include_bytes!("../../../tests/fixtures/typed-membership/membership.proof");
const QUESTION: &[u8] =
    include_bytes!("../../../tests/fixtures/typed-membership/membership.question");

#[derive(Default)]
struct Phase {
    wall: Duration,
    cpu: Duration,
}
impl Phase {
    fn measure<T>(&mut self, operation: impl FnOnce() -> T) -> T {
        let cpu = || {
            let time =
                nix::time::clock_gettime(nix::time::ClockId::CLOCK_PROCESS_CPUTIME_ID).unwrap();
            Duration::new(time.tv_sec() as u64, time.tv_nsec() as u32)
        };
        let start = Instant::now();
        let begin = cpu();
        let result = operation();
        self.cpu += cpu() - begin;
        self.wall += start.elapsed();
        result
    }
    fn json(&self) -> serde_json::Value {
        json!({"wall_ns":self.wall.as_nanos() as u64,"cpu_ns":self.cpu.as_nanos() as u64})
    }
}

fn helpers(graph: &mut Graph) -> Vec<crate::Envelope> {
    HELPERS
        .iter()
        .map(|source| {
            let (object, receipt) = graph.produce(&format!("00{}", hex(source))).unwrap();
            assert_eq!(receipt.status, "accepted");
            object
        })
        .collect()
}

fn drain(work: &mut Work, context: &dyn ContextView, budget: &Budget) -> usize {
    let mut units = 0;
    while work.advance(budget, context).unwrap() {
        units += work.last_quantum_steps();
    }
    units
}

async fn frame_bytes(body: wire::Body) -> usize {
    let mut output = libp2p::futures::io::Cursor::new(Vec::new());
    libp2p::request_response::Codec::write_response(
        &mut wire::Codec::default(),
        &wire::PROTOCOL,
        &mut output,
        wire::Frame::new(body),
    )
    .await
    .unwrap();
    output.into_inner().len()
}

fn compare_results(
    proof: &naome_checker::program::CheckedProgram,
    authored: &naome_checker::CheckedProof,
    question: &ResearchQuestion,
    results: &[StepResult],
    digests: &[[u8; 32]],
) {
    assert_eq!(proof.conclusion(), Some(authored.conclusion()));
    assert_eq!(proof.manifest().statement_id(), authored.statement_id());
    assert_eq!(
        question.classify_checked_program(proof).unwrap(),
        naome_checker::question::QuestionOutcome::Proved
    );
    assert_eq!(
        ResearchQuestion::from_checked_program(proof).unwrap(),
        *question
    );
    for (&position, digest) in results.iter().zip(digests) {
        let result = match position {
            StepResult::Result(position) => {
                let (digest, proved) = proof.result_digest(position).unwrap();
                assert!(proved);
                digest
            }
            StepResult::InstantiationAxiom(position) => {
                proof.instantiation_digest(position).unwrap()
            }
        };
        assert_eq!(result, *digest, "step {position:?}");
    }
    assert_eq!(
        proof
            .dependencies_after(None, 4)
            .unwrap()
            .into_iter()
            .map(|dep| dep.proof_id().into())
            .collect::<Vec<ArtifactId>>(),
        authored.direct_artifact_dependencies().as_ref(),
    );
    assert!(
        proof
            .definition_dependencies_after(None, 4)
            .unwrap()
            .is_empty()
    );
}

async fn publish_program(graph: &mut Graph, checked: &CheckedWork) -> serde_json::Value {
    let proof = checked.proof().unwrap();
    let manifest = proof.manifest();
    let root = manifest.artifact_id();
    let mut registration = Phase::default();
    let mut chunks = Vec::new();
    registration.measure(|| {
        let store = graph.ownership();
        store.start_program(manifest).unwrap();
        let mut start = 0;
        while start < manifest.commands {
            let chunk = proof
                .input_chunk(start, CHUNK_RECORDS, CHUNK_BYTES)
                .unwrap();
            store.append_program(manifest, &chunk).unwrap();
            start += chunk.records.len() as u64;
            chunks.push(chunk);
        }
        let mut stage = graph.begin_program_admission(checked).unwrap();
        while !stage.advance(graph, checked, 512).unwrap() {}
        let batch = stage.finish(graph, checked).unwrap();
        graph
            .commit_batch(root, batch, Instant::now() + Duration::from_secs(30))
            .unwrap();
    });
    let mut package_bytes = 0;
    for chunk in chunks {
        package_bytes += frame_bytes(wire::Body::ProgramData {
            root: *root.as_bytes(),
            id: *root.as_bytes(),
            chunk,
        })
        .await;
    }
    let Some(crate::object::ProofDescription::Program(metadata)) = graph.description(root).unwrap()
    else {
        panic!("expected checked program description");
    };
    let description_bytes = frame_bytes(wire::Body::ProgramDescription {
        root: None,
        metadata,
    })
    .await;
    json!({
        "artifact_id":hex(root.as_bytes()), "proof_id":hex(manifest.proof_id().as_bytes()),
        "record_bytes":manifest.input_bytes, "manifest_bytes":manifest.canonical_bytes().unwrap().len(),
        "artifact_discriminator_bytes": MANIFEST_MAGIC.len(), "description_frame_bytes":description_bytes,
        "data_frame_overhead_bytes":package_bytes as u64 - manifest.input_bytes, "compression": "none",
        "data_frame_bytes_max_chunk":package_bytes, "commands":manifest.commands, "register":registration.json(),
    })
}

#[tokio::test]
async fn membership_certificate_and_typed_actions_replay_the_same_derivation() {
    let output = std::env::var_os("NAOME_TYPED_PAIR_OUTPUT").map(PathBuf::from);
    if output.is_none() && std::env::var_os("NAOME_TYPED_MEMBERSHIP_TEST").is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "network::tests::typed_proof::membership_certificate_and_typed_actions_replay_the_same_derivation",
                "--nocapture",
            ])
            .env("NAOME_TYPED_MEMBERSHIP_TEST", "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr),
        );
        return;
    }
    let scratch = ConfigFile::new();
    let directory = output.as_ref().unwrap_or(&scratch.0);
    let source_dir = directory.join("source");
    let typed_dir = directory.join("typed");
    for path in [&source_dir, &typed_dir] {
        std::fs::create_dir_all(path).unwrap();
    }
    let mut graph = Graph::open(&typed_dir).unwrap();
    let mut helper_storage = Phase::default();
    let deps = helper_storage.measure(|| helpers(&mut graph));
    let mut source_phase = Phase::default();
    let authored =
        source_phase.measure(|| checked_certificate(CERTIFICATE, graph.checked_context()));
    let mut projection_phase = Phase::default();
    let projection =
        projection_phase.measure(|| Projection::from_normal_form(authored.normal_form()));
    let question = ResearchQuestion::from_canonical_bytes(QUESTION).unwrap();
    assert_eq!(
        question.classify_checked_proof(&authored).unwrap(),
        naome_checker::question::QuestionOutcome::Proved
    );
    let mut oracle_phase = Phase::default();
    let (_, digests) = oracle_phase.measure(|| {
        check_normal_form_with_step_digests(authored.normal_form().clone(), graph.checked_context())
            .unwrap()
    });

    // These are the chained instantiations of the exact fourth helper. The
    // fixed replay selects operands; the evaluator decides all rule validity.
    let mut selected = Vec::new();
    let mut chain = BTreeSet::new();
    let steps = authored.normal_form().certificate().steps();
    for (i, step) in steps.iter().enumerate() {
        match step {
            ProofStep::ProofReference { .. } => {
                chain.insert(i);
            }
            ProofStep::ModusPonens {
                premise,
                implication,
            } if chain.contains(&(*premise as usize)) => {
                assert!(matches!(
                    steps[*implication as usize],
                    ProofStep::UniversalInstantiation { .. }
                ));
                selected.push(i);
                chain.insert(i);
            }
            _ => {}
        }
    }
    assert_eq!(selected.len(), 12);
    let mut fusion_phase = Phase::default();
    let typed = fusion_phase
        .measure(|| Projection::with_instantiations(authored.normal_form(), &selected).unwrap());

    let budget = Budget {
        memory_bytes: 128 * 1024 * 1024,
        concurrency: 1,
        cache_bytes: 1024 * 1024,
        batch_steps: 512,
        network_requests: 1,
        yield_ms: 0,
        paused: None,
    };
    let mut append = Phase::default();
    let mut checking = Phase::default();
    let mut actions = Phase::default();
    let mut work = Work::open(&typed_dir.join("membership-input.sqlite3")).unwrap();
    let mut units = 0;
    let mut offset = 0;
    for (start, command) in typed.commands().iter().enumerate() {
        let Command::Instantiate {
            premise,
            replacement,
        } = *command
        else {
            continue;
        };
        append.measure(|| work.append_group(&typed.commands()[offset..start]).unwrap());
        units += checking.measure(|| drain(&mut work, graph.checked_context(), &budget));
        let instance = actions.measure(|| {
            let (fact, shape) = work.checked_fact(premise).unwrap();
            assert_eq!(shape, FactShape::Universal);
            work.instantiate(&fact, naome_foundation::FreeVariable::new(replacement))
                .unwrap()
        });
        assert_eq!(instance, start as u64);
        offset = start + 1;
    }
    append.measure(|| work.append_group(&typed.commands()[offset..]).unwrap());
    units += checking.measure(|| drain(&mut work, graph.checked_context(), &budget));
    let mut export = Phase::default();
    let checked = export.measure(|| {
        while !work.prepare_export(&budget).unwrap() {}
        work.into_checked().unwrap()
    });
    compare_results(
        checked.proof().unwrap(),
        &authored,
        &question,
        typed.results(),
        &digests,
    );
    if output.is_none() {
        return;
    }

    let mut typed_report = publish_program(&mut graph, &checked).await;
    typed_report["build_fused_projection"] = fusion_phase.json();
    typed_report["select_and_append_actions"] = actions.json();
    typed_report["append_other_records"] = append.json();
    typed_report["check"] = checking.json();
    typed_report["checker_work_units"] = units.into();
    typed_report["certificate_step_positions"] = json!(
        typed
            .results()
            .iter()
            .map(|position| match position {
                StepResult::Result(p) => (*p, "result"),
                StepResult::InstantiationAxiom(p) => (*p, "instantiation_axiom"),
            })
            .collect::<Vec<_>>()
    );
    typed_report["example_hex"] = json!({
        "modus_ponens_small": hex(&encode_command(&Command::ModusPonens { premise: 2, implication: 127 }).unwrap()),
        "instantiate_wide": hex(&encode_command(&Command::Instantiate { premise: 258, replacement: 772 }).unwrap()),
        "proof_reference": hex(&encode_command(typed.commands().iter().find(|c| matches!(c, Command::ProofReference { .. })).unwrap()).unwrap()),
        "seal": hex(&encode_command(typed.commands().last().unwrap()).unwrap()),
    });
    typed_report["export"] = export.json();

    let projected_dir = directory.join("source_program");
    let mut projected_graph = Graph::open(&projected_dir).unwrap();
    assert_eq!(helpers(&mut projected_graph), deps);
    let mut work = Work::open(&projected_dir.join("membership-input.sqlite3")).unwrap();
    let mut projected_append = Phase::default();
    projected_append.measure(|| work.append_group(projection.commands()).unwrap());
    let mut projected_check = Phase::default();
    let projected_units =
        projected_check.measure(|| drain(&mut work, projected_graph.checked_context(), &budget));
    let mut projected_export = Phase::default();
    let projected = projected_export.measure(|| {
        while !work.prepare_export(&budget).unwrap() {}
        work.into_checked().unwrap()
    });
    compare_results(
        projected.proof().unwrap(),
        &authored,
        &question,
        projection.results(),
        &digests,
    );
    let mut projected_report = publish_program(&mut projected_graph, &projected).await;
    projected_report["append"] = projected_append.json();
    projected_report["check"] = projected_check.json();
    projected_report["checker_work_units"] = projected_units.into();
    projected_report["export"] = projected_export.json();
    assert_ne!(projected_report["proof_id"], typed_report["proof_id"]);

    let envelope = BinaryArtifact::from_checked(&authored).unwrap().envelope();
    let mut source_graph = Graph::open(&source_dir).unwrap();
    assert_eq!(helpers(&mut source_graph), deps);
    let mut source_registration = Phase::default();
    let source_root = authored.artifact_id();
    source_registration.measure(|| {
        assert_eq!(
            source_graph
                .ingest(envelope.clone(), Instant::now())
                .unwrap()
                .status,
            "accepted"
        );
    });

    let source_packet_bytes = frame_bytes(wire::Body::Object {
        root: *source_root.as_bytes(),
        object: envelope,
    })
    .await;
    let mut helper_packet_bytes = 0;
    for dependency in deps.iter().cloned() {
        helper_packet_bytes += frame_bytes(wire::Body::Object {
            root: *source_root.as_bytes(),
            object: dependency,
        })
        .await;
    }
    let helper_bytes = deps
        .iter()
        .map(|object| crate::unhex(&object.payload).unwrap().len())
        .sum::<usize>();
    let witness_report = publish_witness(directory, &question, &budget).await;
    let report = json!({
        "statement_id": hex(authored.statement_id().as_bytes()),
        "primitive_results": digests.len(),
        "typed_universal_actions": selected.len(),
        "exact_helper_artifacts": deps.iter().map(|object| &object.artifact_id).collect::<Vec<_>>(),
        "exact_helper_proofs": deps.iter().map(|object| hex(object.proof_id().unwrap().unwrap().as_bytes())).collect::<Vec<_>>(),
        "question_bytes": QUESTION.len(),
        "helper_canonical_payload_bytes": helper_bytes, "helper_object_frame_bytes": helper_packet_bytes,
        "source_certificate": {"artifact_id": hex(source_root.as_bytes()), "proof_id":hex(authored.proof_id().as_bytes()), "canonical_bytes": authored.normal_form().canonical_bytes().len(),
            "object_frame_bytes":source_packet_bytes, "decode_normalize_check":source_phase.json(),
            "recheck_and_register":source_registration.json()},
        "source_program": projected_report,
        "typed_program": typed_report,
        "source_projection":projection_phase.json(),
        "short_witness":witness_report,
        "independent_certificate_trace":oracle_phase.json(), "seed_helpers":helper_storage.json(),
    });
    drop((checked, graph, source_graph, projected, projected_graph));
    std::fs::write(
        directory.join("seed.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
}

fn checked_certificate(bytes: &[u8], context: &dyn ContextView) -> naome_checker::CheckedProof {
    let certificate = naome_proof::ProofCertificate::from_canonical_bytes(bytes).unwrap();
    naome_checker::normalize_and_check_with_state(certificate, context).unwrap()
}

async fn publish_witness(
    directory: &Path,
    question: &ResearchQuestion,
    budget: &Budget,
) -> serde_json::Value {
    let mut decode = Phase::default();
    let commands = decode.measure(|| {
        decode_records(include_bytes!(
            "../../../../naome-checker/tests/fixtures/membership-witness.program"
        ))
        .unwrap()
    });
    let [
        Command::Deduce {
            assumptions,
            actions,
            ..
        },
    ] = commands
        .iter()
        .filter(|command| matches!(command, Command::Deduce { .. }))
        .collect::<Vec<_>>()
        .as_slice()
    else {
        panic!("one scoped instruction");
    };
    assert_eq!((assumptions.len(), actions.len()), (9, 9));
    let scope_position = commands
        .iter()
        .position(|command| matches!(command, Command::Deduce { .. }))
        .unwrap();
    let record_sum = |slice: &[Command]| {
        slice
            .iter()
            .map(|command| encode_command(command).unwrap().len())
            .sum::<usize>()
    };
    let directory = directory.join("witness");
    let mut graph = Graph::open(&directory).unwrap();
    let mut work = Work::open(&directory.join("membership-input.sqlite3")).unwrap();
    let mut append = Phase::default();
    append.measure(|| work.append_group(&commands).unwrap());
    let mut check = Phase::default();
    let units = check.measure(|| drain(&mut work, graph.checked_context(), budget));
    let mut export = Phase::default();
    let checked = export.measure(|| {
        while !work.prepare_export(budget).unwrap() {}
        work.into_checked().unwrap()
    });
    let proof = checked.proof().unwrap();
    assert_eq!(
        question.classify_checked_program(proof).unwrap(),
        naome_checker::question::QuestionOutcome::Proved
    );
    assert!(proof.dependencies_after(None, 1).unwrap().is_empty());
    assert!(
        proof
            .definition_dependencies_after(None, 1)
            .unwrap()
            .is_empty()
    );
    let mut report = publish_program(&mut graph, &checked).await;
    report["prototype_bytes"] = 215.into();
    report["assumptions"] = assumptions.len().into();
    report["scoped_actions"] = actions.len().into();
    report["graph_bytes"] = record_sum(&commands[..scope_position]).into();
    report["scope_bytes"] = record_sum(&commands[scope_position..scope_position + 1]).into();
    report["close_and_seal_bytes"] = record_sum(&commands[scope_position + 1..]).into();
    report["exact_dependencies"] = json!([]);
    report["independent_hilbert_steps"] = 717.into();
    report["independent_hilbert_bytes"] = 195139.into();
    report["decode"] = decode.json();
    report["append"] = append.json();
    report["check"] = check.json();
    report["export"] = export.json();
    report["checker_work_units"] = units.into();
    report
}

#[test]
fn warm_membership_dependencies() {
    if let Some(directory) = std::env::var_os("NAOME_TYPED_PAIR_WARM") {
        let mut graph = Graph::open(&PathBuf::from(directory)).unwrap();
        assert_eq!(helpers(&mut graph).len(), 4);
    }
}

#[test]
fn natural_number_projection_preserves_the_binder_and_exact_definition() {
    use naome_checker::{ArtifactState, program::Engine};
    use naome_foundation::{FreeVariable, ZfcAxiom};

    let infinity = ZfcAxiom::Infinity.formula();
    let existential = infinity.view().negated().unwrap().to_owned();
    let body = existential
        .open_outer_universal(FreeVariable::new(0))
        .unwrap();
    let inductive = body.view().negated().unwrap().to_owned();
    use naome_proof::{DefinedFormula, DefinitionCertificate, ProofCertificate, ProofFormula};
    let definition =
        DefinitionCertificate::relation(1, DefinedFormula::from_primitive(&inductive).unwrap())
            .unwrap();
    let id = definition.definition_id();
    let mut context = ArtifactState::new();
    let checked = naome_checker::check_definition_with_state(definition, &context).unwrap();
    context.register_definition(checked).unwrap();

    let [j, i, n] = [0, 1, 2].map(FreeVariable::new);
    let body = DefinedFormula::implies(
        DefinedFormula::defined_relation(id, [j]),
        DefinedFormula::member(n, j),
    );
    let certificate = ProofCertificate::new(vec![
        ProofStep::UniversalInstantiation {
            variable: j,
            replacement: i,
            body: ProofFormula::from_defined(body).unwrap(),
        },
        ProofStep::Generalization {
            premise: 0,
            variable: i,
        },
        ProofStep::Generalization {
            premise: 1,
            variable: n,
        },
    ])
    .unwrap();
    let authored = naome_checker::normalize_and_check_with_state(certificate, &context).unwrap();
    let projection = Projection::from_normal_form(authored.normal_form());
    let (_, digests) =
        check_normal_form_with_step_digests(authored.normal_form().clone(), &context).unwrap();

    let mut engine = Engine::open(rusqlite::Connection::open_in_memory().unwrap()).unwrap();
    engine.append_group(projection.commands()).unwrap();
    while engine.advance(32, 32768, &context).unwrap() {}
    for (&position, digest) in projection.results().iter().zip(digests) {
        let StepResult::Result(position) = position else {
            panic!("unfused projection");
        };
        assert_eq!(engine.result_digest(position).unwrap(), (digest, true));
    }
    while !engine.prepare_export(64).unwrap() {}
    let proof = engine.checked().unwrap();
    assert_eq!(proof.conclusion(), Some(authored.conclusion()));
    assert_eq!(proof.definition_dependencies_after(None, 2).unwrap(), [id]);

    let other = DefinitionCertificate::relation(1, DefinedFormula::equal(j, j)).unwrap();
    assert_ne!(other.definition_id(), id);
    let mut wrong_context = ArtifactState::new();
    let substitute = naome_checker::check_definition_with_state(other, &wrong_context).unwrap();
    wrong_context.register_definition(substitute).unwrap();
    for state in [&ArtifactState::new(), &wrong_context] {
        let mut rejected = Engine::open(rusqlite::Connection::open_in_memory().unwrap()).unwrap();
        rejected.append_group(projection.commands()).unwrap();
        let error = rejected.advance(128, 32768, state).unwrap_err();
        assert_eq!(
            error.diagnostic().unwrap().outcome,
            naome_checker::diagnostics::Outcome::MissingDependency
        );
        assert!(!rejected.status().unwrap().fully_checked);
    }

    let premise = ProofFormula::from_defined(DefinedFormula::for_all(
        i,
        DefinedFormula::defined_relation(id, [i]),
    ))
    .unwrap();
    let scoped = ProofCertificate::new(vec![ProofStep::Simplification {
        antecedent: premise.clone(),
        consequent: premise,
    }])
    .unwrap();
    let checked = naome_checker::normalize_and_check_with_state(scoped, &context).unwrap();
    let scoped = Projection::from_normal_form(checked.normal_form());
    assert_eq!(
        scoped
            .commands()
            .iter()
            .filter(|command| matches!(
                command,
                naome_proof::program::Command::DefinedRelation { .. }
            ))
            .count(),
        1
    );
    let mut engine = Engine::open(rusqlite::Connection::open_in_memory().unwrap()).unwrap();
    engine.append_group(scoped.commands()).unwrap();
    while engine.advance(64, 32768, &context).unwrap() {}
    while !engine.prepare_export(64).unwrap() {}
    assert_eq!(
        engine.checked().unwrap().conclusion(),
        Some(checked.conclusion())
    );
}
