use super::*;
use libp2p::futures::io::Cursor;

fn encoded() -> Vec<u8> {
    let bytes = serde_json::to_vec(
        &Frame::new(Body::Inventory {
            known: None,
            after: None,
            limit: crate::resources::limits().inventory_page,
        })
        .message,
    )
    .unwrap();
    let mut framed = (bytes.len() as u32).to_be_bytes().to_vec();
    framed.extend(bytes);
    framed
}

#[test]
fn current_message_schema_requires_exact_fields_and_types() {
    for body in [
        serde_json::json!([crate::outcome::MessageKind::Inventory,{"known":null,"after":null,"limit":"untrusted"}]),
        serde_json::json!([crate::outcome::MessageKind::Inventory,{"known":null,"after":null,"limit":1,"extra":true}]),
        serde_json::json!([crate::outcome::MessageKind::Inventory,{"after":null,"limit":1}]),
    ] {
        assert!(
            serde_json::from_value::<Message>(
                serde_json::json!({"compatibility":crate::compatibility(),"body":body})
            )
            .is_err()
        );
    }
    assert_eq!(PROTOCOL.as_ref(), "/naome/knowledge");
}

#[test]
fn peer_outcomes_accept_only_codes_in_their_own_domain() {
    let busy = Body::Error {
        code: PeerFailure::OwnerBusy,
    };
    assert_eq!(
        serde_json::to_vec(&busy).unwrap(),
        br#"[1703948,{"code":65537}]"#
    );
    assert!(matches!(
        serde_json::from_slice::<Body>(br#"[1703948,{"code":65537}]"#),
        Ok(Body::Error {
            code: PeerFailure::OwnerBusy
        })
    ));
    for input in [
        br#"[1703948,{"code":131073}]"#.as_slice(),
        br#"[1703948,{"code":131071}]"#,
        br#"[1703948,{"code":65537,"grant":true}]"#,
    ] {
        assert!(serde_json::from_slice::<Body>(input).is_err());
    }
}

#[test]
fn numeric_control_body_rejects_unknown_binary_and_extra_fields() {
    use crate::outcome::MessageKind;
    let missing = u32::from(MessageKind::Missing);
    assert!(matches!(
        serde_json::from_str::<Body>(&format!("[{missing},{{}}]")),
        Ok(Body::Missing)
    ));
    for input in [
        format!("[{missing},{{\"extra\":true}}]"),
        format!("[{missing},{{}},0]"),
        format!("[{missing}]"),
        format!("[{},{{}}]", u32::from(MessageKind::Object)),
        "[4294967295,{}]".to_owned(),
    ] {
        assert!(serde_json::from_str::<Body>(&input).is_err(), "{input}");
    }
}

#[tokio::test]
async fn strict_frames_reject_oversize_trailing_and_truncation() {
    let codec = Codec::default();
    assert!(codec.read(&mut Cursor::new(encoded())).await.is_ok());
    let mut trailing = encoded();
    trailing.push(0);
    assert_eq!(
        stream_failure(&codec.read(&mut Cursor::new(trailing)).await.unwrap_err()),
        WireFailure::TrailingFrameBytes
    );
    let mut truncated = encoded();
    truncated.pop();
    assert!(codec.read(&mut Cursor::new(truncated)).await.is_err());
    let header = (frame_limit() as u32 + 1).to_be_bytes().to_vec();
    assert_eq!(
        stream_failure(&codec.read(&mut Cursor::new(header)).await.unwrap_err()),
        WireFailure::FrameLimit
    );
}

#[tokio::test]
async fn frame_custody_is_shared_and_released_after_handling() {
    let codec = Codec::default();
    let other = codec.clone();
    let mut retained = Vec::new();
    for _ in 0..crate::resources::active_limits().inbound_frames {
        retained.push(codec.read(&mut Cursor::new(encoded())).await.unwrap());
    }
    assert_eq!(
        stream_failure(&other.read(&mut Cursor::new(encoded())).await.unwrap_err()),
        WireFailure::FrameCapacity
    );
    retained.pop();
    assert!(other.read(&mut Cursor::new(encoded())).await.is_ok());
}

#[tokio::test]
async fn program_data_transmits_the_canonical_records_in_a_bounded_frame() {
    use naome_proof::program::{Chunk, Command};
    let chunk = Chunk {
        start: 3,
        previous: [7; 32],
        next: [8; 32],
        records: vec![
            Command::Instantiate {
                premise: 2,
                replacement: 1
            };
            64
        ],
    };
    let codec = Codec::default();
    let frame = Frame::new(Body::ProgramData {
        root: [1; 32],
        id: [2; 32],
        chunk: chunk.clone(),
    });
    let mut output = Cursor::new(Vec::new());
    codec.write(&mut output, frame).await.unwrap();
    let encoded = output.into_inner();
    let decoded = codec.read(&mut Cursor::new(&encoded)).await.unwrap();
    assert!(matches!(decoded.message.body,
        Body::ProgramData { root, id, chunk: decoded }
            if root == [1; 32] && id == [2; 32] && decoded == chunk));

    assert_eq!(
        &encoded[4 + 32 + 1 + 64..],
        chunk.canonical_bytes().unwrap()
    );
    let mut malformed = encoded.clone();
    *malformed.last_mut().unwrap() = 0x80;
    assert!(codec.read(&mut Cursor::new(malformed)).await.is_err());
}

#[tokio::test]
async fn program_offer_binds_the_canonical_question_bytes() {
    use crate::object::ProgramMetadata;
    use naome_checker::question::ResearchQuestion;
    use naome_foundation::{Formula, FreeVariable};
    use naome_proof::program::{Manifest, formula_hash};
    use naome_proof::{DefinedFormula, DefinitionCertificate};

    let x = FreeVariable::new(0);
    let mut context = naome_checker::ArtifactState::new();
    let certificate = DefinitionCertificate::relation(1, DefinedFormula::equal(x, x)).unwrap();
    let definition_id = certificate.definition_id();
    let definition = naome_checker::check_definition_with_state(certificate, &context).unwrap();
    context.register_definition(definition).unwrap();
    let question = ResearchQuestion::from_defined_formula(
        DefinedFormula::for_all(x, DefinedFormula::defined_relation(definition_id, [x])),
        &context,
    )
    .unwrap();
    let target = Formula::for_all(x, Formula::equal(x, x))
        .encode_canonical()
        .unwrap();
    let manifest = Manifest {
        commands: 1,
        input_bytes: 2,
        program_hash: [7; 32],
        stream_root: [8; 32],
        conclusion: formula_hash(question.formula()),
        statement: *naome_proof::StatementId::of_canonical_formula(&target)
            .unwrap()
            .as_bytes(),
    };
    let metadata = ProgramMetadata {
        manifest,
        question: Some(question.to_hex()),
    };
    let codec = Codec::default();
    let mut bytes = Cursor::new(Vec::new());
    codec
        .write(&mut bytes, Frame::new(Body::ProgramOffer { metadata }))
        .await
        .unwrap();
    assert!(bytes.get_ref().ends_with(question.canonical_bytes()));
    let decoded = codec
        .read(&mut Cursor::new(bytes.into_inner()))
        .await
        .unwrap();
    let Body::ProgramOffer { metadata } = decoded.message.body else {
        panic!("expected program offer");
    };
    assert!(
        metadata
            .question(&naome_checker::ArtifactState::new())
            .is_err()
    );
    assert_eq!(metadata.question(&context).unwrap(), Some(question));
}

#[tokio::test]
async fn cold_artifact_frame_packs_exact_bytes_and_bounds_expansion() {
    let object = Envelope {
        compatibility: crate::hex(&crate::compatibility()),
        artifact_id: crate::hex(&[9; 32]),
        statement_id: None,
        obligation_proof: Some(crate::hex(&[10; 32])),
        payload: "04aabbcc".repeat(2048),
    };
    let codec = Codec::default();
    let mut output = Cursor::new(Vec::new());
    codec
        .write(
            &mut output,
            Frame::new(Body::Object {
                root: [3; 32],
                object: object.clone(),
                question: None,
            }),
        )
        .await
        .unwrap();
    let bytes = output.into_inner();
    assert!(bytes.len() < object.payload.len() / 4);
    let decoded = codec.read(&mut Cursor::new(&bytes)).await.unwrap();
    assert!(matches!(&decoded.message.body,
        Body::Object { root, object: decoded, question: None } if *root == [3; 32] && decoded == &object));

    // Five fixed addresses, kind and option flags precede the packed length.
    let packed = 4 + 5 * 32 + 1 + 2;
    assert_ne!(bytes[packed] & 0x80, 0);
    let declared = packed + 4;
    let payload = declared + 4;
    drop(decoded);
    let capacity = codec.budget.available_permits();

    let mut oversized = bytes.clone();
    let excessive = (crate::resources::limits().proof_bytes + 1) as u32;
    oversized[declared..payload].copy_from_slice(&excessive.to_be_bytes());

    let mut wrong_length = bytes.clone();
    let expanded = (object.payload.len() / 2 + 1) as u32;
    wrong_length[declared..payload].copy_from_slice(&expanded.to_be_bytes());

    let mut corrupt = bytes.clone();
    let question_flag = corrupt.len() - 1;
    corrupt[payload..question_flag].fill(0xff);

    for (frame, expected) in [
        (oversized, WireFailure::ArtifactPayloadLimit),
        (wrong_length, WireFailure::ArtifactCompression),
        (corrupt, WireFailure::ArtifactCompression),
    ] {
        let error = codec.read(&mut Cursor::new(frame)).await.unwrap_err();
        assert_eq!(stream_failure(&error), expected);
        assert_eq!(codec.budget.available_permits(), capacity);
        assert!(codec.read(&mut Cursor::new(&bytes)).await.is_ok());
    }
}

#[test]
fn cooperative_messages_use_numeric_kinds_and_strict_payloads() {
    let offer = Body::WorkOffer {
        goal: [7; 32],
        question: "abc".into(),
    };
    let value = serde_json::to_value(&offer).unwrap();
    assert_eq!(value[0], 0x001a_0011_u32);
    assert!(
        matches!(serde_json::from_value::<Body>(value.clone()), Ok(Body::WorkOffer { goal, question }) if goal == [7; 32] && question == "abc")
    );
    let mut incomplete = value;
    incomplete[1].as_object_mut().unwrap().remove("question");
    assert!(serde_json::from_value::<Body>(incomplete).is_err());
    let status = Body::WorkStatus {
        goal: [7; 32],
        question: [8; 32],
        active: true,
        sequence: 9,
    };
    let value = serde_json::to_value(status).unwrap();
    assert_eq!(value[0], 0x001a_0012_u32);
    assert!(
        matches!(serde_json::from_value::<Body>(value), Ok(Body::WorkStatus { goal, question, active: true, sequence: 9 }) if goal == [7; 32] && question == [8; 32])
    );
}
