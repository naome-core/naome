use super::*;

#[test]
fn stored_block_rejects_more_than_the_storage_record_limit() {
    let id = ArtifactId::from_bytes([3; 32]);
    let chunk = Chunk {
        start: 0,
        previous: [0; 32],
        next: [0; 32],
        records: vec![
            naome_proof::program::Command::Equal { left: 0, right: 0 };
            BLOCK_RECORDS + 1
        ],
    };
    let bytes = chunk.canonical_bytes().unwrap();
    let digest = chunk_digest(id, 0, 0, &bytes);
    assert!(decode_chunk(id, 0, 0, &bytes, digest).is_err());
}

#[test]
fn failed_rollback_reports_uncertain_program_durability() {
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
    let mut db = Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE item(value INTEGER); INSERT INTO item VALUES(1)")
        .unwrap();
    db.authorizer(Some(|context: AuthContext<'_>| {
        if matches!(
            context.action,
            AuthAction::Transaction {
                operation: TransactionOperation::Rollback
            }
        ) {
            Authorization::Deny
        } else {
            Authorization::Allow
        }
    }))
    .unwrap();
    let tx = begin(&db, TransactionBehavior::Immediate).unwrap();
    tx.execute("UPDATE item SET value=2", []).unwrap();
    let error =
        finish_program(tx, Err(crate::InputFault::CatalogProgramInputHash.into())).unwrap_err();
    assert!(matches!(error, crate::Error::UncertainDurability(failure)
        if failure.code == crate::DurabilityCode::RollbackUnconfirmed
            && failure.sqlite_code.is_some_and(|code| code.get() == rusqlite::ffi::SQLITE_AUTH)));
    db.authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
        .unwrap();
    db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        db.query_row("SELECT value FROM item", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn missing_staged_program_and_invalid_addresses_have_distinct_causes() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE programs (id BLOB, manifest BLOB, received INTEGER, input_bytes INTEGER, hash BLOB, remaining BLOB)").unwrap();
    let manifest = Manifest {
        commands: 1,
        input_bytes: 0,
        program_hash: [0; 32],
        stream_root: [0; 32],
        conclusion: [0; 32],
        statement: [0; 32],
    };
    assert!(matches!(
        progress(&db, &manifest),
        Err(crate::Error::InputFault(
            crate::InputFault::CatalogProgramStagingMissing
        ))
    ));
    assert_eq!(
        ordinal(u64::MAX).unwrap_err(),
        crate::Error::from(crate::InputFault::CatalogProgramAddressExhausted)
    );
    assert_eq!(
        positive(-1).unwrap_err(),
        crate::Error::from(crate::InputFault::CatalogProgramAddressNegative)
    );
}
