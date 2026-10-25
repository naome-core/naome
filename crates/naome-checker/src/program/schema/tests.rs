use super::*;

#[test]
fn existing_work_keeps_its_records_and_current_constraints() {
    let mut connection = Connection::open_in_memory().unwrap();
    initialize(&mut connection).unwrap();
    connection
        .execute(
            "INSERT INTO input VALUES(0,?1,zeroblob(32))",
            [b"command".as_slice()],
        )
        .unwrap();
    initialize(&mut connection).unwrap();
    let command: Vec<u8> = connection
        .query_row("SELECT command FROM input WHERE position=0", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(command, b"command");
    assert!(
        connection
            .execute("INSERT INTO result VALUES(0,0,2)", [])
            .is_err()
    );
}

#[test]
fn damaged_schema_and_unknown_objects_are_refused_without_replacing_records() {
    for change in [
        "ALTER TABLE input ADD COLUMN unexpected INTEGER",
        "DROP INDEX equation_order",
        "CREATE TRIGGER unexpected AFTER INSERT ON input BEGIN DELETE FROM result; END",
    ] {
        let mut connection = Connection::open_in_memory().unwrap();
        initialize(&mut connection).unwrap();
        connection
            .execute("INSERT INTO result VALUES(0,0,1)", [])
            .unwrap();
        connection.execute_batch(change).unwrap();
        assert!(verify_database(&connection).is_err(), "{change}");
        assert!(initialize(&mut connection).is_err(), "{change}");
        let proved: i64 = connection
            .query_row("SELECT proved FROM result WHERE position=0", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(proved, 1);
    }
}

#[test]
fn unrelated_database_is_neither_admitted_nor_initialized() {
    let mut connection = Connection::open_in_memory().unwrap();
    connection
        .execute("CREATE TABLE unrelated(value INTEGER)", [])
        .unwrap();
    assert!(verify_database(&connection).is_err());
    assert!(initialize(&mut connection).is_err());
    let names = connection
        .prepare("SELECT name FROM sqlite_schema ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(names, ["unrelated"]);
}
