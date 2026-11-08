use super::*;
#[test]
fn complete_experience_roundtrips_and_noncanonical_phases_fail_closed() {
    for value in 0..32u8 {
        let p = Packed(
            u64::MAX,
            [1000; CONTEXT],
            [value; 3],
            "11".repeat(32),
            "11".repeat(32),
            Some("33".repeat(32)),
            u64::MAX,
            [120, 0],
            [true, false],
            [u64::MAX, u64::MAX],
            [
                0,
                0,
                crate::learning::transfer::Summary::prefix(crate::learning::transfer::CASES),
            ],
        );
        let bytes = serde_json::to_vec(&p).unwrap();
        let decoded = Experience::try_from(p);
        if (value >> 2) & 3 == 3 {
            assert!(decoded.is_err());
        } else {
            let experience = decoded.unwrap();
            assert_eq!(
                serde_json::to_vec(&Packed::from(&experience)).unwrap(),
                bytes
            );
            let named = serde_json::to_vec(&experience).unwrap();
            let restored: Experience = serde_json::from_slice(&named).unwrap();
            assert_eq!(serde_json::to_vec(&restored).unwrap(), named);
        }
    }
    let mut invalid = serde_json::to_value(Packed(
        1,
        [0; CONTEXT],
        [0; 3],
        "11".repeat(32),
        "11".repeat(32),
        None,
        0,
        [0, 0],
        [false, false],
        [0, 0],
        [0; 3],
    ))
    .unwrap();
    invalid[2][0] = 32.into();
    assert!(Experience::try_from(serde_json::from_value::<Packed>(invalid).unwrap()).is_err());
}
