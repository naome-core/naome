//! Admit only ordinary allow ACEs addressed to the already-checked owner.
//!
//! This intentionally does not implement Windows access-check evaluation.
//! Object/callback/conditional ACEs, null DACLs and unknown syntax are refused.

pub(super) fn owner_only(sddl: &str, mut is_owner: impl FnMut(&str) -> bool) -> bool {
    if sddl.len() > 1_048_576 {
        return false;
    }
    let Some(dacl) = sddl.strip_prefix("D:") else {
        return false;
    };
    let Some(first_ace) = dacl.find('(') else {
        return false;
    };
    let mut flags = &dacl[..first_ace];
    let mut seen = 0_u8;
    while !flags.is_empty() {
        let (flag, bit) = if flags.starts_with('P') {
            ("P", 1)
        } else if flags.starts_with("AI") {
            ("AI", 2)
        } else if flags.starts_with("AR") {
            ("AR", 4)
        } else {
            return false;
        };
        if seen & bit != 0 {
            return false;
        }
        seen |= bit;
        flags = &flags[flag.len()..];
    }
    let mut aces = &dacl[first_ace..];
    while !aces.is_empty() {
        let Some(ace) = aces.strip_prefix('(') else {
            return false;
        };
        let Some(end) = ace.find(')') else {
            return false;
        };
        let mut fields = ace[..end].split(';');
        let (Some(kind), Some(flags), Some(rights), Some(object), Some(inherited), Some(sid)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return false;
        };
        if fields.next().is_some()
            || kind != "A"
            || !pairs(flags, &["OI", "CI", "NP", "IO", "ID"])
            || !valid_rights(rights)
            || !object.is_empty()
            || !inherited.is_empty()
            || !valid_trustee(sid)
            || !is_owner(sid)
        {
            return false;
        }
        aces = &ace[end + 1..];
    }
    true
}

fn pairs(value: &str, allowed: &[&str]) -> bool {
    value.is_ascii()
        && value.len().is_multiple_of(2)
        && value
            .as_bytes()
            .chunks_exact(2)
            .all(|part| allowed.iter().any(|allowed| part == allowed.as_bytes()))
}

fn valid_rights(rights: &str) -> bool {
    if let Some(hex) = rights.strip_prefix("0x") {
        return !hex.is_empty() && hex.len() <= 8 && u32::from_str_radix(hex, 16).is_ok();
    }
    !rights.is_empty()
        && pairs(
            rights,
            &[
                "FA", "FR", "FW", "FX", "GA", "GR", "GW", "GX", "RC", "SD", "WD", "WO",
            ],
        )
}

fn valid_trustee(sid: &str) -> bool {
    (sid.len() == 2 && sid.bytes().all(|byte| byte.is_ascii_uppercase()))
        || (sid.starts_with("S-1-")
            && sid.len() <= 184
            && sid[4..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'-'))
}

#[cfg(test)]
mod tests {
    const OWNER: &str = "S-1-5-21-1-2-3-1001";

    fn owner_only(sddl: &str, owner: &str) -> bool {
        super::owner_only(sddl, |sid| sid == owner)
    }

    #[test]
    fn owner_grants_accept_explicit_inherited_and_numeric_rights() {
        for body in [
            "P(A;;FA;;;OWNER)",
            "AI(A;ID;FRFW;;;OWNER)",
            "PAI(A;;0x001f01ff;;;OWNER)(A;OICIIO;FR;;;OWNER)",
        ] {
            assert!(owner_only(
                &format!("D:{}", body.replace("OWNER", OWNER)),
                OWNER
            ));
        }
        // Native ownership comparison resolves aliases outside this parser.
        assert!(super::owner_only("D:PAI(A;;FA;;;LA)", |sid| sid == "LA"));
        assert!(!super::owner_only("D:PAI(A;;FA;;;LA)", |_| false));
    }

    #[test]
    fn any_other_trustee_or_ununderstood_acl_fails_closed() {
        for body in [
            "",
            "NO_ACCESS_CONTROL",
            "P",
            "PP(A;;FA;;;OWNER)",
            "P(A;;FA;;;OWNER)(A;;FR;;;WD)",
            "AI(A;ID;FR;;;BU)",
            "P(A;;FA;;;BA)",
            "P(D;;FR;;;OWNER)",
            "P(OA;;FA;guid;;OWNER)",
            "P(XA;;FA;;;OWNER;(condition))",
            "P(A;ZZ;FA;;;OWNER)",
            "P(A;;ZZ;;;OWNER)",
            "P(A;;0x100000000;;;OWNER)",
            "P(A;;FA;;;OWNER;extra)",
            "P(A;;FA;;;OWNER)S:",
            "P(A;;FA;;;OWNER",
            "P(A;;FA;;;OWNER))",
            "P(A;;FA;;;LAO:SY)",
            "P(A;;FA;;;LA\0)",
        ] {
            assert!(
                !owner_only(&format!("D:{}", body.replace("OWNER", OWNER)), OWNER),
                "{body}"
            );
        }
        assert!(!owner_only("", OWNER));
        assert!(!owner_only("O:S-1-5-18D:P(A;;FA;;;SY)", OWNER));
        for trustee in ["LAO:SY", "LA\0", "S-1-5-21O:SY", "S-1-5-21\0"] {
            assert!(!super::owner_only(
                &format!("D:P(A;;FA;;;{trustee})"),
                |_| panic!("invalid token must not reach native SDDL decoding"),
            ));
        }
    }
}
