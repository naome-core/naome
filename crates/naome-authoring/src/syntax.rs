//! The single source vocabulary and lexical trivia. Source bytes are never rewritten.

pub(crate) fn word_at(source: &str, offset: usize, expected: &str) -> bool {
    let remainder = &source[offset..];
    remainder.starts_with(expected)
        && remainder
            .as_bytes()
            .get(expected.len())
            .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
}

pub(crate) fn is_formula_operator(name: &str) -> bool {
    matches!(
        name,
        "eq" | "mem" | "ne" | "not" | "imp" | "all" | "ex" | "and" | "or" | "iff"
    )
}

pub(crate) fn is_reserved_binding_name(name: &str) -> bool {
    is_formula_operator(name)
        || matches!(
            name,
            "defs"
                | "refs"
                | "let"
                | "goal"
                | "def"
                | "relation"
                | "function"
                | "proof"
                | "return"
                | "parameters"
                | "success"
                | "simp"
                | "frege"
                | "contra"
                | "dist"
                | "vacuous"
                | "inst"
                | "mp"
                | "refl"
                | "subst"
                | "axiom"
                | "sep"
                | "replace"
                | "cite"
                | "gen"
        )
}

pub(crate) fn trivia(source: &str, offset: &mut usize) {
    loop {
        while matches!(
            source.as_bytes().get(*offset),
            Some(b' ' | b'\t' | b'\r' | b'\n')
        ) {
            *offset += 1;
        }
        if source.as_bytes().get(*offset) != Some(&b'#') {
            return;
        }
        while !matches!(source.as_bytes().get(*offset), None | Some(b'\n')) {
            *offset += 1;
        }
    }
}
