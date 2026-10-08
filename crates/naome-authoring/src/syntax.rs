//! Opt-in source vocabulary. It never rewrites literals, names, or source bytes.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum SourceSyntax {
    #[default]
    Legacy,
    V1,
}

impl SourceSyntax {
    /// Recognizes one exact `nao 1` header after ordinary source trivia.
    /// The returned offset remains in the original source; v1 fixes naome:zfc.
    pub(crate) fn header(source: &str) -> Result<(Self, usize), usize> {
        let mut offset = 0;
        trivia(source, &mut offset);
        if !word_at(source, offset, "nao") {
            return Ok((Self::Legacy, 0));
        }
        offset += 3;
        let before_trivia = offset;
        trivia(source, &mut offset);
        let version = offset;
        if offset == before_trivia || source.as_bytes().get(offset) != Some(&b'1') {
            return Err(version);
        }
        offset += 1;
        if source
            .as_bytes()
            .get(offset)
            .is_some_and(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b'#'))
        {
            return Err(version);
        }
        Ok((Self::V1, offset))
    }

    pub(crate) fn keyword(self, canonical: &str) -> &str {
        if self == Self::Legacy {
            return canonical;
        }
        match canonical {
            "definitions" => "defs",
            "formulas" => "let",
            "statement" => "goal",
            "definition" => "def",
            _ => canonical,
        }
    }

    pub(crate) fn formula(self, name: &str) -> &str {
        if self == Self::Legacy {
            return name;
        }
        match name {
            "eq" => "equal",
            "mem" => "member",
            "ne" => "not_equal",
            "not" => "not_",
            "imp" => "implies",
            "all" => "forall",
            "ex" => "exists",
            "and" => "and_",
            "or" => "or_",
            _ => name,
        }
    }

    pub(crate) fn rule(self, name: &str) -> &str {
        if self == Self::Legacy {
            return name;
        }
        match name {
            "simp" => "simplification",
            "contra" => "classical_contraposition",
            "dist" => "universal_distribution",
            "vacuous" => "vacuous_universal",
            "inst" => "universal_instantiation",
            "mp" => "modus_ponens",
            "refl" => "equality_reflexivity",
            "subst" => "equality_substitution",
            "axiom" => "zfc_axiom",
            "sep" => "separation",
            "replace" => "replacement",
            "gen" => "generalization",
            _ => name,
        }
    }

    pub(crate) fn reserves(self, name: &str) -> bool {
        self == Self::V1
            && (matches!(name, "nao" | "defs" | "refs" | "let" | "goal" | "def")
                || self.formula(name) != name
                || self.rule(name) != name)
    }
}

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
        "equal"
            | "member"
            | "not_"
            | "implies"
            | "forall"
            | "and_"
            | "or_"
            | "iff"
            | "exists"
            | "not_equal"
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
