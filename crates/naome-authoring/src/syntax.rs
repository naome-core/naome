//! The single source vocabulary and lexical trivia. Source bytes are never rewritten.

pub(crate) mod formula;

pub(crate) fn word_at(source: &str, offset: usize, expected: &str) -> bool {
    let remainder = &source[offset..];
    remainder.starts_with(expected)
        && remainder
            .as_bytes()
            .get(expected.len())
            .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
}

pub(crate) fn is_formula_operator(name: &str) -> bool {
    formula::Operator::parse(name).is_some()
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

use naome_foundation::{FORMULA_MAX_DEPTH, FreeVariable};
use std::collections::BTreeMap;

/// One allocation order for presentation variables in every source entry point.
#[derive(Default)]
pub(crate) struct Variables<'a> {
    named: BTreeMap<&'a str, FreeVariable>,
    next: u32,
}
impl<'a> Variables<'a> {
    pub(crate) fn contains(&self, name: &str) -> bool {
        self.named.contains_key(name)
    }
    pub(crate) fn named(&mut self, name: &'a str) -> Option<FreeVariable> {
        if let Some(variable) = self.named.get(name) {
            return Some(*variable);
        }
        let variable = self.fresh()?;
        self.named.insert(name, variable);
        Some(variable)
    }
    pub(crate) fn fresh(&mut self) -> Option<FreeVariable> {
        let variable = FreeVariable::new(self.next);
        self.next = self.next.checked_add(1)?;
        Some(variable)
    }
}

pub(crate) fn name<'a>(source: &'a str, offset: &mut usize) -> Option<&'a str> {
    trivia(source, offset);
    let start = *offset;
    if !source
        .as_bytes()
        .get(start)
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
    {
        return None;
    }
    *offset += 1;
    while source
        .as_bytes()
        .get(*offset)
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
    {
        *offset += 1;
    }
    Some(&source[start..*offset])
}
#[derive(Clone, Copy)]
pub(crate) enum BinderError {
    Name(usize),
    Comma(usize),
    Depth,
    Overflow,
}
/// The shared nonempty binder-list grammar, including its optional final comma.
pub(crate) fn binders<'a>(
    source: &'a str,
    offset: &mut usize,
    variables: &mut Variables<'a>,
) -> Result<Vec<FreeVariable>, BinderError> {
    trivia(source, offset);
    let list = source.as_bytes().get(*offset) == Some(&b'[');
    if list {
        *offset += 1;
    }
    let mut result = Vec::new();
    loop {
        if result.len() == FORMULA_MAX_DEPTH as usize {
            return Err(BinderError::Depth);
        }
        trivia(source, offset);
        let start = *offset;
        let name = name(source, offset).ok_or(BinderError::Name(start))?;
        result.push(variables.named(name).ok_or(BinderError::Overflow)?);
        if !list {
            return Ok(result);
        }
        trivia(source, offset);
        if source.as_bytes().get(*offset) == Some(&b']') {
            *offset += 1;
            return Ok(result);
        }
        if source.as_bytes().get(*offset) != Some(&b',') {
            return Err(BinderError::Comma(*offset));
        }
        *offset += 1;
        trivia(source, offset);
        if source.as_bytes().get(*offset) == Some(&b']') {
            *offset += 1;
            return Ok(result);
        }
    }
}

/// Primitive expansion arithmetic is shared; constructors remain domain-specific.
pub(crate) fn binary_shape(
    operator: &str,
    left: (usize, usize),
    right: (usize, usize),
) -> Option<(usize, usize)> {
    let (ln, ld) = left;
    let (rn, rd) = right;
    match operator {
        "imp" => Some((
            ln.checked_add(rn)?.checked_add(1)?,
            ld.max(rd).checked_add(1)?,
        )),
        "and" => Some((
            ln.checked_add(rn)?.checked_add(3)?,
            ld.checked_add(2)?.max(rd.checked_add(3)?),
        )),
        "or" => Some((
            ln.checked_add(rn)?.checked_add(2)?,
            ld.checked_add(2)?.max(rd.checked_add(1)?),
        )),
        "iff" => Some((
            ln.checked_add(rn)?.checked_mul(2)?.checked_add(5)?,
            ld.max(rd).checked_add(4)?,
        )),
        _ => None,
    }
}

#[derive(Clone, Copy)]
pub(crate) enum BindingError {
    Name,
    Reserved,
    Duplicate,
}
pub(crate) fn binding_name<'a>(
    source: &'a str,
    offset: &mut usize,
    duplicate: impl FnOnce(&str) -> bool,
) -> Result<&'a str, BindingError> {
    let name = name(source, offset).ok_or(BindingError::Name)?;
    if is_reserved_binding_name(name) {
        return Err(BindingError::Reserved);
    }
    if duplicate(name) {
        return Err(BindingError::Duplicate);
    }
    Ok(name)
}
