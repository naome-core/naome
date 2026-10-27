//! Owner questions are admitted by conservative lineage before learning.
//! Existing corpus and frontier lineages never enter through this route.
use super::{Case, frontier};
use naome_authoring::CompiledQuestion;
use naome_foundation::{Formula, FormulaView, graph::Node};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::LazyLock};

static ORIGINAL: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("owned-exclusions.json")).expect("sealed corpus shapes")
});
#[derive(serde::Deserialize)]
struct Retired {
    ids: BTreeSet<String>,
    families: BTreeSet<String>,
}
static RETIRED: LazyLock<Retired> = LazyLock::new(|| {
    serde_json::from_str(include_str!("composition-retired.json"))
        .expect("retired composition families")
});
pub(super) fn retired(id: &str) -> bool {
    RETIRED.ids.contains(id)
}
/// Atom kind and connective/quantifier structure survive; names do not.
/// Ignoring atomic arguments intentionally groups more questions together.
pub fn family(formula: &Formula) -> String {
    fn visit(f: FormulaView<'_>, bytes: &mut Vec<u8>) {
        match f.graph_node() {
            Node::Equal(..) => bytes.push(b'e'),
            Node::Member(..) => bytes.push(b'm'),
            Node::Not(a) => {
                bytes.push(b'n');
                visit(a, bytes);
            }
            Node::Implies(a, b) => {
                bytes.push(b'i');
                visit(a, bytes);
                visit(b, bytes);
            }
            Node::ForAll(a) => {
                bytes.push(b'a');
                visit(a, bytes);
            }
        }
    }
    let mut bytes = b"naome:owned-question-family\0".to_vec();
    visit(formula.view(), &mut bytes);
    crate::hex(&Sha256::digest(bytes))
}
pub(super) fn sealed_family(family: &str) -> bool {
    ORIGINAL.contains(family)
        || frontier::BANK.families.contains(family)
        || RETIRED.families.contains(family)
}
pub fn case(question: &str) -> Option<Case> {
    let q = CompiledQuestion::compile(question).ok()?;
    let id = crate::hex(q.resolution_id());
    if let Some(case) = super::learning(&id) {
        return Some(case.clone());
    }
    if super::reserved(&id) {
        return None;
    }
    let family = family(q.proved_target());
    if sealed_family(&family) || super::composition::BANK.reserved_families.contains(&family) {
        return None;
    }
    // Novel owner goals may teach the node. Held-out families are explicitly
    // sealed by their owning corpus; arbitrary hash buckets do not reserve an
    // otherwise unclassified user question.
    Some(Case {
        id,
        source: q.source().to_owned(),
        family: format!("owned-{family}"),
        dependency: family,
        development: false,
    })
}
#[cfg(test)]
pub fn original_exclusions() -> &'static BTreeSet<String> {
    &ORIGINAL
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn new_lineages_keep_reserved_and_existing_structural_siblings_out() {
        assert_eq!(original_exclusions().len(), 2063);
        for existing in super::super::CORPUS.cases.iter().take(12) {
            let q = CompiledQuestion::compile(&existing.source).unwrap();
            assert!(original_exclusions().contains(&family(q.proved_target())));
        }
        for q in super::super::development() {
            assert!(case(&q.source).is_none());
        }
        let first = CompiledQuestion::compile("goal=all(x,all(y,imp(mem(x,x),mem(y,x))))").unwrap();
        let renamed =
            CompiledQuestion::compile("goal=all(u,all(v,imp(mem(v,u),mem(u,u))))").unwrap();
        assert_eq!(
            family(first.proved_target()),
            family(renamed.proved_target())
        );
        assert!(
            frontier::BANK
                .learning
                .iter()
                .all(|q| case(&q.source).is_some())
        );
        assert!(
            frontier::BANK
                .confirmation
                .iter()
                .all(|q| case(&q.source).is_none())
        );
    }
}
