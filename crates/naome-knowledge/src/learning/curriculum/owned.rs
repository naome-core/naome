//! Owner questions are admitted by conservative lineage before learning.
//! Existing corpus and frontier lineages never enter through this route.
use super::{Case, frontier};
use naome_checker::question::ResearchQuestion;
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
    let q = ResearchQuestion::from_hex(question).ok()?;
    let id = crate::hex(q.resolution_id());
    if let Some(case) = super::learning(&id) {
        return Some(case.clone());
    }
    if super::reserved(&id) {
        return None;
    }
    // A continuation of a checked closed source retains its source lineage.
    // Opening outer goal binders does not expose a closed source's bound names.
    if let Some(parent) = crate::training::continuation_parent(q.proved_target())
        && let Ok(source) = ResearchQuestion::from_formula(parent)
    {
        let inherited = case(&source.to_hex())?;
        return Some(Case {
            id,
            source: q.to_hex(),
            family: inherited.family,
            dependency: inherited.dependency,
            development: false,
        });
    }
    let family = family(q.proved_target());
    if sealed_family(&family)
        || super::composition::BANK.reserved_families.contains(&family)
        || super::adaptive::BANK.reserved_families.contains(&family)
    {
        return None;
    }
    // Novel owner goals may teach the node. Held-out families are explicitly
    // sealed by their owning corpus; arbitrary hash buckets do not reserve an
    // otherwise unclassified user question.
    Some(Case {
        id,
        source: q.to_hex(),
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
            let q = ResearchQuestion::from_hex(&existing.source).unwrap();
            assert!(original_exclusions().contains(&family(q.proved_target())));
        }
        for q in super::super::development() {
            assert!(case(&q.source).is_none());
        }
        let first =
            ResearchQuestion::from_hex("04040301010000000101000000010101000000000100000001")
                .unwrap();
        let renamed =
            ResearchQuestion::from_hex("04040301010000000001000000010101000000010100000001")
                .unwrap();
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
    #[test]
    fn proof_continuations_inherit_source_lineage_and_cannot_promote_reserved_parents() {
        fn continuation(source: &str) -> String {
            let q = ResearchQuestion::from_hex(source).unwrap();
            let mut formula = crate::training::continuation(q.proved_target().clone()).unwrap();
            for v in formula.free_variables().into_iter().rev() {
                formula = Formula::for_all(v, formula);
            }
            ResearchQuestion::from_formula(formula)
                .unwrap()
                .to_hex()
                .to_owned()
        }
        let parent = super::super::CORPUS
            .cases
            .iter()
            .find(|c| !c.development)
            .unwrap();
        let child = case(&continuation(&parent.source)).unwrap();
        assert_eq!(child.dependency, parent.dependency);
        assert_eq!(child.family, parent.family);
        assert_ne!(child.id, parent.id);
        let reserved = super::super::development()[0];
        assert!(case(&continuation(&reserved.source)).is_none());
    }
}
