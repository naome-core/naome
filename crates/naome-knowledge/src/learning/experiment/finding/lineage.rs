//! Research split provenance only; this metadata grants no proof authority.
use super::*;
use serde::Deserialize;

pub(super) struct Holdout {
    digest: String,
    families: BTreeSet<String>,
    resolutions: BTreeSet<String>,
    lineages: BTreeSet<String>,
}
impl Holdout {
    pub(super) fn read(bytes: &[u8], expected: &str) -> Result<Self, String> {
        if crate::hex(&Sha256::digest(bytes)) != expected {
            return Err("confirmation source bytes differ from the frozen bank".into());
        }
        let bank: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        let cases = bank["cases"]
            .as_array()
            .ok_or("confirmation cases missing")?;
        if cases.is_empty() {
            return Err("confirmation bank is empty".into());
        }
        let mut result = Self {
            digest: expected.to_owned(),
            families: BTreeSet::new(),
            resolutions: BTreeSet::new(),
            lineages: BTreeSet::new(),
        };
        for case in cases {
            let q = CompiledQuestion::compile(case["source"].as_str().ok_or("source missing")?)
                .map_err(|e| e.to_string())?;
            let family = curriculum::owned::family(q.proved_target());
            let resolution = crate::hex(q.resolution_id());
            let lineage = case["lineage"].as_str().ok_or("authored lineage missing")?;
            if lineage.is_empty()
                || case["family"] != family
                || case["resolution"] != resolution
                || !result.resolutions.insert(resolution)
            {
                return Err("confirmation source identity differs".into());
            }
            result.families.insert(family);
            result.lineages.insert(lineage.to_owned());
        }
        Ok(result)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Material {
    question: String,
    /// Original authored family, independent of the target's structural hash.
    lineage: Option<String>,
    experience: Option<experience::ExperienceSummary>,
    /// Content digests of complete immediate input records, never entity IDs.
    parents: BTreeSet<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ledger {
    bank: String,
    materials: BTreeMap<String, Material>,
}
impl Ledger {
    pub(super) fn new(holdout: &Holdout) -> Self {
        Self {
            bank: holdout.digest.clone(),
            materials: BTreeMap::new(),
        }
    }

    pub(super) fn original(
        &mut self,
        question: &CompiledQuestion,
        lineage: &str,
        experience: &experience::ExperienceSummary,
    ) -> Result<String, String> {
        experience.validate()?;
        if lineage.is_empty() || experience.question != crate::hex(question.resolution_id()) {
            return Err("original experience source differs".into());
        }
        self.insert(Material {
            question: question.source().to_owned(),
            lineage: Some(lineage.to_owned()),
            experience: Some(experience.clone()),
            parents: BTreeSet::new(),
        })
    }

    pub(super) fn derived(
        &mut self,
        question: &CompiledQuestion,
        parents: BTreeSet<String>,
    ) -> Result<String, String> {
        if parents.is_empty() || parents.iter().any(|p| !self.materials.contains_key(p)) {
            return Err("derived material lacks its complete known parents".into());
        }
        self.insert(Material {
            question: question.source().to_owned(),
            lineage: None,
            experience: None,
            parents,
        })
    }

    fn insert(&mut self, material: Material) -> Result<String, String> {
        let key = digest(&material);
        let mut next = self.clone();
        next.materials.insert(key.clone(), material);
        // This is one bounded experiment input page, not a second source store.
        if serde_json::to_vec(&next).map_err(|e| e.to_string())?.len() > history::PAGE_BYTES {
            return Err("experience lineage page exceeds the existing history bound".into());
        }
        *self = next;
        Ok(key)
    }

    pub(super) fn read(bytes: &[u8], holdout: &Holdout) -> Result<Self, String> {
        if bytes.len() > history::PAGE_BYTES {
            return Err("experience lineage page exceeds the existing history bound".into());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if value.bank != holdout.digest || value.materials.is_empty() {
            return Err("experience lineage bank differs or has no original source".into());
        }
        for key in value.materials.keys() {
            value.allowed(key, holdout)?;
        }
        Ok(value)
    }

    pub(super) fn allowed(&self, key: &str, holdout: &Holdout) -> Result<BTreeSet<String>, String> {
        if self.bank != holdout.digest {
            return Err("experience lineage bank differs".into());
        }
        let mut todo = vec![key.to_owned()];
        let mut visited = BTreeSet::new();
        let mut roots = BTreeSet::new();
        while let Some(key) = todo.pop() {
            if !visited.insert(key.clone()) {
                continue;
            }
            let material = self
                .materials
                .get(&key)
                .ok_or("source ancestor is missing")?;
            if digest(material) != key {
                return Err("source ancestor bytes differ".into());
            }
            let question =
                CompiledQuestion::compile(&material.question).map_err(|e| e.to_string())?;
            if holdout
                .families
                .contains(&curriculum::owned::family(question.proved_target()))
                || holdout
                    .resolutions
                    .contains(&crate::hex(question.resolution_id()))
                || material
                    .lineage
                    .as_ref()
                    .is_some_and(|l| holdout.lineages.contains(l))
            {
                return Err("held-out source or ancestor entered experiment material".into());
            }
            match (
                &material.experience,
                &material.lineage,
                material.parents.is_empty(),
            ) {
                (Some(experience), Some(lineage), true) if !lineage.is_empty() => {
                    experience.validate()?;
                    if experience.question != crate::hex(question.resolution_id()) {
                        return Err("original source and experience differ".into());
                    }
                    roots.insert(key);
                }
                (None, None, false) => todo.extend(material.parents.iter().cloned()),
                _ => return Err("source ancestry is incomplete or ambiguous".into()),
            }
        }
        if roots.is_empty() {
            return Err("source ancestry does not reach an original experience".into());
        }
        Ok(roots)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn question(source: &str) -> CompiledQuestion {
        CompiledQuestion::compile(source).unwrap()
    }
    fn receipt(q: &CompiledQuestion) -> experience::ExperienceSummary {
        crate::frontier::evidence::observed_completion(
            q,
            1,
            experience::TerminalEvidence::Unknown,
            0,
            None,
        )
        .experience
        .unwrap()
    }
    fn bank(q: &CompiledQuestion) -> (Vec<u8>, Holdout) {
        let bytes = serde_json::to_vec(&json!({"cases":[{
            "source":q.source(),"resolution":crate::hex(q.resolution_id()),
            "family":curriculum::owned::family(q.proved_target()),"lineage":"reserved-family"
        }]}))
        .unwrap();
        let frozen = crate::hex(&Sha256::digest(&bytes));
        let guard = Holdout::read(&bytes, &frozen).unwrap();
        (bytes, guard)
    }

    #[test]
    fn changed_target_and_multiple_derivations_cannot_hide_a_reserved_ancestor() {
        let held = question("goal=all(x,eq(x,x))");
        let other = question("goal=all(x,imp(eq(x,x),eq(x,x)))");
        let (_, guard) = bank(&held);
        assert!(
            !guard
                .families
                .contains(&curriculum::owned::family(other.proved_target()))
        );
        let mut ledger = Ledger::new(&guard);
        let root = ledger
            .original(&held, "reserved-family", &receipt(&held))
            .unwrap();
        let fragment = ledger.derived(&other, [root].into()).unwrap();
        let independent = ledger
            .original(&other, "training-family", &receipt(&other))
            .unwrap();
        assert!(ledger.allowed(&independent, &guard).is_ok());
        let composite = ledger
            .derived(&other, [fragment, independent].into())
            .unwrap();
        assert!(ledger.allowed(&composite, &guard).is_err());
        let sibling = ledger
            .original(&other, "reserved-family", &receipt(&other))
            .unwrap();
        assert!(ledger.allowed(&sibling, &guard).is_err());
        assert!(Ledger::read(&serde_json::to_vec(&ledger).unwrap(), &guard).is_err());
    }

    #[test]
    fn restored_lineage_requires_complete_bound_sources() {
        let held = question("goal=all(x,eq(x,x))");
        let other = question("goal=all(x,imp(eq(x,x),eq(x,x)))");
        let (_, guard) = bank(&held);
        let mut ledger = Ledger::new(&guard);
        let before = digest(&ledger);
        assert!(
            ledger
                .original(&other, "training", &receipt(&held))
                .is_err()
        );
        assert_eq!(before, digest(&ledger));
        let root = ledger
            .original(&other, "training", &receipt(&other))
            .unwrap();
        let derived = ledger.derived(&other, [root.clone()].into()).unwrap();
        let restored = Ledger::read(&serde_json::to_vec(&ledger).unwrap(), &guard).unwrap();
        assert_eq!(
            restored.allowed(&derived, &guard).unwrap(),
            [root.clone()].into()
        );
        assert_eq!(digest(&restored), digest(&ledger));
        let before = digest(&ledger);
        assert!(ledger.derived(&other, BTreeSet::new()).is_err());
        assert!(ledger.derived(&other, [digest(&"absent")].into()).is_err());
        assert_eq!(before, digest(&ledger));
        ledger.materials.remove(&root);
        assert!(Ledger::read(&serde_json::to_vec(&ledger).unwrap(), &guard).is_err());
    }

    #[test]
    fn frozen_bank_and_original_receipts_are_checked_before_use() {
        let held = question("goal=all(x,eq(x,x))");
        let other = question("goal=all(x,imp(eq(x,x),eq(x,x)))");
        let (bytes, guard) = bank(&held);
        assert!(Holdout::read(&bytes, &digest(&"different bank")).is_err());
        let mut bank: Value = serde_json::from_slice(&bytes).unwrap();
        bank["cases"][0]["family"] = json!(digest(&"incorrect family"));
        let corrupt = serde_json::to_vec(&bank).unwrap();
        assert!(Holdout::read(&corrupt, &crate::hex(&Sha256::digest(&corrupt))).is_err());
        let mut ledger = Ledger::new(&guard);
        let root = ledger
            .original(&other, "training", &receipt(&other))
            .unwrap();
        let mut corrupt = ledger.materials.remove(&root).unwrap();
        corrupt.experience.as_mut().unwrap().job += 1;
        let forged = digest(&corrupt);
        ledger.materials.insert(forged.clone(), corrupt);
        assert!(ledger.allowed(&forged, &guard).is_err());
    }
}
