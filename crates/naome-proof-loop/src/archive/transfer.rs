use super::{Archive, Artifact, EntryId, LEAN_LIBRARIES, LEAN_TOOLCHAIN};
use crate::Result;
use crate::lean::Lean;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};

const MAX_ARTIFACT_BYTES: usize = 65_536;
const MAX_CLOSURE_BYTES: usize = 512 * 1024;
const MAX_OBJECTS: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelArtifact {
    pub(super) dependencies: Vec<EntryId>,
    pub(super) terms: Value,
}

impl KernelArtifact {
    pub fn id(&self) -> Result<EntryId> {
        self.identity_and_size().map(|(id, _)| id)
    }

    fn identity_and_size(&self) -> Result<(EntryId, usize)> {
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err("kernel artifact byte limit exceeded".into());
        }
        let mut hash = Sha256::new();
        hash.update(b"naome:lean-kernel-artifact\0");
        for part in [
            LEAN_TOOLCHAIN.as_bytes(),
            LEAN_LIBRARIES.as_bytes(),
            bytes.as_slice(),
        ] {
            hash.update((part.len() as u64).to_le_bytes());
            hash.update(part);
        }
        Ok((EntryId(hash.finalize().into()), bytes.len()))
    }

    pub(super) fn validate(&self) -> Result<()> {
        if !self.terms.is_object() {
            return Err("kernel terms must be an object".into());
        }
        if self.dependencies.len() >= MAX_OBJECTS
            || self.dependencies.windows(2).any(|ids| ids[0] >= ids[1])
        {
            return Err("kernel dependencies must be unique and sorted".into());
        }
        Ok(())
    }
}

/// A complete, content-addressed dependency closure in dependency order.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelBundle {
    pub root: EntryId,
    declarations: Vec<KernelArtifact>,
}

impl KernelBundle {
    /// The maximum canonical size of a complete encoded bundle.
    pub const MAX_BYTES: usize = MAX_CLOSURE_BYTES;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > Self::MAX_BYTES {
            return Err("kernel bundle byte limit exceeded".into());
        }
        let bundle: Self = serde_json::from_slice(bytes)?;
        if bundle.to_bytes()? != bytes {
            return Err("noncanonical kernel bundle".into());
        }
        Ok(bundle)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.verify_order()?;
        self.encode()
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > Self::MAX_BYTES {
            return Err("kernel bundle byte limit exceeded".into());
        }
        Ok(bytes)
    }

    fn verify_order(&self) -> Result<Vec<EntryId>> {
        if self.declarations.is_empty() || self.declarations.len() > MAX_OBJECTS {
            return Err("invalid kernel bundle object count".into());
        }
        let mut parents = BTreeMap::new();
        let mut ids = Vec::with_capacity(self.declarations.len());
        for artifact in &self.declarations {
            artifact.validate()?;
            if !artifact
                .dependencies
                .iter()
                .all(|id| parents.contains_key(id))
            {
                return Err("kernel bundle dependency missing or out of order".into());
            }
            let id = artifact.id()?;
            if parents
                .insert(id, artifact.dependencies.as_slice())
                .is_some()
            {
                return Err("duplicate kernel artifact".into());
            }
            ids.push(id);
        }
        if ids.last().copied() != Some(self.root) {
            return Err("kernel bundle root does not match its final declaration".into());
        }
        let mut ordered = Vec::with_capacity(ids.len());
        append_dependencies(self.root, &parents, &mut HashSet::new(), &mut ordered);
        if ordered != ids {
            return Err(
                "kernel bundle must contain only the root closure in canonical order".into(),
            );
        }
        Ok(ids)
    }
}

fn append_dependencies(
    id: EntryId,
    parents: &BTreeMap<EntryId, &[EntryId]>,
    seen: &mut HashSet<EntryId>,
    ordered: &mut Vec<EntryId>,
) {
    if seen.insert(id) {
        for &dependency in parents[&id] {
            append_dependencies(dependency, parents, seen, ordered);
        }
        ordered.push(id);
    }
}

/// Result of a fresh Lean check followed by an atomic archive commit.
#[derive(Debug, Serialize)]
pub struct KernelImport {
    pub root: EntryId,
    pub checked: Vec<EntryId>,
    pub axioms: Vec<String>,
}

impl Archive {
    /// Seal the exact checked terms reachable from an archived declaration.
    pub fn export_kernel(&mut self, root: EntryId) -> Result<KernelBundle> {
        let mut mapped = HashMap::new();
        let mut declarations = BTreeMap::new();
        let mut visiting = HashSet::new();
        let mut pending = vec![(root, false)];
        let mut total_bytes = 0usize;

        while let Some((id, expanded)) = pending.pop() {
            if mapped.contains_key(&id) {
                continue;
            }
            let artifact = self.read(id)?;
            if !expanded {
                if mapped.len() + visiting.len() >= MAX_OBJECTS || !visiting.insert(id) {
                    return Err("archive export closure too large or cyclic".into());
                }
                pending.push((id, true));
                pending.extend(
                    artifact
                        .dependencies()
                        .iter()
                        .rev()
                        .map(|&dep| (dep, false)),
                );
                continue;
            }

            self.load(&[id])?;
            let kernel = if let Artifact::Kernel { artifact, .. } = artifact {
                artifact
            } else {
                let aliases = artifact
                    .dependencies()
                    .iter()
                    .map(|dep| (dep.lean_name(), EntryId::lean_name(mapped[dep])))
                    .collect::<Vec<_>>();
                let (terms, references) = self.lean.export_kernel(&id.lean_name(), &aliases)?;
                let mut dependencies = references
                    .iter()
                    .map(|name| {
                        name.strip_prefix("NaomeArchive.e_")
                            .ok_or_else(|| "invalid kernel declaration name".into())
                            .and_then(str::parse)
                    })
                    .collect::<Result<Vec<EntryId>>>()?;
                dependencies.sort_unstable();
                KernelArtifact {
                    dependencies,
                    terms,
                }
            };
            kernel.validate()?;
            let (portable, size) = kernel.identity_and_size()?;
            if let std::collections::btree_map::Entry::Vacant(slot) = declarations.entry(portable) {
                total_bytes += size;
                if total_bytes > MAX_CLOSURE_BYTES {
                    return Err("kernel bundle byte limit exceeded".into());
                }
                slot.insert(kernel);
            }
            mapped.insert(id, portable);
            visiting.remove(&id);
        }

        let root = mapped[&root];
        let parents = declarations
            .iter()
            .map(|(&id, artifact)| (id, artifact.dependencies.as_slice()))
            .collect();
        let mut ordered = Vec::new();
        append_dependencies(root, &parents, &mut HashSet::new(), &mut ordered);

        let bundle = KernelBundle {
            root,
            declarations: ordered
                .into_iter()
                .map(|id| declarations.remove(&id).expect("mapped export declaration"))
                .collect(),
        };
        bundle.to_bytes()?;
        Ok(bundle)
    }

    /// Check every term in a fresh Lean environment before storing the closure.
    pub fn import_kernel(&mut self, bundle: KernelBundle) -> Result<KernelImport> {
        let ids = bundle.verify_order()?;
        bundle.encode()?;
        let mut verifier = Lean::spawn()?;
        let mut checked = Vec::with_capacity(ids.len());
        for (id, artifact) in ids.iter().zip(bundle.declarations) {
            let names = super::names(&artifact.dependencies);
            let (receipt, target) =
                verifier.import_kernel(&id.lean_name(), &names, &artifact.terms)?;
            checked.push((Artifact::Kernel { target, artifact }, receipt));
        }

        let transaction = self.connection.transaction()?;
        let mut axioms = Vec::new();
        for (id, (artifact, receipt)) in ids.iter().zip(checked) {
            Self::store_checked(&transaction, *id, &artifact, receipt.symbols)?;
            axioms = receipt.axioms;
        }
        transaction.commit()?;
        Ok(KernelImport {
            root: bundle.root,
            checked: ids,
            axioms,
        })
    }
}
