use super::*;

/// Canonical signed-original content. Node IDs are claims until verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofPackage {
    pub(super) author: AccountId,
    pub(super) root: ProofId,
    pub(super) nodes: Vec<(ProofId, Vec<u8>)>,
}

impl ProofPackage {
    /// Canonicalizes only node order and byte-identical duplicate entries.
    /// Certificate bytes themselves are never repaired.
    pub fn new(
        author: AccountId,
        root: ProofId,
        nodes: Vec<(ProofId, Vec<u8>)>,
        profile: &Profile,
    ) -> Result<Self, ResearchError> {
        let limit = profile.limits().new_helpers as usize + 1;
        if nodes.is_empty() || nodes.len() > limit {
            return Err(ResearchError::Limit("new proof count"));
        }
        let mut unique = BTreeMap::new();
        let mut size = 2usize + 32 + 32 + 4;
        for (id, bytes) in nodes {
            size = size
                .checked_add(36 + bytes.len())
                .ok_or(ResearchError::Overflow)?;
            if size > profile.limits().package_bytes as usize {
                return Err(ResearchError::Limit("original package bytes"));
            }
            let _ = bounded_certificate(&bytes, profile)?;
            if let Some(previous) = unique.insert(id, bytes.clone())
                && previous != bytes
            {
                return Err(ResearchError::Invalid(
                    "conflicting certificate under one proof ID",
                ));
            }
        }
        if !unique.contains_key(&root) {
            return Err(ResearchError::Invalid("missing package root"));
        }
        let ordered = topological(&unique, profile)?;
        let nodes = ordered
            .into_iter()
            .map(|id| (id, unique.remove(&id).expect("ordered node exists")))
            .collect();
        Ok(Self {
            author,
            root,
            nodes,
        })
    }

    pub fn author(&self) -> AccountId {
        self.author
    }
    pub fn root(&self) -> ProofId {
        self.root
    }
    pub fn certificates(&self) -> &[(ProofId, Vec<u8>)] {
        &self.nodes
    }
    pub fn encode(&self) -> Result<Vec<u8>, ResearchError> {
        let mut w = Writer::new();
        w.u16(1);
        w.fixed(self.author.as_bytes());
        w.fixed(self.root.as_bytes());
        w.u32(self.nodes.len() as u32);
        for (id, bytes) in &self.nodes {
            w.fixed(id.as_bytes());
            w.bytes(bytes)?;
        }
        Ok(w.finish())
    }
    pub fn original_hash(&self) -> PackageHash {
        PackageHash::from_bytes(hash(
            b"naome:state:package:v1\0",
            &[&self
                .encode()
                .expect("bounded package fields fit canonical framing")],
        ))
    }
    pub fn decode(bytes: &[u8], profile: &Profile) -> Result<Self, ResearchError> {
        let mut r = Reader::new(bytes, profile.limits().package_bytes as usize)?;
        if r.u16()? != 1 {
            return Err(ResearchError::Invalid("proof package version"));
        }
        let author = AccountId::from_bytes(r.fixed()?);
        let root = ProofId::from_bytes(r.fixed()?);
        let count = r.u32()? as usize;
        if count == 0 || count > profile.limits().new_helpers as usize + 1 {
            return Err(ResearchError::Limit("new proof count"));
        }
        let mut nodes = Vec::with_capacity(count);
        for _ in 0..count {
            nodes.push((
                ProofId::from_bytes(r.fixed()?),
                r.bytes(profile.limits().certificate_bytes as usize)?
                    .to_vec(),
            ));
        }
        r.finish()?;
        let package = Self::new(author, root, nodes, profile)?;
        if package.encode()? != bytes {
            return Err(ResearchError::Invalid("noncanonical proof package"));
        }
        Ok(package)
    }
}

/// Every dependency internal to this graph precedes its user. Ties use ProofId.
pub(super) fn topological(
    nodes: &BTreeMap<ProofId, Vec<u8>>,
    profile: &Profile,
) -> Result<Vec<ProofId>, ResearchError> {
    let mut pending = BTreeMap::new();
    for (id, bytes) in nodes {
        let certificate = bounded_certificate(bytes, profile)?;
        pending.insert(
            *id,
            dependencies(&certificate)
                .into_iter()
                .filter(|id| nodes.contains_key(id))
                .collect::<BTreeSet<_>>(),
        );
    }
    let mut ordered = Vec::with_capacity(nodes.len());
    while !pending.is_empty() {
        let next = pending
            .iter()
            .find(|(_, dependencies)| dependencies.is_empty())
            .map(|(id, _)| *id)
            .ok_or(ResearchError::Invalid("cyclic proof group"))?;
        pending.remove(&next);
        for dependencies in pending.values_mut() {
            dependencies.remove(&next);
        }
        ordered.push(next);
    }
    Ok(ordered)
}
