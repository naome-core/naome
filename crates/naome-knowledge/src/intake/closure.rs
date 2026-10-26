//! Necessary certificate and program helpers remain a private checked prefix
//! of the selected parent's atomic batch. Canonical program commands own every
//! citation; scans, checking and registration advance in bounded quanta.
use super::program::transfer_records;
use super::*;
use crate::{
    graph::dependencies::Dependencies,
    graph::program::{ProgramAdmission, ProgramCheck},
    object::{ProgramMetadata, id_bytes},
    proof_work::CheckedWork,
    resources::adaptive::Observer,
};
use naome_proof::program::CHUNK_RECORDS;
use naome_proof::program::{CHUNK_BYTES, Chunk, Command, Manifest};

struct Helper {
    manifest: Manifest,
    scanned: u64,
    available: u64,
    dependencies: BTreeSet<ArtifactId>,
    checking: Option<ProgramCheck>,
    checked: Option<CheckedWork>,
}
pub(in crate::intake) struct Closure {
    root: ArtifactId,
    statement: Option<StatementId>,
    items: BTreeMap<ArtifactId, Helper>,
    certificates: BTreeMap<ArtifactId, crate::object::Candidate>,
    needed: BTreeSet<ArtifactId>,
    usage: certificate::Usage,
    prefix: Option<CheckedBatch>,
    registration: Option<(ArtifactId, ProgramAdmission)>,
    active: Option<ArtifactId>,
    schedule: Dependencies,
    observed_root: Option<[u8; 32]>,
    scan_ready: BTreeSet<ArtifactId>,
    receiving: BTreeSet<ArtifactId>,
    budget: Observer,
}
impl Closure {
    pub(in crate::intake) fn new(root: ArtifactId, statement: Option<StatementId>) -> Self {
        Self {
            root,
            statement,
            items: BTreeMap::new(),
            certificates: BTreeMap::new(),
            needed: BTreeSet::new(),
            usage: certificate::Usage::default(),
            prefix: None,
            registration: None,
            active: None,
            schedule: Dependencies::default(),
            observed_root: None,
            scan_ready: BTreeSet::new(),
            receiving: BTreeSet::new(),
            budget: Observer::default(),
        }
    }
    pub(in crate::intake) fn require_root(&mut self, graph: &Graph) -> Result<(), crate::Error> {
        self.synchronize(graph)?;
        if !graph.contains(self.root)? && !self.contains(self.root) {
            self.needed.insert(self.root);
            self.schedule.declare(self.root);
        }
        Ok(())
    }
    pub(in crate::intake) fn has_programs(&self) -> bool {
        !self.items.is_empty()
    }
    pub(in crate::intake) fn certificate_ready(&self) -> bool {
        self.observed_root.is_some()
            && self.needed.is_empty()
            && self.registration.is_none()
            && self.active.is_none()
            && self.items.keys().all(|id| self.schedule.is_complete(*id))
    }
    pub(in crate::intake) fn prepare_certificates(
        &mut self,
        graph: &Graph,
        question: &CompiledQuestion,
    ) -> Result<CheckedBatch, crate::Error> {
        self.synchronize(graph)?;
        let candidates = self
            .certificates
            .iter()
            .filter(|(id, _)| !self.schedule.is_complete(**id))
            .map(|(id, candidate)| candidate.for_admission().map(|candidate| (*id, candidate)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let result = graph.prepare_batch_after(self.root, candidates, question, self.prefix.take());
        if result.is_err() {
            self.invalidate_prefix();
        }
        result
    }
    #[cfg(test)]
    pub(in crate::intake) fn certificate_steps(&self) -> usize {
        self.usage.steps()
    }
    #[cfg(test)]
    pub(in crate::intake) fn certificate_count(&self) -> usize {
        self.certificates.len()
    }
    pub(in crate::intake) fn busy(&self) -> bool {
        self.active.is_some()
            || !self.scan_ready.is_empty()
            || self.needed.is_empty() && self.receiving.is_empty() && !self.ready()
    }
    pub(in crate::intake) fn contains(&self, id: ArtifactId) -> bool {
        self.items.contains_key(&id) || self.certificates.contains_key(&id)
    }
    pub(in crate::intake) fn needs(&self, id: ArtifactId) -> bool {
        self.needed.contains(&id)
    }
    pub(in crate::intake) fn needed(&self) -> impl Iterator<Item = ArtifactId> + '_ {
        self.needed.iter().copied()
    }
    pub(in crate::intake) fn members(&self) -> impl Iterator<Item = ArtifactId> + '_ {
        self.items
            .keys()
            .copied()
            .chain(self.certificates.keys().copied())
            .chain(self.needed())
    }
    pub(in crate::intake) fn member_count(&self) -> usize {
        self.items.len()
            + self.certificates.len()
            + self.needed.len()
            + usize::from(!self.contains(self.root) && !self.needed.contains(&self.root))
    }
    pub(in crate::intake) fn working_cache(&self, bytes: u64) -> Result<u64, crate::Error> {
        if bytes < 4096 {
            return Err(crate::Error::ExecutionLimit);
        }
        Ok(bytes)
    }
    pub(in crate::intake) fn ready(&self) -> bool {
        self.observed_root.is_some()
            && self.needed.is_empty()
            && self.schedule.only_pending(self.root)
            && self.registration.is_none()
            && self.active.is_none()
    }
    pub(in crate::intake) fn context<'a>(
        &'a self,
        graph: &'a Graph,
    ) -> &'a naome_checker::DiskArtifactState {
        self.prefix
            .as_ref()
            .map_or(graph.checked_context(), CheckedBatch::context)
    }
    pub(in crate::intake) fn take_prefix(&mut self) -> Option<CheckedBatch> {
        self.prefix.take()
    }
    pub(in crate::intake) fn invalidate_prefix(&mut self) {
        self.prefix = None;
        self.registration = None;
        self.active = None;
        self.observed_root = None;
        self.schedule = Dependencies::default();
        for helper in self.items.values_mut() {
            helper.checking = None;
        }
    }
    fn require(&mut self, id: ArtifactId, graph: &Graph) -> Result<(), crate::Error> {
        if id == self.root {
            return Err("cited closure has cyclic dependencies".into());
        }
        if self.schedule.is_complete(id) || self.contains(id) || self.needed.contains(&id) {
            return Ok(());
        }
        if graph.contains(id)? {
            self.schedule.finish(id);
            return Ok(());
        }
        if self.member_count() >= crate::resources::limits().closure_objects {
            return Err(crate::Error::InputLimit("cited closure operation capacity"));
        }
        self.needed.insert(id);
        self.schedule.declare(id);
        Ok(())
    }
    fn track(
        &mut self,
        id: ArtifactId,
        dependencies: &BTreeSet<ArtifactId>,
        graph: &Graph,
    ) -> Result<(), crate::Error> {
        if self.schedule.is_complete(id) {
            return Ok(());
        }
        for dependency in dependencies {
            if !self.schedule.known(*dependency) && graph.contains(*dependency)? {
                self.schedule.finish(*dependency);
            }
        }
        self.schedule.add(id, dependencies)
    }
    /// Rebuild disposable readiness only when its checked predecessor changes.
    /// Mathematical checking and the publication stamp remain authoritative.
    pub(in crate::intake) fn synchronize(&mut self, graph: &Graph) -> Result<bool, crate::Error> {
        let root = graph.content_root();
        let stale = self.observed_root.is_some_and(|observed| observed != root)
            || self
                .prefix
                .as_ref()
                .map(|prefix| graph.batch_current(prefix))
                .transpose()?
                .is_some_and(|current| !current);
        if !stale && self.observed_root == Some(root) {
            return Ok(false);
        }
        self.invalidate_prefix();
        self.observed_root = Some(root);
        for helper in self.items.values_mut() {
            if let Some(proof) = &mut helper.checked {
                proof.suspend_cache()?;
            }
        }
        for id in self.members().collect::<BTreeSet<_>>() {
            if graph.contains(id)? {
                self.schedule.finish(id);
                self.needed.remove(&id);
            } else {
                self.schedule.declare(id);
            }
        }
        let dependencies: Vec<_> = self
            .certificates
            .iter()
            .map(|(id, candidate)| (*id, candidate.dependencies.clone()))
            .chain(
                self.items
                    .iter()
                    .filter(|(_, helper)| helper.scanned == helper.manifest.commands)
                    .map(|(id, helper)| (*id, helper.dependencies.clone())),
            )
            .collect();
        for (id, dependencies) in dependencies {
            self.track(id, &dependencies, graph)?;
        }
        Ok(true)
    }
    /// Read only the authenticated canonical command stream. No secondary
    /// dependency index or saved checked flag can supply mathematical authority.
    pub(in crate::intake) fn scan_dependencies(
        &mut self,
        manifest: &Manifest,
        cursor: &mut u64,
        graph: &Graph,
    ) -> Result<(bool, BTreeSet<ArtifactId>), crate::Error> {
        self.synchronize(graph)?;
        if *cursor == manifest.commands {
            return Ok((true, BTreeSet::new()));
        }
        let progress = graph.ownership().program_progress(manifest)?;
        if *cursor >= progress.commands {
            return Ok((false, BTreeSet::new()));
        }
        let records = crate::resources::adaptive::batch(CHUNK_RECORDS);
        if records == 0 {
            return Ok((false, BTreeSet::new()));
        }
        let chunk = graph
            .ownership()
            .program_chunk(manifest, *cursor, records, CHUNK_BYTES)?;
        let mut dependencies = BTreeSet::new();
        for command in &chunk.records {
            let id = match command {
                Command::ProofReference { proof_id } => Some(ArtifactId::from_proof_id(
                    naome_proof::ProofId::from_bytes(*proof_id),
                )),
                Command::DefinedRelation { definition_id, .. } => {
                    Some(ArtifactId::from_definition_id(
                        naome_proof::DefinitionId::from_bytes(*definition_id),
                    ))
                }
                _ => None,
            };
            // Keep only the bounded unpublished closure. A program may cite
            // arbitrarily many committed facts; its canonical stream owns them.
            if let Some(id) = id
                && !graph.contains(id)?
            {
                self.require(id, graph)?;
                dependencies.insert(id);
            }
        }
        *cursor += chunk.records.len() as u64;
        Ok((*cursor == manifest.commands, dependencies))
    }
    pub(in crate::intake) fn insert(
        &mut self,
        metadata: ProgramMetadata,
        graph: &Graph,
    ) -> Result<(), crate::Error> {
        self.synchronize(graph)?;
        let id = metadata.manifest.artifact_id();
        if let Some(helper) = self.items.get(&id) {
            if helper.manifest != metadata.manifest {
                return Err("cited program manifest changed".into());
            }
            return Ok(());
        }
        if self.certificates.contains_key(&id) {
            return Err("closure member representation differs".into());
        }
        self.require(id, graph)?;
        let progress = graph.ownership().start_program(&metadata.manifest)?;
        if progress.commands < metadata.manifest.commands {
            self.receiving.insert(id);
        }
        if progress.commands > 0 {
            self.scan_ready.insert(id);
        }
        self.needed.remove(&id);
        self.items.insert(
            id,
            Helper {
                manifest: metadata.manifest,
                scanned: 0,
                available: progress.commands,
                dependencies: BTreeSet::new(),
                checking: None,
                checked: None,
            },
        );
        Ok(())
    }
    pub(in crate::intake) fn certificate_payload(
        &mut self,
        id: ArtifactId,
        object: Envelope,
        graph: &Graph,
        transfer: &TransferGrant,
    ) -> Result<(), crate::Error> {
        transfer.check(Instant::now())?;
        self.synchronize(graph)?;
        if !self.needed.contains(&id) || id_bytes(&object.artifact_id)? != *id.as_bytes() {
            return Err("unrequested or mismatched proof payload".into());
        }
        // The same cumulative charge covers root certificates and every helper,
        // before decoding allocates their trees. Rejected payloads change nothing.
        let usage = self.usage.add(&object)?;
        let candidate = object.prepare()?;
        transfer.check(Instant::now())?;
        if id == self.root
            && self
                .statement
                .is_some_and(|statement| Some(statement) != candidate.statement)
        {
            return Err("root statement differs from approved metadata".into());
        }
        let mut missing = Vec::new();
        for dependency in &candidate.dependencies {
            if !self.contains(*dependency)
                && !self.needed.contains(dependency)
                && !graph.contains(*dependency)?
            {
                if *dependency == self.root {
                    return Err("cited closure has cyclic dependencies".into());
                }
                missing.push(*dependency);
            }
        }
        if self
            .member_count()
            .checked_add(missing.len())
            .is_none_or(|count| count > crate::resources::limits().closure_objects)
        {
            return Err(crate::Error::InputLimit(
                "staged closure dependency capacity",
            ));
        }
        self.needed.remove(&id);
        for dependency in missing {
            self.needed.insert(dependency);
            self.schedule.declare(dependency);
        }
        self.track(id, &candidate.dependencies, graph)?;
        self.certificates.insert(id, candidate);
        self.usage = usage;
        Ok(())
    }
    pub(in crate::intake) fn request(
        &self,
        graph: &Graph,
    ) -> Result<Option<(ArtifactId, u64, usize)>, crate::Error> {
        if let Some(id) = self.receiving.first() {
            let helper = &self.items[id];
            let progress = graph.ownership().program_progress(&helper.manifest)?;
            if progress.commands < helper.manifest.commands {
                let records = transfer_records();
                return Ok((records > 0).then_some((*id, progress.commands, records)));
            }
        }
        Ok(None)
    }
    pub(in crate::intake) fn payload(
        &mut self,
        id: ArtifactId,
        chunk: Chunk,
        graph: &Graph,
    ) -> Result<(), crate::Error> {
        let helper = self
            .items
            .get_mut(&id)
            .ok_or("unrequested cited program payload")?;
        let progress = graph.ownership().append_program(&helper.manifest, &chunk)?;
        helper.available = progress.commands;
        if helper.scanned < helper.available {
            self.scan_ready.insert(id);
        }
        if helper.available == helper.manifest.commands {
            self.receiving.remove(&id);
        }
        Ok(())
    }
    pub(in crate::intake) fn advance(
        &mut self,
        graph: &Graph,
    ) -> Result<Vec<ArtifactId>, crate::Error> {
        self.synchronize(graph)?;
        let snapshot = self.budget.refresh(graph.ownership().directory())?.clone();
        let cache = self.working_cache(snapshot.budget.cache_bytes)?;
        if let Some(id) = self.active {
            let helper = self.items.get_mut(&id).expect("active cited program");
            if let Some(check) = &mut helper.checking {
                check.restrict_cache(cache)?;
            }
            if let Some(proof) = &mut helper.checked {
                proof.restrict_cache(cache)?;
            }
        }
        if snapshot.budget.paused.is_some() {
            return Ok(Vec::new());
        }
        if let Some(id) = self.scan_ready.first().copied() {
            let (manifest, mut cursor) = {
                let helper = &self.items[&id];
                (helper.manifest.clone(), helper.scanned)
            };
            let (_, dependencies) = self.scan_dependencies(&manifest, &mut cursor, graph)?;
            let helper = self.items.get_mut(&id).expect("cited program scan");
            helper.scanned = cursor;
            helper.dependencies.extend(dependencies);
            if cursor == manifest.commands {
                let dependencies = helper.dependencies.clone();
                self.scan_ready.remove(&id);
                self.track(id, &dependencies, graph)?;
            } else if cursor == helper.available {
                self.scan_ready.remove(&id);
            }
            return Ok(Vec::new());
        }
        if let Some((id, admission)) = &mut self.registration {
            let proof = self.items[id]
                .checked
                .as_ref()
                .ok_or("cited checked program missing")?;
            match admission.advance(graph, proof, snapshot.budget.batch_steps.max(1)) {
                Ok(false) => return Ok(Vec::new()),
                Ok(true) => {
                    let (id, admission) = self
                        .registration
                        .take()
                        .expect("cited program registration");
                    match admission.finish(graph, proof) {
                        Ok(prefix) => self.prefix = Some(prefix),
                        Err(error) => {
                            self.invalidate_prefix();
                            return Err(error);
                        }
                    }
                    self.items
                        .get_mut(&id)
                        .expect("registered helper")
                        .checked
                        .as_mut()
                        .expect("checked helper")
                        .suspend_cache()?;
                    self.active = None;
                    self.schedule.finish(id);
                    return Ok(vec![id]);
                }
                Err(crate::Error::StaleAuthority) => self.invalidate_prefix(),
                Err(error) => return Err(error),
            }
            return Ok(Vec::new());
        }
        let next = self.active.or_else(|| self.schedule.next(Some(self.root)));
        if let Some(id) = next {
            if let Some(proof) = self.certificates.get(&id) {
                let proof = proof.for_admission()?;
                self.prefix = match graph.prepare_helper_after(proof, self.prefix.take()) {
                    Ok(prefix) => Some(prefix),
                    Err(error) => {
                        self.invalidate_prefix();
                        return Err(error);
                    }
                };
                self.schedule.finish(id);
                return Ok(vec![id]);
            }
            let context = self.context(graph).clone();
            let helper = self
                .items
                .get_mut(&id)
                .ok_or("ready program member missing")?;
            self.active = Some(id);
            if helper.checked.is_none() {
                if helper.checking.is_none() {
                    helper.checking = Some(ProgramCheck::open(graph, helper.manifest.clone())?);
                }
                let check = helper.checking.as_mut().expect("cited program check");
                check.restrict_cache(cache)?;
                if let Some(mut checked) = check.advance(graph, &context)? {
                    checked.suspend_cache()?;
                    helper.checking = None;
                    helper.checked = Some(checked);
                }
                return Ok(Vec::new());
            }
            let proof = helper.checked.as_mut().expect("checked cited program");
            proof.restrict_cache(cache)?;
            match graph.begin_program_admission_after(proof, self.prefix.take()) {
                Ok(admission) => self.registration = Some((id, admission)),
                Err(error) => {
                    self.invalidate_prefix();
                    return Err(error);
                }
            }
            return Ok(Vec::new());
        }
        if self.needed.is_empty()
            && self.receiving.is_empty()
            && !self.ready()
            && self.schedule.defined()
        {
            return Err("cited program closure has cyclic dependencies".into());
        }
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests;
