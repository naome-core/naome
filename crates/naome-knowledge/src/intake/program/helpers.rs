//! Necessary certificate and program helpers remain a private checked prefix
//! of the selected parent's atomic batch. Canonical program commands own every
//! citation; scans, checking and registration advance in bounded quanta.
use super::*;
use naome_proof::program::{CHUNK_BYTES, Command, Manifest};

struct Helper {
    manifest: Manifest,
    scanned: u64,
    received: bool,
    dependencies: BTreeSet<ProofId>,
    checking: Option<ProgramCheck>,
    checked: Option<CheckedWork>,
}
#[derive(Default)]
pub(in crate::intake) struct Helpers {
    items: BTreeMap<ProofId, Helper>,
    certificates: BTreeMap<ProofId, crate::object::BinaryProof>,
    needed: BTreeSet<ProofId>,
    certificate_bytes: usize,
    certificate_steps: usize,
    prefix: Option<CheckedBatch>,
    registration: Option<(ProofId, ProgramAdmission)>,
    registered: BTreeSet<ProofId>,
    budget: ProgramBudget,
}
impl Helpers {
    pub(in crate::intake) fn busy(&self) -> bool {
        self.items.values().any(|helper| {
            helper.checking.is_some()
                || helper.received && helper.scanned < helper.manifest.commands
        }) || self.registration.is_some()
            || self.needed.is_empty()
                && !self.ready()
                && self.items.values().all(|helper| helper.received)
    }
    pub(in crate::intake) fn contains(&self, id: ProofId) -> bool {
        self.items.contains_key(&id) || self.certificates.contains_key(&id)
    }
    pub(in crate::intake) fn needs(&self, id: ProofId) -> bool {
        self.needed.contains(&id)
    }
    pub(in crate::intake) fn needed(&self) -> impl Iterator<Item = ProofId> + '_ {
        self.needed.iter().copied()
    }
    pub(in crate::intake) fn members(&self) -> impl Iterator<Item = ProofId> + '_ {
        self.items
            .keys()
            .copied()
            .chain(self.certificates.keys().copied())
            .chain(self.needed())
    }
    pub(in crate::intake) fn member_count(&self) -> usize {
        self.items.len() + self.certificates.len() + self.needed.len()
    }
    pub(in crate::intake) fn cache_share(&self, bytes: u64) -> Result<u64, crate::Error> {
        let share = bytes / (self.items.len() as u64 + 1);
        if share < 4096 {
            return Err(crate::Error::ExecutionLimit);
        }
        Ok(share)
    }
    pub(in crate::intake) fn is_empty(&self) -> bool {
        self.items.is_empty() && self.certificates.is_empty() && self.needed.is_empty()
    }
    pub(in crate::intake) fn ready(&self) -> bool {
        self.needed.is_empty()
            && self.registered.len() == self.items.len() + self.certificates.len()
            && self.registration.is_none()
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
        self.registered.clear();
    }
    pub(in crate::intake) fn certificate_usage(&self) -> (usize, usize, usize) {
        (
            self.certificates.len(),
            self.certificate_bytes,
            self.certificate_steps,
        )
    }
    fn require(&mut self, id: ProofId, graph: &Graph) -> Result<(), crate::Error> {
        if graph.contains(id)? || self.contains(id) || self.needed.contains(&id) {
            return Ok(());
        }
        if self.items.len() + self.certificates.len() + self.needed.len()
            >= crate::resources::limits().closure_objects
        {
            return Err(crate::Error::InputLimit("cited closure operation capacity"));
        }
        self.needed.insert(id);
        Ok(())
    }
    /// Read only the authenticated canonical command stream. No secondary
    /// dependency index or saved checked flag can supply mathematical authority.
    pub(in crate::intake) fn scan_dependencies(
        &mut self,
        manifest: &Manifest,
        cursor: &mut u64,
        graph: &Graph,
    ) -> Result<(bool, BTreeSet<ProofId>), crate::Error> {
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
            if let Command::ProofReference { proof_id } = command {
                let id = ProofId::from_bytes(*proof_id);
                if !graph.contains(id)? {
                    self.require(id, graph)?;
                    dependencies.insert(id);
                }
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
        let id = metadata.manifest.proof_id();
        if let Some(helper) = self.items.get(&id) {
            if helper.manifest != metadata.manifest {
                return Err("cited program manifest changed".into());
            }
            return Ok(());
        }
        self.require(id, graph)?;
        let progress = graph.ownership().start_program(&metadata.manifest)?;
        let received = progress.commands == metadata.manifest.commands;
        self.needed.remove(&id);
        self.items.insert(
            id,
            Helper {
                manifest: metadata.manifest,
                scanned: 0,
                received,
                dependencies: BTreeSet::new(),
                checking: None,
                checked: None,
            },
        );
        Ok(())
    }
    pub(in crate::intake) fn certificate_payload(
        &mut self,
        id: ProofId,
        object: Envelope,
        graph: &Graph,
    ) -> Result<(), crate::Error> {
        if !self.needed.contains(&id) || id_bytes(&object.proof_id)? != *id.as_bytes() {
            return Err("unrequested cited certificate payload".into());
        }
        let (bytes, steps) = crate::intake::certificate::resources(&object)?;
        if self.certificate_bytes + bytes > crate::resources::limits().closure_bytes
            || self.certificate_steps + steps > crate::resources::limits().closure_steps
            || (self.certificates.len() + 1) * naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES
                > crate::resources::limits().closure_work_bytes
        {
            return Err(crate::Error::InputLimit(
                "cited certificate resource capacity",
            ));
        }
        let candidate = object.prepare()?;
        for dependency in &candidate.dependencies {
            self.require(*dependency, graph)?;
        }
        self.needed.remove(&id);
        self.certificates.insert(id, candidate.record());
        self.certificate_bytes += bytes;
        self.certificate_steps += steps;
        Ok(())
    }
    pub(in crate::intake) fn request(
        &self,
        graph: &Graph,
    ) -> Result<Option<(ProofId, u64, usize)>, crate::Error> {
        for (id, helper) in &self.items {
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
        id: ProofId,
        chunk: Chunk,
        graph: &Graph,
    ) -> Result<(), crate::Error> {
        let helper = self
            .items
            .get_mut(&id)
            .ok_or("unrequested cited program payload")?;
        let progress = graph.ownership().append_program(&helper.manifest, &chunk)?;
        helper.received = progress.commands == helper.manifest.commands;
        Ok(())
    }
    fn dependencies_ready(
        &self,
        dependencies: &BTreeSet<ProofId>,
        graph: &Graph,
    ) -> Result<bool, crate::Error> {
        for id in dependencies {
            if !self.registered.contains(id) && !graph.contains(*id)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    pub(in crate::intake) fn advance(
        &mut self,
        graph: &Graph,
    ) -> Result<Vec<ProofId>, crate::Error> {
        let snapshot = self.budget.refresh(graph.ownership().directory())?.clone();
        let cache = self.cache_share(snapshot.budget.cache_bytes)?;
        for helper in self.items.values_mut() {
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
        if self
            .prefix
            .as_ref()
            .map(|prefix| graph.batch_current(prefix))
            .transpose()?
            .is_some_and(|current| !current)
        {
            self.invalidate_prefix();
        }
        let mut fulfilled = Vec::new();
        for id in self.members().collect::<BTreeSet<_>>() {
            if !self.registered.contains(&id) && graph.contains(id)? {
                fulfilled.push(id);
            }
        }
        for id in &fulfilled {
            self.needed.remove(id);
            if self.contains(*id) {
                self.registered.insert(*id);
            }
        }
        if !fulfilled.is_empty() {
            return Ok(fulfilled);
        }
        if let Some(id) = self
            .items
            .iter()
            .find_map(|(id, helper)| (helper.scanned < helper.manifest.commands).then_some(*id))
        {
            let (manifest, mut cursor) = {
                let helper = &self.items[&id];
                (helper.manifest.clone(), helper.scanned)
            };
            let (_, dependencies) = self.scan_dependencies(&manifest, &mut cursor, graph)?;
            let helper = self.items.get_mut(&id).expect("cited program scan");
            helper.scanned = cursor;
            helper.dependencies.extend(dependencies);
            if cursor < manifest.commands {
                return Ok(Vec::new());
            }
        }
        if let Some((id, admission)) = &mut self.registration {
            let proof = self
                .items
                .get(id)
                .and_then(|helper| helper.checked.as_ref())
                .ok_or("cited checked program missing")?;
            match admission.advance(graph, proof, snapshot.budget.batch_steps.max(1)) {
                Ok(false) => return Ok(Vec::new()),
                Ok(true) => {
                    let (id, admission) = self
                        .registration
                        .take()
                        .expect("cited program registration");
                    self.prefix = Some(admission.finish(graph, proof)?);
                    self.registered.insert(id);
                    return Ok(vec![id]);
                }
                Err(crate::Error::StaleAuthority) => self.invalidate_prefix(),
                Err(error) => return Err(error),
            }
            return Ok(Vec::new());
        }
        let mut next_certificate = None;
        for (id, proof) in &self.certificates {
            if !self.registered.contains(id)
                && self.dependencies_ready(&proof.dependencies, graph)?
            {
                next_certificate = Some(*id);
                break;
            }
        }
        if let Some(id) = next_certificate {
            let proof = self.certificates[&id].clone().prepare()?;
            self.prefix = match graph.prepare_helper_after(proof, self.prefix.take()) {
                Ok(prefix) => Some(prefix),
                Err(error) => {
                    self.invalidate_prefix();
                    return Err(error);
                }
            };
            self.registered.insert(id);
            return Ok(vec![id]);
        }
        let mut next_program = None;
        for (id, helper) in &self.items {
            if !self.registered.contains(id)
                && helper.scanned == helper.manifest.commands
                && self.dependencies_ready(&helper.dependencies, graph)?
            {
                next_program = Some(*id);
                break;
            }
        }
        if let Some(id) = next_program {
            let context = self
                .prefix
                .as_ref()
                .map_or(graph.checked_context(), CheckedBatch::context)
                .clone();
            let helper = self.items.get_mut(&id).expect("cited program");
            if helper.checked.is_none() {
                if helper.checking.is_none() {
                    helper.checking = Some(ProgramCheck::open(graph, helper.manifest.clone())?);
                }
                if let Some(checked) = helper
                    .checking
                    .as_mut()
                    .expect("cited program check")
                    .advance(graph, &context)?
                {
                    helper.checking = None;
                    helper.checked = Some(checked);
                }
                return Ok(Vec::new());
            }
            let admission = graph.begin_program_admission_after(
                helper.checked.as_ref().expect("checked cited program"),
                self.prefix.take(),
            );
            match admission {
                Ok(admission) => self.registration = Some((id, admission)),
                Err(error) => {
                    self.invalidate_prefix();
                    return Err(error);
                }
            }
        }
        if self.registration.is_none()
            && self.needed.is_empty()
            && !self.ready()
            && self
                .items
                .values()
                .all(|helper| helper.scanned == helper.manifest.commands)
        {
            return Err("cited program closure has cyclic dependencies".into());
        }
        Ok(Vec::new())
    }
}

impl Intake {
    pub(crate) fn enqueue_program_helper(
        &mut self,
        peer: PeerId,
        root: ProofId,
        metadata: ProgramMetadata,
        graph: &Graph,
    ) -> Result<(), crate::Error> {
        let id = metadata.manifest.proof_id();
        if self.programs.authorizes(peer, root, id) {
            return self.programs.insert_helper(peer, root, metadata, graph);
        }
        if !self.authorizes(peer, root, id) {
            return Err("unrequested cited program description".into());
        }
        self.programs.remove(id);
        self.active
            .as_mut()
            .expect("approved parent")
            .helpers
            .insert(metadata, graph)
    }
    pub(in crate::intake) fn advance_program_helpers<F, Fut>(
        &mut self,
        graph: &Graph,
        questions: &mut LocalQuestions<F>,
    ) -> Result<(), crate::Error>
    where
        F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, String>> + Send + 'static,
    {
        let Some(root) = &mut self.active else {
            return Ok(());
        };
        if root.helpers.is_empty() {
            return Ok(());
        }
        let assessment = root
            .final_assessment
            .as_ref()
            .or(root.initial.as_ref())
            .ok_or("cited program has no parent assessment")?;
        questions.prepare_exchange(graph, &root.question, assessment)?;
        if let Some(grant) = &root.description.grant {
            grant.check()?;
        }
        if Instant::now().duration_since(root.description.created)
            >= crate::resources::limits().root_timeout
        {
            return Ok(());
        }
        for id in root.helpers.advance(graph)? {
            root.needed.remove(&id);
        }
        if root.member_count() > crate::resources::limits().closure_objects {
            return Err(crate::Error::InputLimit(
                "cited closure dependency capacity",
            ));
        }
        Ok(())
    }
}
