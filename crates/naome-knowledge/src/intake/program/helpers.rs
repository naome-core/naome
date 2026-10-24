//! Large cited inputs remain a private prefix of the selected parent's batch.
use super::*;
use naome_proof::program::Manifest;

struct Helper {
    manifest: Manifest,
    checking: Option<ProgramCheck>,
    checked: Option<CheckedWork>,
}
#[derive(Default)]
pub(in crate::intake) struct Helpers {
    items: BTreeMap<ProofId, Helper>,
    prefix: Option<CheckedBatch>,
    registration: Option<(ProofId, ProgramAdmission)>,
    registered: BTreeSet<ProofId>,
    budget: ProgramBudget,
}
impl Helpers {
    pub(in crate::intake) fn busy(&self) -> bool {
        self.items.values().any(|helper| helper.checking.is_some())
            || !self.items.is_empty()
                && self.items.values().all(|helper| helper.checked.is_some())
                && !self.ready()
    }
    pub(in crate::intake) fn contains(&self, id: ProofId) -> bool {
        self.items.contains_key(&id)
    }
    pub(in crate::intake) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    pub(in crate::intake) fn ready(&self) -> bool {
        self.registered.len() == self.items.len() && self.registration.is_none()
    }
    pub(in crate::intake) fn take_prefix(&mut self) -> Option<CheckedBatch> {
        self.prefix.take()
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
        if self.items.len() >= crate::resources::limits().closure_objects {
            return Err("cited program capacity".into());
        }
        graph.ownership().start_program(&metadata.manifest)?;
        self.items.insert(
            id,
            Helper {
                manifest: metadata.manifest,
                checking: None,
                checked: None,
            },
        );
        Ok(())
    }
    pub(in crate::intake) fn request(
        &self,
        graph: &Graph,
    ) -> Result<Option<(ProofId, u64, usize)>, crate::Error> {
        for (id, helper) in &self.items {
            let progress = graph.ownership().program_progress(&helper.manifest)?;
            if progress.commands < helper.manifest.commands {
                let records = crate::resources::adaptive::batch(CHUNK_RECORDS);
                return Ok((records > 0).then_some((*id, progress.commands, records)));
            }
        }
        Ok(None)
    }
    pub(in crate::intake) fn payload(
        &self,
        id: ProofId,
        chunk: Chunk,
        graph: &Graph,
    ) -> Result<(), crate::Error> {
        let helper = self
            .items
            .get(&id)
            .ok_or("unrequested cited program payload")?;
        graph.ownership().append_program(&helper.manifest, &chunk)?;
        Ok(())
    }
    pub(in crate::intake) fn advance(
        &mut self,
        graph: &Graph,
    ) -> Result<Vec<ProofId>, crate::Error> {
        let snapshot = self.budget.refresh(graph.ownership().directory())?.clone();
        for helper in self.items.values_mut() {
            if let Some(check) = &mut helper.checking {
                check.restrict_cache(snapshot.budget.cache_bytes)?;
            }
            if let Some(proof) = &mut helper.checked {
                proof.restrict_cache(snapshot.budget.cache_bytes)?;
            }
        }
        if snapshot.budget.paused.is_some() {
            return Ok(Vec::new());
        }
        for (id, helper) in &mut self.items {
            if helper.checked.is_some() {
                continue;
            }
            if graph
                .ownership()
                .program_progress(&helper.manifest)?
                .commands
                < helper.manifest.commands
            {
                return Ok(Vec::new());
            }
            if helper.checking.is_none() {
                helper.checking = Some(ProgramCheck::open(graph, helper.manifest.clone())?);
            }
            if let Some(checked) = helper
                .checking
                .as_mut()
                .expect("cited program check")
                .advance(graph)?
            {
                helper.checking = None;
                helper.checked = Some(checked);
                return Ok(vec![*id]);
            }
            return Ok(Vec::new());
        }
        if self
            .prefix
            .as_ref()
            .map(|prefix| graph.batch_current(prefix))
            .transpose()?
            .is_some_and(|current| !current)
        {
            self.prefix = None;
            self.registration = None;
            self.registered.clear();
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
                }
                Err(crate::Error::StaleAuthority) => {
                    self.prefix = None;
                    self.registration = None;
                    self.registered.clear();
                }
                Err(error) => return Err(error),
            }
            return Ok(Vec::new());
        }
        if let Some((id, helper)) = self
            .items
            .iter()
            .find(|(id, _)| !self.registered.contains(id))
        {
            let proof = helper.checked.as_ref().ok_or("cited program not checked")?;
            self.registration = Some((
                *id,
                graph.begin_program_admission_after(proof, self.prefix.take())?,
            ));
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
        Ok(())
    }
}
