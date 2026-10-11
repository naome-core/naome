//! Complete immutable provider inputs, captured from the checked runtime graph.
//! Deserializing a request grants no mathematical or publication authority.
#[cfg(test)]
use crate::Graph;
use crate::corpus::ProofCorpus as CheckedContext;
use crate::corpus::{Reference, snapshot};
use crate::{jobs, runtime::OwnerProfile};
use naome_authoring::CompiledQuestion;
use naome_checker::question::{AssessmentLimits, PrefilterPolicy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// The serialized request includes instructions, context and task without truncation.
/// This fits the existing process frame and journal reservations; model adapters
/// must reject unsupported token windows rather than shorten these instructions.
pub(crate) const MAX_REQUEST_BYTES: usize = 256 * 1024;
mod retrieval;
use crate::corpus::semantic;
pub(crate) use retrieval::ResultPage as ToolResult;
pub(crate) use retrieval::Status as ToolStatus;

const MAX_UNAVAILABLE_REASON_BYTES: usize = 256;
const NATIVE: &str = include_str!("generation/native_authoring.txt");
const QUESTION: &str = include_str!("generation/question.txt");
const PROOF: &str = include_str!("generation/proof.txt");

pub(crate) enum OwnerContext {
    Available(OwnerProfile),
    Unavailable { reason: String },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "availability", rename_all = "snake_case", deny_unknown_fields)]
enum OwnerInterests {
    Available {
        version: u8,
        revision: u64,
        interest: String,
        digest: String,
    },
    Unavailable {
        reason: String,
    },
}

impl OwnerInterests {
    fn capture(owner: OwnerContext) -> Result<Self, String> {
        let owner = match owner {
            OwnerContext::Available(profile) => Self::Available {
                version: profile.version,
                revision: profile.revision,
                interest: profile.interest,
                digest: profile.digest,
            },
            OwnerContext::Unavailable { reason } => Self::Unavailable { reason },
        };
        owner.validate()?;
        Ok(owner)
    }
    fn validate(&self) -> Result<(), String> {
        match self {
            Self::Available {
                version,
                revision,
                interest,
                digest,
            } => {
                if *version != 1 || interest.len() > 1024 {
                    return Err("generation owner profile version or byte limit".into());
                }
                // Same exact configuration bytes as the existing owner receipt.
                // Preserve the owner configuration declaration order.
                #[derive(Serialize)]
                struct Configuration<'a> {
                    version: u8,
                    revision: u64,
                    interest: &'a str,
                }
                let actual = digest_value(&Configuration {
                    version: *version,
                    revision: *revision,
                    interest,
                });
                if actual != *digest {
                    return Err("generation owner profile digest differs".into());
                }
            }
            Self::Unavailable { reason }
                if reason.is_empty() || reason.len() > MAX_UNAVAILABLE_REASON_BYTES =>
            {
                return Err("generation owner availability reason limit".into());
            }
            Self::Unavailable { .. } => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
enum Task {
    Question {
        cursor: u64,
    },
    Proof {
        question: String,
        source_hash: String,
        resolution_id: String,
        proved_target: String,
        refuted_target: String,
    },
}
impl Task {
    fn from_input(input: &jobs::Input) -> Result<Self, String> {
        match input {
            jobs::Input::Find { cursor } => Ok(Self::Question { cursor: *cursor }),
            jobs::Input::Solve { question } => {
                let compiled = CompiledQuestion::compile(question).map_err(|e| e.to_string())?;
                Ok(Self::Proof {
                    question: question.clone(),
                    source_hash: crate::hex(compiled.source_hash()),
                    resolution_id: crate::hex(compiled.resolution_id()),
                    proved_target: compiled.proved_target().to_source(),
                    refuted_target: compiled.refuted_target().to_source(),
                })
            }
            jobs::Input::Interest { .. } => Err("interest is not a generation task".into()),
        }
    }
    fn system(&self) -> String {
        format!(
            "{}\n\n{}",
            match self {
                Self::Question { .. } => QUESTION,
                Self::Proof { .. } => PROOF,
            },
            NATIVE
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AssessmentRequirements {
    formula_nodes: usize,
    dependencies: usize,
    operations: usize,
    formula_work_bytes: usize,
    certificate_steps: usize,
    certificate_bytes: usize,
}
impl AssessmentRequirements {
    fn values(&self) -> [usize; 6] {
        [
            self.formula_nodes,
            self.dependencies,
            self.operations,
            self.formula_work_bytes,
            self.certificate_steps,
            self.certificate_bytes,
        ]
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Requirements {
    question_source_bytes: usize,
    question_target_nodes: usize,
    question_target_depth: usize,
    proof_source_bytes: usize,
    proof_helpers: usize,
    proof_closure_bytes: usize,
    proof_closure_steps: usize,
    proof_dependencies: usize,
    request_bytes: usize,
    policy_revision: u64,
    policy_rule_set: u64,
    /// nodes, dependencies, operations, formula-work bytes, certificate steps/bytes.
    assessment_limits: AssessmentRequirements,
}
impl Requirements {
    fn new(policy: PrefilterPolicy) -> Self {
        let limits = policy.limits;
        Self {
            question_source_bytes: naome_authoring::QUESTION_SOURCE_MAX_BYTES,
            question_target_nodes: naome_authoring::QUESTION_TARGET_MAX_NODES,
            question_target_depth: naome_authoring::QUESTION_TARGET_MAX_DEPTH,
            proof_source_bytes: crate::MAX_PROOF_BYTES,
            proof_helpers: crate::intake::MAX_CLOSURE_OBJECTS - 1,
            proof_closure_bytes: crate::intake::MAX_CLOSURE_BYTES,
            proof_closure_steps: crate::intake::MAX_CLOSURE_STEPS,
            proof_dependencies: crate::MAX_DEPENDENCIES,
            request_bytes: MAX_REQUEST_BYTES,
            policy_revision: policy.revision,
            policy_rule_set: policy.rule_set,
            assessment_limits: AssessmentRequirements {
                formula_nodes: limits.formula_nodes,
                dependencies: limits.dependencies,
                operations: limits.operations,
                formula_work_bytes: limits.formula_work_bytes,
                certificate_steps: limits.certificate_steps,
                certificate_bytes: limits.certificate_bytes,
            },
        }
    }
    fn policy(&self) -> PrefilterPolicy {
        let [
            formula_nodes,
            dependencies,
            operations,
            formula_work_bytes,
            certificate_steps,
            certificate_bytes,
        ] = self.assessment_limits.values();
        PrefilterPolicy {
            revision: self.policy_revision,
            rule_set: self.policy_rule_set,
            limits: AssessmentLimits {
                formula_nodes,
                dependencies,
                operations,
                formula_work_bytes,
                certificate_steps,
                certificate_bytes,
            },
        }
    }
    fn validate(&self, binding: &jobs::Binding) -> Result<(), String> {
        let policy = self.policy();
        let maximum = Self::new(PrefilterPolicy::default())
            .assessment_limits
            .values();
        if *self != Self::new(policy)
            || policy.revision == 0
            || policy.rule_set != 2
            || self
                .assessment_limits
                .values()
                .iter()
                .zip(maximum)
                .any(|(v, m)| *v == 0 || *v > m)
            || crate::hex(&policy.identity()) != binding.policy
        {
            return Err("generation admission policy or capacity differs".into());
        }
        Ok(())
    }
}

/// Provider-neutral, ready-to-send system instructions and separate task data.
/// No request string is interpolated into the authoritative system instructions.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    version: u8,
    request_id: String,
    pub(crate) system: String,
    binding: jobs::Binding,
    task: Task,
    owner_interests: OwnerInterests,
    // Retained v1 requests preserve their exact bytes as inert recovery evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checked_context: Option<CheckedContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) retrieval_snapshot: Option<snapshot::Handle>,
    // Node custody only. Never serialized to a provider or admitted from a pipe.
    #[serde(skip)]
    frozen: Option<Arc<snapshot::Frozen>>,
    #[serde(skip)]
    cursor_key: Option<crate::corpus::cursor::Key>,
    requirements: Requirements,
    tools: Vec<retrieval::Tool>,
}
impl Request {
    #[cfg(test)]
    pub(crate) fn build(
        input: &jobs::Input,
        binding: &jobs::Binding,
        graph: &Graph,
        owner: OwnerContext,
    ) -> Result<Self, String> {
        Self::build_with_policy(input, binding, graph, owner, PrefilterPolicy::default())
    }
    #[cfg(test)]
    pub(crate) fn build_with_policy(
        input: &jobs::Input,
        binding: &jobs::Binding,
        graph: &Graph,
        owner: OwnerContext,
        policy: PrefilterPolicy,
    ) -> Result<Self, String> {
        let frozen = snapshot::Frozen::capture(graph, None, &binding.snapshot)?;
        Self::build_from_snapshot(input, binding, Arc::new(frozen), owner, policy)
    }
    pub(crate) fn build_from_snapshot(
        input: &jobs::Input,
        binding: &jobs::Binding,
        frozen: Arc<snapshot::Frozen>,
        owner: OwnerContext,
        policy: PrefilterPolicy,
    ) -> Result<Self, String> {
        if frozen.handle().knowledge_snapshot != binding.snapshot {
            return Err("generation frozen knowledge binding differs".into());
        }
        let task = Task::from_input(input)?;
        let mut request = Self {
            version: 2,
            request_id: String::new(),
            system: task.system(),
            binding: binding.clone(),
            task,
            owner_interests: OwnerInterests::capture(owner)?,
            checked_context: None,
            retrieval_snapshot: Some(frozen.handle().clone()),
            frozen: Some(frozen),
            cursor_key: Some(crate::corpus::cursor::Key::ephemeral()?),
            requirements: Requirements::new(policy),
            tools: retrieval::tools(),
        };
        request.request_id = request.content_identity();
        request.validate(input, binding)?;
        Ok(request)
    }
    pub(crate) fn validate(
        &self,
        input: &jobs::Input,
        binding: &jobs::Binding,
    ) -> Result<(), String> {
        self.validate_retained(input, binding)?;
        if !self.current_instructions() {
            return Err("generation instructions or tool contract are superseded".into());
        }
        Ok(())
    }
    pub(crate) fn current_instructions(&self) -> bool {
        self.version == 2 && self.system == self.task.system() && self.tools == retrieval::tools()
    }
    pub(crate) fn validate_retained(
        &self,
        input: &jobs::Input,
        binding: &jobs::Binding,
    ) -> Result<(), String> {
        if serde_json::to_vec(self).map_err(|e| e.to_string())?.len() > MAX_REQUEST_BYTES {
            return Err("generation complete request byte limit".into());
        }
        if self.request_id != self.content_identity()
            || ![1, 2].contains(&self.version)
            || self.binding != *binding
            || self.task != Task::from_input(input)?
        {
            return Err("generation request input, instructions or binding differs".into());
        }
        self.owner_interests.validate()?;
        self.requirements.validate(binding)?;
        match (
            self.version,
            &self.checked_context,
            &self.retrieval_snapshot,
        ) {
            (1, Some(context), None) => context.validate(),
            (2, None, Some(handle)) => {
                handle.validate()?;
                if handle.knowledge_snapshot != binding.snapshot {
                    return Err("generation frozen knowledge identity differs".into());
                }
                if self
                    .frozen
                    .as_ref()
                    .is_some_and(|source| source.handle() != handle)
                {
                    return Err("generation private source differs from compact handle".into());
                }
                Ok(())
            }
            _ => Err("generation request source layout differs".into()),
        }
    }
    #[cfg(test)]
    pub(crate) fn recheck(
        &self,
        input: &jobs::Input,
        binding: &jobs::Binding,
    ) -> Result<(), String> {
        self.validate(input, binding)?;
        if self.version == 1 {
            self.context()?.recheck()
        } else {
            self.source().map(|_| ())
        }
    }
    pub(crate) fn recheck_retained(
        &self,
        input: &jobs::Input,
        binding: &jobs::Binding,
    ) -> Result<(), String> {
        self.validate_retained(input, binding)?;
        if self.version == 1 {
            self.context()?.recheck()
        } else {
            self.source().map(|_| ())
        }
    }
    #[cfg(test)]
    pub(crate) fn obsolete_for_test(mut self) -> Self {
        self.system
            .push_str("\nSuperseded instruction revision for recovery test");
        self.request_id = self.content_identity();
        self
    }
    pub(crate) fn context(&self) -> Result<&CheckedContext, String> {
        if let Some(context) = &self.checked_context {
            return Ok(context);
        }
        self.frozen
            .as_ref()
            .map(|source| source.corpus())
            .ok_or_else(|| {
                "node-owned frozen source is unavailable; provider must use tool RPC".into()
            })
    }
    pub(crate) fn source(&self) -> Result<&Arc<snapshot::Frozen>, String> {
        self.frozen
            .as_ref()
            .ok_or_else(|| "node-owned frozen source unavailable".into())
    }
    #[cfg(test)]
    pub(crate) fn restore_source(&mut self, store: &snapshot::Store) -> Result<(), String> {
        self.restore_shared_source(store, &mut std::collections::BTreeMap::new())
    }
    pub(crate) fn restore_shared_source(
        &mut self,
        store: &snapshot::Store,
        cache: &mut std::collections::BTreeMap<String, Arc<snapshot::Frozen>>,
    ) -> Result<(), String> {
        if let Some(handle) = &self.retrieval_snapshot {
            let source = if let Some(source) = cache.get(&handle.snapshot_id) {
                if source.handle() != handle {
                    return Err("shared recovery source handle differs".into());
                }
                source.clone()
            } else {
                let source = Arc::new(store.load(handle)?);
                cache.insert(handle.snapshot_id.clone(), source.clone());
                source
            };
            self.frozen = Some(source);
            self.cursor_key = Some(store.cursor_key()?);
        }
        Ok(())
    }
    pub(crate) fn attach_cursor_key(&mut self, key: crate::corpus::cursor::Key) {
        self.cursor_key = Some(key);
    }
    pub(crate) fn cursor_key(&self) -> Result<&crate::corpus::cursor::Key, String> {
        self.cursor_key
            .as_ref()
            .ok_or_else(|| "node-owned cursor custody unavailable".into())
    }
    pub(crate) fn persist_source(&self, store: &snapshot::Store) -> Result<(), String> {
        let source = self.source()?;
        if self.retrieval_snapshot.as_ref() != Some(source.handle()) {
            return Err("generation snapshot custody differs".into());
        }
        store.persist(source)
    }
    fn content_identity(&self) -> String {
        if self.version == 1 {
            return digest_value(&(
                "naome:generation-request:v1",
                self.version,
                &self.system,
                &self.binding,
                &self.task,
                &self.owner_interests,
                &self.checked_context,
                &self.requirements,
                &self.tools,
            ));
        }
        digest_value(&(
            "naome:generation-request:v2",
            self.version,
            &self.system,
            &self.binding,
            &self.task,
            &self.owner_interests,
            &self.retrieval_snapshot,
            &self.requirements,
            &self.tools,
        ))
    }
    pub(crate) fn identity(&self) -> String {
        self.request_id.clone()
    }
    pub(crate) fn invoke_tool(
        &self,
        name: &str,
        arguments: &serde_json::Value,
    ) -> Result<retrieval::ResultPage, String> {
        self.invoke_tool_with_retrieval(name, arguments, None)
    }
    pub(crate) fn invoke_tool_with_retrieval(
        &self,
        name: &str,
        arguments: &serde_json::Value,
        backend: Option<(&semantic::SemanticIndex, &mut dyn semantic::SemanticEncoder)>,
    ) -> Result<retrieval::ResultPage, String> {
        let call = retrieval::parse_call(name, arguments)?;
        if call.request_id != self.identity() {
            return Err("retrieval request identity is stale or differs".into());
        }
        if self.version == 1 {
            self.context()?.recheck()
        } else {
            self.source().map(|_| ())
        }?;
        retrieval::invoke(self, &call, backend)
    }

    pub(crate) fn validate_tool_reply(
        &self,
        name: &str,
        arguments: &serde_json::Value,
        reply: &ToolResult,
    ) -> Result<(), String> {
        retrieval::validate_reply(self, name, arguments, reply)
    }
    pub(crate) fn validate_received_window(
        &self,
        query: &str,
        top_k: u16,
        query_id: &str,
        window: &semantic::SemanticPage,
    ) -> Result<(), String> {
        retrieval::validate_received_window(self, query, top_k, query_id, window)
    }

    pub(crate) fn semantic_query(
        &self,
        name: &str,
        arguments: &serde_json::Value,
    ) -> Result<Option<(String, u16, bool)>, String> {
        let call = retrieval::parse_call(name, arguments)?;
        if call.request_id != self.identity() {
            return Err("retrieval request identity is stale or differs".into());
        }
        match call.operation {
            retrieval::Operation::SemanticSearch {
                query,
                top_k,
                after,
                page_size,
                max_bytes,
                ..
            } => {
                if query.trim().is_empty()
                    || query.len() > 1024
                    || !(1..=1024).contains(&top_k)
                    || !(1..=16).contains(&page_size)
                    || !(4096..=MAX_REQUEST_BYTES).contains(&max_bytes)
                {
                    return Err("retrieval semantic query, page or byte limit".into());
                }
                Ok(Some((query, top_k, after.is_some())))
            }
            _ => Ok(None),
        }
    }

    pub(crate) fn invoke_tool_with_ranking(
        &self,
        name: &str,
        arguments: &serde_json::Value,
        ranking: semantic::SemanticPage,
    ) -> Result<ToolResult, String> {
        let call = retrieval::parse_call(name, arguments)?;
        self.context()?;
        retrieval::invoke_ranked(self, &call, None, Some(ranking))
    }
    pub(crate) fn incomplete_tool(
        &self,
        name: &str,
        arguments: &serde_json::Value,
        reason: &str,
    ) -> Result<ToolResult, String> {
        let mut result = self.invoke_tool(name, arguments)?;
        result.status = retrieval::Status::IndexIncomplete;
        result.backend_unavailable_reason = Some(reason.chars().take(256).collect());
        result.remaining_range_complete = false;
        Ok(result)
    }
    pub(crate) fn cursor(&self) -> Result<u64, String> {
        match self.task {
            Task::Question { cursor } => Ok(cursor),
            _ => Err("generation role is not question creation".into()),
        }
    }
    pub(crate) fn question(&self) -> Result<CompiledQuestion, String> {
        match &self.task {
            Task::Proof { question, .. } => {
                CompiledQuestion::compile(question).map_err(|e| e.to_string())
            }
            _ => Err("generation role is not proof creation".into()),
        }
    }
}
pub(crate) fn digest_value(value: &impl Serialize) -> String {
    crate::hex(&Sha256::digest(
        serde_json::to_vec(value).expect("finite generation request"),
    ))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod context_reconstruction_tests;

#[cfg(test)]
mod reference_reuse_tests;

impl PartialEq for Request {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.request_id == other.request_id
            && self.system == other.system
            && self.binding == other.binding
            && self.task == other.task
            && self.owner_interests == other.owner_interests
            && self.checked_context == other.checked_context
            && self.retrieval_snapshot == other.retrieval_snapshot
            && self.requirements == other.requirements
            && self.tools == other.tools
    }
}
impl Eq for Request {}
