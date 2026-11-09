//! The local publication boundary for canonical typed proof programs.
use naome_proof::{
    ProofId,
    program::{Command, Manifest},
};

/// The local candidate's canonical program and the exact expected checked result.
pub(crate) struct Candidate {
    pub commands: Vec<Command>,
    pub manifest: Manifest,
    native_scope: bool,
}

impl Candidate {
    pub(crate) fn artifact(
        solution: &super::Solution,
        source: &str,
    ) -> Result<naome_proof::ArtifactId, String> {
        let question = naome_checker::question::ResearchQuestion::from_hex(source)
            .map_err(|error| error.to_string())?;
        Ok(Self::from_solution(solution, &question)?
            .manifest
            .artifact_id())
    }

    pub(crate) fn from_solution(
        solution: &super::Solution,
        question: &naome_checker::question::ResearchQuestion,
    ) -> Result<Self, String> {
        use naome_proof::{
            ArtifactPayload, StatementId,
            program::{Prefix, Projection, encode_command, formula_hash, stream_hash},
        };
        if let super::search::Tree::Program(packet) = &solution.tree {
            solution.check_target(question)?;
            return Ok(Self {
                commands: packet.commands()?,
                manifest: packet.manifest.clone(),
                native_scope: true,
            });
        }
        let bytes = crate::unhex(&solution.source).map_err(|error| error.to_string())?;
        let ArtifactPayload::Proof(certificate) =
            ArtifactPayload::from_canonical_bytes(&bytes).map_err(|error| error.to_string())?
        else {
            return Err("native program candidate requires a proof certificate".into());
        };
        let target = if solution.refuted {
            question.refuted_target()
        } else {
            question.proved_target()
        };
        let statement = StatementId::of_canonical_formula(
            &target
                .encode_canonical()
                .map_err(|error| error.to_string())?,
        )
        .ok_or("native program statement width")?;
        let proof_id = ProofId::of_canonical_certificate(statement, &bytes[1..])
            .ok_or("native program certificate width")?;
        if crate::hex(proof_id.as_bytes()) != solution.proof_id {
            return Err("native program candidate certificate identity differs".into());
        }

        use super::search::Tree;
        let mut native_scope = false;
        let commands = match &solution.tree {
            Tree::Scoped {
                target: encoded,
                actions,
            } => {
                if target
                    .encode_canonical()
                    .map_err(|error| error.to_string())?
                    != *encoded
                {
                    return Err("scope program target binding differs".into());
                }
                native_scope = true;
                super::search::scope::commands(target, actions)?
            }
            Tree::Definitions {
                entries,
                selected,
                proof,
                ..
            } => {
                let definition = entries.get(*selected).ok_or("definition selection index")?;
                match super::construction::composition::scoped_operands(target, proof, definition)
                    .map_err(|error| error.to_string())?
                {
                    Some(operands) => {
                        native_scope = true;
                        Projection::conjoin(&operands)
                    }
                    None => Projection::with_native_instantiations(
                        &certificate.into_unchecked_normal_form(),
                    )?
                    .into_commands(),
                }
            }
            _ => Projection::with_native_instantiations(&certificate.into_unchecked_normal_form())?
                .into_commands(),
        };
        let mut prefix = Prefix::default();
        for command in &commands {
            prefix.append(&encode_command(command)?)?;
        }
        let mut stream_root = [0; 32];
        for command in commands.iter().rev() {
            stream_root = stream_hash(&encode_command(command)?, stream_root);
        }
        let manifest = Manifest {
            commands: prefix.commands,
            input_bytes: prefix.input_bytes,
            program_hash: prefix.hash,
            stream_root,
            conclusion: formula_hash(target),
            statement: *statement.as_bytes(),
        };
        Ok(Self {
            commands,
            manifest,
            native_scope,
        })
    }

    pub(crate) fn helpers(&self, solution: &super::Solution) -> Result<Vec<String>, String> {
        if matches!(solution.tree, super::search::Tree::Program(_)) {
            return Ok(solution.helpers.clone());
        }
        if !self.native_scope {
            return Ok(solution.helpers.clone());
        }
        use naome_proof::{ArtifactId, ArtifactPayload, DefinitionId};
        let mut needed = self
            .commands
            .iter()
            .filter_map(|command| match command {
                Command::ProofReference { proof_id } => {
                    Some(ArtifactId::from(ProofId::from_bytes(*proof_id)))
                }
                Command::DefinedRelation { definition_id, .. } => {
                    Some(ArtifactId::from(DefinitionId::from_bytes(*definition_id)))
                }
                _ => None,
            })
            .collect::<std::collections::BTreeSet<_>>();
        if needed.is_empty() {
            return Ok(Vec::new());
        }
        let context = super::definitions::proof_context(&solution.tree)?;
        let mut helpers = Vec::new();
        for source in solution.helpers.iter().rev() {
            let bytes = crate::unhex(source).map_err(|error| error.to_string())?;
            let payload =
                ArtifactPayload::from_canonical_bytes(&bytes).map_err(|error| error.to_string())?;
            let (id, dependencies) = match payload {
                ArtifactPayload::Proof(certificate) => {
                    let proof = super::proof::check(certificate, &context)
                        .map_err(|error| error.to_string())?;
                    (
                        proof.artifact_id(),
                        proof.direct_artifact_dependencies().into_vec(),
                    )
                }
                ArtifactPayload::Definition(certificate) => {
                    use naome_checker::ContextView;
                    let id = certificate.definition_id().into();
                    let definition =
                        naome_checker::check_definition_with_state(certificate, &context)
                            .map_err(|error| error.to_string())?;
                    let witness = definition
                        .obligation_statement_id()
                        .map(|statement| {
                            context
                                .statement_header(statement)
                                .map_err(|error| error.to_string())
                        })
                        .transpose()?
                        .flatten();
                    (
                        id,
                        witness
                            .into_iter()
                            .map(|header| ArtifactId::from(header.proof_id()))
                            .collect(),
                    )
                }
            };
            if needed.remove(&id) {
                needed.extend(dependencies);
                helpers.push(source.clone());
            }
        }
        helpers.reverse();
        Ok(helpers)
    }
}
