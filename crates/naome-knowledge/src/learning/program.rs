//! A bounded projection of actual checked program commands, never a new proof authority.
use super::{definitions, proof};
use naome_foundation::{Formula, FreeVariable};
use naome_proof::{
    ProofCertificate, ProofId, ProofStep,
    program::{Command, Manifest},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One exact checker-admitted program and its bounded certificate projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub proof: [u8; 32],
    pub projection: [u8; 32],
}

/// The local candidate's canonical program and the exact expected checked result.
pub(crate) struct Candidate {
    pub commands: Vec<Command>,
    pub manifest: Manifest,
    aliases: Vec<Reference>,
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
        let mut commands = match &solution.tree {
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
                match super::construction::composition::scoped_operands(target, proof, definition)?
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
        let aliases = solution
            .tree
            .composition()
            .map_or_else(Vec::new, |(_, references)| references.to_vec());
        let mut used = std::collections::BTreeSet::new();
        for command in &mut commands {
            if let Command::ProofReference { proof_id } = command
                && let Some(reference) = aliases
                    .iter()
                    .find(|reference| reference.projection == *proof_id)
            {
                *proof_id = reference.proof;
                used.insert(reference.proof);
            }
        }
        if used.len() != aliases.len() {
            return Err("compiled program does not cite the selected checked programs".into());
        }
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
            aliases,
            native_scope,
        })
    }

    pub(crate) fn helpers(&self, solution: &super::Solution) -> Result<Vec<String>, String> {
        if self.aliases.is_empty() && !self.native_scope {
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

/// The admitting graph authenticates the source. This subset is not an independent
/// inclusion proof against the program stream. Its translated mathematics is
/// checked again, and its distinct certificate identity is retained explicitly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    pub manifest: Manifest,
    pub records: Vec<(u64, Command)>,
    pub references: Vec<([u8; 32], [u8; 32])>,
}
const COMMANDS: usize = 2048;
#[derive(Clone)]
struct Value {
    formula: Formula,
    proof: Option<u32>,
}
pub struct Projection {
    pub certificate: ProofCertificate,
    pub origin: Origin,
    pub lemmas: Vec<ProofCertificate>,
    pub definitions: Vec<definitions::Entry>,
}

pub fn project(
    manifest: Manifest,
    mut read: impl FnMut(u64) -> Result<Command, String>,
    mut resolve: impl FnMut(ProofId) -> Result<proof::Verified, String>,
    mut resolve_definition: impl FnMut(
        naome_proof::DefinitionId,
    ) -> Result<Option<definitions::Entry>, String>,
    definitions: Vec<definitions::Entry>,
) -> Result<Projection, String> {
    struct Builder<'a, R, P, D> {
        read: &'a mut R,
        resolve: &'a mut P,
        resolve_definition: &'a mut D,
        values: BTreeMap<u64, Value>,
        records: BTreeMap<u64, Command>,
        references: BTreeMap<[u8; 32], [u8; 32]>,
        steps: Vec<ProofStep>,
        lemmas: Vec<ProofCertificate>,
        definitions: Vec<definitions::Entry>,
        bytes: usize,
    }
    impl<R, P, D> Builder<'_, R, P, D>
    where
        R: FnMut(u64) -> Result<Command, String>,
        P: FnMut(ProofId) -> Result<proof::Verified, String>,
        D: FnMut(naome_proof::DefinitionId) -> Result<Option<definitions::Entry>, String>,
    {
        fn command(&mut self, i: u64) -> Result<Command, String> {
            if let Some(command) = self.records.get(&i) {
                return Ok(command.clone());
            }
            if self.records.len() >= COMMANDS {
                return Err("program projection command capacity".into());
            }
            let command = (self.read)(i)?;
            self.records.insert(i, command.clone());
            Ok(command)
        }

        fn graph_formula(&mut self, root: u64) -> Result<Formula, String> {
            Formula::from_graph(root, |position| {
                let Command::Graph { node } = self.command(position)? else {
                    return Err("program projection expected a primitive graph node".into());
                };
                if node
                    .children()
                    .into_iter()
                    .flatten()
                    .any(|child| child >= position)
                {
                    return Err("program projection forward graph reference".into());
                }
                Ok(node)
            })
        }

        fn push(&mut self, step: ProofStep) -> Result<u32, String> {
            if self.steps.len() >= crate::resources::limits().closure_steps {
                return Err("program projection certificate capacity".into());
            }
            let index = u32::try_from(self.steps.len()).map_err(|_| "projection step width")?;
            self.steps.push(step);
            Ok(index)
        }

        fn instantiate(
            &mut self,
            premise: u32,
            universal: &Formula,
            replacement: FreeVariable,
        ) -> Result<(u32, Formula), String> {
            let mut used = universal.free_variables();
            used.insert(replacement);
            let variable = (0..=u32::MAX)
                .map(FreeVariable::new)
                .find(|variable| !used.contains(variable))
                .ok_or("program projection binder space")?;
            let body = universal
                .open_outer_universal(variable)
                .ok_or("program projection expected a universal premise")?;
            let implication = self.push(ProofStep::UniversalInstantiation {
                variable,
                replacement,
                body: body.clone().into(),
            })?;
            let result = self.push(ProofStep::ModusPonens {
                premise,
                implication,
            })?;
            Ok((result, body.substitute_free(variable, replacement)))
        }

        fn value(&mut self, i: u64, depth: usize) -> Result<Value, String> {
            if let Some(v) = self.values.get(&i) {
                return Ok(v.clone());
            }
            if depth > 256 {
                return Err("program projection command capacity".into());
            }
            let command = self.command(i)?;
            use Command as C;
            let inputs: Vec<u64> = match &command {
                C::Not { formula } | C::Vacuous { formula } => vec![*formula],
                C::Implies {
                    antecedent,
                    consequent,
                }
                | C::Simplification {
                    antecedent,
                    consequent,
                }
                | C::Contraposition {
                    antecedent,
                    consequent,
                }
                | C::Distribution {
                    antecedent,
                    consequent,
                    ..
                } => vec![*antecedent, *consequent],
                C::Frege {
                    first,
                    second,
                    third,
                } => vec![*first, *second, *third],
                C::ForAll { body, .. }
                | C::Substitute { body, .. }
                | C::Instantiation { body, .. }
                | C::Substitution { body, .. } => vec![*body],
                C::Separation { predicate, .. } | C::Replacement { predicate, .. } => {
                    vec![*predicate]
                }
                C::ModusPonens {
                    premise,
                    implication,
                } => vec![*premise, *implication],
                C::Generalization { premise, .. } | C::Instantiate { premise, .. } => {
                    vec![*premise]
                }
                C::Alias { input } => vec![*input],
                C::Seal { proof } => vec![*proof],
                C::Deduce { assumptions, .. } => assumptions.clone(),
                _ => vec![],
            };
            let mut values = Vec::new();
            for input in inputs {
                if input >= i {
                    return Err("program projection forward reference".into());
                }
                values.push(self.value(input, depth + 1)?);
            }
            let f = |n: usize| values[n].formula.clone();
            let p = |n: usize| {
                values[n]
                    .proof
                    .ok_or_else(|| "program projection unproved input".to_owned())
            };
            let v = FreeVariable::new;
            let mut step = None;
            let mut reused = None;
            let formula = match command {
                C::Graph { .. } => self.graph_formula(i)?,
                C::Equal { left, right } => Formula::equal(v(left), v(right)),
                C::Member { element, set } => Formula::member(v(element), v(set)),
                C::Not { .. } => Formula::negate(f(0)),
                C::Implies { .. } => Formula::implies(f(0), f(1)),
                C::ForAll { variable, .. } => Formula::for_all(v(variable), f(0)),
                C::Substitute { from, to, .. } => f(0).substitute_free(v(from), v(to)),
                C::DefinedRelation {
                    definition_id,
                    arguments,
                } => {
                    let id = naome_proof::DefinitionId::from_bytes(definition_id);
                    if !self
                        .definitions
                        .iter()
                        .any(|entry| entry.address().is_ok_and(|address| address == id.into()))
                    {
                        let entry = (self.resolve_definition)(id)?
                            .ok_or("program projection definition capacity")?;
                        if entry.address()? != id.into() {
                            return Err("program projection definition identity differs".into());
                        }
                        self.definitions.push(entry);
                    }
                    let context = definitions::context(&self.definitions)?;
                    naome_proof::DefinedFormula::defined_relation(id, arguments.into_iter().map(v))
                        .expand_with(&context)
                        .map_err(|e| e.to_string())?
                }
                C::Alias { .. } | C::Seal { .. } => {
                    reused = Some(values[0].proof);
                    f(0)
                }
                C::ProofReference { proof_id } => {
                    let known = (self.resolve)(ProofId::from_bytes(proof_id))?;
                    self.references
                        .insert(proof_id, *known.native_id.as_bytes());
                    for d in known.definitions {
                        if !self.definitions.contains(&d) {
                            self.definitions.push(d);
                        }
                    }
                    for c in known
                        .lemmas
                        .into_iter()
                        .chain(std::iter::once(known.certificate))
                    {
                        if !self.lemmas.contains(&c) {
                            self.lemmas.push(c);
                        }
                    }
                    step = Some(ProofStep::ProofReference {
                        proof_id: known.native_id,
                    });
                    known.target
                }
                C::ModusPonens { .. } => {
                    let a = p(0)?;
                    let b = p(1)?;
                    let implication = f(1);
                    let (antecedent, consequent) = implication
                        .view()
                        .implication_parts()
                        .ok_or("program projection MP shape")?;
                    if antecedent != f(0).view() {
                        return Err("program projection MP premise".into());
                    }
                    step = Some(ProofStep::ModusPonens {
                        premise: a,
                        implication: b,
                    });
                    consequent.to_owned()
                }
                C::Deduce {
                    actions, result, ..
                } => {
                    let assumptions = values
                        .iter()
                        .map(|value| value.formula.clone())
                        .collect::<Vec<_>>();
                    let term = super::search::scope::deduce(&assumptions, &actions, result)?;
                    let formula = term.formula();
                    let checked = proof::verify(&term, &formula)?;
                    for certificate in checked.lemmas {
                        if !self.lemmas.contains(&certificate) {
                            self.lemmas.push(certificate);
                        }
                    }
                    let offset =
                        u32::try_from(self.steps.len()).map_err(|_| "scope proof offset")?;
                    let mut tail = None;
                    for step in checked.certificate.steps() {
                        let step = match step {
                            ProofStep::ModusPonens {
                                premise,
                                implication,
                            } => ProofStep::ModusPonens {
                                premise: offset + *premise,
                                implication: offset + *implication,
                            },
                            ProofStep::Generalization { premise, variable } => {
                                ProofStep::Generalization {
                                    premise: offset + *premise,
                                    variable: *variable,
                                }
                            }
                            other => other.clone(),
                        };
                        tail = Some(self.push(step)?);
                    }
                    let mut result = tail.ok_or("scope projection has no checked result")?;
                    let mut current = checked.target;
                    for variable in formula.free_variables() {
                        (result, current) = self.instantiate(result, &current, variable)?;
                    }
                    if current != formula {
                        return Err("scope projection changed the open conclusion".into());
                    }
                    reused = Some(Some(result));
                    formula
                }
                C::Instantiate { replacement, .. } => {
                    let (result, formula) = self.instantiate(p(0)?, &f(0), v(replacement))?;
                    reused = Some(Some(result));
                    formula
                }
                C::Generalization { variable, .. } => {
                    step = Some(ProofStep::Generalization {
                        premise: p(0)?,
                        variable: v(variable),
                    });
                    Formula::for_all(v(variable), f(0))
                }
                other => {
                    let native = match other {
                        C::Simplification { .. } => ProofStep::Simplification {
                            antecedent: f(0).into(),
                            consequent: f(1).into(),
                        },
                        C::Frege { .. } => ProofStep::Frege {
                            first: f(0).into(),
                            second: f(1).into(),
                            third: f(2).into(),
                        },
                        C::Contraposition { .. } => ProofStep::ClassicalContraposition {
                            antecedent: f(0).into(),
                            consequent: f(1).into(),
                        },
                        C::Distribution { variable, .. } => ProofStep::UniversalDistribution {
                            variable: v(variable),
                            antecedent: f(0).into(),
                            consequent: f(1).into(),
                        },
                        C::Vacuous { .. } => ProofStep::VacuousUniversal {
                            formula: f(0).into(),
                        },
                        C::Instantiation {
                            variable,
                            replacement,
                            ..
                        } => ProofStep::UniversalInstantiation {
                            variable: v(variable),
                            replacement: v(replacement),
                            body: f(0).into(),
                        },
                        C::Reflexivity { variable } => ProofStep::EqualityReflexivity {
                            variable: v(variable),
                        },
                        C::Substitution { from, to, .. } => ProofStep::EqualitySubstitution {
                            from: v(from),
                            to: v(to),
                            body: f(0).into(),
                        },
                        C::Axiom { axiom } => ProofStep::ZfcAxiom(axiom.into()),
                        C::Separation {
                            element,
                            source,
                            result,
                            ..
                        } => ProofStep::Separation(naome_proof::ProofSeparation {
                            predicate: f(0).into(),
                            element: v(element),
                            source: v(source),
                            result: v(result),
                            parameters: vec![],
                        }),
                        C::Replacement {
                            input,
                            output,
                            witness,
                            source,
                            result,
                            ..
                        } => ProofStep::Replacement(naome_proof::ProofReplacement {
                            predicate: f(0).into(),
                            input: v(input),
                            output: v(output),
                            uniqueness_witness: v(witness),
                            source: v(source),
                            result: v(result),
                            parameters: vec![],
                        }),
                        _ => return Err("program projection unsupported command".into()),
                    };
                    let context = definitions::context(&self.definitions)?;
                    let formula = proof::Kernel::with_context(native.clone(), &context)?.formula();
                    step = Some(native);
                    formula
                }
            };
            self.bytes = self
                .bytes
                .checked_add(formula.encode_canonical().map_err(|e| e.to_string())?.len())
                .ok_or("projection byte overflow")?;
            if self.bytes > 4 * crate::resources::limits().closure_bytes {
                return Err("program projection formula capacity".into());
            }
            let proof = if let Some(s) = step {
                Some(self.push(s)?)
            } else {
                reused.flatten()
            };
            let value = Value { formula, proof };
            self.values.insert(i, value.clone());
            Ok(value)
        }
    }
    if manifest.commands == 0 {
        return Err("program projection empty source".into());
    }
    let mut b = Builder {
        read: &mut read,
        resolve: &mut resolve,
        resolve_definition: &mut resolve_definition,
        values: BTreeMap::new(),
        records: BTreeMap::new(),
        references: BTreeMap::new(),
        steps: vec![],
        lemmas: vec![],
        definitions,
        bytes: 0,
    };
    let end = manifest.commands - 1;
    let root = b.value(end, 0)?;
    if !matches!(b.records.get(&end), Some(Command::Seal { .. }))
        || root.proof != Some(b.steps.len().saturating_sub(1) as u32)
        || !root.formula.free_variables().is_empty()
        || naome_proof::program::formula_hash(&root.formula) != manifest.conclusion
    {
        return Err("program projection sealed conclusion differs".into());
    }
    let certificate = ProofCertificate::new(b.steps).map_err(|e| e.to_string())?;
    let context = proof::lemma_context(&b.definitions, &b.lemmas)?;
    let checked = proof::check(certificate, &context).map_err(|e| e.to_string())?;
    if checked.conclusion() != &root.formula {
        return Err("program projection checked conclusion differs".into());
    }
    Ok(Projection {
        certificate: checked.normal_form().certificate().clone(),
        origin: Origin {
            manifest,
            records: b.records.into_iter().collect(),
            references: b.references.into_iter().collect(),
        },
        lemmas: b.lemmas,
        definitions: b.definitions,
    })
}

pub fn validate(origin: &Origin, verified: &proof::Verified) -> Result<(), String> {
    if origin.records.len() > COMMANDS
        || serde_json::to_vec(origin).map_err(|e| e.to_string())?.len()
            > crate::resources::limits().closure_bytes
    {
        return Err("program origin capacity".into());
    }
    let records: BTreeMap<_, _> = origin.records.iter().cloned().collect();
    let references: BTreeMap<_, _> = origin.references.iter().copied().collect();
    if records.len() != origin.records.len() || references.len() != origin.references.len() {
        return Err("program origin duplicate key".into());
    }
    let context = proof::lemma_context(&verified.definitions, &verified.lemmas)?;
    let projected = project(
        origin.manifest.clone(),
        |i| {
            records
                .get(&i)
                .cloned()
                .ok_or_else(|| "program origin command absent".into())
        },
        |id| {
            let mapped = references
                .get(id.as_bytes())
                .ok_or("program reference source absent")?;
            let certificate = verified
                .lemmas
                .iter()
                .find(|c| {
                    proof::check((*c).clone(), &context)
                        .is_ok_and(|p| p.proof_id().as_bytes() == mapped)
                })
                .ok_or("program reference translated proof absent")?;
            let checked = proof::check(certificate.clone(), &context).map_err(|e| e.to_string())?;
            proof::verify(
                &proof::Term::Native {
                    certificate: certificate.clone(),
                    lemmas: verified
                        .lemmas
                        .iter()
                        .filter(|c| *c != certificate)
                        .cloned()
                        .collect(),
                    definitions: verified.definitions.clone(),
                    target: checked.conclusion().clone(),
                },
                checked.conclusion(),
            )
        },
        |_| Ok(None),
        verified.definitions.clone(),
    )?;
    if projected.origin != *origin || projected.certificate != verified.certificate {
        return Err("program source projection differs".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unused_large_history_is_not_flattened_and_projected_identity_is_distinct() {
        let end = 100_002;
        let formula = naome_foundation::ZfcAxiom::Pairing.formula();
        let manifest = Manifest {
            commands: end + 1,
            input_bytes: 4_000_000,
            program_hash: [1; 32],
            stream_root: [2; 32],
            conclusion: naome_proof::program::formula_hash(&formula),
            statement: [3; 32],
        };
        let mut reads = Vec::new();
        let projection = project(
            manifest.clone(),
            |i| {
                reads.push(i);
                match i {
                    100_001 => Ok(Command::Axiom {
                        axiom: naome_proof::program::Axiom::Pairing,
                    }),
                    100_002 => Ok(Command::Seal { proof: 100_001 }),
                    _ => panic!("unused command read"),
                }
            },
            |_| Err("no dependency".into()),
            |_| Ok(None),
            vec![],
        )
        .unwrap();
        assert_eq!(reads, vec![end, end - 1]);
        let term = proof::Term::Native {
            certificate: projection.certificate.clone(),
            lemmas: vec![],
            definitions: vec![],
            target: formula.clone(),
        };
        let verified = proof::verify(&term, &formula).unwrap();
        assert_ne!(verified.native_id, manifest.proof_id());
        validate(&projection.origin, &verified).unwrap();
        let packet =
            super::super::evidence::pack_with_program(&verified, Some(projection.origin.clone()))
                .unwrap();
        assert!(
            super::super::peer::matches_artifact(
                &crate::hex(verified.native_id.as_bytes()),
                &crate::hex(manifest.artifact_id().as_bytes()),
                &packet
            )
            .unwrap()
        );
        assert!(
            !super::super::peer::matches_artifact(
                &crate::hex(verified.native_id.as_bytes()),
                &"ff".repeat(32),
                &packet
            )
            .unwrap()
        );
        let mut forged = projection.origin;
        forged.records[0].1 = Command::Axiom {
            axiom: naome_proof::program::Axiom::Union,
        };
        assert!(validate(&forged, &verified).is_err());
    }
}
