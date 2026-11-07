//! A bounded projection of actual checked program commands, never a new proof authority.
use super::{definitions, proof};
use naome_foundation::{Formula, FreeVariable};
use naome_proof::{
    ProofCertificate, ProofId, ProofStep,
    program::{Command, Manifest},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
    definitions: Vec<definitions::Entry>,
) -> Result<Projection, String> {
    struct Builder<'a, R, P> {
        read: &'a mut R,
        resolve: &'a mut P,
        values: BTreeMap<u64, Value>,
        records: BTreeMap<u64, Command>,
        references: BTreeMap<[u8; 32], [u8; 32]>,
        steps: Vec<ProofStep>,
        lemmas: Vec<ProofCertificate>,
        definitions: Vec<definitions::Entry>,
        bytes: usize,
    }
    impl<R, P> Builder<'_, R, P>
    where
        R: FnMut(u64) -> Result<Command, String>,
        P: FnMut(ProofId) -> Result<proof::Verified, String>,
    {
        fn value(&mut self, i: u64, depth: usize) -> Result<Value, String> {
            if let Some(v) = self.values.get(&i) {
                return Ok(v.clone());
            }
            if depth > 256 || self.records.len() >= COMMANDS {
                return Err("program projection command capacity".into());
            }
            let command = (self.read)(i)?;
            self.records.insert(i, command.clone());
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
                C::Generalization { premise, .. } => vec![*premise],
                C::Alias { input } => vec![*input],
                C::Seal { proof } => vec![*proof],
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
                    let context = definitions::context(&self.definitions)?;
                    naome_proof::DefinedFormula::defined_relation(
                        naome_proof::DefinitionId::from_bytes(definition_id),
                        arguments.into_iter().map(v),
                    )
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
                let index = u32::try_from(self.steps.len()).map_err(|_| "projection step width")?;
                self.steps.push(s);
                Some(index)
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
