//! Three replaceable deterministic producers/selectors. Checking is never mocked.
use naome_checker::question::ResearchQuestion;
use naome_foundation::{Formula, FreeVariable, Separation};

use naome_proof::{ArtifactPayload, ProofCertificate, ProofStep};

const CATALOG_SIZE: usize = 3;

fn schema(index: usize) -> Separation {
    let element = FreeVariable::new(0);
    let predicate = match index % CATALOG_SIZE {
        0 => Formula::equal(element, element),
        1 => Formula::negate(Formula::equal(element, element)),
        _ => Formula::member(element, element),
    };
    Separation {
        predicate,
        element,
        source: FreeVariable::new(1),
        result: FreeVariable::new(2),
        parameters: Vec::new(),
    }
}

fn target(index: usize) -> ResearchQuestion {
    ResearchQuestion::from_formula(
        schema(index)
            .formula()
            .expect("fixed schema side conditions"),
    )
    .expect("fixed provider question")
}

/// Repeated calls cycle through a tiny fixed catalog; the cursor is runtime-owned.
pub fn create_question(cursor: u64) -> String {
    target((cursor % CATALOG_SIZE as u64) as usize).to_hex()
}

/// Declared support of this installed provider, independent of proof admission.
pub(crate) fn supports_question(question: &ResearchQuestion) -> bool {
    (0..CATALOG_SIZE).any(|index| target(index) == *question)
}

/// Return a structurally canonical candidate for the independent checker.
pub fn create_proof(question: &ResearchQuestion) -> Option<String> {
    create_padded_proof(question, 0)
}

pub(crate) fn create_padded_proof(question: &ResearchQuestion, padding: usize) -> Option<String> {
    let index = (0..CATALOG_SIZE).find(|&index| target(index) == *question)?;
    // Developer workload uses legal unreachable steps. Normalization strips
    // them after reception, preserving the exact proof and artifact identity.
    let filler = ProofStep::EqualityReflexivity {
        variable: FreeVariable::new(0),
    };
    let conclusion = ProofStep::Separation(schema(index).into());
    let padding = padding.min(
        crate::resources::limits()
            .proof_bytes
            .saturating_sub(5 + conclusion.encoded_length().expect("fixed conclusion width")),
    );
    let count = (padding / filler.encoded_length().expect("fixed filler width"))
        .min(naome_proof::CERTIFICATE_MAX_STEPS - 1);
    let mut steps = vec![filler; count];
    steps.push(conclusion);
    let certificate = ProofCertificate::new(steps).expect("fixed bounded proof fixture");
    let mut bytes = vec![ArtifactPayload::PROOF_TAG];
    bytes.extend(certificate.to_canonical_bytes());
    Some(crate::hex(&bytes))
}

/// Accepts supported candidates after the independent formal prefilter.
/// Structural research ranking belongs to the node, not this provider.
pub fn select_question(
    _: ResearchQuestion,
) -> std::future::Ready<Result<bool, crate::question::SelectionProviderError>> {
    std::future::ready(Ok(true))
}

#[cfg(test)]
mod tests;
