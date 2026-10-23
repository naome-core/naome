//! Three replaceable deterministic producers/selectors. Checking is never mocked.
use naome_authoring::CompiledQuestion;
use naome_foundation::{Formula, FreeVariable, Separation};

const CATALOG_SIZE: usize = 3;

// These schema examples lie outside the elementary question fragment. The
// real prefilter and checker still decide admission and proof validity.
fn catalog(index: usize) -> (String, String) {
    let element = FreeVariable::new(0);
    let source = FreeVariable::new(1);
    let result = FreeVariable::new(2);
    let predicate = match index % CATALOG_SIZE {
        0 => Formula::equal(element, element),
        1 => Formula::negate(Formula::equal(element, element)),
        _ => Formula::member(element, element),
    };
    let statement = Separation {
        predicate: predicate.clone(),
        element,
        source,
        result,
        parameters: Vec::new(),
    }
    .formula()
    .expect("fixed schema side conditions")
    .to_source();
    let question = format!("goal = {statement}");
    let proof = format!(
        "{question} proof: p0=sep({},f0,f1,f2,parameters=[]) return p0",
        predicate.to_source()
    );
    (question, proof)
}

/// Repeated calls cycle through a tiny fixed catalog; the cursor is runtime-owned.
pub fn create_question(cursor: u64) -> String {
    catalog(cursor as usize % CATALOG_SIZE).0
}

/// Unsupported questions have no candidate. This does not establish proof validity.
pub fn create_proof(question: &CompiledQuestion) -> Option<String> {
    (0..CATALOG_SIZE).find_map(|index| {
        let (source, proof) = catalog(index);
        let candidate = CompiledQuestion::compile(&source).expect("fixed mock question source");
        (candidate == *question).then_some(proof)
    })
}

/// Placeholder interest selection, called only after the real formal prefilter.
pub fn assess_interest(_: CompiledQuestion) -> std::future::Ready<Result<bool, String>> {
    std::future::ready(Ok(true))
}

#[cfg(test)]
mod tests;
