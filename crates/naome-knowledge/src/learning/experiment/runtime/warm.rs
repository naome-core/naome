//! Exact, strictly current-format input binding for owned warm diagnostics.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Case {
    pub name: String,
    pub job: u64,
    pub original_job: String,
    pub parent_checkpoint: String,
    pub candidate_checkpoint: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Inputs {
    original_sha256: BTreeMap<String, String>,
    pub cases: Vec<Case>,
}

pub(super) fn inputs(variable: &str) -> Inputs {
    let path = std::env::var(variable).expect("frozen twelve warm cases");
    let inputs: Inputs = read(&path);
    assert_eq!(inputs.cases.len(), 12);
    for (path, hash) in &inputs.original_sha256 {
        assert_eq!(
            crate::hex(&Sha256::digest(std::fs::read(path).unwrap())),
            *hash
        );
    }
    for case in &inputs.cases {
        assert!(inputs.original_sha256.contains_key(&case.original_job));
        let job: Job = read(&case.original_job);
        job.validate().unwrap();
        assert!(job.training && job.base.needs_training());
        assert_eq!(job.base.model.updates, 250);
        let mut store = Store::default();
        assert_eq!(
            checkpoint(&case.parent_checkpoint, &mut store),
            job.base.model
        );
        let candidate = checkpoint(&case.candidate_checkpoint, &mut store);
        assert_eq!(candidate.updates, 500);
        assert_eq!(candidate.seed, job.base.model.seed);
        let progress = job.progress.as_ref().unwrap();
        let experience = &progress.meta_update.as_ref().unwrap().experience;
        assert_eq!(experience.job, case.job);
        assert_eq!(experience.source_model, digest(&job.base.model));
        assert_eq!(experience.candidate_model, Some(digest(&candidate)));
        progress.plan.as_ref().unwrap().plan.validate().unwrap();
        for rehearsal in [false, true] {
            assert!(
                !job.base
                    .training_pool_for(&job.evidence, rehearsal)
                    .unwrap()
                    .is_empty()
            );
        }
    }
    inputs
}
