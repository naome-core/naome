use crate::index::Index;
use crate::{
    dataset::{Corpus, Pair, digest, split},
    model::{Adam, Model, Random},
};
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: u32,
    pub families: usize,
    pub epochs: usize,
    pub seeds: Vec<u64>,
    pub learning_rate: f64,
    pub rejection_threshold: f64,
    pub target_false_rejection: f64,
    pub scale_rows: Vec<usize>,
    pub queries: usize,
    pub repeats: usize,
    pub max_scale_families: usize,
}
impl Config {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != 1
            || !(8..=256).contains(&self.families)
            || !(1..=100).contains(&self.epochs)
            || self.seeds.is_empty()
            || self.seeds.len() > 5
            || self.seeds.contains(&0)
            || self
                .seeds
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.seeds.len()
            || !self.learning_rate.is_finite()
            || !(0.0..=0.1).contains(&self.learning_rate)
            || self.learning_rate == 0.0
            || !(0.0..=1.0).contains(&self.rejection_threshold)
            || self.target_false_rejection != 0.0
            || self.queries == 0
            || self.queries > 32
            || !(1..=5).contains(&self.repeats)
            || !(8..=2048).contains(&self.max_scale_families)
            || self.scale_rows.is_empty()
            || self
                .scale_rows
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.scale_rows.len()
            || self
                .scale_rows
                .iter()
                .any(|r| !(64..=65536).contains(r) || r % 8 != 0)
        {
            return Err("configuration exceeds finite experiment envelope".into());
        }
        Ok(())
    }
}
pub fn train(corpus: &Corpus, config: &Config, seed: u64) -> (Model, serde_json::Value) {
    let mut model = Model::new(seed, corpus.digest());
    let initial = digest(&serde_json::to_vec(&model).unwrap());
    let train = corpus
        .pairs
        .iter()
        .filter(|p| split(corpus.records[p.a].family) == 0)
        .collect::<Vec<_>>();
    let mut optimizer = Adam::new(&model);
    let mut rng = Random(seed);
    let mut order = (0..train.len()).collect::<Vec<_>>();
    let mut losses = Vec::new();
    let clock = Instant::now();
    for _ in 0..config.epochs {
        for i in (1..order.len()).rev() {
            let j = rng.next() as usize % (i + 1);
            order.swap(i, j);
        }
        let mut loss = 0.0;
        for &i in &order {
            let p = train[i];
            let (l, g) = model.gradient(
                &corpus.records[p.a].graph,
                &corpus.records[p.b].graph,
                p.label,
            );
            loss += l;
            optimizer.update(&mut model, &g, config.learning_rate);
        }
        losses.push(loss / train.len() as f64);
    }
    let elapsed = clock.elapsed().as_secs_f64();
    let dev = corpus
        .pairs
        .iter()
        .filter(|p| split(corpus.records[p.a].family) == 1)
        .collect::<Vec<_>>();
    // Chosen exclusively on development useful alternatives; target 0 observed errors.
    // The predeclared floor remains in effect. Strict > avoids accepting a tied maximum.
    let threshold = dev
        .iter()
        .filter(|p| p.label == 1)
        .map(|p| model.score(&corpus.records[p.a].graph, &corpus.records[p.b].graph)[0])
        .fold(config.rejection_threshold, f64::max);
    let report = serde_json::json!({"seed":seed,"parameters":model.parameters(),"initial_model_sha256":initial,"trained_model_sha256":digest(&serde_json::to_vec(&model).unwrap()),"corpus_sha256":model.corpus_digest,"train_pairs":train.len(),"loss_by_epoch":losses,"train_seconds":elapsed,"threshold":threshold,"target_development_false_rejection":0.0,"development":evaluate(corpus,&model,1,threshold)});
    (model, report)
}
fn baseline(c: &Corpus, p: &Pair, structural: bool) -> usize {
    let a = &c.records[p.a];
    let b = &c.records[p.b];
    if a.derivation_id == b.derivation_id {
        0
    } else if structural && a.statement_id == b.statement_id && a.graph.cost < b.graph.cost {
        1
    } else if structural && p.witnesses.len() == 2 {
        2
    } else {
        3
    }
}
pub fn evaluate(c: &Corpus, m: &Model, partition: usize, threshold: f64) -> serde_json::Value {
    let mut neural = [[0usize; 4]; 4];
    let mut exact = neural;
    let mut structural = neural;
    let mut scores = Vec::new();
    let mut brier = 0.0;
    let mut missed = 0;
    let mut useful_lost = 0;
    let mut useful = 0;
    let mut redundant = 0;
    let mut unknown_rejected = 0;
    for p in &c.pairs {
        if split(c.records[p.a].family) != partition {
            continue;
        }
        let prob = m.score(&c.records[p.a].graph, &c.records[p.b].graph);
        let prediction = (0..4).max_by(|a, b| prob[*a].total_cmp(&prob[*b])).unwrap();
        neural[p.label][prediction] += 1;
        exact[p.label][baseline(c, p, false)] += 1;
        structural[p.label][baseline(c, p, true)] += 1;
        for (i, v) in prob.iter().enumerate() {
            brier += (v - if i == p.label { 1.0 } else { 0.0 }).powi(2);
        }
        let reject = prob[0] > threshold;
        if p.label == 0 {
            redundant += 1;
            if !reject {
                missed += 1;
            }
        }
        if p.label == 1 {
            useful += 1;
            if reject {
                useful_lost += 1;
            }
        }
        if p.label == 3 && reject {
            unknown_rejected += 1;
        }
        scores.push(serde_json::json!({"a":p.a,"b":p.b,"family":c.records[p.a].family,"label":p.label,"scores":prob,"advisory_redundancy_flag":reject,"witnesses":p.witnesses}));
    }
    serde_json::json!({"split":partition,"pairs":scores.len(),"neural_confusion":neural,"exact_identity_confusion":exact,"structural_witness_confusion":structural,"brier":brier/scores.len() as f64,"redundant":redundant,"missed_redundant":missed,"useful":useful,"useful_false_rejections":useful_lost,"unknown_flagged":unknown_rejected,"threshold":threshold,"predictions":scores})
}

/// Versioned full scan, retaining row addresses even when vectors are shared.
pub fn benchmark(
    c: &Corpus,
    query_corpus: &Corpus,
    m: &Model,
    rows: usize,
    queries: usize,
    repeats: usize,
) -> (serde_json::Value, Index) {
    let started = Instant::now();
    let mut index = Index::new(m, c);
    let mut incremental_start = Instant::now();
    for i in 0..rows {
        if i == rows - 64 {
            incremental_start = Instant::now();
        }
        index.append(m, &c.records[i % c.records.len()]);
    }
    let build = started.elapsed().as_secs_f64();
    let incremental = incremental_start.elapsed().as_secs_f64();
    let mut samples = Vec::new();
    let mut sink = 0.0;
    let mut candidates = Vec::new();
    let workload = query_corpus
        .records
        .iter()
        .filter(|r| split(r.family) == 2 && r.variant == "direct")
        .take(queries)
        .collect::<Vec<_>>();
    let clock = Instant::now();
    let query_vectors = workload
        .iter()
        .map(|q| m.embedding(&q.graph))
        .collect::<Vec<_>>();
    let query_encoding = clock.elapsed().as_secs_f64();
    let query_digest = digest(
        &serde_json::to_vec(
            &workload
                .iter()
                .map(|r| (&r.proof_id, &r.statement_id, &r.derivation_id))
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    );
    for sample in 0..repeats {
        let clock = Instant::now();
        let mut found = 0;
        for q in &workload {
            found += std::hint::black_box(index.exact_matches(q)).len();
        }
        let exact = clock.elapsed().as_secs_f64();
        let clock = Instant::now();
        let mut alternatives = 0;
        for q in &workload {
            for row in index.statement_matches(q) {
                let entry = &index.entries[index.rows[*row]];
                alternatives += usize::from(
                    entry.derivation_id != q.derivation_id && q.graph.cost < entry.cost,
                );
            }
        }
        std::hint::black_box(alternatives);
        let structural = clock.elapsed().as_secs_f64();
        let clock = Instant::now();
        for (query, q) in workload.iter().enumerate() {
            let mut best = (0, f64::NEG_INFINITY);
            for i in 0..rows {
                let entry = &index.entries[index.rows[i]];
                let scores = m.score_vectors(
                    &query_vectors[query],
                    &entry.vector,
                    (q.graph.cost, entry.cost),
                );
                sink += scores[0];
                if scores[0] > best.1 {
                    best = (i, scores[0]);
                }
            }
            if sample == 0 {
                let entry = &index.entries[index.rows[best.0]];
                candidates.push(serde_json::json!({"query_proof_id":q.proof_id,"candidate_row":best.0,"candidate_proof_id":entry.proof_id,"candidate_statement_id":entry.statement_id,"candidate_derivation_id":entry.derivation_id,"candidate_dependencies":entry.dependencies,"score":best.1,"has_exact_derivation_candidate":!index.exact_matches(q).is_empty(),"top_candidate_matches_derivation":entry.derivation_id==q.derivation_id}));
            }
        }
        let neural = clock.elapsed().as_secs_f64();
        samples.push(serde_json::json!({"sample":sample,"exact_index_query_seconds":exact,"structural_statement_query_seconds":structural,"neural_full_scan_seconds":neural,"known_derivation_matches":found}));
    }
    std::hint::black_box(sink);
    let record_bytes = serde_json::to_vec(&c.records).unwrap().len();
    let index_bytes = serde_json::to_vec(&index).unwrap().len();
    (
        serde_json::json!({"schema":1,"rows":rows,"generated_unique_input_rows":c.records.len(),"repeated_volume_rows":rows-c.records.len(),"counts":c.counts(),"corpus_sha256":index.corpus_digest,"model_sha256":index.model_digest,"policy":m.policy,"cache_key":"model digest + canonical checked ProofId + schema 1 + exact dependency IDs","actual_queries":workload.len(),"fixed_query_sha256":query_digest,"query_encoding_seconds":query_encoding,"vector_cache_entries":index.entries.len(),"vector_payload_bytes":index.entries.len()*crate::model::EMBEDDING*8,"row_address_bytes":rows*std::mem::size_of::<usize>(),"serialized_index_bytes":index_bytes,"serialized_unique_records_bytes":record_bytes,"index_build_seconds":build,"last_64_row_append_seconds":incremental,"samples":samples,"top_candidates":candidates,"candidate_miss_rate":"not applicable: every row scored; no approximate retrieval","limit":"throughput on synthetic schema variants and explicit repeats; no scientific-diversity or semantic-recognition qualification"}),
        index,
    )
}
