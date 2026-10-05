//! Owned f64 dense layers, typed message passing, reverse derivatives and Adam.
use crate::graph::{FEATURES, Graph};
use serde::{Deserialize, Serialize};

pub const WIDTH: usize = 8;
pub const EMBEDDING: usize = WIDTH * 2;
pub const CLASSES: usize = 4;
const PAIR: usize = EMBEDDING * 4 + 2;

pub struct Random(pub u64);
impl Random {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Layer {
    pub input: usize,
    pub output: usize,
    pub weights: Vec<f64>,
}
impl Layer {
    fn new(input: usize, output: usize, rng: &mut Random) -> Self {
        let scale = (6.0 / (input + output) as f64).sqrt();
        let weights = (0..output * (input + 1))
            .map(|i| {
                if i % (input + 1) == input {
                    0.0
                } else {
                    (rng.next() as f64 / u64::MAX as f64 * 2.0 - 1.0) * scale
                }
            })
            .collect();
        Self {
            input,
            output,
            weights,
        }
    }
    fn forward(&self, x: &[f64], activation: bool) -> Vec<f64> {
        (0..self.output)
            .map(|o| {
                let w = &self.weights[o * (self.input + 1)..(o + 1) * (self.input + 1)];
                let z = w[self.input] + x.iter().zip(w).map(|(x, w)| x * w).sum::<f64>();
                if activation { z.tanh() } else { z }
            })
            .collect()
    }
    fn backward(
        &self,
        x: &[f64],
        y: &[f64],
        dy: &[f64],
        activation: bool,
        dw: &mut [f64],
    ) -> Vec<f64> {
        let mut dx = vec![0.0; self.input];
        for o in 0..self.output {
            let dz = dy[o] * if activation { 1.0 - y[o] * y[o] } else { 1.0 };
            let start = o * (self.input + 1);
            for i in 0..self.input {
                dw[start + i] += dz * x[i];
                dx[i] += dz * self.weights[start + i];
            }
            dw[start + self.input] += dz;
        }
        dx
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Model {
    pub schema: u32,
    pub seed: u64,
    pub corpus_digest: String,
    pub policy: String,
    pub layers: Vec<Layer>,
}
struct Encoding {
    states: Vec<Vec<Vec<f64>>>,
    inputs: Vec<Vec<Vec<f64>>>,
    vector: Vec<f64>,
}
impl Model {
    pub fn new(seed: u64, corpus_digest: String) -> Self {
        let mut rng = Random(seed.max(1));
        Self {
            schema: 1,
            seed,
            corpus_digest,
            policy: "checked-relations-v1".into(),
            layers: vec![
                Layer::new(FEATURES, WIDTH, &mut rng),
                Layer::new(WIDTH * 4, WIDTH, &mut rng),
                Layer::new(WIDTH * 4, WIDTH, &mut rng),
                Layer::new(PAIR, WIDTH, &mut rng),
                Layer::new(WIDTH, CLASSES, &mut rng),
            ],
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        self.validate_policy("checked-relations-v1")
    }
    pub(crate) fn validate_policy(&self, policy: &str) -> Result<(), String> {
        let shapes = [
            (FEATURES, WIDTH),
            (WIDTH * 4, WIDTH),
            (WIDTH * 4, WIDTH),
            (PAIR, WIDTH),
            (WIDTH, CLASSES),
        ];
        if self.schema != 1 || self.policy != policy || self.layers.len() != shapes.len() {
            return Err("unsupported model schema/policy".into());
        }
        for (l, (i, o)) in self.layers.iter().zip(shapes) {
            if l.input != i
                || l.output != o
                || l.weights.len() != o * (i + 1)
                || l.weights.iter().any(|w| !w.is_finite())
            {
                return Err("invalid model dimensions or weights".into());
            }
        }
        Ok(())
    }
    pub fn parameters(&self) -> usize {
        self.layers.iter().map(|l| l.weights.len()).sum()
    }
    fn encode(&self, g: &Graph) -> Encoding {
        let mut inputs = vec![g.nodes.iter().map(|n| n.to_vec()).collect::<Vec<_>>()];
        let mut states = vec![
            inputs[0]
                .iter()
                .map(|x| self.layers[0].forward(x, true))
                .collect::<Vec<_>>(),
        ];
        for layer in 1..3 {
            let prev = &states[layer - 1];
            let mut xs = Vec::with_capacity(g.nodes.len());
            for node in 0..g.nodes.len() {
                let mut x = vec![0.0; WIDTH * 4];
                x[..WIDTH].copy_from_slice(&prev[node]);
                for channel in 0..3 {
                    let edges = g.edges[node]
                        .iter()
                        .filter(|(_, c)| *c == channel)
                        .collect::<Vec<_>>();
                    for (to, _) in &edges {
                        for h in 0..WIDTH {
                            x[(channel + 1) * WIDTH + h] += prev[*to][h] / edges.len() as f64;
                        }
                    }
                }
                xs.push(x);
            }
            states.push(
                xs.iter()
                    .map(|x| self.layers[layer].forward(x, true))
                    .collect(),
            );
            inputs.push(xs);
        }
        let last = &states[2];
        let mut vector = last[g.root].clone();
        vector.resize(EMBEDDING, 0.0);
        for s in last {
            for h in 0..WIDTH {
                vector[WIDTH + h] += s[h] / last.len() as f64;
            }
        }
        Encoding {
            states,
            inputs,
            vector,
        }
    }
    pub fn embedding(&self, g: &Graph) -> Vec<f64> {
        self.encode(g).vector
    }
    fn pair(a: &[f64], b: &[f64], costs: (usize, usize)) -> Vec<f64> {
        let mut x = Vec::with_capacity(PAIR);
        x.extend(a);
        x.extend(b);
        x.extend(a.iter().zip(b).map(|(a, b)| a - b));
        x.extend(a.iter().zip(b).map(|(a, b)| a * b));
        x.push((costs.0 as f64).ln_1p() / 8.0);
        x.push((costs.1 as f64).ln_1p() / 8.0);
        x
    }
    pub fn score_vectors(&self, a: &[f64], b: &[f64], costs: (usize, usize)) -> [f64; CLASSES] {
        let hidden = self.layers[3].forward(&Self::pair(a, b, costs), true);
        probabilities(&self.layers[4].forward(&hidden, false))
    }
    pub fn score(&self, a: &Graph, b: &Graph) -> [f64; CLASSES] {
        self.score_vectors(&self.embedding(a), &self.embedding(b), (a.cost, b.cost))
    }
    fn backward_encoding(&self, g: &Graph, e: &Encoding, dv: &[f64], grad: &mut [Vec<f64>]) {
        let mut ds = vec![vec![0.0; WIDTH]; g.nodes.len()];
        for (n, d) in ds.iter_mut().enumerate() {
            for h in 0..WIDTH {
                d[h] = dv[WIDTH + h] / g.nodes.len() as f64 + if n == g.root { dv[h] } else { 0.0 };
            }
        }
        for l in (0..3).rev() {
            let mut previous = vec![vec![0.0; WIDTH]; g.nodes.len()];
            for n in 0..g.nodes.len() {
                let dx = self.layers[l].backward(
                    &e.inputs[l][n],
                    &e.states[l][n],
                    &ds[n],
                    true,
                    &mut grad[l],
                );
                if l == 0 {
                    continue;
                }
                for h in 0..WIDTH {
                    previous[n][h] += dx[h];
                }
                for channel in 0..3 {
                    let edges = g.edges[n]
                        .iter()
                        .filter(|(_, c)| *c == channel)
                        .collect::<Vec<_>>();
                    for (to, _) in &edges {
                        for h in 0..WIDTH {
                            previous[*to][h] += dx[(channel + 1) * WIDTH + h] / edges.len() as f64;
                        }
                    }
                }
            }
            ds = previous;
        }
    }
    pub fn gradient(&self, a: &Graph, b: &Graph, label: usize) -> (f64, Vec<Vec<f64>>) {
        let ea = self.encode(a);
        let eb = self.encode(b);
        let x = Self::pair(&ea.vector, &eb.vector, (a.cost, b.cost));
        let hidden = self.layers[3].forward(&x, true);
        let logits = self.layers[4].forward(&hidden, false);
        let p = probabilities(&logits);
        let mut dp = p;
        dp[label] -= 1.0;
        let mut grad = self
            .layers
            .iter()
            .map(|l| vec![0.0; l.weights.len()])
            .collect::<Vec<_>>();
        let dh = self.layers[4].backward(&hidden, &logits, &dp, false, &mut grad[4]);
        let dx = self.layers[3].backward(&x, &hidden, &dh, true, &mut grad[3]);
        let mut da = vec![0.0; EMBEDDING];
        let mut db = da.clone();
        for i in 0..EMBEDDING {
            da[i] = dx[i] + dx[EMBEDDING * 2 + i] + dx[EMBEDDING * 3 + i] * eb.vector[i];
            db[i] =
                dx[EMBEDDING + i] - dx[EMBEDDING * 2 + i] + dx[EMBEDDING * 3 + i] * ea.vector[i];
        }
        self.backward_encoding(a, &ea, &da, &mut grad);
        self.backward_encoding(b, &eb, &db, &mut grad);
        let max = logits.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let loss = max + logits.iter().map(|z| (z - max).exp()).sum::<f64>().ln() - logits[label];
        (loss, grad)
    }
}
fn probabilities(logits: &[f64]) -> [f64; CLASSES] {
    let max = logits.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let mut p = std::array::from_fn(|i| (logits[i] - max).exp());
    let sum = p.iter().sum::<f64>();
    for v in &mut p {
        *v /= sum;
    }
    p
}
pub struct Adam {
    m: Vec<Vec<f64>>,
    v: Vec<Vec<f64>>,
    step: i32,
}
impl Adam {
    pub fn new(model: &Model) -> Self {
        let m = model
            .layers
            .iter()
            .map(|l| vec![0.0; l.weights.len()])
            .collect::<Vec<_>>();
        Self {
            v: m.clone(),
            m,
            step: 0,
        }
    }
    pub fn update(&mut self, model: &mut Model, grad: &[Vec<f64>], rate: f64) {
        self.step += 1;
        for (l, g) in grad.iter().enumerate() {
            for (i, g) in g.iter().enumerate() {
                let g = g.clamp(-5.0, 5.0);
                self.m[l][i] = 0.9 * self.m[l][i] + 0.1 * g;
                self.v[l][i] = 0.999 * self.v[l][i] + 0.001 * g * g;
                model.layers[l].weights[i] -= rate
                    * (self.m[l][i] / (1.0 - 0.9_f64.powi(self.step)))
                    / ((self.v[l][i] / (1.0 - 0.999_f64.powi(self.step))).sqrt() + 1e-8);
            }
        }
    }
}
