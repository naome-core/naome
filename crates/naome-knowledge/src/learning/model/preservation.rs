//! Anchor-only CPL: attenuate the actual Adam proposal, never its raw gradient.
//! This signal is a local first-order heuristic; native promotion owns quality.
use super::{Policy, canonical_checkpoint};
use burn::{
    module::{Module, ModuleMapper, Param},
    optim::GradientsParams,
    store::ModuleRecord,
    tensor::{Bytes, Tensor},
};

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Default)]
pub(crate) enum Mode {
    #[default]
    Smoothed,
    #[cfg(test)]
    Unmasked,
    #[cfg(test)]
    Binary,
}
impl Mode {
    pub(super) fn enabled(self) -> bool {
        match self {
            Self::Smoothed => true,
            #[cfg(test)]
            Self::Binary => true,
            #[cfg(test)]
            Self::Unmasked => false,
        }
    }
}

pub(super) struct Preservation {
    ema: Policy,
    steps: u64,
}

#[derive(Default)]
struct Values(GradientsParams);
impl ModuleMapper for Values {
    fn map_float<const D: usize>(&mut self, param: Param<Tensor<D>>) -> Param<Tensor<D>> {
        self.0.register(param.id, param.val().inner());
        param
    }
}
impl Values {
    fn of(policy: &Policy) -> Self {
        let mut values = Self::default();
        drop(policy.clone().map(&mut values));
        values
    }
}

impl Preservation {
    pub fn fresh(policy: &Policy) -> Self {
        struct Zero;
        impl ModuleMapper for Zero {
            fn map_float<const D: usize>(&mut self, param: Param<Tensor<D>>) -> Param<Tensor<D>> {
                param.map(|v| Tensor::zeros(v.shape(), &v.device()))
            }
        }
        Self {
            ema: policy.clone().valid().map(&mut Zero),
            steps: 0,
        }
    }

    pub fn apply(
        &mut self,
        before: &Policy,
        proposed: Policy,
        gradient: &GradientsParams,
        mode: Mode,
    ) -> Result<Policy, String> {
        #[cfg(test)]
        if matches!(mode, Mode::Unmasked) {
            return Ok(proposed);
        }
        self.steps = self
            .steps
            .checked_add(1)
            .ok_or("preservation steps overflow")?;
        let mut update = Apply {
            before: Values::of(before),
            previous: Values::of(&self.ema),
            next: Values::default(),
            gradient,
            steps: self.steps,
            mode,
            error: None,
        };
        let policy = proposed.map(&mut update);
        if let Some(error) = update.error {
            return Err(error);
        }
        struct Restore(Values);
        impl ModuleMapper for Restore {
            fn map_float<const D: usize>(&mut self, param: Param<Tensor<D>>) -> Param<Tensor<D>> {
                let value = self.0.0.remove(param.id).expect("complete EMA traversal");
                param.map(|_| value)
            }
        }
        self.ema = self.ema.clone().map(&mut Restore(update.next));
        Ok(policy)
    }

    pub fn encode(&self, adam: Bytes) -> Result<Bytes, String> {
        let ema = self
            .ema
            .clone()
            .into_record()
            .into_bytes()
            .map_err(|e| e.to_string())?;
        let mut tensors = Vec::new();
        let mut metadata = Vec::new();
        let mut scalars = vec![(
            "preservation_steps".to_owned(),
            burn_pack::Scalar::from(self.steps),
        )];
        for (prefix, bytes) in [("adam/", adam), ("ema/", ema)] {
            let reader = burn_pack::Reader::from_bytes(bytes).map_err(|e| e.to_string())?;
            metadata.extend(
                reader
                    .metadata()
                    .iter()
                    .map(|(k, v)| (format!("{prefix}{k}"), v.clone())),
            );
            scalars.extend(
                reader
                    .scalars()
                    .iter()
                    .map(|(k, v)| (format!("{prefix}{k}"), *v)),
            );
            for mut tensor in reader.into_tensors().map_err(|e| e.to_string())? {
                tensor.name = format!("{prefix}{}", tensor.name);
                tensors.push(tensor);
            }
        }
        tensors.sort_by(|a, b| a.name.cmp(&b.name));
        let mut writer = burn_pack::Writer::new(tensors);
        for (key, value) in metadata {
            writer = writer.with_metadata(&key, &value);
        }
        for (key, value) in scalars {
            writer = writer.with_scalar(&key, value);
        }
        writer.into_bytes().map_err(|e| e.to_string())
    }

    pub fn decode(&mut self, bytes: Bytes, updates: u64) -> Result<Bytes, String> {
        let reader = burn_pack::Reader::from_bytes(bytes).map_err(|e| e.to_string())?;
        let steps = reader
            .scalars()
            .get("preservation_steps")
            .copied()
            .ok_or("missing preservation step count")?;
        let steps = u64::try_from(steps).map_err(|e| e.to_string())?;
        if steps > updates {
            return Err("preservation count exceeds actual updates".into());
        }
        // Module loading may restore source parameter IDs. Bind EMA explicitly
        // to the current policy's paths, shapes and IDs before loading it.
        let template = self
            .ema
            .clone()
            .into_record()
            .into_bytes()
            .map_err(|e| e.to_string())?;
        let mut expected: std::collections::BTreeMap<_, _> =
            burn_pack::Reader::from_bytes(template)
                .map_err(|e| e.to_string())?
                .into_tensors()
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|t| (t.name, (t.dtype, t.shape, t.param_id)))
                .collect();
        let prefixes = ["adam/", "ema/"];
        let mut tensors = [Vec::new(), Vec::new()];
        let mut metadata = [Vec::new(), Vec::new()];
        let mut scalars = [Vec::new(), Vec::new()];
        let group = |name: &str| {
            prefixes
                .iter()
                .position(|p| name.starts_with(p))
                .ok_or_else(|| "unknown optimizer memory field".to_owned())
        };
        for (key, value) in reader.metadata() {
            let i = group(key)?;
            metadata[i].push((key[prefixes[i].len()..].to_owned(), value.clone()));
        }
        for (key, value) in reader.scalars() {
            if key == "preservation_steps" {
                continue;
            }
            let i = group(key)?;
            scalars[i].push((key[prefixes[i].len()..].to_owned(), *value));
        }
        for mut tensor in reader.into_tensors().map_err(|e| e.to_string())? {
            let i = group(&tensor.name)?;
            tensor.name = tensor.name[prefixes[i].len()..].to_owned();
            if i == 1 {
                let descriptor = expected.remove(&tensor.name);
                if descriptor != Some((tensor.dtype, tensor.shape.clone(), tensor.param_id))
                    || tensor.dtype != burn_pack::DType::F32
                {
                    return Err("EMA parameter path, type, shape or identity differs".into());
                }
                for word in tensor
                    .to_bytes()
                    .map_err(|e| e.to_string())?
                    .chunks_exact(4)
                {
                    let value = f32::from_le_bytes(word.try_into().unwrap());
                    if !value.is_finite()
                        || !(0.0..=1.0).contains(&value)
                        || steps == 0 && value != 0.0
                    {
                        return Err("non-finite or unbounded preservation memory".into());
                    }
                }
            }
            tensors[i].push(tensor);
        }
        if !expected.is_empty() {
            return Err("incomplete preservation memory".into());
        }
        let mut parts = Vec::new();
        for i in 0..2 {
            let mut writer = burn_pack::Writer::new(std::mem::take(&mut tensors[i]));
            for (k, v) in &metadata[i] {
                writer = writer.with_metadata(k, v);
            }
            for (k, v) in &scalars[i] {
                writer = writer.with_scalar(k, *v);
            }
            parts.push(writer.into_bytes().map_err(|e| e.to_string())?);
        }
        self.ema = self
            .ema
            .clone()
            .try_load_record(
                ModuleRecord::from_bytes(parts.pop().unwrap()).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?
            .valid();
        self.steps = steps;
        canonical_checkpoint(parts.pop().unwrap())
    }
}

struct Apply<'a> {
    before: Values,
    previous: Values,
    next: Values,
    gradient: &'a GradientsParams,
    steps: u64,
    mode: Mode,
    error: Option<String>,
}
impl ModuleMapper for Apply<'_> {
    fn map_float<const D: usize>(&mut self, param: Param<Tensor<D>>) -> Param<Tensor<D>> {
        let id = param.id;
        let (Some(before), Some(previous)) = (self.before.0.remove(id), self.previous.0.remove(id))
        else {
            self.error = Some("preservation parameter identity differs".into());
            return param;
        };
        param.map(|proposed| {
            let require_grad = proposed.is_require_grad();
            let strategy = proposed.gradient_checkpointing_strategy();
            let delta = proposed.clone().inner() - before.clone();
            let gradient = self
                .gradient
                .get(id)
                .unwrap_or_else(|| Tensor::zeros(delta.shape(), &delta.device()));
            let (ema, coefficient) =
                attenuation(previous, gradient, delta.clone(), self.steps, self.mode);
            self.next.0.register(id, ema);
            let mut value = Tensor::from_inner(before + coefficient * delta);
            if let Some(strategy) = strategy {
                value = value.with_gradient_checkpointing_strategy(strategy);
            }
            if require_grad {
                value = value.require_grad();
            }
            value
        })
    }
}

fn attenuation<const D: usize>(
    previous: Tensor<D>,
    gradient: Tensor<D>,
    delta: Tensor<D>,
    steps: u64,
    mode: Mode,
) -> (Tensor<D>, Tensor<D>) {
    let permit = (gradient * delta).lower_equal_elem(0.).float();
    let beta: f64 = match mode {
        Mode::Smoothed => 0.9,
        #[cfg(test)]
        Mode::Binary => 0.,
        #[cfg(test)]
        Mode::Unmasked => unreachable!("unmasked proposals bypass attenuation"),
    };
    let ema = previous * beta + permit * (1. - beta);
    let correction = 1. - beta.powf(steps as f64);
    let coefficient = (ema.clone() / correction as f32).clamp(0., 1.);
    (ema, coefficient)
}
