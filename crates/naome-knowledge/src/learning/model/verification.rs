//! Reject foreign tensor layouts before loading exchange artifacts into Burn.
use super::{Bytes, Module, Policy};
use burn_pack::{DType, Reader, Shape, Tensor};
use std::collections::BTreeMap;

pub(super) struct Descriptors(BTreeMap<u64, (String, Shape)>);

fn tensor_values(tensor: &Tensor, nonnegative: bool) -> Result<(), String> {
    for word in tensor
        .to_bytes()
        .map_err(|e| e.to_string())?
        .chunks_exact(4)
    {
        let value = f32::from_le_bytes(word.try_into().expect("f32 width"));
        if !value.is_finite() || nonnegative && value < 0.0 {
            return Err("non-finite model tensor or negative Adam second moment".into());
        }
    }
    Ok(())
}

pub(super) fn model(policy: &Policy, bytes: Bytes) -> Result<Descriptors, String> {
    let template = policy
        .clone()
        .into_record()
        .into_bytes()
        .map_err(|e| e.to_string())?;
    let template = Reader::from_bytes(template).map_err(|e| e.to_string())?;
    let reader = Reader::from_bytes(bytes).map_err(|e| e.to_string())?;
    if reader.metadata() != template.metadata() || reader.scalars() != template.scalars() {
        return Err("native model tensor metadata differs".into());
    }
    let mut expected: BTreeMap<_, _> = template
        .into_tensors()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|tensor| (tensor.name, (tensor.param_id, tensor.dtype, tensor.shape)))
        .collect();
    let mut descriptors = BTreeMap::new();
    for tensor in reader.into_tensors().map_err(|e| e.to_string())? {
        let id = tensor
            .param_id
            .ok_or("model tensor parameter identity missing")?;
        if tensor.dtype != DType::F32
            || expected.remove(&tensor.name) != Some((Some(id), tensor.dtype, tensor.shape.clone()))
        {
            return Err("model parameter identity, shape or type differs".into());
        }
        tensor_values(&tensor, false)?;
        descriptors.insert(id, (tensor.name, tensor.shape));
    }
    if !expected.is_empty() {
        return Err("model tensor parameters are incomplete".into());
    }
    Ok(Descriptors(descriptors))
}

pub(super) fn adam(descriptors: &Descriptors, bytes: Bytes, updates: u64) -> Result<(), String> {
    let reader = Reader::from_bytes(bytes).map_err(|e| e.to_string())?;
    for (field, value) in reader.scalars() {
        let (id, field) = field
            .split_once('.')
            .ok_or("Adam scalar parameter identity missing")?;
        let id = id.parse::<u64>().map_err(|e| e.to_string())?;
        let (_, shape) = descriptors
            .0
            .get(&id)
            .ok_or("Adam scalar parameter identity differs")?;
        let value = u64::try_from(*value).map_err(|e| e.to_string())?;
        if match field {
            "__rank" => value != shape.rank() as u64,
            // Burn casts this counter to i32 for the next bias correction.
            "momentum.time" => {
                value == 0
                    || value > updates
                    || value
                        > (i32::MAX as u64)
                            - u64::from(super::TRAINING_UNITS) * super::UPDATES_PER_UNIT
            }
            _ => true,
        } {
            return Err("Adam rank or update count differs".into());
        }
    }
    for (id, path) in reader.metadata() {
        let id = id.parse::<u64>().map_err(|e| e.to_string())?;
        if descriptors
            .0
            .get(&id)
            .is_none_or(|(expected, _)| path != expected)
        {
            return Err("Adam parameter path differs".into());
        }
    }
    for tensor in reader.into_tensors().map_err(|e| e.to_string())? {
        let id = tensor
            .param_id
            .ok_or("Adam tensor parameter identity missing")?;
        let (name, field) = tensor
            .name
            .split_once('.')
            .ok_or("Adam tensor field missing")?;
        let (_, shape) = descriptors
            .0
            .get(&id)
            .ok_or("Adam tensor parameter identity differs")?;
        if name != id.to_string()
            || !matches!(field, "momentum.moment_1" | "momentum.moment_2")
            || tensor.dtype != DType::F32
            || tensor.shape != *shape
        {
            return Err("Adam tensor parameter, shape or type differs".into());
        }
        tensor_values(&tensor, field == "momentum.moment_2")?;
    }
    Ok(())
}
