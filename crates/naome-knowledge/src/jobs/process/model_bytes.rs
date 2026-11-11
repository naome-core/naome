//! Compact private model frames stay inside the existing supervisor line bound.
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};

pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error> {
    bytes
        .as_ref()
        .map(|value| STANDARD_NO_PAD.encode(value))
        .serialize(serializer)
}

pub fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<u8>>, D::Error> {
    let encoded = Option::<&str>::deserialize(deserializer)?;
    encoded
        .map(|value| {
            // Three binary chunks encode to at most four chunk widths,
            // exactly the previous payload ceiling.
            if value.len() > 4 * crate::resources::limits().native_model_chunk_bytes {
                return Err(D::Error::custom("native model frame byte capacity"));
            }
            STANDARD_NO_PAD
                .decode(value)
                .map_err(|_| D::Error::custom("native model frame encoding"))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn measured_development_profiles_roundtrip_through_the_real_supervisor_frame() {
        let progress = crate::learning::tests::measured_progress();
        let expected = serde_json::to_value(&progress).unwrap();
        let encoded = serde_json::to_vec(&Frame::Learning {
            id: 1,
            unit: 26,
            progress: Box::new(progress),
        })
        .unwrap();
        let Frame::Learning { progress, .. } = serde_json::from_slice::<Frame>(&encoded).unwrap()
        else {
            panic!("learning frame")
        };
        assert_eq!(serde_json::to_value(progress).unwrap(), expected);
    }

    #[test]
    fn full_model_group_fits_the_original_frame_and_parent_response_bounds() {
        let bytes = vec![255; 3 * crate::resources::limits().native_model_chunk_bytes];
        let frame = Frame::Model {
            id: 1,
            unit: 1,
            blob: crate::learning::Blob::of(&bytes),
            range: 0..3,
            bytes: Some(bytes.clone()),
        };
        let encoded = serde_json::to_vec(&frame).unwrap();
        assert!(encoded.len() + 1 < max_frame_bytes());
        let Frame::Model {
            bytes: restored, ..
        } = serde_json::from_slice(&encoded).unwrap()
        else {
            panic!("model frame")
        };
        assert_eq!(restored.unwrap(), bytes);
        let encoded = serde_json::to_vec(&Grant {
            id: 1,
            next: 1,
            data: Some(bytes.clone()),
        })
        .unwrap();
        assert!(encoded.len() + 1 < crate::resources::limits().native_model_chunk_bytes * 5 + 1024);
        let restored: Grant = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(restored.data.unwrap(), bytes);
    }
}
