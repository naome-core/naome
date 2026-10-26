//! Compact private model frames stay inside the existing supervisor line bound.
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};

pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error> {
    bytes
        .as_ref()
        .map(|value| crate::hex(value))
        .serialize(serializer)
}
pub fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<u8>>, D::Error> {
    let encoded = Option::<String>::deserialize(deserializer)?;
    encoded
        .map(|value| {
            if value.len() % 2 != 0
                || value.len() > 4 * crate::resources::limits().native_model_chunk_bytes
            {
                return Err(D::Error::custom("native model frame byte capacity"));
            }
            fn digit(value: u8) -> Option<u8> {
                match value {
                    b'0'..=b'9' => Some(value - b'0'),
                    b'a'..=b'f' => Some(value - b'a' + 10),
                    _ => None,
                }
            }
            value
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    digit(pair[0])
                        .zip(digit(pair[1]))
                        .map(|(high, low)| high * 16 + low)
                        .ok_or_else(|| D::Error::custom("native model frame encoding"))
                })
                .collect()
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn full_model_pair_fits_the_original_frame_and_parent_response_bounds() {
        let bytes = vec![255; 2 * crate::resources::limits().native_model_chunk_bytes];
        let frame = Frame::Model {
            id: 1,
            unit: 1,
            blob: crate::learning::Blob::of(&bytes),
            range: 0..2,
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
