//! Lossless working-state encoding. Full named experiences remain in their
//! original owned trial records; this representation retains every field.
use super::*;

#[derive(Serialize, Deserialize)]
struct Packed(
    u64,
    [u16; CONTEXT],
    [u8; 3],
    String,
    String,
    Option<String>,
    u64,
    [u16; 2],
    [bool; 2],
    [u64; 2],
);
impl From<&Experience> for Packed {
    fn from(e: &Experience) -> Self {
        Self(
            e.job,
            e.context,
            e.plan.phases.map(|p| {
                u8::from(p.focused)
                    | u8::from(p.rehearsal) << 1
                    | p.ranking_quarters << 2
                    | u8::from(p.gentle_rate) << 4
            }),
            e.source_model.clone(),
            e.selected_model.clone(),
            e.candidate_model.clone(),
            e.source_epoch,
            [e.before, e.after],
            [e.protected_loss, e.anchor_loss],
            [e.lower_cpu_micros, e.lower_wall_micros],
        )
    }
}
impl TryFrom<Packed> for Experience {
    type Error = String;
    fn try_from(p: Packed) -> Result<Self, Self::Error> {
        if p.2.iter().any(|v| *v > 31 || (v >> 2) & 3 > 2) {
            return Err("meta memory phase encoding differs".into());
        }
        let experience = Self {
            job: p.0,
            context: p.1,
            plan: Plan {
                phases: p.2.map(|v| Phase {
                    focused: v & 1 != 0,
                    rehearsal: v & 2 != 0,
                    ranking_quarters: (v >> 2) & 3,
                    gentle_rate: v & 16 != 0,
                }),
            },
            source_model: p.3,
            selected_model: p.4,
            candidate_model: p.5,
            source_epoch: p.6,
            before: p.7[0],
            after: p.7[1],
            protected_loss: p.8[0],
            anchor_loss: p.8[1],
            lower_cpu_micros: p.9[0],
            lower_wall_micros: p.9[1],
        };
        experience.validate()?;
        Ok(experience)
    }
}
pub(super) fn serialize<S: serde::Serializer>(
    memory: &[Experience],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    memory
        .iter()
        .map(Packed::from)
        .collect::<Vec<_>>()
        .serialize(serializer)
}
pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<Experience>, D::Error> {
    let packed = Vec::<Packed>::deserialize(deserializer)?;
    if packed.len() > MEMORY {
        return Err(serde::de::Error::custom("meta memory capacity"));
    }
    packed
        .into_iter()
        .map(|p| p.try_into().map_err(serde::de::Error::custom))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_experience_roundtrips_and_noncanonical_phases_fail_closed() {
        for value in 0..32u8 {
            let p = Packed(
                u64::MAX,
                [1000; CONTEXT],
                [value; 3],
                "11".repeat(32),
                "22".repeat(32),
                Some("33".repeat(32)),
                u64::MAX,
                [120, 0],
                [true, false],
                [u64::MAX, u64::MAX],
            );
            let bytes = serde_json::to_vec(&p).unwrap();
            let decoded = Experience::try_from(p);
            if (value >> 2) & 3 == 3 {
                assert!(decoded.is_err());
            } else {
                let experience = decoded.unwrap();
                assert_eq!(
                    serde_json::to_vec(&Packed::from(&experience)).unwrap(),
                    bytes
                );
                let named = serde_json::to_vec(&experience).unwrap();
                let restored: Experience = serde_json::from_slice(&named).unwrap();
                assert_eq!(serde_json::to_vec(&restored).unwrap(), named);
            }
        }
        let mut invalid = serde_json::to_value(Packed(
            1,
            [0; CONTEXT],
            [0; 3],
            "11".repeat(32),
            "22".repeat(32),
            None,
            0,
            [0, 0],
            [false, false],
            [0, 0],
        ))
        .unwrap();
        invalid[2][0] = 32.into();
        assert!(Experience::try_from(serde_json::from_value::<Packed>(invalid).unwrap()).is_err());
    }
}
