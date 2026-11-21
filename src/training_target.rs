use crate::profile::{Document, Kind};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TrainingTarget {
    Quantity {
        ticks: i64,
        scale: u8,
        unit: String,
    },
    Interval {
        lower: i64,
        upper: i64,
        scale: u8,
        unit: String,
        interpretation: IntervalMeaning,
    },
    TimeToEvent {
        time: u64,
        unit: String,
        status: EventStatus,
    },
    Readings {
        variants: Vec<Reading>,
    },
    Missing {
        reason: MissingReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IntervalMeaning {
    AbsoluteBound,
    Confidence { level_ppm: u32 },
    Credible { level_ppm: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventStatus {
    Event,
    RightCensored,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingReason {
    NotSampled,
    Unavailable,
    Withdrawn,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reading {
    pub id: String,
    pub text: String,
    pub selector: String,
}

impl TrainingTarget {
    pub(crate) fn check(&self, profile: &Document, outcome: &Document) -> Result<()> {
        ensure!(
            profile.kind == Kind::Profile
                && profile.scope == "training-target-1"
                && outcome.kind == Kind::Occurrence,
            "unsupported target profile or evidence kind"
        );
        let expected: String = profile.field("target_type")?;
        let actual = match self {
            Self::Quantity { scale, unit, .. } => {
                ensure!(
                    *scale <= 18 && !unit.is_empty() && *unit == profile.field::<String>("unit")?,
                    "quantity grid or unit mismatch"
                );
                "quantity"
            }
            Self::Interval {
                lower,
                upper,
                scale,
                unit,
                interpretation,
            } => {
                ensure!(
                    lower <= upper
                        && *scale <= 18
                        && !unit.is_empty()
                        && *unit == profile.field::<String>("unit")?,
                    "invalid interval or unit"
                );
                let meaning = match interpretation {
                    IntervalMeaning::AbsoluteBound => "absolute_bound",
                    IntervalMeaning::Confidence { level_ppm }
                    | IntervalMeaning::Credible { level_ppm } => {
                        ensure!((1..1_000_000).contains(level_ppm), "invalid interval level");
                        if matches!(interpretation, IntervalMeaning::Confidence { .. }) {
                            "confidence"
                        } else {
                            "credible"
                        }
                    }
                };
                ensure!(
                    meaning == profile.field::<String>("interval_meaning")?,
                    "interval interpretation differs from profile"
                );
                "interval"
            }
            Self::TimeToEvent { unit, .. } => {
                ensure!(
                    !unit.is_empty() && *unit == profile.field::<String>("unit")?,
                    "time unit differs from profile"
                );
                "time_to_event"
            }
            Self::Readings { variants } => {
                let ids: BTreeSet<_> = variants.iter().map(|r| r.id.as_str()).collect();
                let sources: BTreeSet<_> = outcome
                    .inputs
                    .iter()
                    .filter(|e| e.role == "variant-source")
                    .map(|e| e.qualifier.as_str())
                    .collect();
                ensure!(
                    !ids.is_empty()
                        && ids.len() == variants.len()
                        && ids == sources
                        && variants.iter().all(|v| !v.id.trim().is_empty()
                            && !v.text.trim().is_empty()
                            && !v.selector.trim().is_empty()),
                    "each reading needs a unique identifier, source and selector"
                );
                "readings"
            }
            Self::Missing { .. } => {
                ensure!(
                    ["quantity", "interval", "time_to_event", "readings"]
                        .contains(&expected.as_str()),
                    "unknown missing target type"
                );
                return Ok(());
            }
        };
        ensure!(actual == expected, "target shape differs from profile");
        Ok(())
    }
}
