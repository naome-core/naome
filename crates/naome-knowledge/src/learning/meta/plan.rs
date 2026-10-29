//! Bounded compositions of actual data and optimizer methods, not strategy IDs.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Phase {
    pub focused: bool,
    pub rehearsal: bool,
    /// 0, 1 or 2 quarters of the checked-action pairwise objective.
    pub ranking_quarters: u8,
    pub gentle_rate: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub phases: [Phase; 3],
}
impl Plan {
    pub fn balanced() -> Self {
        Self {
            phases: [Phase {
                focused: false,
                rehearsal: false,
                ranking_quarters: 0,
                gentle_rate: false,
            }; 3],
        }
    }
    pub fn targeted() -> Self {
        Self {
            phases: [Phase {
                focused: true,
                rehearsal: true,
                ranking_quarters: 0,
                gentle_rate: false,
            }; 3],
        }
    }
    pub fn mixture() -> Self {
        Self {
            phases: [
                Phase {
                    focused: false,
                    rehearsal: true,
                    ranking_quarters: 0,
                    gentle_rate: false,
                },
                Phase {
                    focused: true,
                    rehearsal: true,
                    ranking_quarters: 2,
                    gentle_rate: false,
                },
                Phase {
                    focused: false,
                    rehearsal: true,
                    ranking_quarters: 1,
                    gentle_rate: true,
                },
            ],
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.phases.iter().any(|p| p.ranking_quarters > 2) {
            return Err("meta plan objective bound".into());
        }
        Ok(())
    }
    pub fn phase(&self, unit: u32) -> Phase {
        self.phases[if unit < 8 {
            0
        } else if unit < 17 {
            1
        } else {
            2
        }]
    }
    pub fn random(seed: &mut u64) -> Self {
        let mut plan = Self::balanced();
        for phase in &mut plan.phases {
            let value = super::super::model::random(seed);
            phase.focused = value & 1 != 0;
            phase.rehearsal = value & 2 != 0;
            phase.ranking_quarters = ((value >> 2) % 3) as u8;
            phase.gentle_rate = value & 16 != 0;
        }
        plan
    }
    pub fn features(&self) -> [f32; 27] {
        let mut features = [0.; 27];
        for (i, p) in self.phases.iter().enumerate() {
            features[i * 9 + usize::from(p.focused)] = 1.;
            features[i * 9 + 2 + usize::from(p.rehearsal)] = 1.;
            features[i * 9 + 4 + usize::from(p.ranking_quarters)] = 1.;
            features[i * 9 + 7 + usize::from(p.gentle_rate)] = 1.;
        }
        features
    }
}
