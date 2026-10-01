//! Independent calendar allowances with admission-window settlement.

use chrono::{DateTime, Duration, LocalResult, NaiveDateTime, TimeZone, Timelike, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Period {
    Hour,
    Day,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Allowance {
    pub amount: u64,
    pub period: Period,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Budgets {
    pub timezone: String,
    pub research: Allowance,
    pub discoveries: Allowance,
    pub evaluations: Allowance,
}
impl Budgets {
    pub fn validate(&self) -> Result<(), String> {
        self.timezone
            .parse::<Tz>()
            .map_err(|_| "unknown IANA budget timezone".to_owned())?;
        Ok(())
    }
    pub fn allowance(&self, phase: Phase) -> Allowance {
        match phase {
            Phase::Solve => self.research,
            Phase::Discover => self.discoveries,
            Phase::Evaluate => self.evaluations,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Discover,
    Evaluate,
    Solve,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Window {
    pub start: i64,
    pub end: i64,
}

/// UTC instants identify calendar windows, including both fallback-hour folds.
pub fn window(now: i64, timezone: &str, period: Period) -> Result<Window, String> {
    let zone: Tz = timezone
        .parse()
        .map_err(|_| "unknown IANA budget timezone")?;
    let utc = DateTime::<Utc>::from_timestamp(now, 0).ok_or("clock outside supported calendar")?;
    let local = utc.with_timezone(&zone);
    let floor = match period {
        Period::Hour => local.date_naive().and_hms_opt(local.hour(), 0, 0),
        Period::Day => local.date_naive().and_hms_opt(0, 0, 0),
    }
    .ok_or("calendar boundary invalid")?;
    let step = match period {
        Period::Hour => Duration::hours(1),
        Period::Day => Duration::days(1),
    };
    // A timezone gap can eliminate a local boundary. Examine adjacent boundary
    // labels without assuming every civil day contains 24 hours.
    let mut start = None;
    let mut end = None;
    for offset in -48..=48 {
        let Some(label) = floor.checked_add_signed(step * offset) else {
            continue;
        };
        for candidate in boundary_instants(zone, label)? {
            if candidate <= now {
                start = Some(start.map_or(candidate, |s: i64| s.max(candidate)));
            } else {
                end = Some(end.map_or(candidate, |e: i64| e.min(candidate)));
            }
        }
    }
    Ok(Window {
        start: start.ok_or("calendar window start unavailable")?,
        end: end.ok_or("calendar window end unavailable")?,
    })
}

fn boundary_instants(zone: Tz, label: NaiveDateTime) -> Result<Vec<i64>, String> {
    Ok(match zone.from_local_datetime(&label) {
        LocalResult::Single(t) => vec![t.timestamp()],
        LocalResult::Ambiguous(a, b) => vec![a.timestamp(), b.timestamp()],
        LocalResult::None => vec![],
    })
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Bucket {
    pub window: Window,
    pub used: u64,
}
impl Bucket {
    pub fn new(window: Window) -> Self {
        Self { window, used: 0 }
    }
    pub fn renew(&mut self, next: Window) -> Result<(), String> {
        if next.start < self.window.start {
            return Err("budget window rollback".into());
        }
        if next.start > self.window.start {
            self.window = next;
            self.used = 0;
        } else if next != self.window {
            return Err("timezone window contract changed".into());
        }
        Ok(())
    }
    pub fn available(&self, allocation: Allowance) -> bool {
        self.used < allocation.amount
    }
    pub fn charge(&mut self, amount: u64) -> Result<(), String> {
        self.used = self
            .used
            .checked_add(amount)
            .ok_or("budget accounting overflow")?;
        Ok(())
    }
}

/// The final cumulative usage of one fresh ephemeral thread. Subcounts are
/// validated but never added to their already inclusive parent totals.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub input: u64,
    pub output: u64,
    pub total: u64,
    pub cached: u64,
    pub reasoning: u64,
}
impl Usage {
    pub fn from_complete_provider(value: &Value) -> Result<Self, String> {
        if value["complete"] != true {
            return Err("provider accounting completeness unavailable".into());
        }
        let responses = value["responseUsage"]
            .as_array()
            .filter(|r| !r.is_empty() && r.len() <= 4096)
            .ok_or("upstream completion accounting unavailable")?;
        let mut seen = std::collections::BTreeMap::new();
        let mut sum = Self {
            input: 0,
            output: 0,
            total: 0,
            cached: 0,
            reasoning: 0,
        };
        for response in responses {
            let id = response["responseId"]
                .as_str()
                .filter(|id| !id.is_empty() && id.len() <= 256)
                .ok_or("invalid upstream response identity")?;
            let usage = Self::from_provider(&serde_json::json!({"total":response}))?;
            if let Some(previous) = seen.insert(id, usage) {
                if previous != usage {
                    return Err("conflicting upstream usage duplicate".into());
                }
                continue;
            }
            sum.input = sum.input.checked_add(usage.input).ok_or("usage overflow")?;
            sum.output = sum
                .output
                .checked_add(usage.output)
                .ok_or("usage overflow")?;
            sum.total = sum.total.checked_add(usage.total).ok_or("usage overflow")?;
            sum.cached = sum
                .cached
                .checked_add(usage.cached)
                .ok_or("usage overflow")?;
            sum.reasoning = sum
                .reasoning
                .checked_add(usage.reasoning)
                .ok_or("usage overflow")?;
        }
        if Self::from_provider(value)? != sum {
            return Err("incomplete cumulative token usage".into());
        }
        Ok(sum)
    }
    pub fn from_provider(value: &Value) -> Result<Self, String> {
        let v = &value["total"];
        let integer = |field: &str| {
            v[field]
                .as_u64()
                .ok_or_else(|| format!("missing or invalid cumulative {field}"))
        };
        let input = integer("inputTokens")?;
        let output = integer("outputTokens")?;
        let total = integer("totalTokens")?;
        let optional = |field: &str| -> Result<u64, String> {
            match v.get(field) {
                None => Ok(0),
                Some(v) => v.as_u64().ok_or_else(|| format!("invalid {field}")),
            }
        };
        let cached = optional("cachedInputTokens")?;
        let reasoning = optional("reasoningOutputTokens")?;
        if input.checked_add(output) != Some(total) || cached > input || reasoning > output {
            return Err("inconsistent cumulative provider token usage".into());
        }
        Ok(Self {
            input,
            output,
            total,
            cached,
            reasoning,
        })
    }
    pub fn follows(&self, previous: &Self) -> bool {
        self.input >= previous.input
            && self.output >= previous.output
            && self.total >= previous.total
            && self.cached >= previous.cached
            && self.reasoning >= previous.reasoning
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn utc(value: &str) -> i64 {
        DateTime::parse_from_rfc3339(value).unwrap().timestamp()
    }
    #[test]
    fn berlin_calendar_days_and_repeated_hours_have_distinct_utc_keys() {
        let spring = window(utc("2026-03-29T12:00:00Z"), "Europe/Berlin", Period::Day).unwrap();
        assert_eq!(spring.end - spring.start, 23 * 3600);
        let autumn = window(utc("2026-10-25T12:00:00Z"), "Europe/Berlin", Period::Day).unwrap();
        assert_eq!(autumn.end - autumn.start, 25 * 3600);
        let first = window(utc("2026-10-25T00:30:00Z"), "Europe/Berlin", Period::Hour).unwrap();
        let second = window(utc("2026-10-25T01:30:00Z"), "Europe/Berlin", Period::Hour).unwrap();
        assert_eq!(first.end, second.start);
        assert_ne!(first.start, second.start);
        assert_eq!(second.end - second.start, 3600);
    }
    #[test]
    fn renew_discards_unused_allocation_and_refuses_rollback() {
        let mut bucket = Bucket::new(Window {
            start: 0,
            end: 3600,
        });
        bucket.charge(12).unwrap();
        assert!(!bucket.available(Allowance {
            amount: 10,
            period: Period::Hour
        }));
        bucket
            .renew(Window {
                start: 3600,
                end: 7200,
            })
            .unwrap();
        assert_eq!(bucket.used, 0);
        assert!(
            bucket
                .renew(Window {
                    start: 0,
                    end: 3600
                })
                .is_err()
        );
    }
    #[test]
    fn total_usage_includes_all_responses_without_subcount_or_event_double_charging() {
        let usage=Usage::from_provider(&serde_json::json!({"last":{"totalTokens":14},"total":{"inputTokens":30,"outputTokens":8,"totalTokens":38,"cachedInputTokens":20,"reasoningOutputTokens":4}})).unwrap();
        assert_eq!(usage.total, 38);
        assert!(Usage::from_provider(&Value::Null).is_err());
        assert!(
            Usage::from_provider(
                &serde_json::json!({"total":{"inputTokens":10,"outputTokens":4,"totalTokens":15}})
            )
            .is_err()
        );
        assert!(usage.follows(&usage));
        assert!(!Usage { total: 37, ..usage }.follows(&usage));
    }
    #[test]
    fn malformed_numbers_subsets_and_overflows_never_become_known_usage() {
        let valid = serde_json::json!({"total":{"inputTokens":10,"outputTokens":4,"totalTokens":14,"cachedInputTokens":3,"reasoningOutputTokens":2}});
        for (field, bad) in [
            ("inputTokens", serde_json::json!(-1)),
            ("outputTokens", serde_json::json!(1.5)),
            ("totalTokens", serde_json::json!("14")),
            ("inputTokens", Value::Null),
            ("cachedInputTokens", serde_json::json!(11)),
            ("reasoningOutputTokens", serde_json::json!(5)),
            ("cachedInputTokens", serde_json::json!(-1)),
        ] {
            let mut malformed = valid.clone();
            malformed["total"][field] = bad;
            assert!(Usage::from_provider(&malformed).is_err(), "{field}");
        }
        assert!(Usage::from_provider(&serde_json::json!({"total":{"inputTokens":u64::MAX,"outputTokens":1,"totalTokens":0}})).is_err());
    }
    #[test]
    fn complete_response_ledger_deduplicates_identical_ids_and_rejects_conflicts() {
        let first = serde_json::json!({"responseId":"first","inputTokens":5,"outputTokens":2,"totalTokens":7,"cachedInputTokens":3,"reasoningOutputTokens":1});
        let second = serde_json::json!({"responseId":"second","inputTokens":4,"outputTokens":1,"totalTokens":5,"cachedInputTokens":2,"reasoningOutputTokens":0});
        let value = serde_json::json!({"complete":true,"total":{"inputTokens":9,"outputTokens":3,"totalTokens":12,"cachedInputTokens":5,"reasoningOutputTokens":1},"responseUsage":[first.clone(),second,first]});
        let usage = Usage::from_complete_provider(&value).unwrap();
        assert_eq!(usage.total, 12);
        assert_eq!(usage.cached, 5);
        let mut conflicting = value.clone();
        conflicting["responseUsage"][2]["cachedInputTokens"] = serde_json::json!(2);
        assert!(Usage::from_complete_provider(&conflicting).is_err());
        let mut omitted = value.clone();
        omitted["responseUsage"].as_array_mut().unwrap().remove(1);
        assert!(Usage::from_complete_provider(&omitted).is_err());
        let mut missing = value.clone();
        missing["responseUsage"][1]
            .as_object_mut()
            .unwrap()
            .remove("outputTokens");
        assert!(Usage::from_complete_provider(&missing).is_err());
        let mut stale = value;
        stale["complete"] = serde_json::json!(false);
        assert!(Usage::from_complete_provider(&stale).is_err());
    }
}
