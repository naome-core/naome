//! Deterministic exploration order for the installed policy coordinate space.
use super::Span;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Subset {
    pub spans: Vec<Span>,
    pub changed: u32,
    pub checked: u32,
}

pub(super) fn rank(
    mask: &Subset,
    gains: u32,
    protected: u32,
) -> (bool, u32, u32, std::cmp::Reverse<u32>) {
    rank_checked(mask.checked, mask.changed, gains, protected)
}

fn rank_checked(
    checked: u32,
    changed: u32,
    gains: u32,
    protected: u32,
) -> (bool, u32, u32, std::cmp::Reverse<u32>) {
    (
        checked & protected == protected && checked & gains != 0,
        (checked & gains).count_ones(),
        (checked & protected).count_ones(),
        std::cmp::Reverse(changed),
    )
}

/// Verify the candidate only while it can still outrank the current selection.
/// An unvisited case counts as a success solely for this upper bound.
pub(super) fn screen(
    incumbent: &Subset,
    changed: u32,
    gains: u32,
    protected: u32,
    mut check: impl FnMut(usize) -> Result<(bool, u8), crate::Error>,
) -> Result<(u32, u32), crate::Error> {
    let best = rank(incumbent, gains, protected);
    let mut remaining = gains | protected;
    let mut checked = 0;
    let mut paid = 0;
    while remaining != 0 && rank_checked(checked | remaining, changed, gains, protected) > best {
        // Prioritize capabilities the best update has not yet retained.
        let missing = remaining & protected & !incumbent.checked;
        let next = if missing != 0 { missing } else { remaining };
        let index = next.trailing_zeros();
        let bit = 1 << index;
        let (solved, expansions) = check(index as usize)?;
        if solved {
            checked |= bit;
        }
        remaining &= !bit;
        paid += u32::from(expansions);
    }
    Ok((checked, paid))
}

pub(super) fn intervention(
    round: usize,
    modules: &[Span],
    best: &Subset,
    gained: u32,
) -> Vec<Span> {
    let count = modules.len();
    let full = Span {
        start: 0,
        end: modules.last().expect("policy parameters").end,
    };
    if round < count {
        return vec![modules[round]];
    }
    if round < 2 * count {
        return subtract(&[full], modules[round - count]);
    }
    let step = round - 2 * count;
    if best.checked & gained != 0 {
        let first = best.spans.first().expect("checked intervention").start;
        let last = best.spans.last().expect("checked intervention").end;
        if let Some(&module) = modules
            .iter()
            .find(|span| span.start <= first && span.end >= last)
        {
            if step < 14 {
                // Isolate every half, quarter and eighth of the same promising
                // module. Each candidate gets independent checked outcomes.
                let (parts, position) = match step {
                    0..=1 => (2, step),
                    2..=5 => (4, step - 2),
                    _ => (8, step - 6),
                };
                return partition(module, parts, position);
            }
            let width = last - first;
            if step < 16 {
                return partition(
                    Span {
                        start: first,
                        end: last,
                    },
                    2,
                    step - 14,
                );
            }
            let point = first + (step as u32 - 16) * (width - 1) / 2;
            return vec![Span {
                start: point,
                end: point + 1,
            }];
        }
    }
    // Cross-module combinations allow effects which require joint changes.
    let pairs = (0..count)
        .flat_map(|a| (a + 1..count).map(move |b| (a, b)))
        .collect::<Vec<_>>();
    let (a, b) = pairs[step % pairs.len()];
    vec![modules[a], modules[b]]
}

fn partition(span: Span, parts: usize, position: usize) -> Vec<Span> {
    let width = span.end - span.start;
    let start = span.start + position as u32 * width / parts as u32;
    let end = span.start + (position + 1) as u32 * width / parts as u32;
    if start == end {
        Vec::new()
    } else {
        vec![Span { start, end }]
    }
}

pub(super) fn subtract(spans: &[Span], cut: Span) -> Vec<Span> {
    let mut remaining = Vec::new();
    for span in spans {
        if cut.end <= span.start || span.end <= cut.start {
            remaining.push(*span);
        } else {
            if span.start < cut.start {
                remaining.push(Span {
                    start: span.start,
                    end: cut.start,
                });
            }
            if cut.end < span.end {
                remaining.push(Span {
                    start: cut.end,
                    end: span.end,
                });
            }
        }
    }
    remaining
}
