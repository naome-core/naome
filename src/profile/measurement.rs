//! Positional scientific fields in the existing canonical envelope term grammar.
use super::Document;
use crate::wire::Term;
use anyhow::{Result, bail};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fields {
    gauge: String,
    positions: [i64; 2],
    mode: String,
    event: i64,
    unit: String,
    source: String,
}

fn signed(n: i64) -> Term {
    Term::Uint(((n as u64) << 1) ^ ((n >> 63) as u64))
}

fn from_signed(n: u64) -> i64 {
    ((n >> 1) as i64) ^ -((n & 1) as i64)
}

impl Fields {
    pub(super) fn encode(self, doc: &Document) -> Term {
        Term::Array(vec![
            Term::Text(doc.subject.clone()),
            Term::Text(doc.scope.clone()),
            Term::Text(self.gauge),
            Term::Array(self.positions.into_iter().map(signed).collect()),
            Term::Text(self.mode),
            signed(self.event),
            Term::Text(self.unit),
            Term::Text(self.source),
        ])
    }

    pub(super) fn decode(
        body: &Term,
    ) -> Result<(String, String, BTreeMap<String, serde_json::Value>)> {
        use Term::{Array, Text, Uint};
        let Array(items) = body else {
            bail!("expected paired measurement body")
        };
        let [
            Text(subject),
            Text(scope),
            Text(gauge),
            Array(positions),
            Text(mode),
            Uint(event),
            Text(unit),
            Text(source),
        ] = items.as_slice()
        else {
            bail!("invalid paired measurement fields");
        };
        let [Uint(first), Uint(second)] = positions.as_slice() else {
            bail!("expected two integer positions");
        };
        let fields = [
            ("gauge", gauge.clone().into()),
            (
                "positions",
                serde_json::json!([from_signed(*first), from_signed(*second)]),
            ),
            ("mode", mode.clone().into()),
            ("event", from_signed(*event).into()),
            ("unit", unit.clone().into()),
            ("source", source.clone().into()),
        ];
        Ok((
            subject.clone(),
            scope.clone(),
            fields
                .into_iter()
                .map(|(name, value)| (name.into(), value))
                .collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        profile::{Kind, MEASUREMENT_PROFILE, PUBLIC},
        wire::{Format, Id, Record},
    };

    #[test]
    fn paired_measurement_retains_both_signed_integer_extremes() -> Result<()> {
        let doc = Document::new(
            Kind::Occurrence,
            "sample",
            "transition",
            serde_json::json!({"gauge":"A","positions":[i64::MIN,i64::MAX],"mode":"axial","event":-1,"unit":"um","source":"fixture"}),
            Vec::new(),
        )?;
        let record = doc.encode(Id::blob(PUBLIC))?;
        assert_eq!(record.profile, Id::blob(MEASUREMENT_PROFILE));
        for format in [Format::A, Format::B] {
            let wire = record.encode(format);
            assert_eq!(Document::decode(&Record::decode(&wire, format)?)?, doc);
        }
        Ok(())
    }
}
