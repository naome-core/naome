//! Fail-closed prospective design admission, before any candidate model exists.
use super::*;

pub(super) struct Design {
    pub bank: Bank,
    pub identity: Value,
    pub bands: [[usize; 3]; 3],
    pub holdout: lineage::Holdout,
}
impl Design {
    pub fn read(bank_bytes: &[u8], calibration_bytes: &[u8]) -> Result<Self, String> {
        let result: Value = serde_json::from_slice(calibration_bytes).map_err(|e| e.to_string())?;
        if result["complete"] != true || result["feasible"] != true {
            return Err(format!(
                "reference calibration does not admit a trajectory: {}",
                result["reason"]
            ));
        }
        let rates: [[f64; 6]; 3] =
            serde_json::from_value(result["rates"].clone()).map_err(|e| e.to_string())?;
        let bands = calibration::bands(&rates)?;
        if result["bands"] != json!(bands)
            || result["assessment_model_calls"] != 0
            || result["candidate_optimizer_updates"] != 0
        {
            return Err("calibration selection or independence differs".into());
        }
        let bank: Bank = serde_json::from_slice(bank_bytes).map_err(|e| e.to_string())?;
        let mut prior_families = BTreeSet::new();
        let mut prior_roots = BTreeSet::new();
        let mut prior_ids = BTreeSet::new();
        for (rows, families_per_cell) in [
            (&bank.acquisition, 8),
            (&bank.calibration, 6),
            (&bank.assessment, 12),
            (&bank.pilot, 6),
        ] {
            let mut families = BTreeSet::new();
            let mut roots = BTreeSet::new();
            let mut ids = BTreeSet::new();
            let mut cells: BTreeMap<(usize, usize), BTreeMap<&str, usize>> = BTreeMap::new();
            for case in rows {
                if case.track >= 3 || !(1..=6).contains(&case.recipe) || case.variant > 1 {
                    return Err("capability cell or variant differs".into());
                }
                let q = CompiledQuestion::compile(&case.source).map_err(|e| e.to_string())?;
                if case.family != curriculum::owned::family(q.proved_target())
                    || case.resolution != crate::hex(q.resolution_id())
                    || case.construction != lineage::normalized_family(&q)
                    || !ids.insert(case.resolution.clone())
                {
                    return Err("capability question identity or construction differs".into());
                }
                families.insert(case.family.clone());
                roots.insert(case.construction.clone());
                *cells
                    .entry((case.track, case.recipe))
                    .or_default()
                    .entry(&case.construction)
                    .or_default() += 1;
            }
            if cells.len() != 18
                || cells.values().any(|groups| {
                    groups.len() != families_per_cell || groups.values().any(|count| *count != 2)
                })
                || !families.is_disjoint(&prior_families)
                || !roots.is_disjoint(&prior_roots)
                || !ids.is_disjoint(&prior_ids)
            {
                return Err("whole source families cross a split or lack coverage".into());
            }
            prior_families.extend(families);
            prior_roots.extend(roots);
            prior_ids.extend(ids);
        }
        let expected = bank
            .calibration
            .iter()
            .map(|c| (c.resolution.clone(), c))
            .collect::<BTreeMap<_, _>>();
        let mut counts = [[[0u32; 2]; 6]; 3];
        let mut observed = BTreeSet::new();
        for row in result["rows"].as_array().ok_or("calibration rows absent")? {
            let reference = row["reference"]
                .as_u64()
                .ok_or("reference identity absent")?;
            let case: Case =
                serde_json::from_value(row["case"].clone()).map_err(|e| e.to_string())?;
            if reference > 1
                || !observed.insert((reference, case.resolution.clone()))
                || expected
                    .get(&case.resolution)
                    .is_none_or(|original| digest(*original) != digest(&case))
            {
                return Err("calibration rows lack their exact separate source".into());
            }
            let solved = row["solved"]
                .as_bool()
                .ok_or("calibration outcome absent")?;
            counts[case.track][case.recipe - 1][0] += u32::from(solved);
            counts[case.track][case.recipe - 1][1] += 1;
        }
        for (track, cells) in counts.iter().enumerate() {
            for (recipe, [successes, count]) in cells.iter().enumerate() {
                if *count != 24 || rates[track][recipe] != f64::from(*successes) / f64::from(*count)
                {
                    return Err(
                        "calibration rates do not equal complete paired reference observations"
                            .into(),
                    );
                }
            }
        }
        let excluded = bank.calibration.iter().chain(&bank.assessment).chain(&bank.pilot).map(|c|
            json!({"source":c.source,"resolution":c.resolution,"family":c.family,"lineage":c.construction})).collect::<Vec<_>>();
        let bytes = serde_json::to_vec(&json!({"cases":excluded})).map_err(|e| e.to_string())?;
        let holdout = lineage::Holdout::read(&bytes, &crate::hex(&Sha256::digest(&bytes)))?;
        Ok(Self {
            identity: json!({"protocol_sha256":crate::hex(&Sha256::digest(PROTOCOL.as_bytes())),
                "bank_sha256":crate::hex(&Sha256::digest(bank_bytes)),
                "calibration_sha256":crate::hex(&Sha256::digest(calibration_bytes))}),
            bank,
            bands,
            holdout,
        })
    }
}
