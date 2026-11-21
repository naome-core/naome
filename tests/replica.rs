use anyhow::Result;
use naome_protocol::{
    evaluation::{Standing, assess},
    fixture,
    profile::{self, PUBLIC, READ_ONLY},
    store::{
        Archive, Packet, Snapshot,
        sharing::{MAX_MEMBER_BYTES, MAX_MEMBERS, Replica},
    },
    wire::{Format, Id},
};

fn replica(source: &Archive, s: &Snapshot) -> Result<Replica> {
    let mut replica = Replica::new(s.id()?, s.clone())?;
    for packet in source.export(s, "read")?.packets {
        replica.accept(packet.id, packet)?;
    }
    Ok(replica)
}

#[test]
fn only_released_readable_members_are_served_and_mirrors_preserve_rights() -> Result<()> {
    let source = Archive::memory()?;
    let dest = Archive::memory()?;
    let id = source.blob(b"read-only specimen", Id::blob(READ_ONLY))?;
    let s = source.snapshot("lab", Default::default())?;
    let head = s.id()?;
    assert!(source.released_member(head, id).is_err());
    source.release(head)?;
    let outside = source.blob(b"not released", Id::blob(PUBLIC))?;
    assert!(source.released_member(head, outside).is_err());
    assert_eq!(replica(&source, &s)?.commit(&dest)?, head);
    assert_eq!(dest.released_member(head, id)?.access, Id::blob(READ_ONLY));
    assert!(dest.resolve(&s, id, "train").is_err());
    dest.withdraw(id)?;
    assert!(!dest.releases()?.contains(&head));
    assert!(dest.observed_releases()?.contains(&head));
    assert_eq!(dest.head(head)?, s);
    assert!(dest.released_member(head, id).is_err());
    assert!(replica(&source, &s)?.commit(&dest).is_err());
    assert!(dest.resolve(&s, id, "read").is_err());

    let denied = source.blob(br#"{"purposes":[],"version":1}"#, Id::blob(PUBLIC))?;
    source.blob(b"withheld", denied)?;
    let private = source.snapshot("restricted", [head].into())?.id()?;
    assert!(source.release(private).is_err());
    assert!(source.released_manifest(private).is_err());
    Ok(())
}

#[test]
fn frames_must_match_the_requested_identity_and_inventory_before_commit() -> Result<()> {
    let source = Archive::memory()?;
    let dest = Archive::memory()?;
    let public = Id::blob(PUBLIC);
    let id = source.blob(b"measurement", public)?;
    let s = source.snapshot("lab", Default::default())?;
    let head = s.id()?;
    source.release(head)?;
    assert!(Replica::new(public, s.clone()).is_err());
    let mut partial = Replica::new(head, s.clone())?;
    assert!(
        partial
            .accept(public, source.released_member(head, id)?)
            .is_err()
    );
    assert!(
        partial
            .accept(
                id,
                Packet {
                    id,
                    access: public,
                    hex: "ff".into()
                }
            )
            .is_err()
    );
    assert!(
        partial
            .accept(
                id,
                Packet {
                    id,
                    access: public,
                    hex: "00".repeat(MAX_MEMBER_BYTES + 1)
                }
            )
            .is_err()
    );
    partial.accept(id, source.released_member(head, id)?)?;
    assert!(
        partial
            .accept(id, source.released_member(head, id)?)
            .is_err()
    );
    assert!(partial.commit(&dest).is_err());
    assert!(dest.head(head).is_err());
    assert!(dest.resolve(&s, id, "read").is_err());
    let oversized = Snapshot {
        objects: (0..=MAX_MEMBERS)
            .map(|n| Id::blob(&n.to_le_bytes()))
            .collect(),
        ..s
    };
    assert!(Replica::new(oversized.id()?, oversized).is_err());
    Ok(())
}

#[test]
fn access_conflicts_and_bad_signatures_roll_back_the_whole_release() -> Result<()> {
    let source = Archive::memory()?;
    let dest = Archive::memory()?;
    let public = Id::blob(PUBLIC);
    let id = source.blob(b"prior protected sample", public)?;
    let new = source.blob(b"another sample", public)?;
    dest.blob(b"prior protected sample", Id::blob(READ_ONLY))?;
    let s = source.snapshot("first", Default::default())?;
    assert!(replica(&source, &s)?.commit(&dest).is_err());
    assert!(dest.releases()?.is_empty());
    assert!(dest.resolve(&s, new, "read").is_err());
    assert!(dest.resolve(&s, id, "train").is_err());

    let mut attestation = profile::attest(
        id,
        "bench",
        "calibration",
        "research-policy-1",
        &fixture::fixture_key(1),
    )?;
    attestation
        .fields
        .insert("signature".into(), "00".repeat(64).into());
    source.document(&attestation, Format::A, public)?;
    let forged = source.snapshot("bad signature", Default::default())?;
    assert!(source.release(forged.id()?).is_err());
    let clean = Archive::memory()?;
    assert!(replica(&source, &forged)?.commit(&clean).is_err());
    assert!(clean.head(forged.id()?).is_err());
    assert!(clean.resolve(&forged, new, "read").is_err());
    Ok(())
}

#[test]
fn an_authentic_but_unadmitted_correction_does_not_change_the_judgment() -> Result<()> {
    let source = Archive::memory()?;
    let dest = Archive::memory()?;
    let case = fixture::seed(&source, Format::A)?;
    let notice = fixture::notice(&source, Format::A, case.calibration, 80, 9)?;
    let s = source.snapshot("other laboratory", [case.published].into())?;
    replica(&source, &s)?.commit(&dest)?;
    let result = assess(&dest, &s, &case.queries[2])?;
    assert!(result.visible_notices.contains(&notice));
    assert!(!result.applicable_notices.contains(&notice));
    assert_eq!(result.result, Some(Standing::Supported));
    Ok(())
}
