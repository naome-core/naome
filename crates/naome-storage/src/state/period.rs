//! One anchored, owner-authorized fresh key pair per exact selected parent.

use ed25519_dalek::SigningKey;
use naome_ledger::{
    AccountId, AuthorityUnitId, LedgerState, ResolutionId,
    authority::{CandidateAdmissionOffer, NextPeriodKeys, PeriodKeys, UnitOrigin},
    profile::Genesis,
};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

use super::signer::StateSigner;
use super::{
    StateStorageError as Error,
    codec::{Reader, bytes},
    history::StateHistory,
    log::{FileLog, Limits},
};

const MAGIC: &[u8; 8] = b"NAOSKEY5";
const JOURNAL_MAGIC: &[u8; 8] = b"NAOSOFJ5";
const OFFER: u8 = 1;
const SIGNER_READY: u8 = 2;
const CANDIDATE_MAGIC: &[u8; 8] = b"NAOCAND5";
const KEY_FILE_MAX: u64 = 2048;
const OFFER_BYTES_MAX: usize = 1024;
type CustodyFiles = (Vec<u8>, Limits, String, String, String, String);

#[derive(Clone, Debug, PartialEq, Eq)]
enum CustodyOffer {
    Rotation(NextPeriodKeys),
    Candidate(CandidateAdmissionOffer),
}
impl CustodyOffer {
    fn keys(&self) -> &PeriodKeys {
        match self {
            Self::Rotation(v) => v.keys(),
            Self::Candidate(v) => v.keys(),
        }
    }
    fn encode(&self) -> Vec<u8> {
        let (tag, content) = match self {
            Self::Rotation(v) => (1, v.encode()),
            Self::Candidate(v) => (2, v.encode()),
        };
        let mut out = vec![tag];
        out.extend(content);
        out
    }
    fn decode(input: &[u8]) -> Result<Self, Error> {
        match input.split_first() {
            Some((1, content)) => Ok(Self::Rotation(NextPeriodKeys::decode(content)?)),
            Some((2, content)) => Ok(Self::Candidate(CandidateAdmissionOffer::decode(content)?)),
            _ => Err(Error::Invalid("custody offer kind")),
        }
    }
    fn verify(
        &self,
        parent: &LedgerState,
        unit: AuthorityUnitId,
        owner: &SigningKey,
    ) -> Result<(), Error> {
        match self {
            Self::Rotation(offer) => {
                if offer.unit() != unit {
                    return Err(Error::Invalid("period offer unit"));
                }
                offer.verify(
                    parent.authority(),
                    parent.head(),
                    parent.commitment(),
                    parent
                        .authority()
                        .effective_height()
                        .checked_add(1)
                        .ok_or(Error::Limit("period height"))?,
                    owner.verifying_key().to_bytes(),
                )?;
            }
            Self::Candidate(offer) => {
                let entry = parent
                    .join_intent(offer.family())
                    .ok_or(Error::Invalid("candidate intent absent"))?;
                let claim = parent
                    .claims()
                    .get(&offer.family())
                    .ok_or(Error::Invalid("candidate claim absent"))?;
                if AuthorityUnitId::for_claim(offer.family()) != unit
                    || entry.receipt().operation != offer.intent_receipt()
                    || claim.author != AccountId::for_key(owner.verifying_key().as_bytes())
                    || entry.intent().consensus_key() != offer.keys().consensus()
                    || entry.intent().transport_key() != offer.keys().transport()
                    || entry.intent().endpoint() != offer.keys().endpoint()
                    || !parent.join_queue().contains(&offer.family())
                {
                    return Err(Error::Invalid(
                        "candidate offer differs from finalized intent",
                    ));
                }
                offer.verify(
                    parent.authority(),
                    parent.head(),
                    parent.commitment(),
                    owner.verifying_key().to_bytes(),
                )?;
            }
        }
        Ok(())
    }
}

/// The journal keeps the public offer after local secret deletion. If a
/// completed offer loses its secret file, reopening fails closed; it can never
/// generate a second pair for the same parent.
pub struct StatePeriodCustody {
    path: PathBuf,
    offer: CustodyOffer,
    effective_height: u64,
    consensus: SigningKey,
    transport: SigningKey,
    signer_ready: bool,
    _journal: FileLog,
}
impl StatePeriodCustody {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn stage_offer_with_keys_for_test(
        directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        parent: &LedgerState,
        unit: AuthorityUnitId,
        owner: &SigningKey,
        consensus: &SigningKey,
        transport: &SigningKey,
        endpoint: String,
    ) -> Result<Self, Error> {
        let (_, _, _, _, _, secret) = context(parent, unit)?;
        let path = directory.as_ref().join(secret);
        let offer = NextPeriodKeys::sign(
            parent.authority(),
            parent.head(),
            parent.commitment(),
            unit,
            owner,
            consensus,
            transport,
            endpoint.clone(),
        )?;
        let mut contents = Zeroizing::new(MAGIC.to_vec());
        contents.extend_from_slice(consensus.as_bytes());
        contents.extend_from_slice(transport.as_bytes());
        bytes(&mut contents, &offer.encode())?;
        let mut file = private_create(&path)?;
        file.write_all(&contents)?;
        file.sync_all()?;
        sync_secret_directory(directory.as_ref())?;
        drop(file);
        Self::stage_offer(directory, anchor_directory, parent, unit, owner, endpoint)
    }
    pub fn stage_offer(
        directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        parent: &LedgerState,
        unit: AuthorityUnitId,
        owner: &SigningKey,
        endpoint: String,
    ) -> Result<Self, Error> {
        let directory = directory.as_ref();
        let anchor_directory = anchor_directory.as_ref();
        let (prefix, limits, journal_name, lock_name, anchor_name, secret_name) =
            context(parent, unit)?;
        let journal_path = directory.join(&journal_name);
        let anchor_path = anchor_directory.join(&anchor_name);
        let mut anchored = None;
        let mut signer_ready = false;
        let mut journal = if journal_path.exists() || anchor_path.exists() {
            FileLog::open(
                directory,
                anchor_directory,
                &journal_name,
                &lock_name,
                &anchor_name,
                &prefix,
                limits,
                |body| replay_offer(body, &mut anchored, &mut signer_ready, parent, unit, owner),
            )?
        } else {
            FileLog::create(
                directory,
                anchor_directory,
                &journal_name,
                &lock_name,
                &anchor_name,
                &prefix,
                limits,
            )?
        };
        let path = directory.join(secret_name);
        let (offer, consensus, transport) = match fs::symlink_metadata(&path) {
            Ok(_) => read_secret(&path, parent, unit, owner)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && anchored.is_none() => {
                let (offer, consensus, transport) =
                    create_secret(&path, parent, unit, owner, endpoint)?;
                (offer, consensus, transport)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::Invalid("anchored offer lost its secret keys"));
            }
            Err(error) => return Err(error.into()),
        };
        if let Some(saved) = anchored {
            if saved != CustodyOffer::Rotation(offer.clone()) {
                return Err(Error::Invalid("period secret differs from anchored offer"));
            }
        } else {
            let mut body = vec![OFFER];
            bytes(&mut body, &CustodyOffer::Rotation(offer.clone()).encode())?;
            journal.core.append(&body)?;
        }
        Ok(Self {
            path,
            offer: CustodyOffer::Rotation(offer),
            effective_height: parent.authority().effective_height() + 1,
            consensus,
            transport,
            signer_ready,
            _journal: journal,
        })
    }
    /// Imports the caller's already registered candidate pair exactly once.
    /// All per-parent preparation journals refer to this single local secret
    /// file, so retirement does not leave copies from unsuccessful attempts.
    pub fn import_candidate(
        directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        genesis: &Genesis,
        family: ResolutionId,
        owner: &SigningKey,
        consensus: &SigningKey,
        transport: &SigningKey,
    ) -> Result<(), Error> {
        let directory = directory.as_ref();
        let (prefix, limits, name, lock, anchor, secret) =
            candidate_context(genesis, family, owner);
        let anchor_directory = anchor_directory.as_ref();
        let mut anchored = None;
        let mut journal =
            if directory.join(&name).exists() || anchor_directory.join(&anchor).exists() {
                FileLog::open(
                    directory,
                    anchor_directory,
                    &name,
                    &lock,
                    &anchor,
                    &prefix,
                    limits,
                    |body| {
                        if anchored.is_some() || body.len() != 64 {
                            return Err(Error::Invalid("candidate import journal"));
                        }
                        anchored = Some(body.to_vec());
                        Ok(())
                    },
                )?
            } else {
                FileLog::create(
                    directory,
                    anchor_directory,
                    &name,
                    &lock,
                    &anchor,
                    &prefix,
                    limits,
                )?
            };
        let mut public = consensus.verifying_key().to_bytes().to_vec();
        public.extend(transport.verifying_key().to_bytes());
        if anchored.as_ref().is_some_and(|saved| saved != &public) {
            return Err(Error::Invalid("conflicting candidate import"));
        }
        let path = directory.join(secret);
        let mut contents = Zeroizing::new(prefix.clone());
        contents.extend_from_slice(consensus.as_bytes());
        contents.extend_from_slice(transport.as_bytes());
        match private_open(&path) {
            Ok(file) => {
                let mut saved = Zeroizing::new(Vec::new());
                file.take(KEY_FILE_MAX + 1).read_to_end(&mut saved)?;
                if *saved != *contents {
                    return Err(Error::Invalid("candidate import secret mismatch"));
                }
            }
            Err(Error::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound && anchored.is_none() =>
            {
                let mut file = private_create(&path)?;
                file.write_all(&contents)?;
                file.sync_all()?;
                sync_secret_directory(directory)?;
            }
            Err(error) => return Err(error),
        }
        if anchored.is_none() {
            journal.core.append(&public)?;
        }
        Ok(())
    }
    pub fn stage_candidate(
        directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        parent: &LedgerState,
        family: ResolutionId,
        owner: &SigningKey,
    ) -> Result<Self, Error> {
        let directory = directory.as_ref();
        let anchor_directory = anchor_directory.as_ref();
        let (path, consensus, transport) =
            read_candidate(directory, anchor_directory, parent.genesis(), family, owner)?;
        let entry = parent
            .join_intent(family)
            .ok_or(Error::Invalid("candidate intent absent"))?;
        if entry.expires() <= parent.time() {
            return Err(Error::Invalid("candidate intent expired"));
        }
        let offer = CustodyOffer::Candidate(CandidateAdmissionOffer::sign(
            parent.authority(),
            parent.head(),
            parent.commitment(),
            family,
            entry.receipt().operation,
            owner,
            &consensus,
            &transport,
            entry.intent().endpoint().to_owned(),
        )?);
        let unit = AuthorityUnitId::for_claim(family);
        offer.verify(parent, unit, owner)?;
        let (prefix, limits, name, lock, anchor, _) = context(parent, unit)?;
        let mut saved = None;
        let mut signer_ready = false;
        let mut journal =
            if directory.join(&name).exists() || anchor_directory.join(&anchor).exists() {
                FileLog::open(
                    directory,
                    anchor_directory,
                    &name,
                    &lock,
                    &anchor,
                    &prefix,
                    limits,
                    |body| replay_offer(body, &mut saved, &mut signer_ready, parent, unit, owner),
                )?
            } else {
                FileLog::create(
                    directory,
                    anchor_directory,
                    &name,
                    &lock,
                    &anchor,
                    &prefix,
                    limits,
                )?
            };
        if let Some(saved) = saved {
            if saved != offer {
                return Err(Error::Invalid("conflicting candidate preparation"));
            }
        } else {
            let mut body = vec![OFFER];
            bytes(&mut body, &offer.encode())?;
            journal.core.append(&body)?;
        }
        Ok(Self {
            path,
            offer,
            effective_height: parent.authority().effective_height() + 1,
            consensus,
            transport,
            signer_ready,
            _journal: journal,
        })
    }
    /// An already selected incoming authority can restore only the exact
    /// committed pair. No file creation or genesis-key fallback occurs here.
    pub fn open_for_selected(
        directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        history: &StateHistory,
        owner: &SigningKey,
    ) -> Result<Option<Self>, Error> {
        let selected = history.head()?;
        if selected.state().height() == 0 {
            return Ok(None);
        }
        let owner_id = AccountId::for_key(owner.verifying_key().as_bytes());
        let Some(unit) = selected.authority().owner(owner_id) else {
            return Ok(None);
        };
        let Some(keys) = unit.keys() else {
            return Ok(None);
        };
        let parent = history.branch_at(selected.state().height() - 1)?;
        let (prefix, limits, journal_name, lock_name, anchor_name, secret_name) =
            context(parent.state(), unit.id())?;
        let mut anchored = None;
        let mut signer_ready = false;
        let journal = FileLog::open(
            directory.as_ref(),
            anchor_directory.as_ref(),
            &journal_name,
            &lock_name,
            &anchor_name,
            &prefix,
            limits,
            |body| {
                replay_offer(
                    body,
                    &mut anchored,
                    &mut signer_ready,
                    parent.state(),
                    unit.id(),
                    owner,
                )
            },
        )?;
        let saved = anchored.ok_or(Error::Invalid("selected period offer not anchored"))?;
        let (path, consensus, transport) = match &saved {
            CustodyOffer::Rotation(_) => {
                let path = directory.as_ref().join(secret_name);
                let (offer, consensus, transport) =
                    read_secret(&path, parent.state(), unit.id(), owner)?;
                if saved != CustodyOffer::Rotation(offer) {
                    return Err(Error::Invalid("selected period offer mismatch"));
                }
                (path, consensus, transport)
            }
            CustodyOffer::Candidate(offer) => read_candidate(
                directory.as_ref(),
                anchor_directory.as_ref(),
                selected.state().genesis(),
                offer.family(),
                owner,
            )?,
        };
        if consensus.verifying_key().to_bytes() != *keys.consensus()
            || transport.verifying_key().to_bytes() != *keys.transport()
            || saved.keys() != keys
        {
            return Err(Error::Invalid(
                "selected period keys differ from anchored offer",
            ));
        }
        Ok(Some(Self {
            path,
            offer: saved,
            effective_height: selected.authority().effective_height(),
            consensus,
            transport,
            signer_ready,
            _journal: journal,
        }))
    }
    pub fn offer(&self) -> Option<&NextPeriodKeys> {
        match &self.offer {
            CustodyOffer::Rotation(v) => Some(v),
            _ => None,
        }
    }
    pub fn candidate_offer(&self) -> Option<&CandidateAdmissionOffer> {
        match &self.offer {
            CustodyOffer::Candidate(v) => Some(v),
            _ => None,
        }
    }
    pub fn consensus_key(&self) -> &SigningKey {
        &self.consensus
    }
    pub fn transport_key(&self) -> &SigningKey {
        &self.transport
    }
    /// Finish a crash-interrupted retirement without loading either old seed.
    /// The stopped journal and exact selected public offer identify the only
    /// local secret file that may be removed. Missing files make retry safe.
    pub fn retire_for_selected(
        directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        history: &StateHistory,
        owner: &SigningKey,
        signer: &StateSigner,
    ) -> Result<(), Error> {
        let selected = history.branch_at(signer.branch()?.state().height())?;
        if selected.state().height() == 0 {
            return Err(Error::Invalid("genesis retirement uses initial custody"));
        }
        let parent = history.branch_at(selected.state().height() - 1)?;
        Self::retire_for_selected_branch(
            directory,
            anchor_directory,
            &selected,
            parent.state(),
            owner,
            signer,
        )
    }
    /// Retire one predecessor while a single authenticated history walk holds
    /// both the selected signing branch and its exact previous branch. The
    /// visitor has already verified their sealed successor relationship.
    pub fn retire_for_selected_branch(
        directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        selected: &naome_consensus::state::StateBranch,
        parent: &LedgerState,
        owner: &SigningKey,
        signer: &StateSigner,
    ) -> Result<(), Error> {
        if !signer.stopped()? || signer.branch()?.commitment() != selected.commitment() {
            return Err(Error::Invalid(
                "retirement requires exact stopped selected signer",
            ));
        }
        if selected.state().height() == 0
            || parent.height().checked_add(1) != Some(selected.state().height())
            || parent.genesis().id() != selected.state().genesis().id()
        {
            return Err(Error::Invalid("retired period parent"));
        }
        let owner_id = AccountId::for_key(owner.verifying_key().as_bytes());
        let unit = selected
            .authority()
            .owner(owner_id)
            .ok_or(Error::Invalid("retired owner not selected"))?;
        if unit
            .keys()
            .is_none_or(|keys| keys.consensus() != signer.signer().as_bytes())
        {
            return Err(Error::Invalid("retired signer differs from selected owner"));
        }
        retire_public_offer(
            directory.as_ref(),
            anchor_directory.as_ref(),
            parent,
            owner,
            selected,
            false,
        )
    }
    /// Retire an incoming period that was selected and then superseded before
    /// its ordinary signer was ever created. The anchored offer must prove
    /// the exact selected public keys, and its signer marker must be absent.
    pub fn retire_unactivated_for_selected_branch(
        directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        selected: &naome_consensus::state::StateBranch,
        parent: &LedgerState,
        owner: &SigningKey,
    ) -> Result<(), Error> {
        if selected.state().height() == 0
            || parent.height().checked_add(1) != Some(selected.state().height())
            || parent.genesis().id() != selected.state().genesis().id()
        {
            return Err(Error::Invalid("unactivated period parent"));
        }
        let Some(unit) = selected
            .authority()
            .owner(AccountId::for_key(owner.verifying_key().as_bytes()))
        else {
            return Ok(());
        };
        if unit.keys().is_none() {
            return Ok(());
        }
        let directory = directory.as_ref();
        let anchor_directory = anchor_directory.as_ref();
        let (_, _, name, _, anchor, secret) = context(parent, unit.id())?;
        let journal_exists = path_present(&directory.join(name))?;
        let anchor_exists = path_present(&anchor_directory.join(anchor))?;
        if !journal_exists && !anchor_exists {
            if path_present(&directory.join(secret))? {
                return Err(Error::Invalid(
                    "selected period secret has no custody journal",
                ));
            }
            if let UnitOrigin::Earned { family, .. } = unit.origin() {
                retire_unstaged_candidate(
                    directory,
                    anchor_directory,
                    selected.state().genesis(),
                    family,
                    owner,
                    unit.keys().expect("checked active unit"),
                )?;
            }
            return Ok(());
        }
        if !journal_exists || !anchor_exists {
            return Err(Error::Invalid(
                "selected period custody journal or anchor missing",
            ));
        }
        retire_public_offer(directory, anchor_directory, parent, owner, selected, true)
    }
    /// Delete a fresh outgoing courier pair that did not become the selected
    /// successor's authority key. The offer journal binds its public keys to
    /// the exact selected parent, so no retired seed needs to be loaded.
    pub fn retire_unselected_offer_for_transition(
        directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        outgoing: &LedgerState,
        selected: &naome_consensus::state::StateBranch,
        owner: &SigningKey,
    ) -> Result<(), Error> {
        if outgoing.height().checked_add(1) != Some(selected.state().height())
            || outgoing.genesis().id() != selected.state().genesis().id()
        {
            return Err(Error::Invalid("unselected offer transition"));
        }
        let owner_id = AccountId::for_key(owner.verifying_key().as_bytes());
        let Some(unit) = outgoing.authority().owner(owner_id) else {
            return Ok(());
        };
        let directory = directory.as_ref();
        let anchor_directory = anchor_directory.as_ref();
        let (prefix, limits, name, lock, anchor, secret) = context(outgoing, unit.id())?;
        let journal_exists = path_present(&directory.join(&name))?;
        let anchor_exists = path_present(&anchor_directory.join(&anchor))?;
        if !journal_exists && !anchor_exists {
            if path_present(&directory.join(secret))? {
                return Err(Error::Invalid(
                    "unselected offer secret has no custody journal",
                ));
            }
            return Ok(());
        }
        if !journal_exists || !anchor_exists {
            return Err(Error::Invalid("outgoing offer journal or anchor missing"));
        }
        let mut saved = None;
        let mut signer_ready = false;
        let _journal = FileLog::open(
            directory,
            anchor_directory,
            &name,
            &lock,
            &anchor,
            &prefix,
            limits,
            |body| {
                replay_offer(
                    body,
                    &mut saved,
                    &mut signer_ready,
                    outgoing,
                    unit.id(),
                    owner,
                )
            },
        )?;
        let saved = saved.ok_or(Error::Invalid("outgoing offer missing"))?;
        let CustodyOffer::Rotation(offer) = saved else {
            return Err(Error::Invalid("outgoing authority has candidate custody"));
        };
        if selected
            .authority()
            .owner(owner_id)
            .and_then(|unit| unit.keys())
            == Some(offer.keys())
        {
            return Ok(());
        }
        match fs::remove_file(directory.join(secret)) {
            Ok(()) => sync_secret_directory(directory)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
    /// On restart, remove an imported claimant pair only after selected state
    /// proves that it is neither installed nor still eligible to retry. The
    /// import journal remains as evidence that this pair cannot be recreated.
    pub fn retire_closed_candidate_import(
        directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        selected: &LedgerState,
        family: ResolutionId,
        owner: &SigningKey,
    ) -> Result<(), Error> {
        let directory = directory.as_ref();
        let anchor_directory = anchor_directory.as_ref();
        let secret = candidate_context(selected.genesis(), family, owner).5;
        if !path_present(&directory.join(secret))? {
            return Ok(());
        }
        let (path, consensus, transport) = read_candidate(
            directory,
            anchor_directory,
            selected.genesis(),
            family,
            owner,
        )?;
        let keys = (
            consensus.verifying_key().to_bytes(),
            transport.verifying_key().to_bytes(),
        );
        let owner_id = AccountId::for_key(owner.verifying_key().as_bytes());
        if selected.authority().owner(owner_id).is_some_and(|unit| {
            matches!(unit.origin(), UnitOrigin::Earned { family: installed, .. } if installed == family)
                && unit.keys().is_some_and(|current| {
                    current.consensus() == &keys.0 && current.transport() == &keys.1
                })
        }) || candidate_retry_live(selected, family, owner_id, &keys.0, &keys.1) {
            return Ok(());
        }
        fs::remove_file(path)?;
        sync_secret_directory(directory)
    }
    /// A selected finite terminal record never activates its incoming keys.
    /// Complete their local retirement without reloading private material.
    pub fn retire_terminal_selected(
        directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        history: &StateHistory,
        owner: &SigningKey,
    ) -> Result<(), Error> {
        let selected = history.head()?;
        if !selected.state().terminated() {
            return Err(Error::Invalid(
                "terminal retirement requires terminated selected history",
            ));
        }
        if selected
            .authority()
            .owner(AccountId::for_key(owner.verifying_key().as_bytes()))
            .and_then(|unit| unit.keys())
            .is_none()
        {
            return Ok(());
        }
        let parent = history.branch_at(selected.state().height() - 1)?;
        retire_public_offer(
            directory.as_ref(),
            anchor_directory.as_ref(),
            parent.state(),
            owner,
            selected,
            false,
        )
    }
    /// Create or reopen the exact selected signer, then anchor its existence
    /// before returning it for any ordinary signature. Missing signer files
    /// after that marker are a terminal storage failure.
    pub fn open_or_create_selected_signer(
        &mut self,
        signer_directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        history: &StateHistory,
        maximum_round: u64,
    ) -> Result<StateSigner, Error> {
        let selected = history.head()?;
        if selected.state().height().checked_add(1) != Some(self.effective_height)
            || selected
                .authority()
                .consensus_unit(self.consensus.verifying_key().as_bytes())
                .is_none()
        {
            return Err(Error::Invalid("period signer not selected"));
        }
        let signer = match StateSigner::open_for_selected(
            &signer_directory,
            &anchor_directory,
            history,
            self.consensus.clone(),
            maximum_round,
        ) {
            Ok(signer) => signer,
            Err(Error::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound && !self.signer_ready =>
            {
                StateSigner::create_for_selected(
                    &signer_directory,
                    &anchor_directory,
                    history,
                    self.consensus.clone(),
                    maximum_round,
                )?
            }
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::Invalid("anchored signer journal or anchor missing"));
            }
            Err(error) => return Err(error),
        };
        if !self.signer_ready {
            let mut body = vec![SIGNER_READY];
            body.extend_from_slice(self.consensus.verifying_key().as_bytes());
            self._journal.core.append(&body)?;
            self.signer_ready = true;
        }
        Ok(signer)
    }
    /// This removes locally controlled secret file capabilities after the
    /// outgoing signer journal has STOP and old transport is closed. Backups
    /// and external seeds are operator-attested, outside this store.
    pub fn retire(self) -> Result<(), Error> {
        fs::remove_file(&self.path)?;
        let directory = self
            .path
            .parent()
            .ok_or(Error::Invalid("period secret directory"))?;
        sync_secret_directory(directory)?;
        Ok(())
    }
    /// An omitted candidate offer does not consume a still-queued claim. Its
    /// parent-specific preparation may be dropped while the one imported pair
    /// remains available for a new exact-parent offer.
    pub fn abandon_unselected_candidate(self, selected: &LedgerState) -> Result<(), Error> {
        let CustodyOffer::Candidate(offer) = &self.offer else {
            return Err(Error::Invalid(
                "candidate abandonment requires candidate custody",
            ));
        };
        if self.effective_height != selected.authority().effective_height()
            || selected
                .authority()
                .units()
                .iter()
                .any(|unit| unit.keys() == Some(offer.keys()))
        {
            return Err(Error::Invalid(
                "candidate custody is selected or wrong height",
            ));
        }
        let owner_id = selected
            .claims()
            .get(&offer.family())
            .map(|claim| claim.author)
            .ok_or(Error::Invalid("candidate claim missing after transition"))?;
        if candidate_retry_live(
            selected,
            offer.family(),
            owner_id,
            offer.keys().consensus(),
            offer.keys().transport(),
        ) {
            return Ok(());
        }
        self.retire()
    }
}

fn candidate_retry_live(
    selected: &LedgerState,
    family: ResolutionId,
    owner: AccountId,
    consensus: &[u8; 32],
    transport: &[u8; 32],
) -> bool {
    !selected.terminated()
        && selected.join_queue().contains(&family)
        && !selected.consumed_claims().contains(&family)
        && selected
            .claims()
            .get(&family)
            .is_some_and(|claim| claim.author == owner)
        && selected.join_intent(family).is_some_and(|entry| {
            entry.expires() > selected.time()
                && entry.intent().consensus_key() == consensus
                && entry.intent().transport_key() == transport
        })
}

fn retire_public_offer(
    directory: &Path,
    anchor_directory: &Path,
    parent: &LedgerState,
    owner: &SigningKey,
    selected: &naome_consensus::state::StateBranch,
    require_unactivated: bool,
) -> Result<(), Error> {
    let unit = selected
        .authority()
        .owner(AccountId::for_key(owner.verifying_key().as_bytes()))
        .ok_or(Error::Invalid("retired owner not selected"))?;
    let (prefix, limits, name, lock, anchor, secret) = context(parent, unit.id())?;
    let mut saved = None;
    let mut ready = false;
    let _journal = FileLog::open(
        directory,
        anchor_directory,
        &name,
        &lock,
        &anchor,
        &prefix,
        limits,
        |body| replay_offer(body, &mut saved, &mut ready, parent, unit.id(), owner),
    )?;
    let saved = saved.ok_or(Error::Invalid("retired period offer missing"))?;
    if unit.keys() != Some(saved.keys()) {
        return Err(Error::Invalid("retired offer differs from selected keys"));
    }
    if require_unactivated && ready {
        return Err(Error::Invalid(
            "selected signer marker exists without journal",
        ));
    }
    let path = match saved {
        CustodyOffer::Rotation(_) => directory.join(secret),
        CustodyOffer::Candidate(offer) => {
            directory.join(candidate_context(selected.state().genesis(), offer.family(), owner).5)
        }
    };
    match fs::remove_file(path) {
        Ok(()) => sync_secret_directory(directory)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn path_present(path: &Path) -> Result<bool, Error> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// The other three incoming units can seal an admitted candidate's period
/// while its owner is offline. An imported pair may then have no period
/// journal; its anchored public keys still prove which secret to retire.
fn retire_unstaged_candidate(
    directory: &Path,
    anchor_directory: &Path,
    genesis: &Genesis,
    family: ResolutionId,
    owner: &SigningKey,
    selected_keys: &PeriodKeys,
) -> Result<(), Error> {
    let (prefix, limits, name, lock, anchor, secret) = candidate_context(genesis, family, owner);
    let path = directory.join(secret);
    if !path_present(&path)? {
        return Ok(());
    }
    if !path_present(&directory.join(&name))? || !path_present(&anchor_directory.join(&anchor))? {
        return Err(Error::Invalid(
            "selected candidate import journal or anchor missing",
        ));
    }
    let mut public = None;
    let _journal = FileLog::open(
        directory,
        anchor_directory,
        &name,
        &lock,
        &anchor,
        &prefix,
        limits,
        |body| {
            if public.is_some() || body.len() != 64 {
                return Err(Error::Invalid("candidate import journal"));
            }
            public = Some(body.to_vec());
            Ok(())
        },
    )?;
    let mut expected = selected_keys.consensus().to_vec();
    expected.extend_from_slice(selected_keys.transport());
    if public != Some(expected) {
        return Err(Error::Invalid(
            "candidate import differs from selected keys",
        ));
    }
    drop(private_open(&path)?);
    fs::remove_file(path)?;
    sync_secret_directory(directory)?;
    Ok(())
}

fn context(parent: &LedgerState, unit: AuthorityUnitId) -> Result<CustodyFiles, Error> {
    let mut prefix = JOURNAL_MAGIC.to_vec();
    prefix.extend_from_slice(parent.genesis().id().as_bytes());
    prefix.extend_from_slice(&parent.height().to_be_bytes());
    prefix.extend_from_slice(parent.head().as_bytes());
    prefix.extend_from_slice(parent.commitment().as_bytes());
    prefix.extend_from_slice(unit.as_bytes());
    let height = parent.height();
    let journal = format!("state-period-{height}.journal");
    let lock = format!("state-period-{height}.lock");
    let anchor = format!("state-period-{height}.anchor");
    let secret = format!("state-period-{height}.secret");
    let limits = Limits {
        payload_bytes: (1 + 4 + OFFER_BYTES_MAX) as u32,
        frames: 2,
        file_bytes: prefix.len() as u64 + 2 * (36 + 1 + 4 + OFFER_BYTES_MAX as u64),
    };
    Ok((prefix, limits, journal, lock, anchor, secret))
}
fn replay_offer(
    body: &[u8],
    saved: &mut Option<CustodyOffer>,
    signer_ready: &mut bool,
    parent: &LedgerState,
    unit: AuthorityUnitId,
    owner: &SigningKey,
) -> Result<(), Error> {
    let mut r = Reader::new(body);
    match r.u8()? {
        SIGNER_READY if saved.is_some() && !*signer_ready => {
            let key = r.fixed::<32>()?;
            if saved
                .as_ref()
                .is_none_or(|offer| offer.keys().consensus() != &key)
            {
                return Err(Error::Invalid("signer marker key"));
            }
            r.finish()?;
            *signer_ready = true;
            return Ok(());
        }
        OFFER if saved.is_none() => {}
        _ => return Err(Error::Invalid("period offer journal event order")),
    }
    let offer = CustodyOffer::decode(r.bytes(OFFER_BYTES_MAX)?)?;
    r.finish()?;
    offer.verify(parent, unit, owner)?;
    *saved = Some(offer);
    Ok(())
}
fn create_secret(
    path: &Path,
    parent: &LedgerState,
    unit: AuthorityUnitId,
    owner: &SigningKey,
    endpoint: String,
) -> Result<(NextPeriodKeys, SigningKey, SigningKey), Error> {
    let mut consensus_seed = Zeroizing::new([0u8; 32]);
    let mut transport_seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *consensus_seed)
        .map_err(|_| Error::Invalid("consensus entropy unavailable"))?;
    getrandom::fill(&mut *transport_seed)
        .map_err(|_| Error::Invalid("transport entropy unavailable"))?;
    let consensus = SigningKey::from_bytes(&consensus_seed);
    let transport = SigningKey::from_bytes(&transport_seed);
    let offer = NextPeriodKeys::sign(
        parent.authority(),
        parent.head(),
        parent.commitment(),
        unit,
        owner,
        &consensus,
        &transport,
        endpoint,
    )?;
    let mut contents = Zeroizing::new(MAGIC.to_vec());
    contents.extend_from_slice(&*consensus_seed);
    contents.extend_from_slice(&*transport_seed);
    bytes(&mut contents, &offer.encode())?;
    let mut file = private_create(path)?;
    file.write_all(&contents)?;
    file.sync_all()?;
    sync_secret_directory(
        path.parent()
            .ok_or(Error::Invalid("period secret directory"))?,
    )?;
    Ok((offer, consensus, transport))
}
fn read_secret(
    path: &Path,
    parent: &LedgerState,
    unit: AuthorityUnitId,
    owner: &SigningKey,
) -> Result<(NextPeriodKeys, SigningKey, SigningKey), Error> {
    let file = private_open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() > KEY_FILE_MAX {
        return Err(Error::Invalid("period secret file kind or size"));
    }
    let mut input = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(KEY_FILE_MAX + 1).read_to_end(&mut input)?;
    if input.len() as u64 != metadata.len() {
        return Err(Error::Invalid("period secret changed during read"));
    }
    let mut r = Reader::new(&input);
    if r.fixed::<8>()? != *MAGIC {
        return Err(Error::Invalid("period secret format"));
    }
    let mut consensus_seed = Zeroizing::new(r.fixed::<32>()?);
    let mut transport_seed = Zeroizing::new(r.fixed::<32>()?);
    let consensus = SigningKey::from_bytes(&consensus_seed);
    let transport = SigningKey::from_bytes(&transport_seed);
    let offer = NextPeriodKeys::decode(r.bytes(OFFER_BYTES_MAX)?)?;
    r.finish()?;
    consensus_seed.fill(0);
    transport_seed.fill(0);
    if offer.unit() != unit
        || offer.keys().consensus() != consensus.verifying_key().as_bytes()
        || offer.keys().transport() != transport.verifying_key().as_bytes()
    {
        return Err(Error::Invalid("period secret does not match offer"));
    }
    offer.verify(
        parent.authority(),
        parent.head(),
        parent.commitment(),
        parent
            .authority()
            .effective_height()
            .checked_add(1)
            .ok_or(Error::Limit("period height"))?,
        owner.verifying_key().to_bytes(),
    )?;
    Ok((offer, consensus, transport))
}

fn candidate_context(genesis: &Genesis, family: ResolutionId, owner: &SigningKey) -> CustodyFiles {
    let mut prefix = CANDIDATE_MAGIC.to_vec();
    prefix.extend(genesis.id().as_bytes());
    prefix.extend(family.as_bytes());
    prefix.extend(owner.verifying_key().as_bytes());
    let family: String = family
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let base = format!("state-candidate-{family}");
    let limits = Limits {
        payload_bytes: 64,
        frames: 1,
        file_bytes: prefix.len() as u64 + 36 + 64,
    };
    (
        prefix,
        limits,
        format!("{base}.journal"),
        format!("{base}.lock"),
        format!("{base}.anchor"),
        format!("{base}.secret"),
    )
}
fn read_candidate(
    directory: &Path,
    anchor_directory: &Path,
    genesis: &Genesis,
    family: ResolutionId,
    owner: &SigningKey,
) -> Result<(PathBuf, SigningKey, SigningKey), Error> {
    let (prefix, limits, name, lock, anchor, secret) = candidate_context(genesis, family, owner);
    let mut public = None;
    let _journal = FileLog::open(
        directory,
        anchor_directory,
        &name,
        &lock,
        &anchor,
        &prefix,
        limits,
        |body| {
            if public.is_some() || body.len() != 64 {
                return Err(Error::Invalid("candidate import journal"));
            }
            public = Some(body.to_vec());
            Ok(())
        },
    )?;
    let public = public.ok_or(Error::Invalid("candidate import not anchored"))?;
    let path = directory.join(secret);
    let file = private_open(&path)?;
    let mut input = Zeroizing::new(Vec::new());
    file.take(KEY_FILE_MAX + 1).read_to_end(&mut input)?;
    if input.len() != prefix.len() + 64 || !input.starts_with(&prefix) {
        return Err(Error::Invalid("candidate secret context"));
    }
    let consensus_seed = Zeroizing::new(
        <[u8; 32]>::try_from(&input[prefix.len()..prefix.len() + 32])
            .map_err(|_| Error::Invalid("candidate consensus seed"))?,
    );
    let transport_seed = Zeroizing::new(
        <[u8; 32]>::try_from(&input[prefix.len() + 32..])
            .map_err(|_| Error::Invalid("candidate transport seed"))?,
    );
    let consensus = SigningKey::from_bytes(&consensus_seed);
    let transport = SigningKey::from_bytes(&transport_seed);
    if consensus.verifying_key().as_bytes() != &public[..32]
        || transport.verifying_key().as_bytes() != &public[32..]
    {
        return Err(Error::Invalid(
            "candidate secret differs from anchored import",
        ));
    }
    Ok((path, consensus, transport))
}

#[cfg(unix)]
fn private_create(path: &Path) -> Result<fs::File, Error> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?)
}
#[cfg(unix)]
fn private_open(path: &Path) -> Result<fs::File, Error> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(Error::Invalid("period secret ownership or permissions"));
    }
    Ok(file)
}
#[cfg(not(unix))]
fn private_create(_path: &Path) -> Result<fs::File, Error> {
    Err(Error::Invalid("period secret platform unsupported"))
}
#[cfg(not(unix))]
fn private_open(_path: &Path) -> Result<fs::File, Error> {
    Err(Error::Invalid("period secret platform unsupported"))
}
fn sync_secret_directory(directory: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        fs::File::open(directory)?.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Err(Error::Invalid("period secret platform unsupported"))
    }
}
