//! Durable preparation for one selected authority transition.
//!
//! Agreement, READY and TERMINAL transcripts are anchored before signing. A
//! completed TERMINAL signature remains private until the old signer has
//! durably stopped and the runtime has retired its old transport. Each height
//! has a separate journal, so a restart cannot silently choose a second
//! agreement at the same height.

use ed25519_dalek::{Signer, SigningKey};
use naome_consensus::{
    ConsensusKey,
    state::{SEAL_SIGNATURE_BYTES, SealRole, SealSignature, StateAgreement, StateSeal},
};
use naome_ledger::profile::Genesis;
use std::path::Path;

use super::{
    StateStorageError as Error,
    codec::{Reader, bytes},
    history::StateHistory,
    log::{FileLog, Limits},
    signer::StateSigner,
};

const MAGIC: &[u8; 8] = b"NAOSHOF5";
const STAGE: u8 = 1;
const READY_INTENT: u8 = 2;
const READY_DONE: u8 = 3;
const TERMINAL_INTENT: u8 = 4;
const TERMINAL_DONE: u8 = 5;
const RELEASE: u8 = 6;
/// Anchored custody for exactly one height and one agreed record.
pub struct StateHandoffJournal {
    height: u64,
    maximum_round: u64,
    replay: Replay,
    log: FileLog,
}

#[derive(Default)]
struct Replay {
    agreement: Option<StateAgreement>,
    ready_signer: Option<ConsensusKey>,
    ready: Option<SealSignature>,
    terminal_signer: Option<ConsensusKey>,
    ready_quorum: Option<Vec<SealSignature>>,
    terminal: Option<SealSignature>,
    released: bool,
}

impl Replay {
    fn apply(
        &mut self,
        body: &[u8],
        height: u64,
        history: &StateHistory,
        maximum_round: u64,
    ) -> Result<(), Error> {
        let mut r = Reader::new(body);
        match r.u8()? {
            STAGE if self.agreement.is_none() => {
                if r.u64()? != height {
                    return Err(Error::Invalid("handoff height"));
                }
                let parent = history.branch_at(height - 1)?;
                let agreement = parent.decode_agreement(
                    r.bytes(
                        history
                            .last_finalized()?
                            .state()
                            .genesis()
                            .profile()
                            .limits()
                            .transport_frame_bytes as usize,
                    )?,
                    maximum_round,
                )?;
                if agreement.seal_context().height() != height {
                    return Err(Error::Invalid("handoff agreement height"));
                }
                self.agreement = Some(agreement);
            }
            READY_INTENT if self.ready_signer.is_none() => {
                let signer = ConsensusKey::from_bytes(r.fixed()?);
                let agreement = self
                    .agreement
                    .as_ref()
                    .ok_or(Error::Invalid("READY without agreement"))?;
                if agreement
                    .incoming()
                    .consensus_unit(signer.as_bytes())
                    .is_none()
                {
                    return Err(Error::Invalid("READY signer outside incoming authority"));
                }
                self.ready_signer = Some(signer);
            }
            READY_DONE if self.ready.is_none() => {
                let agreement = self
                    .agreement
                    .as_ref()
                    .ok_or(Error::Invalid("READY without agreement"))?;
                let signer = self
                    .ready_signer
                    .ok_or(Error::Invalid("READY without intent"))?;
                let signature = SealSignature::decode(r.bytes(SEAL_SIGNATURE_BYTES)?)?;
                signature.verify(
                    SealRole::Ready,
                    agreement.seal_context(),
                    agreement.outgoing(),
                    agreement.incoming(),
                )?;
                if signature.signer() != signer {
                    return Err(Error::Invalid("READY signer differs from intent"));
                }
                self.ready = Some(signature);
            }
            TERMINAL_INTENT if self.terminal_signer.is_none() => {
                let agreement = self
                    .agreement
                    .as_ref()
                    .ok_or(Error::Invalid("TERMINAL without agreement"))?;
                let signer = ConsensusKey::from_bytes(r.fixed()?);
                if agreement
                    .outgoing()
                    .consensus_unit(signer.as_bytes())
                    .is_none()
                {
                    return Err(Error::Invalid("TERMINAL signer outside outgoing authority"));
                }
                let count = r.u8()? as usize;
                if !(3..=4).contains(&count) {
                    return Err(Error::Invalid("READY quorum count"));
                }
                let mut quorum = Vec::with_capacity(count);
                for _ in 0..count {
                    quorum.push(SealSignature::decode(r.take(SEAL_SIGNATURE_BYTES)?)?);
                }
                StateSeal::verify_ready(
                    &quorum,
                    agreement.seal_context(),
                    agreement.outgoing(),
                    agreement.incoming(),
                )?;
                self.terminal_signer = Some(signer);
                self.ready_quorum = Some(quorum);
            }
            TERMINAL_DONE if self.terminal.is_none() => {
                let agreement = self
                    .agreement
                    .as_ref()
                    .ok_or(Error::Invalid("TERMINAL without agreement"))?;
                let signer = self
                    .terminal_signer
                    .ok_or(Error::Invalid("TERMINAL without intent"))?;
                let signature = SealSignature::decode(r.bytes(SEAL_SIGNATURE_BYTES)?)?;
                signature.verify(
                    SealRole::Terminal,
                    agreement.seal_context(),
                    agreement.outgoing(),
                    agreement.incoming(),
                )?;
                if signature.signer() != signer {
                    return Err(Error::Invalid("TERMINAL signer differs from intent"));
                }
                self.terminal = Some(signature);
            }
            RELEASE if self.terminal.is_some() && !self.released => {
                self.released = true;
            }
            _ => return Err(Error::Invalid("handoff journal event order")),
        }
        r.finish()
    }
}

impl StateHandoffJournal {
    pub fn create(
        directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        genesis: Genesis,
        height: u64,
        maximum_round: u64,
    ) -> Result<Self, Error> {
        let (prefix, limits, name, lock, anchor) = context(&genesis, height, maximum_round)?;
        let log = FileLog::create(
            directory.as_ref(),
            anchor_directory.as_ref(),
            &name,
            &lock,
            &anchor,
            &prefix,
            limits,
        )?;
        Ok(Self {
            height,
            maximum_round,
            replay: Replay::default(),
            log,
        })
    }
    pub fn open(
        directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        genesis: Genesis,
        height: u64,
        maximum_round: u64,
        history: &StateHistory,
    ) -> Result<Self, Error> {
        let (prefix, limits, name, lock, anchor) = context(&genesis, height, maximum_round)?;
        let mut replay = Replay::default();
        let log = FileLog::open(
            directory.as_ref(),
            anchor_directory.as_ref(),
            &name,
            &lock,
            &anchor,
            &prefix,
            limits,
            |body| replay.apply(body, height, history, maximum_round),
        )?;
        Ok(Self {
            height,
            maximum_round,
            replay,
            log,
        })
    }
    pub fn open_or_create(
        directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        genesis: Genesis,
        height: u64,
        maximum_round: u64,
        history: &StateHistory,
    ) -> Result<Self, Error> {
        let (_, _, name, _, anchor) = context(&genesis, height, maximum_round)?;
        let exists = directory.as_ref().join(name).exists()
            || anchor_directory.as_ref().join(anchor).exists();
        if exists {
            Self::open(
                directory,
                anchor_directory,
                genesis,
                height,
                maximum_round,
                history,
            )
        } else {
            Self::create(directory, anchor_directory, genesis, height, maximum_round)
        }
    }
    pub fn agreement(&self) -> Option<&StateAgreement> {
        self.replay.agreement.as_ref()
    }
    pub fn ready(&self) -> Option<&SealSignature> {
        self.replay.ready.as_ref()
    }
    pub fn terminal(&self) -> Option<&SealSignature> {
        self.replay
            .released
            .then_some(self.replay.terminal.as_ref())
            .flatten()
    }
    pub fn terminal_prepared(&self) -> bool {
        self.replay.terminal_signer.is_some()
    }
    pub fn terminal_saved(&self) -> bool {
        self.replay.terminal.is_some()
    }
    pub fn ready_quorum(&self) -> Option<&[SealSignature]> {
        self.replay.ready_quorum.as_deref()
    }
    pub fn stage(
        &mut self,
        agreement: &StateAgreement,
        history: &StateHistory,
    ) -> Result<(), Error> {
        self.log.core.ensure()?;
        if let Some(staged) = &self.replay.agreement {
            return if staged.seal_context() == agreement.seal_context() {
                Ok(())
            } else {
                Err(Error::Invalid("different handoff agreement already staged"))
            };
        }
        let parent = history.branch_at(self.height - 1)?;
        let encoded = agreement.encode()?;
        let verified = parent.decode_agreement(&encoded, self.maximum_round)?;
        if verified.seal_context().height() != self.height || verified.encode()? != encoded {
            return Err(Error::Invalid("handoff agreement parent"));
        }
        let mut body = vec![STAGE];
        body.extend_from_slice(&self.height.to_be_bytes());
        bytes(&mut body, &encoded)?;
        self.log.core.append(&body)?;
        self.replay.agreement = Some(verified);
        Ok(())
    }
    pub fn prepare_ready(&mut self, signer: ConsensusKey) -> Result<Vec<u8>, Error> {
        self.log.core.ensure()?;
        let agreement = self
            .replay
            .agreement
            .as_ref()
            .ok_or(Error::Invalid("handoff agreement missing"))?;
        if agreement
            .incoming()
            .consensus_unit(signer.as_bytes())
            .is_none()
        {
            return Err(Error::Invalid("READY signer outside incoming authority"));
        }
        match self.replay.ready_signer {
            Some(old) if old != signer => return Err(Error::Invalid("different READY intent")),
            None => {
                self.log
                    .core
                    .reserve_batch(&[1 + 32, 1 + 4 + SEAL_SIGNATURE_BYTES])?;
                let mut body = vec![READY_INTENT];
                body.extend_from_slice(signer.as_bytes());
                self.log.core.append(&body)?;
                self.replay.ready_signer = Some(signer);
            }
            _ => {}
        }
        Ok(SealSignature::signing_bytes(
            SealRole::Ready,
            agreement.seal_context(),
            signer,
        ))
    }
    pub fn complete_ready(&mut self, signature: [u8; 64]) -> Result<SealSignature, Error> {
        self.log.core.ensure()?;
        if let Some(ready) = &self.replay.ready {
            return Ok(ready.clone());
        }
        let agreement = self
            .replay
            .agreement
            .as_ref()
            .ok_or(Error::Invalid("handoff agreement missing"))?;
        let signer = self
            .replay
            .ready_signer
            .ok_or(Error::Invalid("READY intent missing"))?;
        let ready = SealSignature::complete(
            SealRole::Ready,
            agreement.seal_context(),
            signer,
            signature,
            agreement.outgoing(),
            agreement.incoming(),
        )?;
        let mut body = vec![READY_DONE];
        bytes(&mut body, &ready.encode())?;
        self.log.core.append(&body)?;
        self.replay.ready = Some(ready.clone());
        Ok(ready)
    }
    pub fn sign_ready(&mut self, key: &SigningKey) -> Result<SealSignature, Error> {
        let signer = ConsensusKey::from_bytes(key.verifying_key().to_bytes());
        let transcript = self.prepare_ready(signer)?;
        if let Some(ready) = &self.replay.ready {
            return Ok(ready.clone());
        }
        self.complete_ready(key.sign(&transcript).to_bytes())
    }
    pub fn prepare_terminal(
        &mut self,
        signer: ConsensusKey,
        ready: &[SealSignature],
    ) -> Result<Vec<u8>, Error> {
        self.log.core.ensure()?;
        let agreement = self
            .replay
            .agreement
            .as_ref()
            .ok_or(Error::Invalid("handoff agreement missing"))?;
        if agreement
            .outgoing()
            .consensus_unit(signer.as_bytes())
            .is_none()
        {
            return Err(Error::Invalid("TERMINAL signer outside outgoing authority"));
        }
        StateSeal::verify_ready(
            ready,
            agreement.seal_context(),
            agreement.outgoing(),
            agreement.incoming(),
        )?;
        match self.replay.terminal_signer {
            Some(old) if old != signer || self.replay.ready_quorum.as_deref() != Some(ready) => {
                return Err(Error::Invalid("different TERMINAL intent"));
            }
            None => {
                let mut body = vec![TERMINAL_INTENT];
                body.extend_from_slice(signer.as_bytes());
                body.push(ready.len() as u8);
                for signature in ready {
                    body.extend(signature.encode());
                }
                self.log
                    .core
                    .reserve_batch(&[body.len(), 1 + 4 + SEAL_SIGNATURE_BYTES, 1])?;
                self.log.core.append(&body)?;
                self.replay.terminal_signer = Some(signer);
                self.replay.ready_quorum = Some(ready.to_vec());
            }
            _ => {}
        }
        Ok(SealSignature::signing_bytes(
            SealRole::Terminal,
            agreement.seal_context(),
            signer,
        ))
    }
    pub fn complete_terminal(&mut self, signature: [u8; 64]) -> Result<(), Error> {
        self.log.core.ensure()?;
        if self.replay.terminal.is_some() {
            return Ok(());
        }
        let agreement = self
            .replay
            .agreement
            .as_ref()
            .ok_or(Error::Invalid("handoff agreement missing"))?;
        let signer = self
            .replay
            .terminal_signer
            .ok_or(Error::Invalid("TERMINAL intent missing"))?;
        let terminal = SealSignature::complete(
            SealRole::Terminal,
            agreement.seal_context(),
            signer,
            signature,
            agreement.outgoing(),
            agreement.incoming(),
        )?;
        let mut body = vec![TERMINAL_DONE];
        bytes(&mut body, &terminal.encode())?;
        self.log.core.append(&body)?;
        self.replay.terminal = Some(terminal);
        Ok(())
    }
    pub fn sign_terminal(
        &mut self,
        key: &SigningKey,
        ready: &[SealSignature],
    ) -> Result<(), Error> {
        let signer = ConsensusKey::from_bytes(key.verifying_key().to_bytes());
        let transcript = self.prepare_terminal(signer, ready)?;
        if self.replay.terminal.is_some() {
            return Ok(());
        }
        self.complete_terminal(key.sign(&transcript).to_bytes())
    }
    /// The caller must close its old transport before this call. The signer
    /// must already have a durable terminal stop; only then are bytes released.
    pub fn release_terminal(
        &mut self,
        outgoing_signer: &StateSigner,
    ) -> Result<SealSignature, Error> {
        self.log.core.ensure()?;
        let terminal = self
            .replay
            .terminal
            .as_ref()
            .ok_or(Error::Invalid("TERMINAL signature missing"))?;
        if outgoing_signer.signer() != terminal.signer() || !outgoing_signer.stopped()? {
            return Err(Error::Invalid("outgoing signer has not retired"));
        }
        if !self.replay.released {
            self.log.core.append(&[RELEASE])?;
            self.replay.released = true;
        }
        Ok(terminal.clone())
    }
}

fn context(
    genesis: &Genesis,
    height: u64,
    maximum_round: u64,
) -> Result<(Vec<u8>, Limits, String, String, String), Error> {
    if height == 0
        || height > genesis.profile().limits().run_records
        || maximum_round > genesis.profile().limits().consensus_rounds
    {
        return Err(Error::Limit("handoff height or round"));
    }
    let mut prefix = MAGIC.to_vec();
    prefix.extend_from_slice(genesis.id().as_bytes());
    prefix.extend_from_slice(&height.to_be_bytes());
    prefix.extend_from_slice(&maximum_round.to_be_bytes());
    let frame = genesis.profile().limits().transport_frame_bytes;
    let limits = Limits {
        payload_bytes: u32::try_from(frame).map_err(|_| Error::Limit("handoff frame"))?,
        frames: 6,
        file_bytes: genesis.profile().handoff_journal_bytes()?,
    };
    Ok((
        prefix,
        limits,
        format!("state-handoff-{height}.journal"),
        format!("state-handoff-{height}.lock"),
        format!("state-handoff-{height}.anchor"),
    ))
}
