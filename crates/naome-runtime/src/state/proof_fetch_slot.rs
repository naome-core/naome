//! Public proof retrieval targets a stable slot across period-key rotation.

use super::*;
use naome_ledger::AuthoritySlotId;
use naome_proof::ProofId;

impl StateRuntime {
    fn proof_slot_peer(&self, slot: AuthoritySlotId) -> Result<PeerId> {
        let keys = self
            .state()?
            .authority()
            .slot(slot)
            .and_then(|unit| unit.keys())
            .ok_or_else(|| StateRuntimeError::Rejected("proof slot is unavailable".into()))?;
        naome_network::state_peer_id(*keys.transport())
            .map_err(|error| StateRuntimeError::Transport(error.to_string()))
    }

    pub fn start_proof_fetch_slot(&mut self, slot: AuthoritySlotId, proof: ProofId) -> Result<()> {
        self.expire_proof_fetches();
        if self
            .proof_fetches
            .iter()
            .any(|fetch| fetch.slot == Some(slot) && fetch.proof == proof)
        {
            return Ok(());
        }
        let peer = self.proof_slot_peer(slot)?;
        self.start_proof_fetch(peer, proof)?;
        let fetch = self
            .proof_fetches
            .iter_mut()
            .find(|fetch| fetch.peer == peer && fetch.proof == proof)
            .ok_or(StateRuntimeError::Configuration(
                "proof request not retained",
            ))?;
        fetch.slot = Some(slot);
        Ok(())
    }

    pub fn take_proof_fetch_slot(
        &mut self,
        slot: AuthoritySlotId,
        proof: ProofId,
    ) -> Result<Option<Vec<u8>>> {
        let peer = self
            .proof_fetches
            .iter()
            .find(|fetch| fetch.slot == Some(slot) && fetch.proof == proof)
            .map(|fetch| fetch.peer)
            .ok_or_else(|| {
                StateRuntimeError::Rejected(
                    "proof fetch was not requested or its result expired".into(),
                )
            })?;
        self.take_proof_fetch(peer, proof)
    }

    /// Invoke after installing the selected successor network. A new identity
    /// gets a new transport request while retaining the original deadline and
    /// the same maximum of four owned requests/results.
    pub(super) fn refresh_slot_proof_fetches(&mut self) -> Result<()> {
        let peers: BTreeMap<_, _> = self
            .state()?
            .authority()
            .units()
            .iter()
            .map(|unit| {
                let peer = unit
                    .keys()
                    .map(|keys| {
                        naome_network::state_peer_id(*keys.transport())
                            .map_err(|error| StateRuntimeError::Transport(error.to_string()))
                    })
                    .transpose()?;
                Ok((unit.slot(), peer))
            })
            .collect::<Result<_>>()?;
        for fetch in &mut self.proof_fetches {
            if fetch.outcome.is_some() {
                continue;
            }
            let Some(slot) = fetch.slot else {
                continue;
            };
            match peers.get(&slot).copied().flatten() {
                Some(peer) if peer != fetch.peer => {
                    fetch.peer = peer;
                    fetch.ticket = None;
                }
                None => {
                    fetch.ticket = None;
                    fetch.outcome = Some(Err("proof slot is unavailable".into()));
                }
                _ => {}
            }
        }
        self.expire_proof_fetches();
        Ok(())
    }
}
