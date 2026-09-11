//! Approval certificates and deterministic delayed membership transitions.

use super::*;

/// A canonical request with a strictly ordered, distinct current-operator quorum.
/// This is approval evidence only; consensus must still finalize its inclusion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedMembershipRequest {
    request: MembershipRequest,
    approvals: Vec<MembershipApproval>,
}

impl ApprovedMembershipRequest {
    const MAGIC: &'static [u8] = b"naome/verified-membership/v0/approved\0";
    pub const MAX_BYTES: usize = 64 + MembershipRequest::MAX_BYTES + MAX_MEMBERS * 128;

    pub fn new(
        request: MembershipRequest,
        approvals: Vec<MembershipApproval>,
        snapshot: &MembershipSnapshot,
    ) -> Result<Self, MembershipError> {
        let result = Self { request, approvals };
        result.validate(snapshot)?;
        Ok(result)
    }

    pub fn validate(&self, snapshot: &MembershipSnapshot) -> Result<(), MembershipError> {
        self.request.validate(snapshot)?;
        if self.approvals.len() > MAX_MEMBERS {
            return Err(MembershipError::Limit);
        }
        if self.approvals.len() < snapshot.quorum() || self.approvals.len() < 3 {
            return Err(MembershipError::Quorum);
        }
        let request = self.request.id();
        let bytes = transcript(
            b"naome/verified-membership/v0/operator-approval\0",
            &request,
        );
        let mut previous = None;
        for approval in &self.approvals {
            if previous.is_some_and(|id| id >= approval.organization) {
                return Err(MembershipError::Duplicate);
            }
            previous = Some(approval.organization);
            if approval.request != request {
                return Err(MembershipError::StaleRequest);
            }
            let member = snapshot
                .member(&approval.organization)
                .ok_or(MembershipError::UnknownMember)?;
            verify(&member.approval_key, &bytes, &approval.signature)?;
        }
        Ok(())
    }

    pub const fn request(&self) -> &MembershipRequest {
        &self.request
    }
    pub fn approvals(&self) -> &[MembershipApproval] {
        &self.approvals
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let request = self.request.to_bytes();
        let mut bytes = Self::MAGIC.to_vec();
        bytes.extend_from_slice(&(request.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&request);
        bytes.extend_from_slice(&(self.approvals.len() as u16).to_be_bytes());
        for approval in &self.approvals {
            bytes.extend_from_slice(&approval.organization);
            bytes.extend_from_slice(&approval.request);
            bytes.extend_from_slice(&approval.signature);
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MembershipError> {
        let mut reader = Reader::new(bytes, Self::MAX_BYTES)?;
        if reader.take(Self::MAGIC.len())? != Self::MAGIC {
            return Err(MembershipError::Encoding);
        }
        let length = reader.u16()? as usize;
        let request = MembershipRequest::from_bytes(reader.take(length)?)?;
        let count = reader.u16()? as usize;
        if !(3..=MAX_MEMBERS).contains(&count) {
            return Err(MembershipError::Limit);
        }
        let mut approvals = Vec::with_capacity(count);
        for _ in 0..count {
            approvals.push(MembershipApproval {
                organization: reader.array()?,
                request: reader.array()?,
                signature: reader.array()?,
            });
        }
        reader.finish()?;
        Ok(Self { request, approvals })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingMembership {
    request_id: [u8; 32],
    included_height: u64,
    activation_height: u64,
    successor: MembershipSnapshot,
}

/// Branch-local membership projection, installed only with finalized consensus.
/// One pending change serializes admissions and prevents combined removals from
/// violating the minimum. Offline members remain in the quorum denominator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipState {
    active: MembershipSnapshot,
    pending: Option<PendingMembership>,
}

impl MembershipState {
    pub fn genesis(snapshot: MembershipSnapshot) -> Result<Self, MembershipError> {
        if snapshot.generation != 0 {
            return Err(MembershipError::StaleRequest);
        }
        Ok(Self {
            active: snapshot,
            pending: None,
        })
    }

    pub fn active_at(&self, height: u64) -> &MembershipSnapshot {
        match &self.pending {
            Some(pending) if height >= pending.activation_height => &pending.successor,
            _ => &self.active,
        }
    }

    pub fn pending_activation(&self) -> Option<u64> {
        self.pending
            .as_ref()
            .map(|pending| pending.activation_height)
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut bytes = self.active.id.to_vec();
        match &self.pending {
            None => bytes.push(0),
            Some(pending) => {
                bytes.push(1);
                bytes.extend_from_slice(&pending.request_id);
                bytes.extend_from_slice(&pending.included_height.to_be_bytes());
                bytes.extend_from_slice(&pending.activation_height.to_be_bytes());
                bytes.extend_from_slice(&pending.successor.id);
            }
        }
        digest(b"naome/verified-membership/v0/state\0", &bytes)
    }

    pub(super) fn transition(
        &self,
        height: u64,
        operation: Option<&ApprovedMembershipRequest>,
    ) -> Result<Self, MembershipError> {
        if height == 0 {
            return Err(MembershipError::Encoding);
        }
        let mut child = self.clone();
        if child
            .pending
            .as_ref()
            .is_some_and(|pending| height >= pending.activation_height)
        {
            child.active = child
                .pending
                .take()
                .expect("pending activation was checked")
                .successor;
        }
        if let Some(operation) = operation {
            if child.pending.is_some() {
                return Err(MembershipError::PendingTransition);
            }
            operation.validate(&child.active)?;
            let epoch = (height - 1) / EPOCH_HEIGHTS;
            let activation_height = epoch
                .checked_add(2)
                .and_then(|epoch| epoch.checked_mul(EPOCH_HEIGHTS))
                .and_then(|height| height.checked_add(1))
                .ok_or(MembershipError::Overflow)?;
            child.pending = Some(PendingMembership {
                request_id: operation.request.id(),
                included_height: height,
                activation_height,
                successor: operation.request.successor(&child.active)?,
            });
        }
        Ok(child)
    }
}
