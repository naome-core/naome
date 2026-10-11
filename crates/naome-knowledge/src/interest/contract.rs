use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A transport snapshot, never another owner-profile store or authority.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Owner {
    pub version: u8,
    pub revision: u64,
    pub digest: String,
    pub interest: String,
    pub text_sha256: String,
}

impl Owner {
    pub(crate) fn from_profile(profile: crate::runtime::OwnerProfile) -> Result<Self, String> {
        let owner = Self {
            version: profile.version,
            revision: profile.revision,
            digest: profile.digest,
            text_sha256: crate::hex(&Sha256::digest(profile.interest.as_bytes())),
            interest: profile.interest,
        };
        owner.validate()?;
        Ok(owner)
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || self.interest.len() > 1024
            || self.text_sha256 != crate::hex(&Sha256::digest(self.interest.as_bytes()))
        {
            return Err("interest owner transport identity or byte limit differs".into());
        }
        crate::object::id_bytes(&self.digest)?;
        crate::object::id_bytes(&self.text_sha256)?;
        Ok(())
    }

    pub(crate) fn profile_hash(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"naome:owner-interest:profile:v1\0");
        hash.update((self.interest.len() as u64).to_be_bytes());
        hash.update(self.interest.as_bytes());
        crate::hex(&hash.finalize())
    }
}
