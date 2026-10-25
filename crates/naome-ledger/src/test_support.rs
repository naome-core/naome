use crate::{Amount, Genesis, Output};
use naome_wallet::WalletKey;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

pub(crate) fn key() -> WalletKey {
    let bytes = hex::decode(concat!(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    ))
    .unwrap();
    WalletKey::from_keypair_bytes(&bytes.try_into().unwrap()).unwrap()
}
pub(crate) fn genesis() -> Genesis {
    Genesis {
        version: 1,
        chain_id: [7; 32],
        outputs: vec![Output {
            address: key().address(),
            amount: Amount::from_units(1000),
        }],
    }
}
pub(crate) struct Directory(pub(crate) PathBuf);
impl Directory {
    pub(crate) fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(
            std::fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!(
                    "naome-ledger-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                )),
        )
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
