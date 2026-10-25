use super::*;
fn create_ledger(owner: &NodeWallet, directory: &Path) -> NetworkId {
    let genesis = naome_ledger::Genesis {
        version: 1,
        chain_id: [1; 32],
        outputs: vec![naome_ledger::Output {
            address: owner.signing_address(),
            amount: Amount::from_units(1000),
        }],
    };
    let network = genesis.network().unwrap();
    drop(Ledger::create(directory, &genesis).unwrap());
    network
}

use std::{
    fs,
    sync::atomic::{AtomicU64, Ordering},
};
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "naome-wallet-service-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        crate::storage::private_directory(&path).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
    fn wallet(&self) -> NodeWallet {
        super::super::initialize(&self.0).unwrap();
        NodeWallet::open(&self.0).unwrap()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn internal_services_share_existing_wallets_and_retain_revocable_full_spending_access() {
    let owner_dir = Directory::new();
    let first_dir = Directory::new();
    let second_dir = Directory::new();
    let recipient_dir = Directory::new();
    let ledger_dir = Directory::new();
    let owner = owner_dir.wallet();
    let first = first_dir.wallet();
    let second = second_dir.wallet();
    let recipient = recipient_dir.wallet();
    let original = fs::read(owner_dir.0.join("wallet.key")).unwrap();
    let network = create_ledger(&owner, &ledger_dir.0);
    owner
        .connect(&ledger_dir.0, network, owner.signing_address())
        .unwrap();
    let unrelated = Directory::new();
    let other_genesis = naome_ledger::Genesis {
        version: 1,
        chain_id: [9; 32],
        outputs: vec![naome_ledger::Output {
            address: owner.signing_address(),
            amount: Amount::from_units(1000),
        }],
    };
    drop(Ledger::create(&unrelated.0, &other_genesis).unwrap());
    assert!(
        owner
            .connect(&unrelated.0, network, owner.signing_address())
            .is_err()
    );
    assert_eq!(owner.status().unwrap().network, Some(network));

    assert!(
        first
            .connect(&ledger_dir.0, network, owner.signing_address())
            .is_err()
    );
    for node in [&first, &second] {
        owner.authorize_node(node.signing_address()).unwrap();
        node.connect(&ledger_dir.0, network, owner.signing_address())
            .unwrap();
        assert_eq!(
            node.status().unwrap().wallet_address,
            Some(owner.signing_address())
        );
    }
    assert!(first.authorize_node(recipient.signing_address()).is_err());
    first
        .pay(recipient.signing_address(), Amount::from_units(300))
        .unwrap();
    second
        .pay(recipient.signing_address(), Amount::from_units(200))
        .unwrap();
    assert_eq!(owner.funds().unwrap().available.units(), 500);
    assert_eq!(owner.funds().unwrap().authorized_nodes.len(), 2);
    let first = NodeWallet::open(&first_dir.0).unwrap();
    let second = NodeWallet::open(&second_dir.0).unwrap();
    assert_eq!(first.funds().unwrap().available.units(), 500);
    owner.revoke_node(first.signing_address()).unwrap();
    assert!(!first.funds().unwrap().can_spend);
    assert!(
        first
            .pay(recipient.signing_address(), Amount::from_units(1))
            .is_err()
    );
    second
        .pay(recipient.signing_address(), Amount::from_units(100))
        .unwrap();
    first.disconnect().unwrap();
    assert_eq!(first.status().unwrap().connection, WalletConnection::Local);
    assert!(
        first
            .connect(&ledger_dir.0, network, owner.signing_address())
            .is_err()
    );
    assert!(second.funds().unwrap().can_spend);
    // The user explicitly chose full access rather than a per-node allowance.
    second
        .pay(recipient.signing_address(), Amount::from_units(400))
        .unwrap();
    assert_eq!(owner.funds().unwrap().available.units(), 0);
    recipient
        .connect(&ledger_dir.0, network, recipient.signing_address())
        .unwrap();
    assert_eq!(recipient.funds().unwrap().available.units(), 1000);
    second.disconnect().unwrap();
    assert!(owner.funds().unwrap().authorized_nodes.is_empty());
    assert_eq!(fs::read(owner_dir.0.join("wallet.key")).unwrap(), original);
    for directory in [&first_dir, &second_dir] {
        assert_ne!(fs::read(directory.0.join("wallet.key")).unwrap(), original);
    }
}

#[test]
fn passive_status_is_bounded_and_available_when_ledger_access_is_busy_or_missing() {
    let directory = Directory::new();
    let ledger_dir = Directory::new();
    assert!(NodeWallet::open(&directory.0).is_err());
    assert!(!directory.0.join("wallet.key").exists());
    let wallet = directory.wallet();
    let network = create_ledger(&wallet, &ledger_dir.0);
    wallet
        .connect(&ledger_dir.0, network, wallet.signing_address())
        .unwrap();
    let locked = Ledger::open(&ledger_dir.0, network).unwrap();
    assert!(
        wallet.funds().is_err(),
        "unavailable funds must never become a zero balance"
    );
    let status = wallet.status().unwrap();
    assert_eq!(status.connection, WalletConnection::Connected);
    assert_eq!(status.wallet_address, Some(wallet.signing_address()));
    assert!(serde_json::to_vec(&status).unwrap().len() < 512);
    drop(locked);
    fs::remove_file(ledger_dir.0.join("ledger.sqlite3")).unwrap();
    assert!(wallet.funds().is_err());
    assert!(
        wallet.disconnect().is_err(),
        "disconnect cannot pretend a missing ledger confirmed revocation"
    );
    assert_eq!(
        wallet.status().unwrap().connection,
        WalletConnection::Connected
    );
    fs::write(directory.0.join("wallet-connection.json"), b"corrupt").unwrap();
    assert_eq!(
        wallet.status().unwrap().connection,
        WalletConnection::Unavailable
    );
    assert!(wallet.status().unwrap().wallet_address.is_none());
}

#[test]
fn a_missing_existing_key_disables_service_payments_without_replacement() {
    let directory = Directory::new();
    let ledger_dir = Directory::new();
    let wallet = directory.wallet();
    let network = create_ledger(&wallet, &ledger_dir.0);
    wallet
        .connect(&ledger_dir.0, network, wallet.signing_address())
        .unwrap();
    fs::remove_file(directory.0.join("wallet.key")).unwrap();
    assert!(!wallet.status().unwrap().key_available);
    assert!(!wallet.funds().unwrap().can_spend);
    assert!(
        wallet
            .pay(wallet.signing_address(), Amount::from_units(1))
            .is_err()
    );
    assert!(!directory.0.join("wallet.key").exists());
    assert_eq!(wallet.funds().unwrap().available.units(), 1000);
}
