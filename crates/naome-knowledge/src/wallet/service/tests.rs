use super::*;
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
fn create_ledger(owner: &NodeWallet, directory: &Path) -> Ledger {
    Ledger::create(
        directory,
        &naome_ledger::Genesis {
            version: 1,
            chain_id: [1; 32],
            outputs: vec![naome_ledger::Output {
                address: owner.signing_address(),
                amount: Amount::from_units(1000),
            }],
        },
    )
    .unwrap()
}
fn pay(wallet: &NodeWallet, ledger: &mut Ledger, recipient: Address, amount: u64) -> TransactionId {
    let request = wallet
        .prepare_payment(ledger, recipient, Amount::from_units(amount))
        .unwrap();
    wallet.submit_payment(ledger, request).unwrap()
}

#[test]
fn internal_services_share_one_checked_session_with_individual_revocation_and_no_key_copy() {
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
    let mut ledger = create_ledger(&owner, &ledger_dir.0);
    let network = ledger.state().unwrap().network();
    owner.connect(&ledger, owner.signing_address()).unwrap();
    // The retained session owns the database. Every following wallet operation
    // would fail Busy if it attempted to open/replay a second ledger handle.
    assert!(matches!(
        Ledger::open(&ledger_dir.0, network),
        Err(naome_ledger::Error::Busy)
    ));
    let unrelated = Directory::new();
    let other = Ledger::create(
        &unrelated.0,
        &naome_ledger::Genesis {
            version: 1,
            chain_id: [9; 32],
            outputs: vec![naome_ledger::Output {
                address: owner.signing_address(),
                amount: Amount::from_units(1000),
            }],
        },
    )
    .unwrap();
    assert!(owner.connect(&other, owner.signing_address()).is_err());
    assert!(matches!(
        owner.funds(&other),
        Err(WalletError::Ledger(naome_ledger::Error::WrongNetwork))
    ));
    assert_eq!(owner.status().unwrap().network, Some(network));
    assert!(matches!(
        first.connect(&ledger, owner.signing_address()),
        Err(WalletError::Ledger(naome_ledger::Error::Unauthorized))
    ));
    for node in [&first, &second] {
        owner
            .authorize_node(&mut ledger, node.signing_address())
            .unwrap();
        node.connect(&ledger, owner.signing_address()).unwrap();
        assert_eq!(
            node.status().unwrap().wallet_address,
            Some(owner.signing_address())
        );
    }
    assert!(matches!(
        first.authorize_node(&mut ledger, recipient.signing_address()),
        Err(WalletError::Ledger(naome_ledger::Error::Unauthorized))
    ));
    pay(&first, &mut ledger, recipient.signing_address(), 300);
    pay(&second, &mut ledger, recipient.signing_address(), 200);
    assert_eq!(owner.funds(&ledger).unwrap().available.units(), 500);
    assert_eq!(owner.funds(&ledger).unwrap().authorized_nodes.len(), 2);
    let first = NodeWallet::open(&first_dir.0).unwrap();
    let second = NodeWallet::open(&second_dir.0).unwrap();
    assert_eq!(first.funds(&ledger).unwrap().available.units(), 500);
    owner
        .revoke_node(&mut ledger, first.signing_address())
        .unwrap();
    assert!(!first.funds(&ledger).unwrap().can_spend);
    assert!(matches!(
        first.prepare_payment(&ledger, recipient.signing_address(), Amount::from_units(1)),
        Err(WalletError::Ledger(naome_ledger::Error::Unauthorized))
    ));
    pay(&second, &mut ledger, recipient.signing_address(), 100);
    first.disconnect(&mut ledger).unwrap();
    assert_eq!(first.status().unwrap().connection, WalletConnection::Local);
    assert!(first.connect(&ledger, owner.signing_address()).is_err());
    assert!(second.funds(&ledger).unwrap().can_spend);
    // Full access remains the selected contract, without a per-node allowance.
    pay(&second, &mut ledger, recipient.signing_address(), 400);
    assert_eq!(owner.funds(&ledger).unwrap().available.units(), 0);
    recipient
        .connect(&ledger, recipient.signing_address())
        .unwrap();
    assert_eq!(recipient.funds(&ledger).unwrap().available.units(), 1000);
    second.disconnect(&mut ledger).unwrap();
    assert!(owner.funds(&ledger).unwrap().authorized_nodes.is_empty());
    assert_eq!(fs::read(owner_dir.0.join("wallet.key")).unwrap(), original);
    for directory in [&first_dir, &second_dir] {
        assert_ne!(fs::read(directory.0.join("wallet.key")).unwrap(), original);
    }
}

#[test]
fn passive_status_remains_bounded_when_the_ledger_is_exclusively_owned_or_missing() {
    let directory = Directory::new();
    let ledger_dir = Directory::new();
    assert!(NodeWallet::open(&directory.0).is_err());
    assert!(!directory.0.join("wallet.key").exists());
    let wallet = directory.wallet();
    let mut ledger = create_ledger(&wallet, &ledger_dir.0);
    wallet.connect(&ledger, wallet.signing_address()).unwrap();
    assert!(matches!(
        Ledger::open(&ledger_dir.0, ledger.state().unwrap().network()),
        Err(naome_ledger::Error::Busy)
    ));
    let status = wallet.status().unwrap();
    assert_eq!(status.connection, WalletConnection::Connected);
    assert_eq!(status.wallet_address, Some(wallet.signing_address()));
    assert!(serde_json::to_vec(&status).unwrap().len() < 512);
    fs::remove_file(ledger_dir.0.join("ledger.sqlite3")).unwrap();
    assert!(
        wallet.funds(&ledger).is_err(),
        "unavailable funds never become a zero balance"
    );
    assert!(
        wallet.disconnect(&mut ledger).is_err(),
        "missing state cannot confirm revocation"
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
fn a_missing_existing_key_disables_submission_without_replacement() {
    let directory = Directory::new();
    let ledger_dir = Directory::new();
    let wallet = directory.wallet();
    let mut ledger = create_ledger(&wallet, &ledger_dir.0);
    wallet.connect(&ledger, wallet.signing_address()).unwrap();
    let request = wallet
        .prepare_payment(&ledger, wallet.signing_address(), Amount::from_units(1))
        .unwrap();
    fs::remove_file(directory.0.join("wallet.key")).unwrap();
    assert!(!wallet.status().unwrap().key_available);
    assert!(!wallet.funds(&ledger).unwrap().can_spend);
    assert!(wallet.submit_payment(&mut ledger, request).is_err());
    assert!(!directory.0.join("wallet.key").exists());
    assert_eq!(wallet.funds(&ledger).unwrap().available.units(), 1000);
    assert_eq!(ledger.state().unwrap().transaction_count(), 0);
}

#[test]
fn corrupt_or_redirected_prepared_records_never_create_a_payment() {
    let directory = Directory::new();
    let ledger_dir = Directory::new();
    let wallet = directory.wallet();
    let mut ledger = create_ledger(&wallet, &ledger_dir.0);
    wallet.connect(&ledger, wallet.signing_address()).unwrap();
    let recipient = WalletKey::generate().unwrap().address();
    let request = wallet
        .prepare_payment(&ledger, recipient, Amount::from_units(300))
        .unwrap();
    let path = directory
        .0
        .join("wallet-payments")
        .join(request.to_string());
    let bytes = fs::read(&path).unwrap();
    let mut forged: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    forged["operation"]["outputs"][0]["amount"] = serde_json::json!(301);
    fs::write(&path, serde_json::to_vec(&forged).unwrap()).unwrap();
    assert!(wallet.submit_payment(&mut ledger, request).is_err());
    let saved = directory.0.join("saved-payment");
    fs::write(&saved, &bytes).unwrap();
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&saved, &path).unwrap();
    assert!(wallet.submit_payment(&mut ledger, request).is_err());
    assert_eq!(ledger.state().unwrap().transaction_count(), 0);
    assert_eq!(
        ledger.state().unwrap().balance(recipient).unwrap().units(),
        0
    );
    fs::remove_file(&path).unwrap();
    fs::write(&path, bytes).unwrap();
    wallet.submit_payment(&mut ledger, request).unwrap();
    assert_eq!(
        ledger.state().unwrap().balance(recipient).unwrap().units(),
        300
    );
}

#[test]
fn host_session_reserves_memory_and_releases_it_on_cancelled_open_or_close() {
    const CHILD: &str = "NAOME_WALLET_SESSION_MEMORY_TEST";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "wallet::service::tests::host_session_reserves_memory_and_releases_it_on_cancelled_open_or_close", "--nocapture"])
            .env(CHILD, "1").output().unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    let directory = Directory::new();
    let ledger_dir = Directory::new();
    let wallet = directory.wallet();
    let ledger = create_ledger(&wallet, &ledger_dir.0);
    let network = ledger.state().unwrap().network();
    wallet.connect(&ledger, wallet.signing_address()).unwrap();
    drop(ledger);
    let baseline = crate::resources::memory_usage().0;
    let policy = crate::resources::limits();
    let reservation =
        policy.ledger_state_bytes + policy.ledger_cache_bytes + 16 * naome_ledger::MAX_RECORD_BYTES;
    crate::resources::fail_next_memory_allocation();
    assert!(matches!(
        wallet.open_ledger(network, &Control::default()),
        Err(WalletError::Host(crate::Error::MemoryOverload { .. }))
    ));
    assert_eq!(crate::resources::memory_usage().0, baseline);
    let session = wallet.open_ledger(network, &Control::default()).unwrap();
    assert_eq!(crate::resources::memory_usage().0, baseline + reservation);
    assert_eq!(session.state().unwrap().transaction_count(), 0);
    assert!(matches!(
        wallet.open_ledger(network, &Control::default()),
        Err(WalletError::Ledger(naome_ledger::Error::Busy))
    ));
    assert_eq!(wallet.funds(&session).unwrap().available.units(), 1000);
    assert_eq!(crate::resources::memory_usage().0, baseline + reservation);
    drop(session);
    assert_eq!(crate::resources::memory_usage().0, baseline);
    let cancelled = Control::default();
    cancelled.cancel();
    assert!(matches!(
        wallet.open_ledger(network, &cancelled),
        Err(WalletError::Ledger(naome_ledger::Error::Cancelled))
    ));
    assert_eq!(crate::resources::memory_usage().0, baseline);
    let mut session = wallet.open_ledger(network, &Control::default()).unwrap();
    let request = wallet
        .prepare_payment(&session, wallet.signing_address(), Amount::from_units(1))
        .unwrap();
    assert!(matches!(
        wallet.submit_payment_with_control(&mut session, request, &cancelled),
        Err(WalletError::Ledger(naome_ledger::Error::Cancelled))
    ));
    assert_eq!(session.state().unwrap().transaction_count(), 0);
    wallet.submit_payment(&mut session, request).unwrap();
    assert_eq!(session.state().unwrap().transaction_count(), 1);
    drop(session);
    assert_eq!(crate::resources::memory_usage().0, baseline);
}

#[test]
fn a_resource_rejection_preserves_the_prepared_request_for_a_larger_host_budget() {
    let directory = Directory::new();
    let ledger_dir = Directory::new();
    let wallet = directory.wallet();
    let ledger = create_ledger(&wallet, &ledger_dir.0);
    let network = ledger.state().unwrap().network();
    let minimum = ledger.state().unwrap().state_bytes();
    wallet.connect(&ledger, wallet.signing_address()).unwrap();
    drop(ledger);
    let mut ledger = Ledger::open_with_limits(
        &ledger_dir.0,
        network,
        naome_ledger::Limits {
            state_bytes: minimum,
            ..naome_ledger::Limits::default()
        },
        &Control::default(),
    )
    .unwrap();
    let recipient = WalletKey::generate().unwrap().address();
    let request = wallet
        .prepare_payment(&ledger, recipient, Amount::from_units(300))
        .unwrap();
    assert!(matches!(
        wallet.submit_payment(&mut ledger, request),
        Err(WalletError::Ledger(
            naome_ledger::Error::ResourceLimit { .. }
        ))
    ));
    assert_eq!(ledger.state().unwrap().transaction_count(), 0);
    assert_eq!(
        wallet.payment_status(&ledger, request).unwrap(),
        PaymentStatus::Prepared
    );
    drop(ledger);
    let mut ledger = Ledger::open(&ledger_dir.0, network).unwrap();
    assert_eq!(
        wallet.submit_payment(&mut ledger, request).unwrap(),
        request
    );
    assert_eq!(
        wallet.submit_payment(&mut ledger, request).unwrap(),
        request
    );
    assert_eq!(
        ledger.state().unwrap().balance(recipient).unwrap().units(),
        300
    );
    assert_eq!(ledger.state().unwrap().transaction_count(), 1);
}

#[test]
fn retry_after_a_lost_process_result_reuses_the_durable_request_and_pays_once() {
    const CHILD: &str = "NAOME_WALLET_LOST_PAYMENT_RESULT";
    if let Some(input) = std::env::var_os(CHILD) {
        let paths: (PathBuf, PathBuf, NetworkId, TransactionId) =
            serde_json::from_slice(&fs::read(input).unwrap()).unwrap();
        let wallet = NodeWallet::open(&paths.0).unwrap();
        let mut ledger = Ledger::open(&paths.1, paths.2).unwrap();
        wallet.submit_payment(&mut ledger, paths.3).unwrap();
        std::process::exit(87);
    }
    let directory = Directory::new();
    let ledger_dir = Directory::new();
    let recipient = WalletKey::generate().unwrap().address();
    let wallet = directory.wallet();
    let mut ledger = create_ledger(&wallet, &ledger_dir.0);
    let network = ledger.state().unwrap().network();
    wallet.connect(&ledger, wallet.signing_address()).unwrap();
    let request = wallet
        .prepare_payment(&ledger, recipient, Amount::from_units(300))
        .unwrap();
    assert_eq!(
        wallet.payment_status(&ledger, request).unwrap(),
        PaymentStatus::Prepared
    );
    assert_eq!(wallet.funds(&ledger).unwrap().available.units(), 1000);
    drop(ledger);
    let input = directory.0.join("child-input.json");
    fs::write(
        &input,
        serde_json::to_vec(&(&directory.0, &ledger_dir.0, network, request)).unwrap(),
    )
    .unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "wallet::service::tests::retry_after_a_lost_process_result_reuses_the_durable_request_and_pays_once"])
        .env(CHILD, &input).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().unwrap();
    assert_eq!(status.code(), Some(87));
    let wallet = NodeWallet::open(&directory.0).unwrap();
    ledger = Ledger::open(&ledger_dir.0, network).unwrap();
    assert_eq!(
        wallet.payment_status(&ledger, request).unwrap(),
        PaymentStatus::Committed
    );
    assert_eq!(
        wallet.submit_payment(&mut ledger, request).unwrap(),
        request
    );
    assert_eq!(
        wallet.submit_payment(&mut ledger, request).unwrap(),
        request
    );
    assert_eq!(ledger.state().unwrap().transaction_count(), 1);
    assert_eq!(
        ledger.state().unwrap().balance(recipient).unwrap().units(),
        300
    );
    assert_eq!(wallet.funds(&ledger).unwrap().available.units(), 700);
    fs::remove_file(
        directory
            .0
            .join("wallet-payments")
            .join(request.to_string()),
    )
    .unwrap();
    assert!(wallet.submit_payment(&mut ledger, request).is_err());
    assert_eq!(ledger.state().unwrap().transaction_count(), 1);
}
