use std::cell::Cell;
thread_local! { static REPLAY: Cell<(usize, Option<usize>)> = const { Cell::new((0, None)) }; }
pub(super) fn replayed(control: &crate::Control) {
    REPLAY.with(|counter| {
        let (count, stop) = counter.get();
        counter.set((count + 1, stop));
        if stop == Some(count + 1) {
            control.cancel();
        }
    });
}
use super::*;
use crate::{
    Amount,
    test_support::{Directory, genesis, key},
};
use naome_wallet::WalletKey;

#[test]
fn cancelled_or_over_budget_replay_releases_custody_without_changing_history() {
    let directory = Directory::new();
    let owner = key();
    let mut ledger = Ledger::create(&directory.0, &genesis()).unwrap();
    let minimum = ledger.state().unwrap().state_bytes();
    for _ in 0..3 {
        let payment = ledger
            .state()
            .unwrap()
            .payment(
                owner.address(),
                &owner,
                owner.address(),
                Amount::from_units(1000),
            )
            .unwrap();
        ledger.submit(&payment).unwrap();
    }
    let expected = ledger.state().unwrap().clone();
    drop(ledger);
    let bytes = fs::read(directory.0.join(DATABASE)).unwrap();
    let network = genesis().network().unwrap();
    let limits = Limits {
        state_bytes: minimum - 1,
        ..Limits::default()
    };
    assert!(matches!(
        Ledger::open_with_limits(&directory.0, network, limits, &Control::default()),
        Err(Error::ResourceLimit { .. })
    ));
    let deadline = Control::until(std::time::Instant::now());
    assert!(matches!(
        Ledger::open_with_limits(&directory.0, network, Limits::default(), &deadline),
        Err(Error::Deadline)
    ));
    REPLAY.with(|counter| counter.set((0, Some(2))));
    assert!(matches!(
        Ledger::open_with_limits(
            &directory.0,
            network,
            Limits::default(),
            &Control::default()
        ),
        Err(Error::Cancelled)
    ));
    assert_eq!(REPLAY.with(|counter| counter.get().0), 2);
    REPLAY.with(|counter| counter.set((0, None)));
    assert_eq!(fs::read(directory.0.join(DATABASE)).unwrap(), bytes);
    let ledger = Ledger::open(&directory.0, network).unwrap();
    assert_eq!(ledger.state().unwrap(), &expected);
    assert_eq!(REPLAY.with(|counter| counter.get().0), 3);
}

#[test]
fn cancellation_during_staging_rolls_back_and_allows_a_fresh_operation() {
    let directory = Directory::new();
    let owner = key();
    let mut ledger = Ledger::create(&directory.0, &genesis()).unwrap();
    let payment = ledger
        .state()
        .unwrap()
        .payment(
            owner.address(),
            &owner,
            owner.address(),
            Amount::from_units(1),
        )
        .unwrap();
    let before = ledger.state().unwrap().clone();
    let control = Control::default();
    assert_eq!(
        ledger.submit_controlled(&payment, &control, |_| {
            control.cancel();
            Ok(())
        }),
        Err(Error::Cancelled)
    );
    assert_eq!(ledger.state().unwrap(), &before);
    assert_eq!(ledger.transaction(payment.id().unwrap()).unwrap(), None);
    assert_eq!(ledger.submit(&payment).unwrap(), payment.id().unwrap());
    assert_eq!(ledger.state().unwrap().transaction_count(), 1);
}

#[test]
fn an_unconfirmed_rollback_poisoning_blocks_cached_reads_and_subsequent_writes() {
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
    let directory = Directory::new();
    let owner = key();
    let mut ledger = Ledger::create(&directory.0, &genesis()).unwrap();
    let payment = ledger
        .state()
        .unwrap()
        .payment(
            owner.address(),
            &owner,
            owner.address(),
            Amount::from_units(1),
        )
        .unwrap();
    ledger
        .connection
        .authorizer(Some(|context: AuthContext<'_>| {
            if matches!(
                context.action,
                AuthAction::Transaction {
                    operation: TransactionOperation::Rollback
                }
            ) {
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }))
        .unwrap();
    assert_eq!(
        ledger.submit_at(&payment, |_| Err(Error::Invalid("rejected before commit"))),
        Err(Error::RecoveryRequired)
    );
    assert_eq!(ledger.state(), Err(Error::RecoveryRequired));
    assert_eq!(ledger.submit(&payment), Err(Error::RecoveryRequired));
    ledger
        .connection
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
        .unwrap();
    drop(ledger);
    let ledger = Ledger::open(&directory.0, genesis().network().unwrap()).unwrap();
    assert_eq!(ledger.state().unwrap().transaction_count(), 0);
    assert_eq!(
        ledger
            .state()
            .unwrap()
            .balance(owner.address())
            .unwrap()
            .units(),
        1000
    );
}

#[test]
fn in_place_database_changes_invalidate_a_retained_session() {
    let directory = Directory::new();
    let mut ledger = Ledger::create(&directory.0, &genesis()).unwrap();
    let payment = ledger
        .state()
        .unwrap()
        .payment(
            key().address(),
            &key(),
            key().address(),
            Amount::from_units(1),
        )
        .unwrap();
    OpenOptions::new()
        .write(true)
        .open(directory.0.join(DATABASE))
        .unwrap()
        .set_len(0)
        .unwrap();
    assert!(ledger.state().is_err());
    assert!(ledger.submit(&payment).is_err());
}

#[test]
fn a_partial_unpublished_identity_receipt_can_resume_but_an_active_receipt_cannot_be_recreated() {
    let directory = Directory::new();
    drop(Ledger::create(&directory.0, &genesis()).unwrap());
    connect(&directory.0.join(DATABASE))
        .unwrap()
        .execute("UPDATE metadata SET active=0", [])
        .unwrap();
    fs::remove_file(directory.0.join(RECEIPT)).unwrap();
    write_new(&directory.0.join(PENDING_RECEIPT), b"{\"version\":").unwrap();
    let ledger = Ledger::open(&directory.0, genesis().network().unwrap()).unwrap();
    assert_eq!(ledger.state().unwrap().transaction_count(), 0);
    assert_eq!(ledger.state().unwrap().supply().units(), 1000);
    assert!(!directory.0.join(PENDING_RECEIPT).exists());
    drop(ledger);
    fs::remove_file(directory.0.join(RECEIPT)).unwrap();
    assert!(Ledger::open(&directory.0, genesis().network().unwrap()).is_err());
}

#[test]
fn first_creation_resumes_an_empty_stage_without_replacing_an_established_ledger() {
    let directory = Directory::new();
    fs::create_dir(&directory.0).unwrap();
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
    drop(new_file(&directory.0.join(PENDING)).unwrap());
    let ledger = Ledger::create(&directory.0, &genesis()).unwrap();
    assert_eq!(ledger.state().unwrap().supply().units(), 1000);
    assert_eq!(ledger.state().unwrap().transaction_count(), 0);
    drop(ledger);
    assert!(Ledger::create(&directory.0, &genesis()).is_err());
    assert_eq!(
        Ledger::open(&directory.0, genesis().network().unwrap())
            .unwrap()
            .state()
            .unwrap()
            .supply()
            .units(),
        1000
    );
}

#[test]
fn accepted_payments_reopen_with_the_same_state_and_rejections_do_not_change_disk() {
    let directory = Directory::new();
    let alice = key();
    let bob = WalletKey::generate().unwrap();
    let mut ledger = Ledger::create(&directory.0, &genesis()).unwrap();
    let payment = ledger
        .state()
        .unwrap()
        .payment(
            alice.address(),
            &alice,
            bob.address(),
            Amount::from_units(300),
        )
        .unwrap();
    ledger.submit(&payment).unwrap();
    let expected = ledger.state().unwrap().clone();
    let bytes = fs::read(directory.0.join(DATABASE)).unwrap();
    assert_eq!(ledger.submit(&payment), Ok(payment.id().unwrap()));
    assert_eq!(fs::read(directory.0.join(DATABASE)).unwrap(), bytes);
    assert_eq!(ledger.state().unwrap(), &expected);
    drop(ledger);
    let ledger = Ledger::open(&directory.0, genesis().network().unwrap()).unwrap();
    assert_eq!(ledger.state().unwrap(), &expected);
    assert_eq!(
        ledger
            .state()
            .unwrap()
            .balance(bob.address())
            .unwrap()
            .units(),
        300
    );
    assert!(Ledger::create(&directory.0, &genesis()).is_err());
}

#[test]
fn simultaneous_owners_are_excluded_and_directory_or_link_misuse_is_rejected() {
    let directory = Directory::new();
    let ledger = Ledger::create(&directory.0, &genesis()).unwrap();
    assert!(matches!(
        Ledger::open(&directory.0, genesis().network().unwrap()),
        Err(Error::Busy)
    ));
    drop(ledger);
    let saved = directory.0.join("saved.sqlite3");
    fs::rename(directory.0.join(DATABASE), &saved).unwrap();
    std::os::unix::fs::symlink(&saved, directory.0.join(DATABASE)).unwrap();
    assert!(Ledger::open(&directory.0, genesis().network().unwrap()).is_err());
    fs::remove_file(directory.0.join(DATABASE)).unwrap();
    fs::rename(saved, directory.0.join(DATABASE)).unwrap();
    let ledger = Ledger::open(&directory.0, genesis().network().unwrap()).unwrap();
    drop(ledger);
    let unrelated = Directory::new();
    fs::create_dir(&unrelated.0).unwrap();
    fs::write(unrelated.0.join("unrelated.txt"), "keep").unwrap();
    assert!(Ledger::create(&unrelated.0, &genesis()).is_err());
    assert_eq!(
        fs::read_to_string(unrelated.0.join("unrelated.txt")).unwrap(),
        "keep"
    );
}

#[test]
fn an_uncertain_commit_requires_reopen_and_does_not_allow_a_second_spend() {
    let directory = Directory::new();
    let key = key();
    let mut ledger = Ledger::create(&directory.0, &genesis()).unwrap();
    let payment = ledger
        .state()
        .unwrap()
        .payment(key.address(), &key, key.address(), Amount::from_units(300))
        .unwrap();
    assert_eq!(
        ledger.submit_at(&payment, |step| if step == 1 {
            Err(Error::Invalid("injected before commit"))
        } else {
            Ok(())
        }),
        Err(Error::Invalid("injected before commit"))
    );
    assert_eq!(ledger.state().unwrap().transaction_count(), 0);
    assert_eq!(
        ledger.submit_at(&payment, |step| if step == 2 {
            Err(Error::Invalid("injected after commit"))
        } else {
            Ok(())
        }),
        Err(Error::RecoveryRequired)
    );
    assert_eq!(ledger.state(), Err(Error::RecoveryRequired));
    assert_eq!(ledger.submit(&payment), Err(Error::RecoveryRequired));
    drop(ledger);
    let mut reopened = Ledger::open(&directory.0, genesis().network().unwrap()).unwrap();
    assert_eq!(reopened.state().unwrap().transaction_count(), 1);
    assert_eq!(reopened.submit(&payment), Ok(payment.id().unwrap()));
}

#[test]
fn abrupt_process_exit_before_and_after_commit_recovers_the_correct_transaction_boundary() {
    const CHILD: &str = "NAOME_TEST_LEDGER_CRASH";
    if let Some(directory) = std::env::var_os(CHILD) {
        let stage: u8 = std::env::var("NAOME_TEST_LEDGER_STAGE")
            .unwrap()
            .parse()
            .unwrap();
        let key = key();
        let mut ledger = Ledger::open(Path::new(&directory), genesis().network().unwrap()).unwrap();
        let payment = ledger
            .state()
            .unwrap()
            .payment(key.address(), &key, key.address(), Amount::from_units(300))
            .unwrap();
        let _ = ledger.submit_at(&payment, |at| {
            if at == stage {
                std::process::exit(87);
            }
            Ok(())
        });
        panic!("crash boundary was not reached");
    }
    for stage in [1, 2] {
        let directory = Directory::new();
        drop(Ledger::create(&directory.0, &genesis()).unwrap());
        let status=std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact","store::tests::abrupt_process_exit_before_and_after_commit_recovers_the_correct_transaction_boundary"])
            .env(CHILD,&directory.0).env("NAOME_TEST_LEDGER_STAGE",stage.to_string())
            .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
            .status().unwrap();
        assert_eq!(status.code(), Some(87));
        let ledger = Ledger::open(&directory.0, genesis().network().unwrap()).unwrap();
        assert_eq!(
            ledger.state().unwrap().transaction_count(),
            u64::from(stage == 2)
        );
        assert_eq!(
            ledger
                .state()
                .unwrap()
                .balance(key().address())
                .unwrap()
                .units(),
            1000
        );
    }
}

#[test]
fn replay_detects_changed_signatures_deleted_records_and_receipt_or_database_loss() {
    for corruption in ["payload", "delete", "head", "receipt", "database"] {
        let directory = Directory::new();
        let key = key();
        let mut ledger = Ledger::create(&directory.0, &genesis()).unwrap();
        let payment = ledger
            .state()
            .unwrap()
            .payment(key.address(), &key, key.address(), Amount::from_units(300))
            .unwrap();
        ledger.submit(&payment).unwrap();
        drop(ledger);
        match corruption {
            "payload" => {
                let mut value = serde_json::to_value(&payment).unwrap();
                value["signature"] = serde_json::json!("00".repeat(64));
                let connection = connect(&directory.0.join(DATABASE)).unwrap();
                connection
                    .execute(
                        "UPDATE events SET payload=?1",
                        [serde_json::to_vec(&value).unwrap()],
                    )
                    .unwrap();
            }
            "delete" => {
                connect(&directory.0.join(DATABASE))
                    .unwrap()
                    .execute("DELETE FROM events", [])
                    .unwrap();
            }
            "head" => {
                connect(&directory.0.join(DATABASE))
                    .unwrap()
                    .execute("UPDATE metadata SET head=zeroblob(32)", [])
                    .unwrap();
            }
            "receipt" => fs::remove_file(directory.0.join(RECEIPT)).unwrap(),
            "database" => fs::remove_file(directory.0.join(DATABASE)).unwrap(),
            _ => unreachable!(),
        }
        assert!(
            Ledger::open(&directory.0, genesis().network().unwrap()).is_err(),
            "{corruption}"
        );
        assert!(
            Ledger::create(&directory.0, &genesis()).is_err(),
            "{corruption}"
        );
    }
}

#[test]
fn interrupted_initial_activation_recovers_only_the_same_empty_genesis() {
    let directory = Directory::new();
    drop(Ledger::create(&directory.0, &genesis()).unwrap());
    connect(&directory.0.join(DATABASE))
        .unwrap()
        .execute("UPDATE metadata SET active=0", [])
        .unwrap();
    fs::remove_file(directory.0.join(RECEIPT)).unwrap();
    fs::rename(directory.0.join(DATABASE), directory.0.join(PENDING)).unwrap();
    let mut other = genesis();
    other.chain_id = [8; 32];
    assert!(Ledger::create(&directory.0, &other).is_err());
    let ledger = Ledger::create(&directory.0, &genesis()).unwrap();
    assert_eq!(ledger.state().unwrap().supply().units(), 1000);
    assert_eq!(ledger.state().unwrap().transaction_count(), 0);
    drop(ledger);
    assert!(Ledger::open(&directory.0, genesis().network().unwrap()).is_ok());
}

#[test]
fn active_custody_excludes_external_sql_writes_and_detects_file_replacement() {
    let directory = Directory::new();
    let key = key();
    let mut ledger = Ledger::create(&directory.0, &genesis()).unwrap();
    let other = Connection::open(directory.0.join(DATABASE)).unwrap();
    other.busy_timeout(std::time::Duration::ZERO).unwrap();
    assert!(other.execute("DELETE FROM events", []).is_err());
    drop(other);
    assert_eq!(
        ledger
            .state()
            .unwrap()
            .balance(key.address())
            .unwrap()
            .units(),
        1000
    );
    let payment = ledger
        .state()
        .unwrap()
        .payment(key.address(), &key, key.address(), Amount::from_units(1))
        .unwrap();
    let moved = directory.0.join("moved.sqlite3");
    fs::rename(directory.0.join(DATABASE), &moved).unwrap();
    fs::copy(&moved, directory.0.join(DATABASE)).unwrap();
    assert!(ledger.state().is_err());
    assert!(ledger.submit(&payment).is_err());
}

#[test]
fn opening_requires_the_selected_network_and_an_empty_genesis_does_not_create_coins() {
    let directory = Directory::new();
    let empty = Genesis {
        version: 1,
        chain_id: [9; 32],
        outputs: vec![],
    };
    let network = empty.network().unwrap();
    let ledger = Ledger::create(&directory.0, &empty).unwrap();
    assert_eq!(ledger.state().unwrap().supply().units(), 0);
    assert_eq!(
        ledger
            .state()
            .unwrap()
            .balance(key().address())
            .unwrap()
            .units(),
        0
    );
    drop(ledger);
    assert!(matches!(
        Ledger::open(&directory.0, genesis().network().unwrap()),
        Err(Error::WrongNetwork)
    ));
    let ledger = Ledger::open(&directory.0, network).unwrap();
    assert_eq!(ledger.state().unwrap().supply().units(), 0);
}
