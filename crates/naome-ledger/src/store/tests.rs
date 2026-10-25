use super::*;
use crate::{
    Amount,
    test_support::{Directory, genesis, key},
};
use naome_wallet::WalletKey;

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
    assert_eq!(ledger.submit(&payment), Err(Error::MissingInput));
    assert_eq!(fs::read(directory.0.join(DATABASE)).unwrap(), bytes);
    assert_eq!(ledger.state().unwrap(), &expected);
    drop(ledger);
    let ledger = Ledger::open(&directory.0).unwrap();
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
    assert!(matches!(Ledger::open(&directory.0), Err(Error::Busy)));
    drop(ledger);
    let saved = directory.0.join("saved.sqlite3");
    fs::rename(directory.0.join(DATABASE), &saved).unwrap();
    std::os::unix::fs::symlink(&saved, directory.0.join(DATABASE)).unwrap();
    assert!(Ledger::open(&directory.0).is_err());
    fs::remove_file(directory.0.join(DATABASE)).unwrap();
    fs::rename(saved, directory.0.join(DATABASE)).unwrap();
    let ledger = Ledger::open(&directory.0).unwrap();
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
    let mut reopened = Ledger::open(&directory.0).unwrap();
    assert_eq!(reopened.state().unwrap().transaction_count(), 1);
    assert_eq!(reopened.submit(&payment), Err(Error::MissingInput));
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
        let mut ledger = Ledger::open(Path::new(&directory)).unwrap();
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
        let ledger = Ledger::open(&directory.0).unwrap();
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
        assert!(Ledger::open(&directory.0).is_err(), "{corruption}");
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
    other.instance = [8; 32];
    assert!(Ledger::create(&directory.0, &other).is_err());
    let ledger = Ledger::create(&directory.0, &genesis()).unwrap();
    assert_eq!(ledger.state().unwrap().supply().units(), 1000);
    assert_eq!(ledger.state().unwrap().transaction_count(), 0);
    drop(ledger);
    assert!(Ledger::open(&directory.0).is_ok());
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
