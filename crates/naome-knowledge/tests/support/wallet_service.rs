use naome_knowledge::{NodeWallet, WalletConnection, runtime::Status};
use naome_ledger::Amount;
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Deserialize)]
struct Input {
    phase: String,
    directories: [PathBuf; 3],
    ledger: PathBuf,
    binary: PathBuf,
}
fn status(input: &Input, index: usize) -> Status {
    let output = Command::new(&input.binary)
        .args(["--json", "status"])
        .env("NAOME_NODE_DIR", &input.directories[index])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
pub(super) fn run(path: &Path) {
    let input: Input = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let owner = NodeWallet::open(&input.directories[0]).unwrap();
    let first = NodeWallet::open(&input.directories[1]).unwrap();
    let second = NodeWallet::open(&input.directories[2]).unwrap();
    if input.phase == "initial" {
        owner
            .create_test_ledger(&input.ledger, Amount::from_units(1000))
            .unwrap();
        owner
            .connect(&input.ledger, owner.signing_address())
            .unwrap();
        assert!(
            first
                .connect(&input.ledger, owner.signing_address())
                .is_err()
        );
        for node in [&first, &second] {
            owner.authorize_node(node.signing_address()).unwrap();
            node.connect(&input.ledger, owner.signing_address())
                .unwrap();
        }
        assert!(first.authorize_node(owner.signing_address()).is_err());
        first
            .pay(first.signing_address(), Amount::from_units(300))
            .unwrap();
        second
            .pay(first.signing_address(), Amount::from_units(200))
            .unwrap();
        assert_eq!(owner.funds().unwrap().available.units(), 500);
        for index in 0..3 {
            let report = status(&input, index);
            assert!(report.running);
            let wallet = report.wallet.unwrap();
            assert_eq!(wallet.connection, WalletConnection::Connected);
            assert_eq!(wallet.wallet_address, Some(owner.signing_address()));
        }
        // Passive node observation must not contend for, or replay, the ledger.
        let locked = naome_ledger::Ledger::open(&input.ledger).unwrap();
        assert!(status(&input, 1).running);
        drop(locked);
    } else {
        assert_eq!(input.phase, "restarted");
        assert_eq!(owner.funds().unwrap().available.units(), 500);
        assert!(first.funds().unwrap().can_spend && second.funds().unwrap().can_spend);
        owner.revoke_node(first.signing_address()).unwrap();
        assert!(!first.funds().unwrap().can_spend);
        assert!(
            first
                .pay(first.signing_address(), Amount::from_units(1))
                .is_err()
        );
        first.disconnect().unwrap();
        assert_eq!(
            status(&input, 1).wallet.unwrap().connection,
            WalletConnection::Local
        );
        assert!(
            first
                .connect(&input.ledger, owner.signing_address())
                .is_err()
        );
        // The remaining authorized node can spend the entire available balance.
        second
            .pay(first.signing_address(), Amount::from_units(500))
            .unwrap();
        assert_eq!(owner.funds().unwrap().available.units(), 0);
        second.disconnect().unwrap();
        assert!(owner.funds().unwrap().authorized_nodes.is_empty());
        first
            .connect(&input.ledger, first.signing_address())
            .unwrap();
        assert_eq!(first.funds().unwrap().available.units(), 1000);
    }
}
