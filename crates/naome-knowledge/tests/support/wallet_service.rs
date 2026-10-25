use naome_knowledge::{NodeWallet, WalletConnection, runtime::Status};
use naome_ledger::{Amount, Ledger};
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
    // Isolated fixture allocations use the production ledger path and a separate network.
    let genesis = naome_ledger::Genesis {
        version: 1,
        chain_id: [2; 32],
        outputs: vec![naome_ledger::Output {
            address: owner.signing_address(),
            amount: Amount::from_units(1000),
        }],
    };
    let network = genesis.network().unwrap();
    if input.phase == "initial" {
        let ledger = Ledger::create(&input.ledger, &genesis).unwrap();
        owner.connect(&ledger, owner.signing_address()).unwrap();
    }
    let mut ledger = owner
        .open_ledger(network, &naome_ledger::Control::default())
        .unwrap();
    if input.phase == "initial" {
        owner.connect(&ledger, owner.signing_address()).unwrap();
        assert!(first.connect(&ledger, owner.signing_address()).is_err());
        for node in [&first, &second] {
            owner
                .authorize_node(&mut ledger, node.signing_address())
                .unwrap();
            node.connect(&ledger, owner.signing_address()).unwrap();
        }
        assert!(
            first
                .authorize_node(&mut ledger, owner.signing_address())
                .is_err()
        );
        let request = first
            .prepare_payment(&ledger, first.signing_address(), Amount::from_units(300))
            .unwrap();
        first.submit_payment(&mut ledger, request).unwrap();
        let request = second
            .prepare_payment(&ledger, first.signing_address(), Amount::from_units(200))
            .unwrap();
        second.submit_payment(&mut ledger, request).unwrap();
        assert_eq!(owner.funds(&ledger).unwrap().available.units(), 500);
        for index in 0..3 {
            let report = status(&input, index);
            assert!(report.running);
            let wallet = report.wallet.unwrap();
            assert_eq!(wallet.connection, WalletConnection::Connected);
            assert_eq!(wallet.wallet_address, Some(owner.signing_address()));
        }
        // Passive node observation must not contend for, or replay, the ledger.
        assert!(matches!(
            Ledger::open(&input.ledger, network),
            Err(naome_ledger::Error::Busy)
        ));
        assert!(status(&input, 1).running);
    } else {
        assert_eq!(input.phase, "restarted");
        assert_eq!(owner.funds(&ledger).unwrap().available.units(), 500);
        assert!(
            first.funds(&ledger).unwrap().can_spend && second.funds(&ledger).unwrap().can_spend
        );
        owner
            .revoke_node(&mut ledger, first.signing_address())
            .unwrap();
        assert!(!first.funds(&ledger).unwrap().can_spend);
        assert!(
            first
                .prepare_payment(&ledger, first.signing_address(), Amount::from_units(1))
                .is_err()
        );
        first.disconnect(&mut ledger).unwrap();
        assert_eq!(
            status(&input, 1).wallet.unwrap().connection,
            WalletConnection::Local
        );
        assert!(first.connect(&ledger, owner.signing_address()).is_err());
        // The remaining authorized node can spend the entire available balance.
        let request = second
            .prepare_payment(&ledger, first.signing_address(), Amount::from_units(500))
            .unwrap();
        second.submit_payment(&mut ledger, request).unwrap();
        assert_eq!(owner.funds(&ledger).unwrap().available.units(), 0);
        second.disconnect(&mut ledger).unwrap();
        assert!(owner.funds(&ledger).unwrap().authorized_nodes.is_empty());
        first.connect(&ledger, first.signing_address()).unwrap();
        assert_eq!(first.funds(&ledger).unwrap().available.units(), 1000);
    }
}
