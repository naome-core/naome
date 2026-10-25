//! Explicit local test-coin commands using existing wallet custody.
use super::{print, read_bounded, store};
use crate::wallet::connection::{self, Connection};
use naome_ledger::{Amount, Ledger, Output, SignedTransaction, TestGenesis};
use naome_wallet::Address;
use std::{ffi::OsString, path::Path};

pub(super) const USAGE: &str = "usage: naome wallet connect <ledger-dir> <wallet-address> | wallet connection | wallet disconnect | wallet test-coins init <ledger-dir> <units> | wallet test-coins balance <ledger-dir> [address] | wallet test-coins send|prepare <ledger-dir> <recipient> <units> | wallet test-coins submit <ledger-dir> <transaction.json> | wallet test-coins authorize|revoke <ledger-dir> <node-wallet-address>";

fn address(value: &OsString) -> Result<Address, String> {
    value
        .to_str()
        .ok_or("wallet address must be UTF-8")?
        .parse()
}
fn amount(value: &OsString) -> Result<Amount, String> {
    value
        .to_str()
        .ok_or("amount must be UTF-8")?
        .parse()
        .map_err(|error: naome_ledger::Error| error.to_string())
}
fn fail(error: naome_ledger::Error) -> String {
    error.to_string()
}
fn owner(directory: &Path, ledger_path: &Path, ledger: &Ledger) -> Result<Address, String> {
    if let Some(connection) = connection::read(directory)? {
        if connection.network != ledger.state().map_err(fail)?.network()
            || connection.ledger
                != std::fs::canonicalize(ledger_path).map_err(|error| error.to_string())?
        {
            return Err("wallet connection belongs to another test ledger".into());
        }
        Ok(connection.wallet)
    } else {
        Ok(store::identity(directory)?
            .ok_or("wallet is not initialized; start the node first")?
            .address)
    }
}

pub(super) async fn execute(arguments: &[OsString]) -> Result<(), String> {
    match arguments {
        [command] if command == "connection" => {
            let directory = super::super::directory()?;
            let Some(connection) = connection::read(&directory)? else {
                return print(&serde_json::json!({"connected":false,"scope":"local_test_coins"}));
            };
            let ledger = Ledger::open(&connection.ledger).map_err(fail)?;
            if ledger.state().map_err(fail)?.network() != connection.network {
                return Err("wallet connection network mismatch".into());
            }
            print(
                &serde_json::json!({"connected":true,"connection":connection,"can_spend":ledger.state().map_err(fail)?.spending_authority(connection.wallet,connection.signer).is_some(),"scope":"local_test_coins"}),
            )
        }
        [command, path, wallet] if command == "connect" => {
            let directory = super::super::directory()?;
            let _guard = super::super::operation_lock(&directory).await?;
            let key = store::key(&directory)?;
            let wallet = address(wallet)?;
            let path = std::fs::canonicalize(Path::new(path)).map_err(|error| error.to_string())?;
            let ledger = Ledger::open(&path).map_err(fail)?;
            let state = ledger.state().map_err(fail)?;
            if state.spending_authority(wallet, key.address()).is_none() {
                return Err(
                    "wallet must first authorize this node's wallet address in the test ledger"
                        .into(),
                );
            }
            let connection = Connection {
                version: 1,
                ledger: path,
                network: state.network(),
                wallet,
                signer: key.address(),
            };
            connection::save(&directory, &connection)?;
            print(
                &serde_json::json!({"connected":true,"connection":connection,"can_spend":true,"scope":"local_test_coins"}),
            )
        }
        [command] if command == "disconnect" => {
            let directory = super::super::directory()?;
            let _guard = super::super::operation_lock(&directory).await?;
            if let Some(connection) = connection::read(&directory)? {
                let mut ledger = Ledger::open(&connection.ledger).map_err(fail)?;
                let state = ledger.state().map_err(fail)?;
                if state.network() != connection.network {
                    return Err("wallet connection network mismatch".into());
                }
                if connection.signer != connection.wallet
                    && state
                        .spending_authority(connection.wallet, connection.signer)
                        .is_some()
                {
                    let key = store::key(&directory)?;
                    let revoke = state
                        .access_change(connection.wallet, &key, connection.signer, false)
                        .map_err(fail)?;
                    ledger.submit(&revoke).map_err(fail)?;
                }
                connection::remove(&directory)?;
            }
            print(&serde_json::json!({"connected":false,"scope":"local_test_coins"}))
        }
        [command, rest @ ..] if command == "test-coins" => coins(rest).await,
        _ => Err(USAGE.into()),
    }
}

async fn coins(arguments: &[OsString]) -> Result<(), String> {
    match arguments {
        [command, path, units] if command == "init" => {
            let directory = super::super::directory()?;
            let _guard = super::super::operation_lock(&directory).await?;
            let key = store::key(&directory)?;
            let amount = amount(units)?;
            let genesis = TestGenesis::random(vec![Output {
                address: key.address(),
                amount,
            }])
            .map_err(fail)?;
            let ledger = Ledger::create(Path::new(path), &genesis).map_err(fail)?;
            print(
                &serde_json::json!({"network":ledger.state().map_err(fail)?.network(),"address":key.address(),"units":amount,"scope":"local_test_coins"}),
            )
        }
        [command, path, rest @ ..] if command == "balance" && rest.len() <= 1 => {
            let ledger = Ledger::open(Path::new(path)).map_err(fail)?;
            let address = if let Some(value) = rest.first() {
                address(value)?
            } else {
                owner(&super::super::directory()?, Path::new(path), &ledger)?
            };
            let state = ledger.state().map_err(fail)?;
            print(
                &serde_json::json!({"network":state.network(),"address":address,"units":state.balance(address).map_err(fail)?,"authorized_nodes":state.authorized_nodes(address),"scope":"local_test_coins"}),
            )
        }
        [command, path, recipient, units] if command == "send" || command == "prepare" => {
            let directory = super::super::directory()?;
            let _guard = super::super::operation_lock(&directory).await?;
            let key = store::key(&directory)?;
            let mut ledger = Ledger::open(Path::new(path)).map_err(fail)?;
            let owner = owner(&directory, Path::new(path), &ledger)?;
            let transaction = ledger
                .state()
                .map_err(fail)?
                .payment(owner, &key, address(recipient)?, amount(units)?)
                .map_err(fail)?;
            if command == "prepare" {
                return print(&transaction);
            }
            let id = ledger.submit(&transaction).map_err(fail)?;
            print(&serde_json::json!({"transaction_id":id,"scope":"local_test_coins"}))
        }
        [command, path, transaction] if command == "submit" => {
            let transaction: SignedTransaction = read_bounded(
                Path::new(transaction),
                naome_ledger::MAX_RECORD_BYTES as u64,
            )?;
            let mut ledger = Ledger::open(Path::new(path)).map_err(fail)?;
            let id = ledger.submit(&transaction).map_err(fail)?;
            print(&serde_json::json!({"transaction_id":id,"scope":"local_test_coins"}))
        }
        [command, path, delegate] if command == "authorize" || command == "revoke" => {
            let directory = super::super::directory()?;
            let _guard = super::super::operation_lock(&directory).await?;
            let key = store::key(&directory)?;
            let mut ledger = Ledger::open(Path::new(path)).map_err(fail)?;
            let owner = owner(&directory, Path::new(path), &ledger)?;
            let transaction = ledger
                .state()
                .map_err(fail)?
                .access_change(owner, &key, address(delegate)?, command == "authorize")
                .map_err(fail)?;
            let id = ledger.submit(&transaction).map_err(fail)?;
            print(&serde_json::json!({"transaction_id":id,"scope":"local_test_coins"}))
        }
        _ => Err(USAGE.into()),
    }
}
