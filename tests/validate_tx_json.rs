// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Diagnostic harness: run the node's own internal-consistency validator over a transaction JSON
//! (as produced by `WasmSignedTransaction::toJson()`) and print the exact consensus error, which
//! `SubmitTransaction` itself never reports — it only answers REJECTED.
//!
//!   TX_JSON=path/to/tx.json [TX_NETWORK=mainnet] [TX_HEIGHT=331681] \
//!     cargo test -p tari_l1_wasm --test validate_tx_json -- --nocapture
//!
//! A pass here means the transaction is internally sound, so a REJECTED verdict comes from the
//! chain-linked checks instead: the spent output is missing from the UTXO set (already spent, or
//! the wallet's view of it is stale) or the input is compact.

use std::str::FromStr;

use tari_common::configuration::Network;
use tari_transaction_components::{
    consensus::ConsensusManager, crypto_factories::CryptoFactories, transaction_components::Transaction,
    validation::transaction::TransactionInternalConsistencyValidator,
};
use tari_utilities::hex::Hex;

#[test]
fn validate_tx_json() {
    let Ok(path) = std::env::var("TX_JSON") else {
        println!("TX_JSON not set — nothing to validate");
        return;
    };
    let network = Network::from_str(&std::env::var("TX_NETWORK").unwrap_or_else(|_| "mainnet".into()))
        .expect("TX_NETWORK");
    Network::set_current(network).ok();
    let height: u64 = std::env::var("TX_HEIGHT")
        .unwrap_or_else(|_| "0".into())
        .parse()
        .expect("TX_HEIGHT");

    let tx: Transaction = serde_json::from_str(&std::fs::read_to_string(&path).expect("read TX_JSON"))
        .expect("parse transaction json");

    println!("network={network} height={height} fee={}", tx.body.kernels()[0].fee);
    for (i, input) in tx.body.inputs().iter().enumerate() {
        // The output hash is what the node looks up in the UTXO set; a mismatch there is the
        // difference between "already spent" and "this wallet reconstructed the output wrongly".
        println!(
            "input[{i}] compact={} output_hash={}",
            input.is_compact(),
            input.output_hash().to_hex()
        );
    }
    for (i, output) in tx.body.outputs().iter().enumerate() {
        println!("output[{i}] hash={}", output.hash().to_hex());
    }

    let validator = TransactionInternalConsistencyValidator::new(
        false,
        ConsensusManager::builder(network).build(),
        CryptoFactories::default(),
    );
    match validator.validate(&tx, None, None, height) {
        Ok(()) => println!("internal consistency: OK"),
        Err(e) => println!("internal consistency: FAILED: {e}"),
    }
}
