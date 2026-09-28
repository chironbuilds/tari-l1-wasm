// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Revealing the sender is a disclosure that cannot be undone once broadcast, so both directions
//! are worth pinning down: that a revealed payment really does reach the recipient carrying the
//! sender's address, and — more importantly — that the default really does carry nothing.
//!
//! The check is end-to-end rather than an assertion about the memo we built: the payment is
//! constructed, its recipient output is taken apart exactly as a chain scanner would, and imported
//! back through `import_scanned_output`. That is the same path a real received output takes, so it
//! proves what a recipient can actually read rather than what we intended to write.

use borsh::BorshSerialize;
use tari_common::configuration::Network;
use tari_l1_wasm::wallet::{build_stealth_payment, create_self_utxo_impl, WasmWallet};
use tari_transaction_components::key_manager::KeyManager;
use tari_transaction_components::transaction_components::{Transaction, TransactionOutput};
use tari_utilities::hex::Hex;
use tari_utilities::ByteArray;

fn borsh_hex<T: BorshSerialize>(value: &T) -> String {
    borsh::to_vec(value).expect("borsh").to_hex()
}

/// Feeds a built output back through the importer the same way a chain scan would.
fn import_as_recipient(wallet: &WasmWallet, output: &TransactionOutput) -> Option<(String, Option<u64>)> {
    let handle = wallet
        .import_scanned_output(
            &output.commitment.to_hex(),
            &output.encrypted_data.as_bytes().to_vec().to_hex(),
            &output.sender_offset_public_key.to_hex(),
            &output.script.to_bytes().to_hex(),
            &borsh_hex(&output.metadata_signature),
            output.minimum_value_promise.as_u64(),
            output.features.maturity,
            output.features.output_type.as_byte(),
            output.features.range_proof_type.as_byte(),
            &output.features.coinbase_extra.as_ref().to_vec().to_hex(),
            &borsh_hex(&output.covenant),
            &output.proof.as_ref().map(|p| p.to_vec().to_hex()).unwrap_or_default(),
            "",
        )
        .ok()?;
    Some((handle.sender_address().unwrap_or_default(), handle.sender_fee_micro()))
}

/// Builds a self-payment so one wallet is both sender and recipient — the recipient output is then
/// recoverable in-process, which is what makes the round trip checkable at all.
fn self_payment(km: &KeyManager, reveal: bool) -> (Transaction, u64) {
    let wallet_address = WasmWallet::from_key_manager_for_test(km.clone(), Network::Esmeralda)
        .get_address()
        .expect("address");
    let input = create_self_utxo_impl(km, 5_000_000).expect("utxo");
    let (tx, fee, _change, _commitment) = build_stealth_payment(
        km,
        Network::Esmeralda,
        vec![input],
        vec![None],
        vec![(
            tari_common_types::tari_address::TariAddress::from_base58(&wallet_address.to_base58())
                .expect("parse own address"),
            1_000_000,
        )],
        2,
        0,
        0,
        reveal,
    )
    .expect("tx build");
    (tx, fee)
}

#[test]
fn default_send_discloses_nothing() {
    let km = KeyManager::new_random().expect("km");
    let wallet = WasmWallet::from_key_manager_for_test(km.clone(), Network::Esmeralda);
    let (tx, _fee) = self_payment(&km, false);

    let disclosed: Vec<String> = tx
        .body
        .outputs()
        .iter()
        .filter_map(|o| import_as_recipient(&wallet, o))
        .map(|(address, _fee)| address)
        .filter(|s| !s.is_empty())
        .collect();

    assert!(
        disclosed.is_empty(),
        "a default send must not tell the recipient who paid, got {disclosed:?}"
    );
}

#[test]
fn revealed_send_carries_the_senders_address() {
    let km = KeyManager::new_random().expect("km");
    let wallet = WasmWallet::from_key_manager_for_test(km.clone(), Network::Esmeralda);
    let expected = wallet.get_address().expect("address").to_base58();
    let (tx, _fee) = self_payment(&km, true);

    let disclosed: Vec<String> = tx
        .body
        .outputs()
        .iter()
        .filter_map(|o| import_as_recipient(&wallet, o))
        .map(|(address, _fee)| address)
        .filter(|s| !s.is_empty())
        .collect();

    assert!(
        disclosed.iter().any(|s| *s == expected),
        "a revealed send must carry this wallet's address; recovered {disclosed:?}, expected {expected}"
    );
}

/// The point of the second build pass: the fee written into the memo has to be the fee the
/// transaction actually pays. A recipient reading "this cost the sender X" and being wrong is
/// worse than being told nothing.
#[test]
fn revealed_send_records_the_fee_actually_paid() {
    let km = KeyManager::new_random().expect("km");
    let wallet = WasmWallet::from_key_manager_for_test(km.clone(), Network::Esmeralda);
    let (tx, fee_paid) = self_payment(&km, true);

    let declared: Vec<u64> = tx
        .body
        .outputs()
        .iter()
        .filter_map(|o| import_as_recipient(&wallet, o))
        .filter(|(address, _)| !address.is_empty())
        .filter_map(|(_, fee)| fee)
        .collect();

    assert!(!declared.is_empty(), "a revealed send should record a fee in the memo");
    for fee in declared {
        assert_eq!(fee, fee_paid, "memo advertises a fee the transaction does not pay");
        assert_ne!(fee, 0, "the fee should be the real one, not the first pass's placeholder");
    }
}
