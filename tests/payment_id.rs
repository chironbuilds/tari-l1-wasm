// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! A payment id embedded in the destination address is what an exchange credits a deposit by, so it
//! has to arrive in the recipient output's memo. The send builder once gave every recipient an
//! empty memo and silently dropped it: the deposit reached the exchange's wallet and could not be
//! matched to an account.
//!
//! Checked end-to-end, as in `reveal_sender.rs`: the payment is built, its outputs are imported
//! back the way a chain scan would, and the payment id is read off what the recipient recovers.

use borsh::BorshSerialize;
use tari_common::configuration::Network;
use tari_common_types::tari_address::TariAddress;
use tari_l1_wasm::wallet::{build_stealth_payment, create_self_utxo_impl, WasmWallet};
use tari_transaction_components::key_manager::KeyManager;
use tari_transaction_components::transaction_components::{Transaction, TransactionOutput};
use tari_utilities::hex::Hex;
use tari_utilities::ByteArray;

fn borsh_hex<T: BorshSerialize>(value: &T) -> String {
    borsh::to_vec(value).expect("borsh").to_hex()
}

/// The payment id a recipient recovers from an output, or None when it is not theirs.
fn recovered_payment_id(wallet: &WasmWallet, output: &TransactionOutput) -> Option<Vec<u8>> {
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
    Some(handle.payment_id())
}

/// Pays this wallet's own address (optionally carrying `payment_id`), so the recipient output is
/// recoverable in-process.
fn self_payment(km: &KeyManager, payment_id: Option<&[u8]>, reveal: bool) -> Transaction {
    let address = WasmWallet::from_key_manager_for_test(km.clone(), Network::Esmeralda)
        .get_address()
        .expect("address");
    let address = match payment_id {
        Some(id) => address.try_with_payment_id(id).expect("attach payment id"),
        None => address,
    };
    let input = create_self_utxo_impl(km, 5_000_000).expect("utxo");
    let (tx, _fee, _change, _commitment) = build_stealth_payment(
        km,
        Network::Esmeralda,
        vec![input],
        vec![None],
        vec![(TariAddress::from_base58(&address.to_base58()).expect("parse own address"), 1_000_000)],
        2,
        0,
        0,
        reveal,
    )
    .expect("tx build");
    tx
}

fn all_recovered(km: &KeyManager, tx: &Transaction) -> Vec<Vec<u8>> {
    let wallet = WasmWallet::from_key_manager_for_test(km.clone(), Network::Esmeralda);
    tx.body
        .outputs()
        .iter()
        .filter_map(|o| recovered_payment_id(&wallet, o))
        .collect()
}

#[test]
fn address_payment_id_reaches_the_recipient_output() {
    let km = KeyManager::new_random().expect("km");
    let tx = self_payment(&km, Some(b"ID5203187469"), false);
    let ids = all_recovered(&km, &tx);
    assert!(
        ids.iter().any(|id| id.as_slice() == b"ID5203187469"),
        "the recipient output must carry the address's payment id; recovered {ids:?}"
    );
}

#[test]
fn address_payment_id_survives_revealing_the_sender() {
    let km = KeyManager::new_random().expect("km");
    let tx = self_payment(&km, Some(b"ID5203187469"), true);
    let ids = all_recovered(&km, &tx);
    assert!(
        ids.iter().any(|id| id.as_slice() == b"ID5203187469"),
        "revealing the sender must not displace the payment id; recovered {ids:?}"
    );
}

#[test]
fn an_address_without_a_payment_id_adds_none() {
    let km = KeyManager::new_random().expect("km");
    let tx = self_payment(&km, None, false);
    let ids = all_recovered(&km, &tx);
    assert!(
        ids.iter().all(|id| id.is_empty()),
        "no payment id was given, none should appear; recovered {ids:?}"
    );
}
