// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! A sub-address is this wallet's own address with a payment id attached. The whole feature rests
//! on one property: attaching a payment id must not change the view or spend key, because those
//! keys are the only thing that makes a received output recoverable. If a sub-address ever carried
//! different key material, funds paid to it would be unspendable — so that is what these tests
//! pin down, along with the round trip through every encoding a user might paste.

use tari_common::configuration::Network;
use tari_l1_wasm::wallet::WasmWallet;
use tari_l1_wasm::WasmTariAddress;

fn wallet() -> WasmWallet {
    WasmWallet::new("mainnet").expect("wallet")
}

#[test]
fn sub_address_keeps_the_wallets_keys() {
    let w = wallet();
    let main = w.get_address().expect("address");
    let sub = main.try_with_payment_id(b"invoice-42").expect("sub-address");

    assert_eq!(
        sub.spend_key_hex(),
        main.spend_key_hex(),
        "a sub-address must spend to the same key, or funds sent to it are unrecoverable"
    );
    assert_eq!(sub.view_key_hex(), main.view_key_hex(), "view key must be unchanged");
    assert_eq!(sub.network(), main.network());
    assert_ne!(sub.to_base58(), main.to_base58(), "it should still be a distinct address string");
}

#[test]
fn sub_address_survives_every_encoding() {
    let w = wallet();
    let main = w.get_address().expect("address");
    let payment_id = b"coffee-stand".to_vec();
    let sub = main.try_with_payment_id(&payment_id).expect("sub-address");

    for parsed in [
        WasmTariAddress::from_base58(&sub.to_base58()).expect("base58"),
        WasmTariAddress::from_hex(&sub.to_hex()).expect("hex"),
        WasmTariAddress::from_emoji(&sub.to_emoji_string()).expect("emoji"),
        WasmTariAddress::from_bytes(&sub.to_bytes()).expect("bytes"),
    ] {
        assert_eq!(parsed.payment_id(), payment_id, "payment id lost in a round trip");
        assert_eq!(parsed.spend_key_hex(), main.spend_key_hex());
        assert_eq!(parsed.view_key_hex(), main.view_key_hex());
    }
}

#[test]
fn payment_id_feature_bit_is_set_and_others_are_kept() {
    let w = wallet();
    let main = w.get_address().expect("address");
    let sub = main.try_with_payment_id(b"x").expect("sub-address");

    assert!(main.feature_names().contains(&"one_sided".to_string()), "wallet address is one-sided");
    assert!(sub.feature_names().contains(&"one_sided".to_string()), "one-sided must survive");
    assert!(sub.feature_names().contains(&"payment_id".to_string()), "payment_id bit must be set");
    assert!(main.payment_id().is_empty(), "the plain address carries no payment id");
}

#[test]
fn distinct_payment_ids_give_distinct_addresses() {
    let w = wallet();
    let main = w.get_address().expect("address");
    let a = main.try_with_payment_id(b"alice").expect("a");
    let b = main.try_with_payment_id(b"bob").expect("b");

    assert_ne!(a.to_base58(), b.to_base58());
    assert_eq!(a.spend_key_hex(), b.spend_key_hex(), "still the same wallet underneath");
}

#[test]
fn payment_id_bounds_are_enforced() {
    let w = wallet();
    let main = w.get_address().expect("address");

    assert!(main.try_with_payment_id(b"").is_err(), "empty payment id is not a sub-address");
    assert!(main.try_with_payment_id(&vec![7u8; 256]).is_ok(), "256 bytes is the documented maximum");
    assert!(main.try_with_payment_id(&vec![7u8; 257]).is_err(), "over the maximum must be rejected");
}

#[test]
fn a_single_address_cannot_carry_a_payment_id() {
    // A single address has no view key, so it cannot receive the one-sided payments a payment id
    // is meant to label. Rejecting it here beats producing an address nothing can pay.
    let single = WasmTariAddress::new_single(
        &WasmWallet::new("mainnet").unwrap().get_address().unwrap().spend_key_hex(),
        "mainnet",
        0b0000_0010,
    )
    .expect("single address");
    assert!(single.try_with_payment_id(b"nope").is_err());
    let _ = Network::MainNet;
}
