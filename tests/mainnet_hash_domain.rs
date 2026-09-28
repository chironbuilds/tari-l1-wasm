// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Consensus hashes are domain-separated by the *current* network byte, which a wasm32 build can
//! only learn from `Network::set_current`. If the wallet does not pin it, every hash it produces
//! belongs to the default (Esmeralda) network and a base node on any other network recomputes
//! different hashes for the same transaction — the spent output is not found in the UTXO set and
//! the kernel signature does not verify, so the transaction is rejected.
//!
//! These tests are self-consistency-proof: the second one checks a real MainNet output against the
//! hash the MainNet node itself reports for it.

use borsh::BorshDeserialize;
use tari_common::configuration::Network;
use tari_common_types::types::{ComAndPubSignature, CompressedCommitment, CompressedPublicKey, RangeProof};
use tari_l1_wasm::wallet::WasmWallet;
use tari_script::TariScript;
use tari_transaction_components::{
    MicroMinotari,
    transaction_components::{
        CoinBaseExtra, EncryptedData, OutputFeatures, OutputFeaturesVersion, OutputType, RangeProofType,
        TransactionOutput, TransactionOutputVersion, covenants::Covenant,
    },
};
use tari_utilities::{ByteArray, hex::Hex};

// MainNet block 331220, as served by `tari.rpc.BaseNode/GetBlocks`.
const COMMITMENT: &str = "6a742797cd64f4b672f3cbab46e78a8d3ddb7d1b35ace10954cb9898c78c5b0b";
const CHAIN_HASH: &str = "380b8ae804c09b1e96c8f1855ea69559885727c5b9afe340c1945ef91131fb6d";
const SCRIPT: &str = "7ebc9434269a7e712324cb50f48702f8917e704f9eafbba4768835ebd3cba15831";
const SENDER_OFFSET_PUB: &str = "28effec915dbf8c00fe9c2b78a9f38da4b3120f2977fd51b3f17718013d8e05a";
const COVENANT: &str = "00";
const ENCRYPTED_DATA: &str = "7c3013007981180364b1465dcdef5ebf94ee15ad9e041abdbdebadf7ce63a9fc82953c75110820b45f5845d351ab3dc03e5cb087bf00800151591820f8b19c83af4480fe390b8ae6c798b34db33c1931fa50cbb30783133eeb1dd083fb840131f8572263a1a37bd20e06e93e7cb9a0de50e3cbdffcf3c4d0e64cd8db5feeb7fbdf1972b97369bfb28010e352fce43a58bf860e957d89d7a2a8a8d3f31115a6671e446c2500e8836fb00c31fb3bae0ec7b989fe02e76a860f98a43a8a4bbb45ca5a713706b6abe46667afd257f2a3abac9443";
const METADATA_SIG: &str = "20000000662dd688baaf73063bc934221080b83b7207aa6c8df9a001966fd4e12b19717f20000000ccffe3ce16e2214694248c2d25be1ed39631aa32c0370c712d219fc1fd3ebe0320000000683636dd57cacdf627f96fb4eacf36c01a594ca8726f80e829d8c7df5be7ae0320000000029e5777496df29fcedac886980e56a53f527ef9c9c1e68f544662f4834ce20e200000009aaa76aff6325e84ca10002ea49f96bcac5b6a43157ffd43e69a83ac0156c609";
const RANGE_PROOF: &str = "019c77e00a18252e2163fbf6bb03739726125743a865f38e2a622ae6ad9581ac0f24f46fcf5a21aac6704d49a49d7e5d4afffa693a0dfa472a6924f12695f7587f980f3a873b6c1693d3c4ea57b48d207dd159261592bbe7b6245ef3865b339b791218f61943fee546023f19e75d913b90e9ba2581a4731e7209475617b6a7122966159d51c12a8319a3b9f3d8310002f1a295d8904e44eea6010c5e4e93530b0bea58daaab766b4305dde2a8011926114b17e1b61f34f35223e59787cad472203fa602ae186c13cd871ddcd6d87a4b3e884739f31ff37e20ee0b405a0711acb6b7459535aa72170a32762737270ab1770d5cfc93c523ccd9ada69780366b35f62743bc898d85e2686c4f80de9552608e5463aa7bcfce07d93c033b223af06e6203a403c099e288615023c6c3fa33df7dffcb60a3fe2a5f30c59b9fcb5cbf43c0868ef98e2b869077d85a228e82ae85db8f9d90795becf2bb1ee437715f66c2639f4add9f1a04fc83f223c7b7c87ce9e920648ca74f696edfdc2f60cb5f2200429dea7b395ff5f14daa7b18479e1fda57af8e02baebdecc8045f0759088b27156394677bf6503235b80ae42679bb32df8f64dbc241bf79e36262e464ffd91e10001c5c2808d9ac8d63c5c6367befac653eab139c2881d64ddcc2a33001f2017600ac3926ce66041a6dbbc37f3408d08c6ae636e0e45dfc8c95d02dca61f895a17ff4b1dca3ee0f30843bfda52545025a930596f9bf6aae7b2f2b7b52f67071590d4268e015d8b6e8b5bb77f42b4b303d3323948ab125906d174cfb230701227056";

fn mainnet_wallet() -> WasmWallet {
    WasmWallet::new("mainnet").expect("mainnet wallet")
}

#[test]
fn creating_a_wallet_pins_the_current_network() {
    let _wallet = mainnet_wallet();
    assert_eq!(
        Network::get_current_or_user_setting_or_default(),
        Network::MainNet,
        "consensus hashing would be domain-separated for the wrong network"
    );
}

#[test]
fn rebuilt_mainnet_output_matches_the_hash_the_node_reports() {
    let _wallet = mainnet_wallet();

    let proof_bytes = Vec::<u8>::from_hex(RANGE_PROOF).unwrap();
    let covenant = Covenant::deserialize(&mut Vec::<u8>::from_hex(COVENANT).unwrap().as_slice()).unwrap();
    let metadata_signature =
        ComAndPubSignature::deserialize(&mut Vec::<u8>::from_hex(METADATA_SIG).unwrap().as_slice()).unwrap();
    let features = OutputFeatures::new(
        OutputFeaturesVersion::V0,
        OutputType::Standard,
        0,
        CoinBaseExtra::default(),
        None,
        RangeProofType::BulletProofPlus,
    );

    let output = TransactionOutput::new(
        TransactionOutputVersion::V0,
        features,
        CompressedCommitment::from_hex(COMMITMENT).unwrap(),
        Some(RangeProof::from_canonical_bytes(&proof_bytes).unwrap()),
        TariScript::from_bytes(&Vec::<u8>::from_hex(SCRIPT).unwrap()).unwrap(),
        CompressedPublicKey::from_hex(SENDER_OFFSET_PUB).unwrap(),
        metadata_signature,
        covenant,
        EncryptedData::from_bytes(&Vec::<u8>::from_hex(ENCRYPTED_DATA).unwrap()).unwrap(),
        MicroMinotari::zero(),
    );

    assert_eq!(output.hash().to_hex(), CHAIN_HASH);
}
