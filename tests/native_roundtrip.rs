// Copyright 2026 The Tari Project
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Native validation of the WASM transaction building pipeline:
//! 1. builds a real transaction through the same code path the WASM bindings expose
//! 2. decodes our hand-rolled protobuf bytes with prost mirror types mirroring
//!    `base_layer/core/src/proto/{transaction,types}.proto` and verifies every field
//! 3. runs the node-side internal consistency validator (range proofs, kernel sigs, metadata sigs)

use prost::Message as _;
use tari_common::configuration::Network;
use tari_common_types::tari_address::{TariAddress, TariAddressFeatures};
use tari_l1_wasm::wire;
use tari_transaction_components::{
    crypto_factories::CryptoFactories,
    key_manager::{KeyManager, TransactionKeyManagerInterface},
    test_helpers::create_consensus_manager,
    transaction_components::Transaction,
    validation::transaction::TransactionInternalConsistencyValidator,
};
use tari_utilities::ByteArray;

// ---------------------------------------------------------------------------
// Mirror proto definitions (field numbers/types match tari's protos exactly)
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, prost::Message)]
pub struct MirrorPrivateKey {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub data: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct MirrorCommitment {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub data: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct MirrorRangeProof {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub proof_bytes: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct MirrorSignature {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub public_nonce: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub signature: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct MirrorComAndPubSignature {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub ephemeral_commitment: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub ephemeral_pubkey: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub u_a: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub u_x: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "5")]
    pub u_y: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct MirrorOutputFeatures {
    #[prost(uint32, optional, tag = "1")]
    pub version: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub output_type: Option<u32>,
    #[prost(uint64, optional, tag = "3")]
    pub maturity: Option<u64>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub coinbase_extra: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "6")]
    pub range_proof_type: Option<u32>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct MirrorTransactionOutput {
    #[prost(message, optional, tag = "1")]
    pub features: Option<MirrorOutputFeatures>,
    #[prost(message, optional, tag = "2")]
    pub commitment: Option<MirrorCommitment>,
    #[prost(message, optional, tag = "3")]
    pub range_proof: Option<MirrorRangeProof>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub script: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "5")]
    pub sender_offset_public_key: Option<Vec<u8>>,
    #[prost(message, optional, tag = "6")]
    pub metadata_signature: Option<MirrorComAndPubSignature>,
    #[prost(bytes = "vec", optional, tag = "7")]
    pub covenant: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "8")]
    pub version: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "9")]
    pub encrypted_data: Option<Vec<u8>>,
    #[prost(uint64, optional, tag = "10")]
    pub minimum_value_promise: Option<u64>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct MirrorTransactionInput {
    #[prost(message, optional, tag = "1")]
    pub features: Option<MirrorOutputFeatures>,
    #[prost(message, optional, tag = "2")]
    pub commitment: Option<MirrorCommitment>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub script: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub input_data: Option<Vec<u8>>,
    #[prost(message, optional, tag = "6")]
    pub script_signature: Option<MirrorComAndPubSignature>,
    #[prost(bytes = "vec", optional, tag = "7")]
    pub sender_offset_public_key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "9")]
    pub covenant: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "10")]
    pub version: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "11")]
    pub encrypted_data: Option<Vec<u8>>,
    #[prost(uint64, optional, tag = "12")]
    pub minimum_value_promise: Option<u64>,
    #[prost(message, optional, tag = "13")]
    pub metadata_signature: Option<MirrorComAndPubSignature>,
    #[prost(bytes = "vec", optional, tag = "14")]
    pub rangeproof_hash: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct MirrorTransactionKernel {
    #[prost(uint32, optional, tag = "1")]
    pub features: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub fee: Option<u64>,
    #[prost(uint64, optional, tag = "3")]
    pub lock_height: Option<u64>,
    #[prost(message, optional, tag = "6")]
    pub excess: Option<MirrorCommitment>,
    #[prost(message, optional, tag = "7")]
    pub excess_sig: Option<MirrorSignature>,
    #[prost(uint32, optional, tag = "8")]
    pub version: Option<u32>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct MirrorAggregateBody {
    #[prost(message, repeated, tag = "1")]
    pub inputs: Vec<MirrorTransactionInput>,
    #[prost(message, repeated, tag = "2")]
    pub outputs: Vec<MirrorTransactionOutput>,
    #[prost(message, repeated, tag = "3")]
    pub kernels: Vec<MirrorTransactionKernel>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct MirrorTransaction {
    #[prost(message, optional, tag = "1")]
    pub offset: Option<MirrorPrivateKey>,
    #[prost(message, optional, tag = "2")]
    pub body: Option<MirrorAggregateBody>,
    #[prost(message, optional, tag = "3")]
    pub script_offset: Option<MirrorPrivateKey>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct MirrorSubmitTransactionRequest {
    #[prost(message, optional, tag = "1")]
    pub transaction: Option<MirrorTransaction>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn build_two_wallet_tx() -> (Transaction, u64) {
    let alice = KeyManager::new_random().expect("alice km");
    let bob = KeyManager::new_random().expect("bob km");
    let bob_view = bob.get_view_key().pub_key.clone();
    let bob_spend = bob.get_spend_key().pub_key.clone();
    let bob_address = TariAddress::new_dual_address(
        bob_view,
        bob_spend,
        Network::Esmeralda,
        TariAddressFeatures::create_one_sided_only(),
        None,
    )
    .expect("address");

    let input = tari_l1_wasm::wallet::create_self_utxo_impl(&alice, 5_000_000).expect("utxo");
    let (tx, fee, _change_val, _change_comm) = tari_l1_wasm::wallet::build_stealth_payment(
        &alice,
        Network::Esmeralda,
        vec![input],
        vec![None],
        vec![(bob_address, 1_000_000)],
        2,
        0,
        0,
        false,
    )
    .expect("tx build");
    (tx, fee)
}

#[test]
fn proto_bytes_decode_to_expected_fields() {
    let (tx, fee) = build_two_wallet_tx();

    // SubmitTransactionRequest wrapper
    let request_bytes = wire::submit_transaction_request_bytes(&tx).expect("encode submit request");
    let request = MirrorSubmitTransactionRequest::decode(request_bytes.as_slice()).expect("decode request");
    let decoded = request.transaction.expect("request must carry a transaction");

    // Direct transaction encoding must equal the wrapped one
    let tx_bytes = wire::transaction_proto_bytes(&tx).expect("encode tx");
    let direct = MirrorTransaction::decode(tx_bytes.as_slice()).expect("decode tx");
    assert_eq!(decoded, direct, "wrapped and raw encodings must agree");

    // offset / script_offset round-trip
    assert_eq!(
        decoded.offset.as_ref().and_then(|o| o.data.clone()).unwrap(),
        tx.offset.as_bytes().to_vec()
    );
    assert_eq!(
        decoded.script_offset.as_ref().and_then(|o| o.data.clone()).unwrap(),
        tx.script_offset.as_bytes().to_vec()
    );

    // Body structure
    let body = decoded.body.expect("body");
    assert_eq!(body.inputs.len(), tx.body.inputs().len());
    assert_eq!(body.outputs.len(), tx.body.outputs().len());
    assert_eq!(body.kernels.len(), tx.body.kernels().len());

    // Kernel fields (proto3 omits zero-valued scalars, so decode with defaults)
    let kernel = &body.kernels[0];
    let native_kernel = tx.body.kernels().first().unwrap();
    assert_eq!(kernel.fee.unwrap_or(0), fee);
    assert_eq!(kernel.lock_height.unwrap_or(0), native_kernel.lock_height);
    assert_eq!(kernel.version.unwrap_or(0), native_kernel.version as u32);
    assert_eq!(
        kernel.excess.as_ref().and_then(|e| e.data.clone()).unwrap(),
        native_kernel.excess.as_bytes().to_vec()
    );
    assert_eq!(
        kernel.excess_sig.as_ref().and_then(|s| s.signature.clone()).unwrap(),
        native_kernel.excess_sig.get_signature().as_bytes().to_vec()
    );
    assert_eq!(
        kernel.excess_sig.as_ref().and_then(|s| s.public_nonce.clone()).unwrap(),
        native_kernel
            .excess_sig
            .get_compressed_public_nonce()
            .as_bytes()
            .to_vec()
    );

    // Output fields: commitment + range proof present and well-sized
    for (mirror, native) in body.outputs.iter().zip(tx.body.outputs()) {
        assert_eq!(
            mirror.commitment.as_ref().and_then(|c| c.data.clone()).unwrap(),
            native.commitment.as_bytes().to_vec()
        );
        assert!(mirror.range_proof.is_some(), "range proof required");
        assert!(mirror.metadata_signature.is_some(), "metadata signature required");
        assert_eq!(
            mirror.minimum_value_promise.unwrap_or(0),
            native.minimum_value_promise.as_u64()
        );
        assert!(!mirror.script.as_ref().unwrap().is_empty());
    }

    // Input fields
    for (mirror, _native) in body.inputs.iter().zip(tx.body.inputs()) {
        assert!(mirror.commitment.is_some(), "input must be full (non-compact)");
        assert!(mirror.metadata_signature.is_some());
        assert!(mirror.features.is_some());
    }
}

#[test]
fn built_tx_passes_internal_consistency_validation() {
    let (tx, fee) = build_two_wallet_tx();
    let rules = create_consensus_manager();
    let factories = CryptoFactories::default();
    let validator = TransactionInternalConsistencyValidator::new(false, rules, factories);
    validator
        .validate(&tx, None, None, u64::MAX)
        .unwrap_or_else(|e| panic!("internal consistency validation failed: {e}"));

    let kernel = tx.body.kernels().first().expect("kernel");
    assert_eq!(kernel.fee.as_u64(), fee);
    assert_eq!(tx.body.outputs().len(), 2, "recipient + change expected for this setup");
    assert_eq!(tx.body.inputs().len(), 1);
}

#[test]
fn json_serialization_matches_serde_schema() {
    let (tx, _fee) = build_two_wallet_tx();
    let json = serde_json::to_string(&tx).expect("json");
    let parsed: Transaction = serde_json::from_str(&json).expect("json roundtrip");
    assert_eq!(parsed, tx);
}
