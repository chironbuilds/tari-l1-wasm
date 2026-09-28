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

//! Minimal protobuf wire-format writer for the subset of `tari.types` messages needed to submit a
//! transaction to a Minotari base node (`SubmitTransactionRequest.transaction`, see
//! `applications/minotari_app_grpc/proto/base_node.proto`).
//!
//! Field numbers mirror `base_layer/core/src/proto/{transaction,types}.proto`; scalar fields follow
//! proto3 semantics (defaults omitted) while present message fields are always emitted, matching how
//! `prost` encodes the same structures in `base_layer/core/src/proto/transaction.rs`.

use borsh::BorshSerialize;
use tari_common_types::types::{ComAndPubSignature, CompressedCommitment, CompressedSignature, PrivateKey, RangeProof};
use tari_transaction_components::transaction_components::{
    OutputFeatures, TransactionInput, TransactionKernel, TransactionOutput,
};
use tari_utilities::ByteArray;

const WIRE_VARINT: u8 = 0;
const WIRE_LEN: u8 = 2;

struct Pb {
    buf: Vec<u8>,
}

impl Pb {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn varint(&mut self, mut v: u64) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.buf.push(b);
                break;
            }
            self.buf.push(b | 0x80);
        }
    }

    fn tag(&mut self, field: u32, wire_type: u8) {
        self.varint((u64::from(field) << 3) | u64::from(wire_type));
    }

    /// proto3: zero-valued scalars are omitted.
    fn uint64(&mut self, field: u32, v: u64) {
        if v != 0 {
            self.tag(field, WIRE_VARINT);
            self.varint(v);
        }
    }

    /// proto3: empty byte strings are omitted.
    fn bytes(&mut self, field: u32, data: &[u8]) {
        if !data.is_empty() {
            self.tag(field, WIRE_LEN);
            self.varint(data.len() as u64);
            self.buf.extend_from_slice(data);
        }
    }

    /// A present message field is always emitted, even when its encoding is empty.
    fn message(&mut self, field: u32, encoded: &[u8]) {
        self.tag(field, WIRE_LEN);
        self.varint(encoded.len() as u64);
        self.buf.extend_from_slice(encoded);
    }
}

fn encode_private_key(key: &PrivateKey) -> Vec<u8> {
    let mut pb = Pb::new();
    pb.bytes(1, key.as_bytes());
    pb.buf
}

fn encode_commitment(commitment: &CompressedCommitment) -> Vec<u8> {
    let mut pb = Pb::new();
    pb.bytes(1, commitment.as_bytes());
    pb.buf
}

fn encode_excess_sig(sig: &CompressedSignature) -> Vec<u8> {
    let mut pb = Pb::new();
    pb.bytes(1, sig.get_compressed_public_nonce().as_bytes());
    pb.bytes(2, sig.get_signature().as_bytes());
    pb.buf
}

fn encode_metadata_sig(sig: &ComAndPubSignature) -> Vec<u8> {
    let mut pb = Pb::new();
    pb.bytes(1, sig.ephemeral_commitment().as_bytes());
    pb.bytes(2, sig.ephemeral_pubkey().as_bytes());
    pb.bytes(3, sig.u_a().as_bytes());
    pb.bytes(4, sig.u_x().as_bytes());
    pb.bytes(5, sig.u_y().as_bytes());
    pb.buf
}

fn encode_output_features(features: &OutputFeatures) -> Vec<u8> {
    let mut pb = Pb::new();
    pb.uint64(1, u64::from(features.version as u32));
    pb.uint64(2, u64::from(features.output_type.as_byte()));
    pb.uint64(3, features.maturity);
    pb.bytes(4, features.coinbase_extra.to_vec().as_slice());
    pb.uint64(6, u64::from(features.range_proof_type.as_byte()));
    pb.buf
}

fn encode_output(output: &TransactionOutput) -> Result<Vec<u8>, String> {
    let mut pb = Pb::new();
    pb.message(1, &encode_output_features(&output.features));
    pb.message(2, &encode_commitment(&output.commitment));
    if let Some(proof) = &output.proof {
        pb.message(3, &encode_commitment_proof(proof));
    }
    pb.bytes(4, output.script.to_bytes().as_slice());
    pb.bytes(5, output.sender_offset_public_key.as_bytes());
    pb.message(6, &encode_metadata_sig(&output.metadata_signature));
    let mut covenant = Vec::new();
    output
        .covenant
        .serialize(&mut covenant)
        .map_err(|e| format!("covenant encoding failed: {e}"))?;
    pb.bytes(7, &covenant);
    pb.uint64(8, output.version as u64);
    pb.bytes(9, output.encrypted_data.as_bytes());
    pb.uint64(10, output.minimum_value_promise.as_u64());
    Ok(pb.buf)
}

fn encode_commitment_proof(proof: &RangeProof) -> Vec<u8> {
    let mut pb = Pb::new();
    pb.bytes(1, proof.to_vec().as_slice());
    pb.buf
}

fn encode_input(input: &TransactionInput) -> Result<Vec<u8>, String> {
    let mut pb = Pb::new();
    if input.is_compact() {
        pb.bytes(4, input.input_data.to_bytes().as_slice());
        pb.message(6, &encode_metadata_sig(&input.script_signature));
        pb.bytes(8, input.output_hash().as_bytes());
    } else {
        pb.message(1, &encode_output_features(input.features().map_err(|e| e.to_string())?));
        pb.message(2, &encode_commitment(input.commitment().map_err(|e| e.to_string())?));
        pb.bytes(3, input.script().map_err(|e| e.to_string())?.to_bytes().as_slice());
        pb.bytes(4, input.input_data.to_bytes().as_slice());
        pb.message(6, &encode_metadata_sig(&input.script_signature));
        pb.bytes(
            7,
            input.sender_offset_public_key().map_err(|e| e.to_string())?.as_bytes(),
        );
        let mut covenant = Vec::new();
        input
            .covenant()
            .map_err(|e| e.to_string())?
            .serialize(&mut covenant)
            .map_err(|e| format!("covenant encoding failed: {e}"))?;
        pb.bytes(9, &covenant);
        pb.uint64(10, input.version as u64);
        pb.bytes(11, input.encrypted_data().map_err(|e| e.to_string())?.as_bytes());
        pb.uint64(12, input.minimum_value_promise().map_err(|e| e.to_string())?.as_u64());
        pb.message(
            13,
            &encode_metadata_sig(input.metadata_signature().map_err(|e| e.to_string())?),
        );
        pb.bytes(14, input.rangeproof_hash().map_err(|e| e.to_string())?.as_bytes());
    }
    Ok(pb.buf)
}

fn encode_kernel(kernel: &TransactionKernel) -> Vec<u8> {
    let mut pb = Pb::new();
    pb.uint64(1, u64::from(kernel.features.bits()));
    pb.uint64(2, kernel.fee.as_u64());
    pb.uint64(3, kernel.lock_height);
    pb.message(6, &encode_commitment(&kernel.excess));
    pb.message(7, &encode_excess_sig(&kernel.excess_sig));
    pb.uint64(8, kernel.version as u64);
    if let Some(burn) = &kernel.burn_commitment {
        pb.message(9, &encode_commitment(burn));
    }
    pb.buf
}

fn encode_transaction(
    transaction: &tari_transaction_components::transaction_components::Transaction,
) -> Result<Vec<u8>, String> {
    let body = transaction.body();
    let mut body_pb = Pb::new();
    for input in body.inputs() {
        body_pb.message(1, &encode_input(input)?);
    }
    for output in body.outputs() {
        body_pb.message(2, &encode_output(output)?);
    }
    for kernel in body.kernels() {
        body_pb.message(3, &encode_kernel(kernel));
    }

    let mut pb = Pb::new();
    pb.message(1, &encode_private_key(&transaction.offset));
    pb.message(2, &body_pb.buf);
    pb.message(3, &encode_private_key(&transaction.script_offset));
    Ok(pb.buf)
}

/// Serialized `proto.types.Transaction` message.
pub fn transaction_proto_bytes(
    transaction: &tari_transaction_components::transaction_components::Transaction,
) -> Result<Vec<u8>, String> {
    encode_transaction(transaction)
}

/// Serialized `SubmitTransactionRequest { transaction = 1 }` ready for the base node gRPC endpoint.
pub fn submit_transaction_request_bytes(
    transaction: &tari_transaction_components::transaction_components::Transaction,
) -> Result<Vec<u8>, String> {
    let mut pb = Pb::new();
    pb.message(1, &encode_transaction(transaction)?);
    Ok(pb.buf)
}
