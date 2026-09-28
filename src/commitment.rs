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

use tari_common_types::types::{CommitmentFactory, CompressedCommitment};
use tari_crypto::commitment::HomomorphicCommitmentFactory;
use tari_crypto::ristretto::RistrettoSecretKey;
use tari_utilities::hex::Hex;
use wasm_bindgen::prelude::*;

fn js_err<E: std::fmt::Display>(context: &str, err: E) -> JsValue {
    JsValue::from_str(&format!("{context}: {err}"))
}

/// Creates a compressed Pedersen commitment for `value` (in micro-Minotari) under the given blinding factor.
#[wasm_bindgen(js_name = commitValue)]
pub fn commitment_commit_value(blinding_factor_hex: &str, value: u64) -> Result<String, JsValue> {
    let k = RistrettoSecretKey::from_hex(blinding_factor_hex).map_err(|e| js_err("invalid blinding factor hex", e))?;
    let factory = CommitmentFactory::default();
    let commitment = factory.commit_value(&k, value);
    Ok(CompressedCommitment::from_commitment(commitment).to_hex())
}

/// Returns true if the blinding factor and value open the given (hex-encoded, compressed) commitment.
#[wasm_bindgen(js_name = openValue)]
pub fn commitment_open_value(blinding_factor_hex: &str, value: u64, commitment_hex: &str) -> Result<bool, JsValue> {
    let k = RistrettoSecretKey::from_hex(blinding_factor_hex).map_err(|e| js_err("invalid blinding factor hex", e))?;
    let commitment = CompressedCommitment::from_hex(commitment_hex).map_err(|e| js_err("invalid commitment hex", e))?;
    let uncompressed = commitment
        .to_commitment()
        .map_err(|e| js_err("invalid commitment", e))?;
    let factory = CommitmentFactory::default();
    Ok(factory.open_value(&k, value, &uncompressed))
}
