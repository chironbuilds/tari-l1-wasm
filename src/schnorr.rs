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

use rand::rng;
use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSchnorr, RistrettoSecretKey};
use tari_utilities::hex::Hex;
use wasm_bindgen::prelude::*;

fn js_err<E: std::fmt::Display>(context: &str, err: E) -> JsValue {
    JsValue::from_str(&format!("{context}: {err}"))
}

fn parse_secret_hex(hex: &str) -> Result<RistrettoSecretKey, JsValue> {
    RistrettoSecretKey::from_hex(hex).map_err(|e| js_err("invalid secret key hex", e))
}

fn parse_public_hex(hex: &str) -> Result<RistrettoPublicKey, JsValue> {
    RistrettoPublicKey::from_hex(hex).map_err(|e| js_err("invalid public key hex", e))
}

/// A Tari (Ristretto) Schnorr signature over a message, using Tari's domain-separated challenge.
#[wasm_bindgen]
pub struct WasmSchnorrSignature(RistrettoSchnorr);

#[wasm_bindgen]
impl WasmSchnorrSignature {
    /// Signs a message with the given secret key. The nonce is generated with the platform CSPRNG.
    #[wasm_bindgen]
    pub fn sign(secret_key_hex: &str, message: &[u8]) -> Result<WasmSchnorrSignature, JsValue> {
        let secret = parse_secret_hex(secret_key_hex)?;
        if secret == RistrettoSecretKey::default() {
            return Err(JsValue::from_str("secret key must not be zero"));
        }
        let sig = RistrettoSchnorr::sign(&secret, message, &mut rng()).map_err(|e| js_err("signing failed", e))?;
        Ok(WasmSchnorrSignature(sig))
    }

    /// Verifies a signature against the public key, public nonce and signature hex values.
    #[wasm_bindgen(js_name = verify)]
    pub fn verify(
        public_key_hex: &str,
        public_nonce_hex: &str,
        signature_hex: &str,
        message: &[u8],
    ) -> Result<bool, JsValue> {
        let public_key = parse_public_hex(public_key_hex)?;
        let public_nonce = parse_public_hex(public_nonce_hex)?;
        let u = parse_secret_hex(signature_hex)?;
        Ok(RistrettoSchnorr::new(public_nonce, u).verify(&public_key, message))
    }

    #[wasm_bindgen(getter, js_name = publicNonceHex)]
    pub fn public_nonce_hex(&self) -> String {
        self.0.get_public_nonce().to_hex()
    }

    #[wasm_bindgen(getter, js_name = signatureHex)]
    pub fn signature_hex(&self) -> String {
        self.0.get_signature().to_hex()
    }
}
