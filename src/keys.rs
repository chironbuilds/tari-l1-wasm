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
use tari_common_types::types::CompressedPublicKey;
use tari_crypto::keys::SecretKey;
use tari_crypto::ristretto::RistrettoSecretKey;
use tari_utilities::hex::Hex;
use wasm_bindgen::prelude::*;

fn js_err<E: std::fmt::Display>(context: &str, err: E) -> JsValue {
    JsValue::from_str(&format!("{context}: {err}"))
}

/// A Ristretto Schnorr keypair (secret + public key).
#[wasm_bindgen]
pub struct WasmKeyPair {
    secret: RistrettoSecretKey,
    public: CompressedPublicKey,
}

#[wasm_bindgen]
impl WasmKeyPair {
    /// Generates a new random keypair using the platform CSPRNG.
    pub fn generate() -> WasmKeyPair {
        let secret = RistrettoSecretKey::random(&mut rng());
        let public = CompressedPublicKey::from_secret_key(&secret);
        WasmKeyPair { secret, public }
    }

    #[wasm_bindgen(js_name = fromSecretKeyHex)]
    pub fn from_secret_key_hex(hex: &str) -> Result<WasmKeyPair, JsValue> {
        let secret = RistrettoSecretKey::from_hex(hex).map_err(|e| js_err("invalid secret key hex", e))?;
        if secret == RistrettoSecretKey::default() {
            return Err(JsValue::from_str("secret key must not be zero"));
        }
        let public = CompressedPublicKey::from_secret_key(&secret);
        Ok(WasmKeyPair { secret, public })
    }

    #[wasm_bindgen(getter, js_name = secretKeyHex)]
    pub fn secret_key_hex(&self) -> String {
        self.secret.to_hex()
    }

    #[wasm_bindgen(getter, js_name = publicKeyHex)]
    pub fn public_key_hex(&self) -> String {
        self.public.to_hex()
    }
}
