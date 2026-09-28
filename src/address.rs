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

use std::str::FromStr;

use tari_common::configuration::Network;
use tari_common_types::{
    tari_address::{TariAddress, TariAddressFeatures},
    types::CompressedPublicKey,
};
use tari_utilities::hex::Hex;
use wasm_bindgen::prelude::*;

pub const FEATURE_ONE_SIDED: u8 = 0b0000_0001;
pub const FEATURE_INTERACTIVE: u8 = 0b0000_0010;
pub const FEATURE_PAYMENT_ID: u8 = 0b0000_0100;

/// Ceiling the address format itself imposes on a payment id (`MAX_ENCRYPTED_DATA_SIZE`).
pub const MAX_PAYMENT_ID_BYTES: usize = 256;

fn js_err<E: std::fmt::Display>(context: &str, err: E) -> JsValue {
    JsValue::from_str(&format!("{context}: {err}"))
}

fn parse_network(network: &str) -> Result<Network, JsValue> {
    Network::from_str(network)
        .map_err(|e| js_err("invalid network (mainnet|stagenet|nextnet|localnet|igor|esmeralda)", e))
}

fn parse_features(bits: u8) -> TariAddressFeatures {
    TariAddressFeatures::from_bits_truncate(bits)
}

fn parse_public_key_hex(hex: &str) -> Result<CompressedPublicKey, JsValue> {
    CompressedPublicKey::from_hex(hex).map_err(|e| js_err("invalid public key hex", e))
}

/// A Tari address (single or dual) with encoding/decoding helpers.
#[wasm_bindgen]
pub struct WasmTariAddress(TariAddress);

impl WasmTariAddress {
    pub fn from_inner(inner: TariAddress) -> Self {
        WasmTariAddress(inner)
    }

    /// Builds a sub-address, or explains why it cannot.
    ///
    /// Kept separate from the `wasm_bindgen` wrapper above so the rules are testable off-wasm:
    /// constructing a `JsValue` panics on a non-wasm target, which would make every error path
    /// impossible to assert in a native test.
    pub fn try_with_payment_id(&self, payment_id: &[u8]) -> Result<WasmTariAddress, String> {
        if payment_id.is_empty() {
            return Err("payment id must not be empty".to_string());
        }
        if payment_id.len() > MAX_PAYMENT_ID_BYTES {
            return Err(format!(
                "payment id is {} bytes; the maximum is {MAX_PAYMENT_ID_BYTES}",
                payment_id.len()
            ));
        }
        let view_key = self
            .0
            .public_view_key()
            .ok_or_else(|| "only a dual address can carry a payment id".to_string())?
            .clone();
        TariAddress::new_dual_address(
            view_key,
            self.0.public_spend_key().clone(),
            self.0.network(),
            self.0.features(),
            Some(payment_id.to_vec()),
        )
        .map(WasmTariAddress)
        .map_err(|e| format!("failed to attach payment id: {e}"))
    }
}

#[wasm_bindgen]
impl WasmTariAddress {
    #[wasm_bindgen(js_name = fromEmoji)]
    pub fn from_emoji(emoji: &str) -> Result<WasmTariAddress, JsValue> {
        TariAddress::from_emoji_string(emoji)
            .map(WasmTariAddress)
            .map_err(|e| js_err("invalid emoji address", e))
    }

    #[wasm_bindgen(js_name = fromBase58)]
    pub fn from_base58(s: &str) -> Result<WasmTariAddress, JsValue> {
        TariAddress::from_base58(s)
            .map(WasmTariAddress)
            .map_err(|e| js_err("invalid base58 address", e))
    }

    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(s: &str) -> Result<WasmTariAddress, JsValue> {
        TariAddress::from_hex(s)
            .map(WasmTariAddress)
            .map_err(|e| js_err("invalid hex address", e))
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmTariAddress, JsValue> {
        TariAddress::from_bytes(bytes)
            .map(WasmTariAddress)
            .map_err(|e| js_err("invalid address bytes", e))
    }

    #[wasm_bindgen(js_name = newDual)]
    pub fn new_dual(
        view_key_hex: &str,
        spend_key_hex: &str,
        network: &str,
        features: u8,
    ) -> Result<WasmTariAddress, JsValue> {
        let view_key = parse_public_key_hex(view_key_hex)?;
        let spend_key = parse_public_key_hex(spend_key_hex)?;
        let network = parse_network(network)?;
        TariAddress::new_dual_address(view_key, spend_key, network, parse_features(features), None)
            .map(WasmTariAddress)
            .map_err(|e| js_err("failed to create dual address", e))
    }

    #[wasm_bindgen(js_name = newSingle)]
    pub fn new_single(spend_key_hex: &str, network: &str, features: u8) -> Result<WasmTariAddress, JsValue> {
        let spend_key = parse_public_key_hex(spend_key_hex)?;
        let network = parse_network(network)?;
        TariAddress::new_single_address(spend_key, network, parse_features(features))
            .map(WasmTariAddress)
            .map_err(|e| js_err("failed to create single address", e))
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_emoji(&self) -> String {
        self.0.to_emoji_string()
    }

    #[wasm_bindgen(js_name = toEmoji)]
    pub fn to_emoji_string(&self) -> String {
        self.0.to_emoji_string()
    }

    #[wasm_bindgen(js_name = toBase58)]
    pub fn to_base58(&self) -> String {
        self.0.to_base58()
    }

    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn network(&self) -> String {
        self.0.network().as_key_str().to_string()
    }

    #[wasm_bindgen(getter, js_name = featureBits)]
    pub fn feature_bits(&self) -> u8 {
        self.0.features().bits()
    }

    #[wasm_bindgen(getter, js_name = features)]
    pub fn feature_names(&self) -> Vec<String> {
        let f = self.0.features();
        let mut names = Vec::new();
        if f.contains(TariAddressFeatures::ONE_SIDED) {
            names.push("one_sided".to_string());
        }
        if f.contains(TariAddressFeatures::INTERACTIVE) {
            names.push("interactive".to_string());
        }
        if f.contains(TariAddressFeatures::PAYMENT_ID) {
            names.push("payment_id".to_string());
        }
        names
    }

    #[wasm_bindgen(getter, js_name = spendKeyHex)]
    pub fn spend_key_hex(&self) -> String {
        self.0.public_spend_key().to_hex()
    }

    #[wasm_bindgen(getter, js_name = viewKeyHex)]
    pub fn view_key_hex(&self) -> Option<String> {
        self.0.public_view_key().map(|k| k.to_hex())
    }

    #[wasm_bindgen(getter, js_name = isSingle)]
    pub fn is_single(&self) -> bool {
        matches!(self.0, TariAddress::Single(_))
    }

    /// Returns this address with a payment id attached — a *sub-address*.
    ///
    /// The view and spend keys are carried over untouched, so a payment to the returned address is
    /// recovered by exactly the same wallet keys as a payment to this one; the payment id only
    /// rides along in the address's memo field (and sets the `payment_id` feature bit). A sending
    /// wallet copies those bytes into the output's memo, which is what lets the recipient tell one
    /// sub-address's payments from another's. Nothing here derives new key material, so a
    /// sub-address can never receive funds this wallet cannot spend.
    ///
    /// Only dual addresses can carry a payment id; a single address has no view key to receive
    /// one-sided payments with in the first place.
    #[wasm_bindgen(js_name = withPaymentId)]
    pub fn with_payment_id(&self, payment_id: &[u8]) -> Result<WasmTariAddress, JsValue> {
        self.try_with_payment_id(payment_id).map_err(|e| JsValue::from_str(&e))
    }

    /// The payment id carried by this address, empty when it is a plain address.
    #[wasm_bindgen(getter, js_name = paymentId)]
    pub fn payment_id(&self) -> Vec<u8> {
        self.0.get_memo_field_payment_id_bytes()
    }
}
