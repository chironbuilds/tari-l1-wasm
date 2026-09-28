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

use tari_transaction_components::fee::Fee;
use tari_transaction_components::tari_amount::MicroMinotari;
use tari_transaction_components::weight::TransactionWeight;
use wasm_bindgen::prelude::*;

fn js_err<E: std::fmt::Display>(context: &str, err: E) -> JsValue {
    JsValue::from_str(&format!("{context}: {err}"))
}

/// Formats an amount in micro-Minotari as a human-readable currency string.
/// `separator` is the thousands separator (e.g. ',' or '.').
#[wasm_bindgen(js_name = amountToCurrencyString)]
pub fn amount_to_currency_string(micro_minotari: u64, separator: char) -> String {
    MicroMinotari::from(micro_minotari).to_currency_string(separator)
}

/// Parses a human-readable Minotari amount string (e.g. "12.345678 T" or "1234567") into micro-Minotari.
#[wasm_bindgen(js_name = parseAmount)]
pub fn parse_amount_string(s: &str) -> Result<u64, JsValue> {
    let trimmed = s.trim();
    let value = if trimmed.chars().all(|c| c.is_ascii_digit()) {
        MicroMinotari::from_str(trimmed).map_err(|e| js_err("invalid amount", e))?
    } else {
        MicroMinotari::from_str(trimmed).map_err(|e| js_err("invalid amount", e))?
    };
    Ok(value.as_u64())
}

/// Computes the absolute transaction fee (in micro-Minotari) using the latest transaction weights.
#[wasm_bindgen(js_name = calculateFee)]
pub fn calculate_fee(
    fee_per_gram_micro: u64,
    num_kernels: usize,
    num_inputs: usize,
    num_outputs: usize,
    features_and_scripts_byte_size: usize,
) -> u64 {
    let fee = Fee::new(TransactionWeight::latest());
    fee.calculate(
        MicroMinotari::from(fee_per_gram_micro),
        num_kernels,
        num_inputs,
        num_outputs,
        features_and_scripts_byte_size,
    )
    .as_u64()
}
