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

//! Browser-oriented WebAssembly bindings for Tari L1 core primitives.
//!
//! Everything exposed here is pure computation (no I/O, no async runtime), so it compiles down to a
//! small wasm module suitable for wallets, explorers and dApps running directly in the browser.

pub mod address;
pub mod amount;
pub mod burn;
pub mod commitment;
pub mod hashing;
pub mod keys;
pub mod schnorr;
pub mod wallet;
pub mod wire;

pub use address::WasmTariAddress;
pub use burn::{WasmBurnBuilder, WasmSignedBurn};
pub use amount::{amount_to_currency_string, calculate_fee, parse_amount_string};
pub use commitment::{commitment_commit_value, commitment_open_value};
pub use hashing::{blake2b_256_hex, blake2b_512_hex};
pub use keys::WasmKeyPair;
pub use schnorr::WasmSchnorrSignature;
pub use wallet::{WasmSignedTransaction, WasmTxBuilder, WasmWallet, WasmWalletOutput};
