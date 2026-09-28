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

use blake2::digest::consts::U32;
use blake2::{Blake2b, Blake2b512, Digest};
use tari_utilities::hex::Hex;
use wasm_bindgen::prelude::*;

/// BLAKE2b-256 hash of the input bytes, hex encoded. Matches Tari's 256-bit Blake2b usage.
#[wasm_bindgen(js_name = blake2b256Hex)]
pub fn blake2b_256_hex(data: &[u8]) -> String {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    hasher.finalize().to_vec().to_hex()
}

/// BLAKE2b-512 hash of the input bytes, hex encoded. This is the digest Tari uses for Schnorr challenges.
#[wasm_bindgen(js_name = blake2b512Hex)]
pub fn blake2b_512_hex(data: &[u8]) -> String {
    let mut hasher = Blake2b512::new();
    hasher.update(data);
    hasher.finalize().to_vec().to_hex()
}
