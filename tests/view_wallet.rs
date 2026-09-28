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

use tari_common_types::types::PrivateKey;
use tari_l1_wasm::WasmWallet;
use tari_transaction_components::{
    key_manager::{KeyManager, TariKeyId, TransactionKeyManagerInterface},
    transaction_components::{
        memo_field::TxType, one_sided::public_key_to_output_encryption_key, EncryptedData,
        MemoField,
    },
};
use tari_utilities::hex::Hex;

#[test]
fn view_wallet_recovers_only_valid_outputs() {
    let full = KeyManager::new_random().unwrap();
    let private_view = full.get_private_view_key();
    let watch = WasmWallet::from_view_key_hex(
        &private_view.to_hex(),
        &full.get_spend_key().pub_key.to_hex(),
        "mainnet",
    )
    .unwrap();
    assert!(watch.is_view_only());
    assert!(!watch.can_spend());
    let unrelated = WasmWallet::new("mainnet").unwrap();
    assert_eq!(
        watch.get_address().unwrap().to_base58(),
        WasmWallet::from_view_key_and_address(
            &private_view.to_hex(),
            &watch.get_address().unwrap().to_base58(),
        )
        .unwrap()
        .get_address()
        .unwrap()
        .to_base58()
    );

    let sender = full.get_view_key().pub_key;
    let shared = full
        .get_diffie_hellman_shared_secret(&TariKeyId::ViewKey, &sender)
        .unwrap();
    let one_sided_key = public_key_to_output_encryption_key(&shared).unwrap();
    let mask = PrivateKey::from(42u64);
    let mask_id = full.create_encrypted_key(mask.clone(), None).unwrap();
    let commitment = full
        .get_commitment(&mask_id, &PrivateKey::from(123u64))
        .unwrap();

    for encryption_key in [private_view, one_sided_key] {
        for (value, output_mask, expected) in [
            (123u64, mask.clone(), true),
            (124u64, mask.clone(), false),
            (123u64, PrivateKey::from(43u64), false),
        ] {
            let data = EncryptedData::encrypt_data(
                &encryption_key,
                &commitment,
                value.into(),
                &output_mask,
                MemoField::new_open(b"view-only fixture".to_vec(), TxType::PaymentToOther).unwrap(),
            )
            .unwrap();
            let args = (commitment.to_hex(), data.to_hex(), sender.to_hex());
            assert!(!unrelated.is_output_mine(&args.0, &args.1, &args.2).unwrap());
            assert_eq!(
                watch.is_output_mine(&args.0, &args.1, &args.2).unwrap(),
                expected
            );
            if expected {
                let output = watch.view_output(&args.0, &args.1, &args.2).unwrap();
                assert_eq!(output.value_micro(), 123);
                assert_eq!(
                    output.payment_id_text().as_deref(),
                    Some("view-only fixture")
                );
            }
        }
    }
}
