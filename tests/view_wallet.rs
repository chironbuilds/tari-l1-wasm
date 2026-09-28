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
