// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Burns built by `WasmBurnBuilder` must pass the node's own consensus checks, and must be addressed
//! so that only the Ootle account holding `p` can claim them: the on-chain claim key has to equal
//! `s·G` for `s = H(p·R) + p`, which is exactly what the Ootle side derives when it claims.
//!
//! Set `BURN_FIXTURE_OUT=path.json` to also write the burn's claim material (plus the account
//! secret) as a fixture, so the Ootle-side claim code can be checked against a real L1 burn.

use tari_common::configuration::Network;
use tari_common_types::types::{CompressedPublicKey, PrivateKey};
use tari_crypto::keys::SecretKey;
use tari_l1_wasm::{burn::build_burn, wallet::WasmWallet};
use tari_transaction_components::{
    crypto_factories::CryptoFactories,
    key_manager::KeyManager,
    test_helpers::create_consensus_manager,
    transaction_components::{SideChainFeatureData, one_sided::diffie_hellman_stealth_domain_hasher},
    validation::transaction::TransactionInternalConsistencyValidator,
};
use tari_utilities::{ByteArray, hex::Hex};

const BURN_AMOUNT: u64 = 1_000_000;

#[test]
fn burn_is_valid_and_claimable_only_by_the_account_secret() {
    let km = KeyManager::new_random().expect("km");
    let wallet = WasmWallet::from_key_manager_for_test(km.clone(), Network::Esmeralda);
    let input = tari_l1_wasm::wallet::create_self_utxo_impl(&km, 5_000_000).expect("utxo");

    // The Ootle account: secret `p`, public `P`.
    let account_secret = PrivateKey::random(&mut rand::rng());
    let account_public = CompressedPublicKey::from_secret_key(&account_secret);

    let burn = build_burn(&wallet, vec![input], BURN_AMOUNT, &account_public, 5, 0)
        .unwrap_or_else(|e| panic!("burn build failed: {e:?}"));
    let tx = burn.transaction();

    let validator =
        TransactionInternalConsistencyValidator::new(false, create_consensus_manager(), CryptoFactories::default());
    validator
        .validate(tx, None, None, u64::MAX)
        .unwrap_or_else(|e| panic!("internal consistency validation failed: {e}"));

    let kernel = tx.body.kernels().first().expect("kernel");
    assert!(kernel.features.is_burned(), "kernel must carry the burn feature");
    assert_eq!(
        kernel.burn_commitment.as_ref().map(|c| c.to_hex()),
        Some(burn.commitment_hex()),
        "kernel must commit to the burned output"
    );
    assert_eq!(kernel.excess_sig.get_compressed_public_nonce().to_hex(), burn.kernel_nonce_hex());
    assert_eq!(kernel.excess_sig.get_signature().to_hex(), burn.kernel_signature_hex());

    let burned: Vec<_> = tx.body.outputs().iter().filter(|o| o.is_burned()).collect();
    assert_eq!(burned.len(), 1, "exactly one burn output");
    let burned = burned[0];
    assert_eq!(burned.sender_offset_public_key.to_hex(), burn.sender_offset_public_key_hex());

    let on_chain_claim_key = match burned.features.sidechain_feature.as_ref().map(|f| &f.data) {
        Some(SideChainFeatureData::ConfidentialOutput(data)) => data.claim_public_key.clone(),
        other => panic!("burn output must carry confidential output data, got {other:?}"),
    };
    assert_ne!(on_chain_claim_key, account_public, "the account key must never appear on chain");

    // Recompute `s = H(p·R) + p` independently of the key manager and check it controls `C`.
    let r_pub = burned.sender_offset_public_key.to_public_key().expect("R");
    let shared = CompressedPublicKey::new_from_pk(&r_pub * &account_secret);
    let hash = diffie_hellman_stealth_domain_hasher(&shared);
    let s = PrivateKey::from_uniform_bytes(hash.as_ref()).expect("scalar") + &account_secret;
    assert_eq!(CompressedPublicKey::from_secret_key(&s), on_chain_claim_key);

    if let Ok(path) = std::env::var("BURN_FIXTURE_OUT") {
        let fixture = serde_json::json!({
            "network": "esmeralda",
            "accountSecretHex": account_secret.to_hex(),
            "accountPublicHex": account_public.to_hex(),
            "stealthClaimPublicHex": on_chain_claim_key.to_hex(),
            "amount": burn.amount_micro(),
            "commitmentHex": burn.commitment_hex(),
            "encryptedDataHex": burn.encrypted_data_hex(),
            "senderOffsetPublicKeyHex": burn.sender_offset_public_key_hex(),
            "ownershipNonceHex": burn.ownership_nonce_hex(),
            "ownershipSignatureHex": burn.ownership_signature_hex(),
            "kernel": {
                "version": burn.kernel_version(),
                "fee": burn.kernel_fee_micro(),
                "lockHeight": burn.kernel_lock_height(),
                "excessHex": burn.kernel_excess_hex(),
                "nonceHex": burn.kernel_nonce_hex(),
                "signatureHex": burn.kernel_signature_hex(),
            },
            "rangeProofPresent": burned.proof.as_ref().map(|p| !p.as_bytes().is_empty()).unwrap_or(false),
        });
        std::fs::write(&path, serde_json::to_string_pretty(&fixture).unwrap()).expect("write fixture");
    }
}
