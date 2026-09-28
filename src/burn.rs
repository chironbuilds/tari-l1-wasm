// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Burning Minotari to an Ootle (L2) account, entirely in WASM.
//!
//! This mirrors the console wallet's `TransactionService::burn_tari` for an L2-bound burn: the burn
//! output's on-chain claim key is the stealth key `C = H(r·P)·G + P` (unlinkable to the Ootle
//! account key `P`), its encrypted data is keyed to `DH(P, r)` so the Ootle wallet can decrypt it
//! with `DH(R, p)`, and the ownership proof commits to `C`. `r` is derived from the commitment mask,
//! so the proof can be regenerated from the seed alone.
//!
//! The result carries everything an Ootle `ClaimBurn` needs except the kernel merkle proof, which
//! only exists once the burn is mined — fetch it from a base node's `/generate_kernel_merkle_proof`
//! with `kernelNonceHex`/`kernelSignatureHex`.

use tari_common_types::types::{CompressedPublicKey, FixedHash};
use tari_script::script;
use tari_transaction_components::{
    MicroMinotari, TransactionBuilder,
    key_manager::{TariKeyId, TransactionKeyManagerInterface},
    transaction_components::{
        KernelFeatures, MemoField, OutputFeatures, Transaction, WalletOutput, WalletOutputBuilder,
        memo_field::TxType,
    },
};
use tari_utilities::hex::Hex;
use wasm_bindgen::prelude::*;

use crate::wallet::{WasmWallet, WasmWalletOutput, constants_for_height, set_current_network};

fn js_err<E: std::fmt::Display>(context: &str, err: E) -> JsValue {
    JsValue::from_str(&format!("{context}: {err}"))
}

/// Builds and signs a burn of `amount` µT, claimable on Ootle by the holder of `claim_public_key`.
///
/// # Example (JS)
/// ```js
/// const builder = new WasmBurnBuilder(wallet, 10_000_000n, ootleAccountPublicKeyHex);
/// builder.addInput(utxo);
/// builder.withFeePerGram(5n);
/// builder.withTipHeight(tip);
/// const burn = builder.build();
/// submit(burn.toJson());
/// ```
#[wasm_bindgen]
pub struct WasmBurnBuilder {
    wallet: WasmWallet,
    inputs: Vec<WalletOutput>,
    amount_micro: u64,
    claim_public_key: CompressedPublicKey,
    fee_per_gram_micro: u64,
    tip_height: u64,
}

#[wasm_bindgen]
impl WasmBurnBuilder {
    /// `claim_public_key_hex` is the Ootle account's 32-byte public key (`P`). A wrong key burns
    /// the funds for good: nothing else can ever claim them.
    #[wasm_bindgen(constructor)]
    pub fn new(wallet: &WasmWallet, amount_micro: u64, claim_public_key_hex: &str) -> Result<WasmBurnBuilder, JsValue> {
        if amount_micro == 0 {
            return Err(JsValue::from_str("burn amount must be greater than zero"));
        }
        let claim_public_key = CompressedPublicKey::from_hex(claim_public_key_hex)
            .map_err(|e| js_err("invalid claim public key", e))?;
        // Decompressing proves the bytes are a real curve point; a burn to a non-point could never
        // be claimed.
        claim_public_key
            .to_public_key()
            .map_err(|e| js_err("claim public key is not a valid point", e))?;
        Ok(WasmBurnBuilder {
            wallet: wallet.clone(),
            inputs: Vec::new(),
            amount_micro,
            claim_public_key,
            fee_per_gram_micro: 0,
            tip_height: 0,
        })
    }

    /// Adds a spendable output (from this wallet) as a full input.
    #[wasm_bindgen(js_name = addInput)]
    pub fn add_input(&mut self, input: &WasmWalletOutput) {
        self.inputs.push(input.inner.clone());
    }

    #[wasm_bindgen(js_name = withFeePerGram)]
    pub fn with_fee_per_gram(&mut self, fee_per_gram_micro: u64) {
        self.fee_per_gram_micro = fee_per_gram_micro;
    }

    /// Sets the current chain tip so the correct consensus-constants epoch is used.
    #[wasm_bindgen(js_name = withTipHeight)]
    pub fn with_tip_height(&mut self, tip_height: u64) {
        self.tip_height = tip_height;
    }

    /// Produces the fully-signed burn transaction and its partial claim proof.
    pub fn build(self) -> Result<WasmSignedBurn, JsValue> {
        build_burn(
            &self.wallet,
            self.inputs,
            self.amount_micro,
            &self.claim_public_key,
            self.fee_per_gram_micro,
            self.tip_height,
        )
    }
}

/// Core burn construction, shared by the WASM binding and native tests.
pub fn build_burn(
    wallet: &WasmWallet,
    inputs: Vec<WalletOutput>,
    amount_micro: u64,
    claim_public_key: &CompressedPublicKey,
    fee_per_gram_micro: u64,
    tip_height: u64,
) -> Result<WasmSignedBurn, JsValue> {
    if inputs.is_empty() {
        return Err(JsValue::from_str("at least one input is required"));
    }
    let km = &wallet.key_manager;
    let network = wallet.network;
    set_current_network(network)?;
    let constants = constants_for_height(network, tip_height);
    let amount = MicroMinotari::from(amount_micro);

    let (commitment_mask_key, _) = km
        .get_next_commitment_mask_and_script_key()
        .map_err(|e| js_err("key derivation failed", e))?;
    // `r`, seed-deterministic from the mask so the proof can be rebuilt after a restore.
    let sender_offset = km
        .derive_burn_sender_offset_key(&commitment_mask_key.key_id)
        .map_err(|e| js_err("sender offset derivation failed", e))?;
    // `C = H(r·P)·G + P`, the on-chain claim key.
    let stealth_claim_public_key = km
        .compute_stealth_claim_public_key(&sender_offset.key_id, claim_public_key)
        .map_err(|e| js_err("stealth claim key derivation failed", e))?;
    // Ootle is the base sidechain, which carries no deployment key.
    let output_features = OutputFeatures::create_burn_confidential_output(stealth_claim_public_key.clone(), None);

    let mut builder = TransactionBuilder::new(constants, km.clone(), network).map_err(|e| js_err("builder init failed", e))?;
    builder
        .with_fee_per_gram(MicroMinotari::from(fee_per_gram_micro))
        .with_prevent_fee_gt_amount(true)
        .with_tx_type(TxType::Burn)
        .with_kernel_features(KernelFeatures::create_burn());
    for input in inputs {
        builder.with_input(input).map_err(|e| js_err("adding input failed", e))?;
    }

    // Keyed to DH(P, r) so the Ootle wallet decrypts with DH(R, p).
    let recovery_key_id = TariKeyId::DHEncryptedData {
        public_key: claim_public_key.clone(),
        private_key: sender_offset.key_id.clone().into(),
    };
    let output = WalletOutputBuilder::new(amount, commitment_mask_key.key_id.clone())
        .with_features(output_features)
        .with_script(script!(Nop).map_err(|e| js_err("script creation failed", e))?)
        .with_input_data(Default::default())
        .with_sender_offset_public_key(sender_offset.pub_key.clone())
        .with_script_key(TariKeyId::Zero)
        .with_minimum_value_promise(MicroMinotari::zero())
        .encrypt_data_for_recovery(km, Some(&recovery_key_id), MemoField::new_empty())
        .map_err(|e| js_err("encrypting burn output failed", e))?
        .sign_metadata_signature(km, &sender_offset.key_id)
        .map_err(|e| js_err("signing burn output failed", e))?
        .try_build(km)
        .map_err(|e| js_err("building burn output failed", e))?;

    builder
        .add_recipient(
            Default::default(),
            output,
            Some(sender_offset.key_id.clone()),
            Some(recovery_key_id),
        )
        .map_err(|e| js_err("adding burn output failed", e))?;

    let finalized = builder.build().map_err(|e| js_err("building transaction failed", e))?;

    let burn_kernel = finalized
        .transaction
        .body
        .kernels()
        .iter()
        .find(|k| k.features.is_burned())
        .cloned()
        .ok_or_else(|| JsValue::from_str("no burn kernel in the built transaction"))?;
    let burned = finalized
        .transaction
        .body
        .outputs()
        .iter()
        .find(|o| o.is_burned())
        .cloned()
        .ok_or_else(|| JsValue::from_str("no burn output in the built transaction"))?;

    let ownership_proof = km
        .generate_burn_claim_signature(&commitment_mask_key.key_id, amount_micro, &stealth_claim_public_key, None)
        .map_err(|e| js_err("ownership proof failed", e))?;

    Ok(WasmSignedBurn {
        fee_micro: finalized.fee.as_u64(),
        change_value_micro: finalized.change.as_ref().map(|o| o.value().as_u64()),
        change_commitment_hex: finalized.change.as_ref().map(|o| o.commitment().to_hex()),
        amount_micro,
        claim_public_key_hex: claim_public_key.to_hex(),
        commitment_hex: burned.commitment.to_hex(),
        output_hash: burned.hash(),
        encrypted_data: burned.encrypted_data.as_bytes().to_vec(),
        sender_offset_public_key_hex: sender_offset.pub_key.to_hex(),
        ownership_nonce_hex: ownership_proof.get_compressed_public_nonce().to_hex(),
        ownership_signature_hex: ownership_proof.get_signature().to_hex(),
        kernel_version: burn_kernel.version.as_u8(),
        kernel_fee_micro: burn_kernel.fee.as_u64(),
        kernel_lock_height: burn_kernel.lock_height,
        kernel_excess_hex: burn_kernel.excess.to_hex(),
        kernel_nonce_hex: burn_kernel.excess_sig.get_compressed_public_nonce().to_hex(),
        kernel_signature_hex: burn_kernel.excess_sig.get_signature().to_hex(),
        transaction: finalized.transaction,
    })
}

/// A signed burn plus the claim-proof material an Ootle `ClaimBurn` needs.
#[wasm_bindgen]
pub struct WasmSignedBurn {
    transaction: Transaction,
    fee_micro: u64,
    change_value_micro: Option<u64>,
    change_commitment_hex: Option<String>,
    amount_micro: u64,
    claim_public_key_hex: String,
    commitment_hex: String,
    output_hash: FixedHash,
    encrypted_data: Vec<u8>,
    sender_offset_public_key_hex: String,
    ownership_nonce_hex: String,
    ownership_signature_hex: String,
    kernel_version: u8,
    kernel_fee_micro: u64,
    kernel_lock_height: u64,
    kernel_excess_hex: String,
    kernel_nonce_hex: String,
    kernel_signature_hex: String,
}

impl WasmSignedBurn {
    /// Native-only access to the built transaction, for tests.
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }
}

#[wasm_bindgen]
impl WasmSignedBurn {
    /// Absolute fee in micro-Minotari.
    #[wasm_bindgen(getter, js_name = feeMicro)]
    pub fn fee_micro(&self) -> u64 {
        self.fee_micro
    }

    #[wasm_bindgen(getter, js_name = changeValueMicro)]
    pub fn change_value_micro(&self) -> Option<u64> {
        self.change_value_micro
    }

    #[wasm_bindgen(getter, js_name = changeCommitmentHex)]
    pub fn change_commitment_hex(&self) -> Option<String> {
        self.change_commitment_hex.clone()
    }

    #[wasm_bindgen(getter, js_name = amountMicro)]
    pub fn amount_micro(&self) -> u64 {
        self.amount_micro
    }

    /// The Ootle account key `P` the burn is addressed to (the proof's `burn_public_key`).
    #[wasm_bindgen(getter, js_name = claimPublicKeyHex)]
    pub fn claim_public_key_hex(&self) -> String {
        self.claim_public_key_hex.clone()
    }

    #[wasm_bindgen(getter, js_name = commitmentHex)]
    pub fn commitment_hex(&self) -> String {
        self.commitment_hex.clone()
    }

    #[wasm_bindgen(getter, js_name = outputHashHex)]
    pub fn output_hash_hex(&self) -> String {
        self.output_hash.to_hex()
    }

    #[wasm_bindgen(getter, js_name = encryptedDataHex)]
    pub fn encrypted_data_hex(&self) -> String {
        self.encrypted_data.to_hex()
    }

    #[wasm_bindgen(getter, js_name = senderOffsetPublicKeyHex)]
    pub fn sender_offset_public_key_hex(&self) -> String {
        self.sender_offset_public_key_hex.clone()
    }

    #[wasm_bindgen(getter, js_name = ownershipNonceHex)]
    pub fn ownership_nonce_hex(&self) -> String {
        self.ownership_nonce_hex.clone()
    }

    #[wasm_bindgen(getter, js_name = ownershipSignatureHex)]
    pub fn ownership_signature_hex(&self) -> String {
        self.ownership_signature_hex.clone()
    }

    #[wasm_bindgen(getter, js_name = kernelVersion)]
    pub fn kernel_version(&self) -> u8 {
        self.kernel_version
    }

    #[wasm_bindgen(getter, js_name = kernelFeeMicro)]
    pub fn kernel_fee_micro(&self) -> u64 {
        self.kernel_fee_micro
    }

    #[wasm_bindgen(getter, js_name = kernelLockHeight)]
    pub fn kernel_lock_height(&self) -> u64 {
        self.kernel_lock_height
    }

    #[wasm_bindgen(getter, js_name = kernelExcessHex)]
    pub fn kernel_excess_hex(&self) -> String {
        self.kernel_excess_hex.clone()
    }

    /// The burn kernel's excess-signature public nonce — half of the merkle-proof lookup key.
    #[wasm_bindgen(getter, js_name = kernelNonceHex)]
    pub fn kernel_nonce_hex(&self) -> String {
        self.kernel_nonce_hex.clone()
    }

    /// The burn kernel's excess-signature scalar — the other half of the merkle-proof lookup key.
    #[wasm_bindgen(getter, js_name = kernelSignatureHex)]
    pub fn kernel_signature_hex(&self) -> String {
        self.kernel_signature_hex.clone()
    }

    /// Serde JSON representation of the transaction, for `submit_transaction`.
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.transaction).map_err(|e| js_err("json serialization failed", e))
    }
}
