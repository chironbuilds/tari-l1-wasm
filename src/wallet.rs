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

use borsh::BorshDeserialize;
use tari_common::configuration::Network;
use tari_common_types::{
    seeds::cipher_seed::CipherSeed,
    tari_address::{TariAddress, TariAddressFeatures},
    types::{ComAndPubSignature, CompressedCommitment, CompressedPublicKey, FixedHash, RangeProof},
};
use tari_script::{TariScript, script};
use tari_transaction_components::{
    MicroMinotari, TransactionBuilder,
    consensus::{ConsensusConstants, NetworkConsensus},
    key_manager::{
        KeyManager, SerializedKeyString, TariKeyId, TransactionKeyManagerInterface,
        wallet_types::{SeedWordsWallet, WalletType},
    },
    transaction_components::TransactionError,
    transaction_components::{
        CoinBaseExtra, EncryptedData, MemoField, OutputFeatures, OutputFeaturesVersion, OutputType, RangeProofType,
        TransactionOutput, TransactionOutputVersion, WalletOutput, covenants::Covenant,
    },
};
use tari_utilities::hex::Hex;
use tari_utilities::ByteArray;
use wasm_bindgen::prelude::*;

fn js_err<E: std::fmt::Display>(context: &str, err: E) -> JsValue {
    JsValue::from_str(&format!("{context}: {err}"))
}

fn parse_network(network: &str) -> Result<Network, JsValue> {
    let network = Network::from_str(network)
        .map_err(|e| js_err("invalid network (mainnet|stagenet|nextnet|localnet|igor|esmeralda)", e))?;
    set_current_network(network)?;
    Ok(network)
}

/// Pins the process-wide current network.
///
/// Every consensus hash (output hashes, and the kernel, metadata and script signature challenges)
/// is domain-separated with the *current* network byte via
/// `DomainSeparatedConsensusHasher::new`, which reads `Network::get_current_or_user_setting_or_default()`.
/// A wasm32 build has neither the `tari_target_network_*` cfg nor a `TARI_NETWORK` environment
/// variable, so without this the default (Esmeralda) is used no matter which network the wallet was
/// created for, and a base node on any other network recomputes different hashes for the very same
/// transaction — the input's output hash misses the UTXO set and the kernel signature does not
/// verify, so the transaction is rejected.
pub(crate) fn set_current_network(network: Network) -> Result<(), JsValue> {
    // `set_current` is a `OnceLock`: the first wallet in this instance wins.
    if Network::set_current(network).is_err() {
        let current = Network::get_current_or_user_setting_or_default();
        if current != network {
            return Err(JsValue::from_str(&format!(
                "this instance is already pinned to the {current} network; reload before using {network}"
            )));
        }
    }
    Ok(())
}

/// Selects the consensus constants effective at `tip_height`.
pub fn constants_for_height(network: Network, tip_height: u64) -> ConsensusConstants {
    let all = NetworkConsensus::from(network).create_consensus_constants();
    // Constants epochs are ordered by `effective_from_height`; pick the newest applicable one.
    match all.iter().rev().find(|c| c.effective_from_height() <= tip_height) {
        Some(c) => c.clone(),
        None => NetworkConsensus::from(network)
            .create_consensus_constants()
            .pop()
            .expect("consensus constants are never empty"),
    }
}

/// A self-contained Tari wallet capable of building fully-signed L1 transactions entirely in WASM.
///
/// Keys are derived from a CipherSeed; the seed can be exported/imported as an enciphered hex blob
/// (no passphrase) for persistence. Recipients must be dual ("one-sided") addresses since payments
/// are constructed as stealth one-sided transactions.
#[derive(Clone)]
#[wasm_bindgen]
pub struct WasmWallet {
    pub(crate) key_manager: KeyManager,
    pub(crate) network: Network,
    cipher_seed: Option<CipherSeed>,
}

impl WasmWallet {
    /// Builds a wallet around an existing key manager. Native-only: the wasm bindings always come
    /// in through a seed, but a test needs to drive the same wallet from both sides of a payment.
    pub fn from_key_manager_for_test(key_manager: KeyManager, network: Network) -> Self {
        WasmWallet { key_manager, network, cipher_seed: None }
    }
}

#[wasm_bindgen]
impl WasmWallet {
    #[wasm_bindgen(constructor)]
    pub fn new(network: &str) -> Result<WasmWallet, JsValue> {
        let network = parse_network(network)?;
        let cipher_seed = CipherSeed::random();
        let seed_wallet =
            SeedWordsWallet::construct_new(cipher_seed.clone()).map_err(|e| js_err("failed to derive keys", e))?;
        Ok(WasmWallet {
            key_manager: KeyManager::new(WalletType::SeedWords(seed_wallet))
                .map_err(|e| js_err("failed to create wallet", e))?,
            network,
            cipher_seed: Some(cipher_seed),
        })
    }

    /// Restores a wallet from an enciphered seed blob (see `getBackupHex`).
    #[wasm_bindgen(js_name = fromBackupHex)]
    pub fn from_backup_hex(backup_hex: &str, network: &str) -> Result<WasmWallet, JsValue> {
        let network = parse_network(network)?;
        let bytes = Vec::<u8>::from_hex(backup_hex).map_err(|e| js_err("invalid backup hex", e))?;
        let seed = CipherSeed::from_enciphered_bytes(&bytes, None).map_err(|e| js_err("invalid backup data", e))?;
        let seed_wallet =
            SeedWordsWallet::construct_new(seed.clone()).map_err(|e| js_err("failed to derive keys", e))?;
        Ok(WasmWallet {
            key_manager: KeyManager::new(WalletType::SeedWords(seed_wallet))
                .map_err(|e| js_err("failed to restore wallet", e))?,
            network,
            cipher_seed: Some(seed),
        })
    }

    /// Exports the wallet seed as an enciphered hex blob for persistence.
    #[wasm_bindgen(js_name = getBackupHex)]
    pub fn get_backup_hex(&self) -> Result<String, JsValue> {
        self.cipher_seed
            .as_ref()
            .ok_or_else(|| JsValue::from_str("wallet has no seed"))?
            .encipher(None)
            .map(|b| b.to_hex())
            .map_err(|e| js_err("failed to encipher seed", e))
    }

    /// The wallet's own dual one-sided payment address.
    #[wasm_bindgen(js_name = getAddress)]
    pub fn get_address(&self) -> Result<crate::address::WasmTariAddress, JsValue> {
        let view_key = self.key_manager.get_view_key();
        let spend_key = self.key_manager.get_spend_key();
        let address = TariAddress::new_dual_address(
            view_key.pub_key.clone(),
            spend_key.pub_key.clone(),
            self.network,
            TariAddressFeatures::create_one_sided_only(),
            None,
        )
        .map_err(|e| js_err("failed to derive address", e))?;
        Ok(crate::address::WasmTariAddress::from_inner(address))
    }

    /// Answers only "is this one mine", and builds nothing.
    ///
    /// A chain scan asks this of every output that has ever existed, and the answer is no for all
    /// but a handful. Routing that through `importScannedOutput` makes each miss pay for a hex
    /// parse of the script, metadata signature, covenant and coinbase extra, the construction of
    /// an `OutputFeatures`, and a thrown JS exception to report the miss — none of which the
    /// answer depends on. Ownership is settled by the commitment, the encrypted data and the
    /// sender offset key alone, so those are all this takes, and it returns a plain bool.
    ///
    /// The caller re-fetches and imports the winners properly; this is a filter, not an import.
    #[wasm_bindgen(js_name = isOutputMine)]
    pub fn is_output_mine(
        &self,
        commitment_hex: &str,
        encrypted_data_hex: &str,
        sender_offset_pub_hex: &str,
    ) -> Result<bool, JsValue> {
        let commitment =
            CompressedCommitment::from_hex(commitment_hex).map_err(|e| js_err("invalid commitment", e))?;
        let encrypted_bytes =
            Vec::<u8>::from_hex(encrypted_data_hex).map_err(|e| js_err("invalid encrypted data", e))?;
        let encrypted_data =
            EncryptedData::from_bytes(&encrypted_bytes).map_err(|e| js_err("invalid encrypted data", e))?;
        let sender_offset_pub = CompressedPublicKey::from_hex(sender_offset_pub_hex)
            .map_err(|e| js_err("invalid sender offset public key", e))?;

        Ok(self
            .key_manager
            .try_output_key_recovery(&commitment, &encrypted_data, &sender_offset_pub)
            .map_err(|e| js_err("recovery failed", e))?
            .is_some())
    }

    /// Recovers a spendable output owned by this wallet from scanned chain data.
    ///
    /// The encrypted value/mask are decrypted internally (view-key and DH stealth flows), verified
    /// against the commitment, and the resulting UTXO becomes spendable by `WasmTxBuilder`.
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = importScannedOutput)]
    pub fn import_scanned_output(
        &self,
        commitment_hex: &str,
        encrypted_data_hex: &str,
        sender_offset_pub_hex: &str,
        script_hex: &str,
        metadata_sig_hex: &str,
        minimum_value_promise_micro: u64,
        maturity: u64,
        output_type_byte: u8,
        range_proof_type_byte: u8,
        coinbase_extra_hex: &str,
        covenant_hex: &str,
        range_proof_hex: &str,
        output_hash_hex: &str,
    ) -> Result<WasmWalletOutput, JsValue> {
        let commitment = CompressedCommitment::from_hex(commitment_hex).map_err(|e| js_err("invalid commitment", e))?;
        let encrypted_bytes =
            Vec::<u8>::from_hex(encrypted_data_hex).map_err(|e| js_err("invalid encrypted data", e))?;
        let encrypted_data =
            EncryptedData::from_bytes(&encrypted_bytes).map_err(|e| js_err("invalid encrypted data", e))?;
        let sender_offset_pub = CompressedPublicKey::from_hex(sender_offset_pub_hex)
            .map_err(|e| js_err("invalid sender offset public key", e))?;

        let (mask_key_id, value, memo) = self
            .key_manager
            .try_output_key_recovery(&commitment, &encrypted_data, &sender_offset_pub)
            .map_err(|e| js_err("recovery failed", e))?
            .ok_or_else(|| JsValue::from_str("output does not belong to this wallet"))?;

        let mut covenant_bytes =
            Vec::<u8>::from_hex(covenant_hex).map_err(|e| js_err("invalid covenant", e))?;
        let covenant = Covenant::deserialize(&mut covenant_bytes.as_slice())
            .map_err(|e| js_err("invalid covenant", e))?;

        let range_proof = if range_proof_hex.is_empty() {
            None
        } else {
            let proof_bytes =
                Vec::<u8>::from_hex(range_proof_hex).map_err(|e| js_err("invalid range proof", e))?;
            Some(
                RangeProof::from_canonical_bytes(&proof_bytes)
                    .map_err(|e| js_err("invalid range proof", e))?,
            )
        };

        let script_bytes = Vec::<u8>::from_hex(script_hex).map_err(|e| js_err("invalid script", e))?;
        let script = TariScript::from_bytes(&script_bytes).map_err(|e| js_err("invalid script", e))?;
        let sig_bytes = Vec::<u8>::from_hex(metadata_sig_hex).map_err(|e| js_err("invalid metadata signature", e))?;
        let metadata_sig = ComAndPubSignature::deserialize(&mut sig_bytes.as_slice())
            .map_err(|e| js_err("invalid metadata signature", e))?;

        let coinbase_extra =
            Vec::<u8>::from_hex(coinbase_extra_hex).map_err(|e| js_err("invalid coinbase extra", e))?;
        let features = OutputFeatures::new(
            OutputFeaturesVersion::get_current_version(),
            OutputType::from_byte(output_type_byte).ok_or_else(|| JsValue::from_str("invalid output type byte"))?,
            maturity,
            CoinBaseExtra::try_from(coinbase_extra).map_err(|e| js_err("invalid coinbase extra", e))?,
            None,
            RangeProofType::from_byte(range_proof_type_byte)
                .ok_or_else(|| JsValue::from_str("invalid range proof type byte"))?,
        );

        let recovered_payment_id = memo.payment_id_as_bytes();
        // A one-sided payment reveals nothing about its sender by design; an address only appears
        // here because the sending wallet chose to put one in the memo (the `AddressAndData`
        // variant). An unset one serialises as the all-zero address, which base58-encodes to a run
        // of `1`s — meaningless to show, so it is reported as absent rather than passed through.
        let recovered_sender_fee = memo.get_fee().map(|f| f.as_u64());
        let recovered_sender = memo.get_sender_address().and_then(|address| {
            let is_unset = address.public_spend_key().as_bytes().iter().all(|b| *b == 0);
            if is_unset { None } else { Some(address.to_base58()) }
        });
        let mask_str = SerializedKeyString::from(mask_key_id.to_string());
        let script_key_id = self
            .key_manager
            .find_script_key_id_from_commitment_mask_key_id(&mask_key_id, None)
            .map_err(|e| js_err("script key derivation failed", e))?
            .unwrap_or(TariKeyId::Derived { key: mask_str });

        let mut wallet_output = WalletOutput::new_current_version(
            value,
            mask_key_id,
            features,
            script,
            Default::default(),
            script_key_id,
            sender_offset_pub,
            metadata_sig,
            0,
            covenant,
            encrypted_data,
            MicroMinotari::from(minimum_value_promise_micro),
            memo,
            &self.key_manager,
        )
        .map_err(|e| js_err("failed to build spendable output", e))?;
        wallet_output.set_range_proof(range_proof);

        let chain_hash = if output_hash_hex.is_empty() {
            None
        } else {
            let hash_bytes =
                Vec::<u8>::from_hex(output_hash_hex).map_err(|e| js_err("invalid output hash", e))?;
            Some(FixedHash::try_from(&hash_bytes[..]).map_err(|e| js_err("invalid output hash", e))?)
        };

        Ok(WasmWalletOutput {
            inner: wallet_output,
            chain_output_hash_hex: chain_hash.map(|h| h.to_hex()),
            seed_error: std::cell::RefCell::new(None),
            payment_id: recovered_payment_id,
            sender_address: recovered_sender,
            sender_fee_micro: recovered_sender_fee,
        })
    }

    /// Creates a fresh spendable UTXO handle owned by this wallet (useful for testing flows and
    /// self-transfer construction before on-chain confirmation).
    #[wasm_bindgen(js_name = createSelfUtxo)]
    pub fn create_self_utxo(&self, value_micro: u64) -> Result<WasmWalletOutput, JsValue> {
        let inner =
            create_self_utxo_impl(&self.key_manager, value_micro).map_err(|e| js_err("failed to build output", e))?;
        Ok(WasmWalletOutput {
            inner,
            chain_output_hash_hex: None,
            seed_error: std::cell::RefCell::new(None),
            payment_id: Vec::new(),
            sender_address: None,
            sender_fee_micro: None,
        })
    }

    /// Debug: hashes range-proof hex with Tari's domain hasher (matches chain rangeproof_hash).
    #[wasm_bindgen(js_name = debugHashRangeProof)]
    pub fn debug_hash_range_proof(range_proof_hex: &str) -> Result<String, JsValue> {
        use tari_common_types::types::BulletRangeProof;
        let bytes =
            Vec::<u8>::from_hex(range_proof_hex).map_err(|e| js_err("invalid range proof", e))?;
        Ok(BulletRangeProof(bytes).hash().to_hex())
    }

    /// Debug: build marker to verify the served wasm is current.
    #[wasm_bindgen(js_name = wasmBuildMarker)]
    pub fn wasm_build_marker() -> String {
        format!(
            "compact-v3 (compact={} full={})",
            COMPACT_CALLS.load(std::sync::atomic::Ordering::Relaxed),
            FULL_CALLS.load(std::sync::atomic::Ordering::Relaxed)
        )
    }
}

static COMPACT_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static FULL_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Creates a fresh spendable output owned by the key manager's wallet (mirrors change-output construction).
pub fn create_self_utxo_impl(
    km: &KeyManager,
    value_micro: u64,
) -> Result<WalletOutput, tari_transaction_components::transaction_components::TransactionError> {
    let (mask_key, script_key) = km
        .get_next_commitment_mask_and_script_key()
        .map_err(|e| TransactionError::BuilderError(e.to_string()))?;
    let sender_offset = km
        .get_random_key(None, None)
        .map_err(|e| TransactionError::BuilderError(e.to_string()))?;
    let sender_offset_public = km
        .get_public_key_at_key_id(&sender_offset.key_id)
        .map_err(|e| TransactionError::BuilderError(e.to_string()))?;

    let value = MicroMinotari::from(value_micro);
    let script = script!(PushPubKey(Box::new(script_key.pub_key.clone())))
        .map_err(|e| TransactionError::BuilderError(format!("script creation failed: {e}")))?;

    let encrypted_data = km
        .encrypt_data_for_recovery(&mask_key.key_id, None, value.as_u64(), MemoField::new_empty())
        .map_err(|e| TransactionError::BuilderError(e.to_string()))?;

    let features = OutputFeatures::default();
    let covenant = Covenant::default();
    let message = TransactionOutput::metadata_signature_message_from_parts(
        TransactionOutputVersion::get_current_version(),
        &script,
        &features,
        &covenant,
        &encrypted_data,
        &MicroMinotari::zero(),
    );

    let metadata_sig = km
        .get_metadata_signature(
            &mask_key.key_id,
            &value.into(),
            &sender_offset.key_id,
            TransactionOutputVersion::get_current_version(),
            &message,
            features.range_proof_type,
        )
        .map_err(|e| TransactionError::BuilderError(e.to_string()))?;

    WalletOutput::new_current_version(
        value,
        mask_key.key_id,
        features,
        script,
        Default::default(),
        script_key.key_id,
        sender_offset_public,
        metadata_sig,
        0,
        covenant,
        encrypted_data,
        MicroMinotari::zero(),
        MemoField::new_empty(),
        km,
    )
}

/// Core transaction-building logic shared by the WASM bindings and native tests.
///
/// Consumes the given inputs, sends the specified amounts to the recipients as stealth one-sided
/// outputs, adds change back to the wallet and returns the fully-signed transaction.
pub fn build_stealth_payment(
    km: &KeyManager,
    network: Network,
    inputs: Vec<WalletOutput>,
    compact_output_hashes: Vec<Option<FixedHash>>,
    recipients: Vec<(TariAddress, u64)>,
    fee_per_gram_micro: u64,
    lock_height: u64,
    tip_height: u64,
    reveal_sender: bool,
) -> Result<
    (
        tari_transaction_components::transaction_components::Transaction,
        u64,
        Option<u64>,
        Option<String>,
    ),
    JsValue,
> {
    if inputs.is_empty() {
        return Err(JsValue::from_str("at least one input is required"));
    }
    if recipients.is_empty() {
        return Err(JsValue::from_str("at least one recipient is required"));
    }
    set_current_network(network)?;
    let constants = constants_for_height(network, tip_height);
    // A one-sided payment is unlinkable to its sender on chain. The recipient only learns who
    // paid if the sender puts their own address in the memo, which travels inside the output's
    // encrypted data and is readable with the recipient's view key. That is a disclosure, so it
    // is opt-in per transaction rather than a default.
    //
    // The fee is recorded as zero rather than the real one: the memo has to be built before the
    // transaction is, and the fee depends on the very weight this memo contributes. Tari's own
    // wallet solves that with a two-pass estimate the builder here does not expose; the address is
    // the part that matters to a recipient, and an honest zero beats a wrong number.
    let sender_address = if reveal_sender {
        let view_key = km.get_view_key();
        let spend_key = km.get_spend_key();
        Some(
            TariAddress::new_dual_address(
                view_key.pub_key.clone(),
                spend_key.pub_key.clone(),
                network,
                TariAddressFeatures::create_one_sided_only(),
                None,
            )
            .map_err(|e| js_err("failed to derive this wallet's address", e))?,
        )
    } else {
        None
    };
    // One whole build of the transaction, with `memo_fee` written into the recipient's memo.
    let build_pass = |memo_fee: MicroMinotari| {
        let mut builder = TransactionBuilder::new(constants.clone(), km.clone(), network)
            .map_err(|e| js_err("builder init failed", e))?;
        builder
            .with_lock_height(lock_height)
            .with_fee_per_gram(MicroMinotari::from(fee_per_gram_micro))
            .with_prevent_fee_gt_amount(true);
        for (idx, input) in inputs.iter().cloned().enumerate() {
            match compact_output_hashes.get(idx).copied().flatten() {
                Some(chain_hash) => {
                    COMPACT_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    builder
                        .with_compact_input(input, chain_hash)
                        .map_err(|e| js_err("adding compact input failed", e))?;
                },
                None => {
                    FULL_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    builder
                        .with_input(input)
                        .map_err(|e| js_err("adding input failed", e))?;
                },
            }
        }
        for (address, amount) in recipients.iter() {
            let memo = match &sender_address {
                Some(own) => MemoField::new_empty()
                    .add_sender_address(own.clone(), true, memo_fee, None)
                    .map_err(|e| js_err("failed to attach the sender address", e))?,
                None => MemoField::new_empty(),
            };
            builder
                .add_stealth_recipient(
                    address.clone(),
                    MicroMinotari::from(*amount),
                    OutputFeatures::default(),
                    memo,
                )
                .map_err(|e| js_err("adding recipient failed", e))?;
        }
        builder.build().map_err(|e| js_err("building transaction failed", e))
    };

    // The memo carries the fee the sender paid, but the fee depends on the weight the memo itself
    // contributes — so it cannot be known when the memo is written. Tari's own wallet resolves
    // this with a fee *estimate* that excludes the change output; a second full build does better,
    // because `MemoField::new_address_and_data` pads to a size derived from the address and
    // payment id, never from the fee value. The memo is therefore the same size whatever number
    // goes in it, the weight is unchanged, and the second pass settles on exactly the fee the
    // recipient will see recorded. Only worth paying for when there is a fee to disclose: a
    // payment that reveals nothing skips the second pass and its range-proof work entirely.
    let finalized = if sender_address.is_some() {
        let first = build_pass(MicroMinotari::zero())?;
        let settled = build_pass(first.fee)?;
        // Size-stability is what makes one extra pass sufficient. If it ever failed to hold, the
        // memo would advertise a fee the transaction does not pay, so say so rather than ship a
        // plausible-looking wrong number.
        if settled.fee != first.fee {
            return Err(JsValue::from_str(&format!(
                "fee did not settle between passes ({} then {}) — refusing to record a fee the transaction does not pay",
                first.fee, settled.fee
            )));
        }
        settled
    } else {
        build_pass(MicroMinotari::zero())?
    };

    let change_value_micro = finalized.change.as_ref().map(|o| o.value().as_u64());
    let change_commitment_hex = finalized.change.as_ref().map(|o| o.commitment().to_hex());
    Ok((
        finalized.transaction,
        finalized.fee.as_u64(),
        change_value_micro,
        change_commitment_hex,
    ))
}

/// A spendable output owned by a `WasmWallet`.
#[wasm_bindgen]
pub struct WasmWalletOutput {
    pub(crate) inner: WalletOutput,
    pub(crate) chain_output_hash_hex: Option<String>,
    pub(crate) seed_error: std::cell::RefCell<Option<String>>,
    /// The payment id the sender attached, recovered from this output's encrypted data. Empty for
    /// an output with no memo. This is what attributes an incoming payment to a sub-address.
    pub(crate) payment_id: Vec<u8>,
    /// The sender's own address, when their wallet chose to include it in the memo.
    pub(crate) sender_address: Option<String>,
    /// The fee the sender recorded paying, when the memo carries one.
    pub(crate) sender_fee_micro: Option<u64>,
}

#[wasm_bindgen]
impl WasmWalletOutput {
    #[wasm_bindgen(getter, js_name = valueMicro)]
    pub fn value_micro(&self) -> u64 {
        self.inner.value().as_u64()
    }

    #[wasm_bindgen(getter, js_name = commitmentHex)]
    pub fn commitment_hex(&self) -> String {
        self.inner.commitment().to_hex()
    }

    /// The chain-stored output hash (if this output was imported from scanned chain data).
    #[wasm_bindgen(getter, js_name = chainOutputHash)]
    pub fn chain_output_hash(&self) -> Option<String> {
        self.chain_output_hash_hex.clone()
    }

    /// Error from the last compact-input seeding attempt, if any.
    #[wasm_bindgen(getter, js_name = seedError)]
    pub fn seed_error(&self) -> Option<String> {
        self.seed_error.borrow().clone()
    }

    /// The payment id the sender attached, as raw bytes — empty when the output carries no memo.
    /// Matching these against a sub-address's payment id is what attributes a received payment.
    #[wasm_bindgen(getter, js_name = paymentId)]
    pub fn payment_id(&self) -> Vec<u8> {
        self.payment_id.clone()
    }

    /// The sender's base58 address, when their wallet included one in the memo.
    ///
    /// Absent for anything that did not: coinbase/mining rewards, wallets that do not attach a
    /// sender address, and anyone who deliberately stayed anonymous. A one-sided payment is
    /// unlinkable to its sender on-chain, so this is a courtesy from the sender, never a
    /// guarantee — and never something to treat as proof of who paid.
    #[wasm_bindgen(getter, js_name = senderAddress)]
    pub fn sender_address(&self) -> Option<String> {
        self.sender_address.clone()
    }

    /// The fee the sender recorded paying for this payment, when the memo carries one.
    #[wasm_bindgen(getter, js_name = senderFeeMicro)]
    pub fn sender_fee_micro(&self) -> Option<u64> {
        self.sender_fee_micro
    }

    /// The payment id as UTF-8 text, when it is valid UTF-8 — sub-addresses created by this wallet
    /// use the label itself, so this is normally the human-readable label.
    #[wasm_bindgen(getter, js_name = paymentIdText)]
    pub fn payment_id_text(&self) -> Option<String> {
        if self.payment_id.is_empty() {
            return None;
        }
        String::from_utf8(self.payment_id.clone()).ok()
    }
}

/// Builds and signs a complete one-sided Minotari transaction entirely in WASM.
///
/// # Example (JS)
/// ```js
/// const builder = new WasmTxBuilder(wallet);
/// builder.addInput(utxo1);
/// builder.addRecipient(recipientAddress, 5_000_000n);
/// builder.withFeePerGram(2n);
/// builder.withTipHeight(currentTipHeight); // selects the consensus-constants epoch
/// const signed = builder.build();
/// // A base node speaks gRPC, not JSON-RPC: hand `signed.toJson()` to a gRPC-speaking
/// // middleware that maps it onto `tari.rpc.BaseNode/SubmitTransaction`.
/// ```
#[wasm_bindgen]
pub struct WasmTxBuilder {
    wallet: WasmWallet,
    inputs: Vec<WalletOutput>,
    compact_output_hashes: Vec<Option<FixedHash>>,
    recipient_addresses: Vec<TariAddress>,
    recipient_amounts: Vec<u64>,
    fee_per_gram_micro: u64,
    lock_height: u64,
    tip_height: u64,
    reveal_sender: bool,
}

#[wasm_bindgen]
impl WasmTxBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(wallet: &WasmWallet) -> WasmTxBuilder {
        WasmTxBuilder {
            wallet: wallet.clone(),
            inputs: Vec::new(),
            compact_output_hashes: Vec::new(),
            recipient_addresses: Vec::new(),
            recipient_amounts: Vec::new(),
            fee_per_gram_micro: 0,
            lock_height: 0,
            tip_height: 0,
            reveal_sender: false,
        }
    }

    /// Adds a spendable output (from this wallet) to be consumed by the transaction.
    ///
    /// The output is spent as a FULL input, carrying all of the spent output's data. A base node
    /// only hydrates compact inputs while validating a *block* body, so a transaction submitted to
    /// its mempool must carry the data itself — see `addCompactInput`.
    #[wasm_bindgen(js_name = addInput)]
    pub fn add_input(&mut self, input: &WasmWalletOutput) {
        self.compact_output_hashes.push(None);
        self.inputs.push(input.inner.clone());
    }

    /// Adds a spendable output as a COMPACT input, referencing the spent output by its
    /// chain-stored hash only.
    ///
    /// Only valid where the consumer hydrates compact inputs from its own database (block
    /// propagation and block validation). The mempool does NOT, so a transaction built this way is
    /// rejected by `SubmitTransaction`; use `addInput` for anything submitted to a base node.
    /// Falls back to a full input when the output has no known chain hash.
    #[wasm_bindgen(js_name = addCompactInput)]
    pub fn add_compact_input(&mut self, input: &WasmWalletOutput) {
        let chain_hash = input.chain_output_hash_hex.as_ref().and_then(|hex_str| {
            let bytes = Vec::<u8>::from_hex(hex_str).ok()?;
            FixedHash::try_from(&bytes[..]).ok()
        });
        self.compact_output_hashes.push(chain_hash);
        self.inputs.push(input.inner.clone());
    }

    /// Adds a recipient; `address` may be emoji, base58 or hex. Must be a dual/one-sided address.
    #[wasm_bindgen(js_name = addRecipient)]
    pub fn add_recipient(&mut self, address: &str, amount_micro: u64) -> Result<(), JsValue> {
        let address = TariAddress::from_str(address).map_err(|e| js_err("invalid recipient address", e))?;
        if address.public_view_key().is_none() {
            return Err(JsValue::from_str(
                "recipient address must be a dual (one-sided) address containing a view key",
            ));
        }
        self.recipient_addresses.push(address);
        self.recipient_amounts.push(amount_micro);
        Ok(())
    }

    #[wasm_bindgen(js_name = withFeePerGram)]
    pub fn with_fee_per_gram(&mut self, fee_per_gram_micro: u64) {
        self.fee_per_gram_micro = fee_per_gram_micro;
    }

    #[wasm_bindgen(js_name = withLockHeight)]
    pub fn with_lock_height(&mut self, lock_height: u64) {
        self.lock_height = lock_height;
    }

    /// Sets the current chain tip so the correct consensus-constants epoch is used.
    #[wasm_bindgen(js_name = withTipHeight)]
    pub fn with_tip_height(&mut self, tip_height: u64) {
        self.tip_height = tip_height;
    }

    /// Includes this wallet's own address in the recipient's memo, so they can see who paid.
    ///
    /// Off by default. A one-sided payment reveals nothing about its sender on chain, and this
    /// deliberately gives that up: anyone who can read the recipient's view key — the recipient,
    /// or whoever they show it to — learns the payment came from this wallet. It cannot be undone
    /// once the transaction is broadcast.
    #[wasm_bindgen(js_name = withSenderRevealed)]
    pub fn with_sender_revealed(&mut self, reveal: bool) {
        self.reveal_sender = reveal;
    }

    /// Produces the fully-signed transaction (range proofs included).
    pub fn build(self) -> Result<WasmSignedTransaction, JsValue> {
        let recipients: Vec<_> = self
            .recipient_addresses
            .into_iter()
            .zip(self.recipient_amounts)
            .collect();
        let (transaction, fee_micro, change_value_micro, change_commitment_hex) = build_stealth_payment(
            &self.wallet.key_manager,
            self.wallet.network,
            self.inputs,
            self.compact_output_hashes,
            recipients,
            self.fee_per_gram_micro,
            self.lock_height,
            self.tip_height,
            self.reveal_sender,
        )?;

        Ok(WasmSignedTransaction {
            transaction,
            fee_micro,
            change_value_micro,
            change_commitment_hex,
        })
    }
}

/// A fully-signed transaction ready for submission to a base node.
#[wasm_bindgen]
pub struct WasmSignedTransaction {
    pub(crate) transaction: tari_transaction_components::transaction_components::Transaction,
    fee_micro: u64,
    change_value_micro: Option<u64>,
    change_commitment_hex: Option<String>,
}

#[wasm_bindgen]
impl WasmSignedTransaction {
    /// Absolute fee in micro-Minotari.
    #[wasm_bindgen(getter, js_name = feeMicro)]
    pub fn fee_micro(&self) -> u64 {
        self.fee_micro
    }

    /// Change returned to this wallet, if any.
    #[wasm_bindgen(getter, js_name = changeValueMicro)]
    pub fn change_value_micro(&self) -> Option<u64> {
        self.change_value_micro
    }

    #[wasm_bindgen(getter, js_name = changeCommitmentHex)]
    pub fn change_commitment_hex(&self) -> Option<String> {
        self.change_commitment_hex.clone()
    }

    /// Serde JSON representation of the transaction, for a middleware that maps it onto the
    /// `tari.rpc.BaseNode/SubmitTransaction` gRPC request.
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.transaction).map_err(|e| js_err("json serialization failed", e))
    }

    /// Protobuf-encoded `proto.types.Transaction` message.
    #[wasm_bindgen(js_name = toProtoBytes)]
    pub fn to_proto_bytes(&self) -> Result<Vec<u8>, JsValue> {
        crate::wire::transaction_proto_bytes(&self.transaction).map_err(|e| JsValue::from_str(&e))
    }

    /// Protobuf-encoded `SubmitTransactionRequest` for gRPC submission.
    #[wasm_bindgen(js_name = toSubmitRequestBytes)]
    pub fn to_submit_request_bytes(&self) -> Result<Vec<u8>, JsValue> {
        crate::wire::submit_transaction_request_bytes(&self.transaction).map_err(|e| JsValue::from_str(&e))
    }
}
