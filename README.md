# tari-l1-wasm

WebAssembly bindings for Tari L1 (Minotari) core primitives. Build fully-signed Minotari
transactions entirely in the browser — no wallet daemon, no backend.

- **Wallet**: seed-based key derivation, address generation, encrypted backup import/export
- **UTXOs**: recover spendable outputs from scanned chain data (view-key + stealth DH decryption)
- **Transactions**: complete one-sided payments with Bulletproofs+ range proofs, kernel excess
  signatures, sender/script offsets and automatic change — all client-side
- **Submission payloads**: serde JSON for the base node HTTP `/json_rpc` endpoint (plain `fetch`),
  or protobuf `SubmitTransactionRequest` bytes for gRPC/gRPC-Web
- **Primitives**: Ristretto Schnorr sign/verify, Pedersen commitments, BLAKE2b, fee estimation

Published to npm as **[`@chironbuilder/tari-l1-wasm`](https://www.npmjs.com/package/@chironbuilder/tari-l1-wasm)**.

## About this repository

This is the **source** of the `@chironbuilder/tari-l1-wasm` package, opened so others can read it,
file issues and contribute.

> **Heads-up — this crate does not build on its own.** It is a crate of the
> [Tari monorepo](https://github.com/tari-project/tari) (`base_layer/tari_l1_wasm`) and depends on
> other workspace crates (`tari_crypto`, `tari_common_types`, `tari_transaction_components`,
> `tari_script`, …) via `workspace = true`. It also carries two small edits to
> `tari_transaction_components` (see [`integration.patch`](./integration.patch)). To compile it you
> need the surrounding workspace — see **Building** below.

## Installation (use the package)

```sh
npm install @chironbuilder/tari-l1-wasm
```

## Usage

```js
import {
  WasmWallet,
  WasmTxBuilder,
} from "@chironbuilder/tari-l1-wasm";
// The module self-initializes its WASM instance on import.
// Bundlers (Vite/webpack/rspack) handle the .wasm import automatically.
// Plain Node >= 22 needs: node --experimental-wasm-modules your-script.mjs

// 1. Wallet (or restore with WasmWallet.fromBackupHex(backup, "esmeralda"))
const alice = new WasmWallet("esmeralda");
console.log(alice.getAddress().toBase58());

// 2. Spendable inputs: from scanned chain data via alice.importScannedOutput(...),
//    or self-created handles for testing:
const utxo = alice.createSelfUtxo(5_000_000n); // amounts are BigInt micro-Minotari (uT)

// 3. Build + sign a payment
const builder = new WasmTxBuilder(alice);
builder.addInput(utxo);
builder.addRecipient(recipientAddressBase58OrEmoji, 1_000_000n);
builder.withFeePerGram(2n);
const signed = builder.build();
console.log("fee:", signed.feeMicro, "change:", signed.changeValueMicro);

// 4a. Submit over plain HTTP (base node wallet service)
await fetch(nodeUrl + "/json_rpc", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    jsonrpc: "2.0", id: "1", method: "submit_transaction",
    params: { transaction: JSON.parse(signed.toJson()), version: 2 },
  }),
});

// 4b. ...or gRPC: send signed.toSubmitRequestBytes() to BaseNode.SubmitTransaction
```

Recipients must be dual ("one-sided") addresses containing a view key.

## Building from source

Because this is a monorepo crate, build it inside a Tari checkout:

```sh
# 1. Clone the Tari monorepo this was built against
git clone https://github.com/tari-project/tari.git
cd tari
git checkout v5.6.0-pre.1

# 2. Drop this crate's source into place (replace <this-repo> with your clone of this repo)
mkdir -p base_layer/tari_l1_wasm
cp -r <this-repo>/{Cargo.toml,LICENSE,README.md,src,tests,scripts,smoke_test.mjs} base_layer/tari_l1_wasm/

# 3. Apply the workspace registration + the two tari_transaction_components edits
git apply <this-repo>/integration.patch

# 4. Build the wasm (needs Rust + the wasm32-unknown-unknown target and wasm-pack)
wasm-pack build base_layer/tari_l1_wasm --target bundler --release --out-dir pkg
node base_layer/tari_l1_wasm/scripts/prepare-package.mjs --scope @chironbuilder
```

The workspace `.cargo/config.toml` (included in `integration.patch`) sets the getrandom `wasm_js`
backend automatically. Native tests (`cargo test -p tari_l1_wasm`) also run from inside the
workspace.

## Contributing

Issues and PRs welcome. Please keep changes to the `tari_l1_wasm` crate here; anything that has to
touch other Tari crates should also go upstream to
[tari-project/tari](https://github.com/tari-project/tari). See `integration.patch` for the exact
cross-crate changes this build relies on.

## License

BSD-3-Clause — see [LICENSE](./LICENSE). Derived from
[tari-project/tari](https://github.com/tari-project/tari); © The Tari Development Community.
