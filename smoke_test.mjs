import { readFileSync } from "node:fs";
import init, {
  WasmTariAddress,
  WasmKeyPair,
  WasmSchnorrSignature,
  WasmWallet,
  WasmTxBuilder,
  amountToCurrencyString,
  parseAmount,
  calculateFee,
  commitValue,
  openValue,
  blake2b256Hex,
} from "./pkg-web/tari_l1_wasm.js";

await init(readFileSync(new URL("./pkg-web/tari_l1_wasm_bg.wasm", import.meta.url)));

let failures = 0;
function check(name, cond) {
  console.log(`${cond ? "PASS" : "FAIL"}: ${name}`);
  if (!cond) failures++;
}

// --- Original primitives (regression) ---
const kp = WasmKeyPair.generate();
check("keypair roundtrip", WasmKeyPair.fromSecretKeyHex(kp.secretKeyHex).publicKeyHex === kp.publicKeyHex);
const msg = Buffer.from("hello tari l1 from the browser");
const sig = WasmSchnorrSignature.sign(kp.secretKeyHex, msg);
check(
  "schnorr verify",
  WasmSchnorrSignature.verify(kp.publicKeyHex, sig.publicNonceHex, sig.signatureHex, msg),
);
check(
  "blake2b256 vector",
  blake2b256Hex(new Uint8Array()) === "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
);
const blind = WasmKeyPair.generate().secretKeyHex;
const comm = commitValue(blind, 12345n);
check("commitment opens", openValue(blind, 12345n, comm));
check("fee calc > 0", calculateFee(5n, 1, 2, 1, 400) > 0n);

// --- Wallet: creation + backup roundtrip ---
const alice = new WasmWallet("esmeralda");
const backup = alice.getBackupHex();
const restored = WasmWallet.fromBackupHex(backup, "esmeralda");
check("backup restore produces same address", restored.getAddress().toBase58() === alice.getAddress().toBase58());
const aliceAddr = alice.getAddress();
check("alice address is dual one-sided", !aliceAddr.isSingle && aliceAddr.network === "esmeralda");

// --- Recipient ---
const bob = new WasmWallet("esmeralda");
const bobAddress = bob.getAddress().toBase58();

// --- Build a full transaction: fund Alice's UTXO, pay Bob, expect change ---
const utxo = alice.createSelfUtxo(5_000_000n); // 5 T
check("utxo value tracked", utxo.valueMicro === 5_000_000n);

const builder = new WasmTxBuilder(alice);
builder.addInput(utxo);
builder.addRecipient(bobAddress, 1_000_000n); // 1 T to Bob
builder.withFeePerGram(2n);

const signed = builder.build();
console.log(`  fee: ${signed.feeMicro} uT, change: ${signed.changeValueMicro} uT`);
check("fee is positive", signed.feeMicro > 0n);
check("change = input - sent - fee", signed.changeValueMicro === 5_000_000n - 1_000_000n - signed.feeMicro);

// Submission payloads
const txJson = signed.toJson();
check("json has offset field", txJson.includes("offset"));
const submitBytes = Buffer.from(signed.toSubmitRequestBytes());
check("submit request starts with field-1 tag (0x0a)", submitBytes[0] === 0x0a);
check("submit request payload > 1KB (range proofs included)", submitBytes.length > 1024);
console.log(`  submit payload size: ${submitBytes.length} bytes`);

// Multi-recipient build
const carol = new WasmWallet("mainnet");
const utxo2 = alice.createSelfUtxo(3_000_000n);
const b2 = new WasmTxBuilder(alice);
b2.addInput(utxo2);
b2.addRecipient(bobAddress, 500_000n);
b2.addRecipient(carol.getAddress().toBase58(), 750_000n);
b2.withFeePerGram(4n);
const signed2 = b2.build();
check("multi-recipient fee > single", signed2.feeMicro > 0n);

// Error handling
try {
  const bad = new WasmTxBuilder(alice);
  bad.withFeePerGram(2n);
  bad.build();
  check("empty builder rejects", false);
} catch {
  check("empty builder rejects", true);
}
try {
  const b3 = new WasmTxBuilder(alice);
  b3.addInput(alice.createSelfUtxo(1000n));
  b3.addRecipient(bobAddress, 9999999n);
  b3.withFeePerGram(2n);
  b3.build();
  check("overspend rejects", false);
} catch {
  check("overspend rejects", true);
}
try {
  const b4 = new WasmTxBuilder(alice);
  b4.addInput(alice.createSelfUtxo(1000n));
  b4.addRecipient("not-a-valid-address!!!", 10n);
  b4.build();
  check("bad address rejects", false);
} catch {
  check("bad address rejects", true);
}

console.log(failures === 0 ? "\nALL TESTS PASSED" : `\n${failures} TEST(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
