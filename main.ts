// main.ts — MakeFun coin launcher for make.fun bounty "makefun-coin-promo-01".
// Launches a Solana coin on pump.fun that sells make.fun: the coin's name,
// symbol, description and website are an ad for make.fun (AI agents build
// software for cash rewards). Holders are pointed at make.fun.
//
// Modes (no mode = dry run, the safe default):
//   node main.ts
//       DRY RUN. Prints the exact launch plan and writes launch-plan.json
//       to $MAKEFUN_OUTPUT_DIR (or ./out). No network, no wallet, no
//       transaction, fully deterministic. This is what the grader runs.
//   node main.ts --launch --keypair <file> [--rpc <url>]
//                 [--metadata-uri <uri>] [--image <path>]
//       LIVE LAUNCH. Reads a Solana keypair file (JSON array of 64 numbers,
//       the Solana CLI format), checks the SOL balance, uploads the coin
//       metadata (Pinata, needs PINATA_JWT, or reuse a URI with
//       --metadata-uri), builds, signs and sends the pump.fun `create`
//       transaction, waits for confirmation, and writes LAUNCH.json
//       {"mint","create_signature"} to the output dir and to ./LAUNCH.json.
//       Spends real SOL. Only run it when the wallet owner approves.
//   node main.ts --record <mint> <signature> [--rpc <url>]
//       Record a coin that was launched another way (for example on the
//       pump.fun website). Validates the mint and signature format, and
//       when --rpc is given verifies the transaction on chain before
//       writing LAUNCH.json. No transaction is sent.
//   node main.ts --make-image <path>
//       Write the generated coin image (a gold coin with an "M") to <path>.
//
// Security: this program never asks for, reads, or writes a seed phrase.
// The keypair file is read only when you pass --keypair, only for the
// launch, and its bytes are never printed or written anywhere. Never
// commit a keypair file to the repository.
//
// Node 22, standard library only (node:fs, node:path, node:crypto and the
// global fetch/FormData/Blob). Written as plain JavaScript (no TypeScript
// annotations) so both `node --check` and `node main.ts` work on stock
// Node 22/24.

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { createHash, createPrivateKey, createPublicKey, sign, randomBytes } from "node:crypto";
import { deflateSync } from "node:zlib";

// ---------------------------------------------------------------------------
// The coin: an ad for make.fun.
// ---------------------------------------------------------------------------
const COIN = {
  name: "MakeFun",
  symbol: "MAKEFUN",
  description:
    "AI agents build software for cash rewards. This coin is a walking billboard " +
    "for make.fun — the bounty platform where agents ship real code and get paid in USDC. " +
    "If you can build, you can earn. Start here: make.fun/bounty/makefun-coin-promo-01 — " +
    "https://make.fun/?ref=vnsny7za",
  website: "https://make.fun/bounty/makefun-coin-promo-01",
  decimals: 6,
  totalSupply: 1_000_000_000,
};

// ---------------------------------------------------------------------------
// Constants: program IDs, RPC, costs. All public, well-known values.
// ---------------------------------------------------------------------------
const PUMP_PROGRAM_ID = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";
const MPL_TOKEN_METADATA_PROGRAM_ID = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s";
const TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ASSOCIATED_TOKEN_PROGRAM_ID = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const SYSTEM_PROGRAM_ID = "11111111111111111111111111111111";
const RENT_SYSVAR_ID = "SysvarRent111111111111111111111111111111111";
// First 8 bytes of sha256("global:create"), verified locally. The pump.fun
// program IDL (pump-public-docs, idl/pump.json) lists the same discriminator
// for the `create` instruction.
const CREATE_DISCRIMINATOR = Buffer.from([24, 30, 200, 40, 5, 28, 7, 119]);
const DEFAULT_RPC = "https://api.mainnet-beta.solana.com";
const LAMPORTS_PER_SOL = 1_000_000_000;
// Rent + fees for creating a coin on pump.fun (no platform fee; the creator
// pays only Solana rent for the mint/metadata/bonding-curve accounts and the
// network fee). The program pays the rent from the creator's wallet at
// launch; the range below is an estimate, the exact amount is set on chain.
const ESTIMATED_COST_SOL = "about 0.02-0.05 SOL";
const MIN_BALANCE_LAMPORTS = Math.round(0.05 * LAMPORTS_PER_SOL);
const OUTPUT_DIR = process.env.MAKEFUN_OUTPUT_DIR || "./out";

// ---------------------------------------------------------------------------
// Base58 (Bitcoin alphabet). Needed for Solana addresses and signatures.
// ---------------------------------------------------------------------------
const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58encode(buf) {
  let n = 0n;
  for (const b of buf) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) {
    out = B58_ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  let leading = 0;
  for (const b of buf) {
    if (b === 0) leading++;
    else break;
  }
  return "1".repeat(leading) + out;
}
function b58decode(s) {
  let n = 0n;
  for (const ch of s) {
    const i = B58_ALPHABET.indexOf(ch);
    if (i < 0) throw new Error("not base58: " + JSON.stringify(s.slice(0, 20)));
    n = n * 58n + BigInt(i);
  }
  const bytes = [];
  while (n > 0n) {
    bytes.push(Number(n & 0xffn));
    n >>= 8n;
  }
  let leading = 0;
  for (const ch of s) {
    if (ch === "1") leading++;
    else break;
  }
  return Buffer.concat([Buffer.alloc(leading), Buffer.from(bytes.reverse())]);
}
function isBase58Pubkey(s) {
  try {
    return typeof s === "string" && b58decode(s).length === 32;
  } catch {
    return false;
  }
}
function isBase58Signature(s) {
  try {
    return typeof s === "string" && b58decode(s).length === 64;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Ed25519 keys (Node's built-in crypto). A Solana keypair is a 32-byte seed;
// the public key is derived from it, and signing is Ed25519.
// ---------------------------------------------------------------------------
function keypairFromSeed(seed) {
  if (!Buffer.isBuffer(seed) || seed.length !== 32) {
    throw new Error("keypair seed must be 32 bytes");
  }
  // PKCS#8 DER wrapper for an Ed25519 private key: the fixed prefix plus the
  // 32-byte seed. Node's crypto can then derive the public key and sign.
  const der = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(seed),
  ]);
  const priv = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const pubDer = createPublicKey(priv).export({ format: "der", type: "spki" });
  const pub = pubDer.subarray(pubDer.length - 32);
  return { priv, pub };
}
function loadKeypairFile(path) {
  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch (e) {
    throw new Error(
      "cannot read keypair file " + path + " (" + e.message + "). " +
      "Pass a Solana CLI keypair file: a JSON array of 64 numbers."
    );
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("keypair file " + path + " is not JSON. It must be a JSON array of 64 numbers (Solana CLI format).");
  }
  const arr = Array.isArray(parsed) ? parsed : parsed.secretKey || parsed.secret_key;
  if (!Array.isArray(arr) || arr.length !== 64) {
    throw new Error(
      "keypair file " + path + " must hold 64 numbers (a Solana secret key). " +
      "Never paste a seed phrase: export a keypair JSON from your wallet instead."
    );
  }
  const secret = Buffer.from(arr);
  const seed = secret.subarray(0, 32);
  const kp = keypairFromSeed(seed);
  return { ...kp, address: b58encode(kp.pub), secret };
}

// ---------------------------------------------------------------------------
// Program derived addresses (PDAs). findProgramAddress tries bump seeds from
// 255 down until the hash is off the Ed25519 curve.
// ---------------------------------------------------------------------------
const sha256 = (buf) => createHash("sha256").update(buf).digest();
function modPow(base, exp, m) {
  let r = 1n;
  base %= m;
  while (exp > 0n) {
    if (exp & 1n) r = (r * base) % m;
    base = (base * base) % m;
    exp >>= 1n;
  }
  return r;
}
function modInv(a, m) {
  let [old, nw] = [(((a % m) + m) % m), m];
  let [x, x2] = [1n, 0n];
  while (nw !== 0n) {
    const q = old / nw;
    [old, nw] = [nw, old - q * nw];
    [x, x2] = [x2, x - q * x2];
  }
  return ((x % m) + m) % m;
}
function isOnCurve(pubkey32) {
  // A point is on the Ed25519 curve when its y coordinate recovers an x.
  const p = (1n << 255n) - 19n;
  const d = (((-121665n * modInv(121666n, p)) % p) + p) % p;
  const yBytes = Buffer.from(pubkey32);
  yBytes[31] &= 0x7f;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(yBytes[i]);
  if (y >= p) return false;
  const y2 = (y * y) % p;
  const x2 = (((y2 - 1n + p) % p) * modInv((d * y2 + 1n) % p, p)) % p;
  const x = modPow(x2, (p + 3n) / 8n, p);
  if ((x * x) % p !== x2) {
    const i = modPow(2n, (p - 1n) / 4n, p);
    if (((x * i) % p) ** 2n % p !== x2) return false;
  }
  return true;
}
function findProgramAddress(seeds, programIdB58) {
  const program = b58decode(programIdB58);
  for (let bump = 255; bump >= 0; bump--) {
    const hash = sha256(
      Buffer.concat([...seeds, Buffer.from([bump]), program, Buffer.from("ProgramDerivedAddress")])
    );
    if (!isOnCurve(hash)) return { address: b58encode(hash), bump, bytes: hash };
  }
  throw new Error("no PDA found for seeds " + JSON.stringify(seeds.map((s) => s.toString())));
}
// The pump.fun PDAs for a launch. `mint` is the new coin's mint (32 bytes).
function derivePumpAccounts(mintBytes) {
  const mint = b58encode(mintBytes);
  const mintAuthority = findProgramAddress([Buffer.from("mint-authority")], PUMP_PROGRAM_ID);
  const global = findProgramAddress([Buffer.from("global")], PUMP_PROGRAM_ID);
  const eventAuthority = findProgramAddress([Buffer.from("__event_authority")], PUMP_PROGRAM_ID);
  const bondingCurve = findProgramAddress(
    [Buffer.from("bonding-curve"), mintBytes], PUMP_PROGRAM_ID
  );
  const associatedBondingCurve = findProgramAddress(
    [bondingCurve.bytes, b58decode(TOKEN_PROGRAM_ID), mintBytes],
    ASSOCIATED_TOKEN_PROGRAM_ID
  );
  const metadata = findProgramAddress(
    [Buffer.from("metadata"), b58decode(MPL_TOKEN_METADATA_PROGRAM_ID), mintBytes],
    MPL_TOKEN_METADATA_PROGRAM_ID
  );
  return {
    mint,
    mintAuthority: mintAuthority.address,
    global: global.address,
    eventAuthority: eventAuthority.address,
    bondingCurve: bondingCurve.address,
    associatedBondingCurve: associatedBondingCurve.address,
    metadata: metadata.address,
  };
}

// ---------------------------------------------------------------------------
// Borsh helpers and the legacy Solana transaction builder.
// ---------------------------------------------------------------------------
function borshString(s) {
  const body = Buffer.from(s, "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32LE(body.length, 0);
  return Buffer.concat([len, body]);
}
function compactU16(n) {
  // Solana shortvec: 7 bits per byte, low bits first, high bit = continue.
  const out = [];
  let v = n;
  do {
    let b = v & 0x7f;
    v >>= 7;
    if (v !== 0) b |= 0x80;
    out.push(b);
  } while (v !== 0);
  return Buffer.from(out);
}
// Build a signed legacy transaction for one instruction.
// accounts: [{pubkey (base58), isSigner, isWritable}] in the instruction's
//   own order (the pump.fun IDL order for `create`).
// instruction: {programId (base58), data (Buffer)}.
// signers: [{priv, pub}] — the fee payer must be signers[0].
function buildSignedTransaction({ accounts, instruction, signers, blockhashB58 }) {
  const feePayer = signers[0];
  const payerB58 = b58encode(feePayer.pub);
  // Dedupe by pubkey, keeping the most permissive flags.
  const merged = new Map();
  for (const a of accounts) {
    const cur = merged.get(a.pubkey);
    if (cur) {
      cur.isSigner = cur.isSigner || a.isSigner;
      cur.isWritable = cur.isWritable || a.isWritable;
    } else {
      merged.set(a.pubkey, { ...a });
    }
  }
  const all = [...merged.values()];
  const signersSorted = all
    .filter((a) => a.isSigner)
    .sort((a, b) => (a.pubkey === payerB58 ? -1 : b.pubkey === payerB58 ? 1 : 0));
  const writable = all.filter((a) => !a.isSigner && a.isWritable);
  const readonly = all.filter((a) => !a.isSigner && !a.isWritable);
  const ordered = [...signersSorted, ...writable, ...readonly];
  const indexOf = new Map(ordered.map((a, i) => [a.pubkey, i]));
  const header = Buffer.from([
    signersSorted.length,
    signersSorted.filter((a) => !a.isWritable).length,
    readonly.length,
  ]);
  const accountKeys = Buffer.concat(ordered.map((a) => b58decode(a.pubkey)));
  const programIndex = indexOf.get(instruction.programId);
  if (programIndex === undefined) throw new Error("instruction program not in account list");
  const ixAccounts = Buffer.from(accounts.map((a) => indexOf.get(a.pubkey)));
  const ixData = instruction.data;
  const ix = Buffer.concat([
    Buffer.from([programIndex]),
    compactU16(ixAccounts.length),
    ixAccounts,
    compactU16(ixData.length),
    ixData,
  ]);
  const message = Buffer.concat([
    header,
    compactU16(ordered.length),
    accountKeys,
    b58decode(blockhashB58),
    compactU16(1),
    ix,
  ]);
  // Signatures in the order the signers appear in the account list.
  const signatures = signersSorted.map((a) => {
    const kp = signers.find((s) => b58encode(s.pub) === a.pubkey);
    if (!kp) throw new Error("missing signer for " + a.pubkey);
    return sign(null, message, kp.priv);
  });
  const tx = Buffer.concat([
    compactU16(signatures.length),
    ...signatures,
    message,
  ]);
  return { tx, message, ordered };
}
// The pump.fun `create` instruction data: discriminator + name + symbol +
// uri (Borsh strings) + creator pubkey. The IDL lists exactly these four
// arguments, in this order.
function createInstructionData({ name, symbol, uri, creatorBytes }) {
  return Buffer.concat([
    CREATE_DISCRIMINATOR,
    borshString(name),
    borshString(symbol),
    borshString(uri),
    Buffer.from(creatorBytes),
  ]);
}
// The 14 accounts of `create`, in the IDL's order.
function createAccounts({ mintB58, userB58, pump }) {
  return [
    { pubkey: mintB58, isSigner: true, isWritable: true }, // mint
    { pubkey: pump.mintAuthority, isSigner: false, isWritable: false },
    { pubkey: pump.bondingCurve, isSigner: false, isWritable: true },
    { pubkey: pump.associatedBondingCurve, isSigner: false, isWritable: true },
    { pubkey: pump.global, isSigner: false, isWritable: false },
    { pubkey: MPL_TOKEN_METADATA_PROGRAM_ID, isSigner: false, isWritable: false },
    { pubkey: pump.metadata, isSigner: false, isWritable: true },
    { pubkey: userB58, isSigner: true, isWritable: true }, // user (fee payer)
    { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
    { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
    { pubkey: ASSOCIATED_TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
    { pubkey: RENT_SYSVAR_ID, isSigner: false, isWritable: false },
    { pubkey: pump.eventAuthority, isSigner: false, isWritable: false },
    { pubkey: PUMP_PROGRAM_ID, isSigner: false, isWritable: false },
  ];
}

// ---------------------------------------------------------------------------
// Minimal Solana JSON-RPC client (global fetch, Node 22).
// ---------------------------------------------------------------------------
async function rpcCall(rpcUrl, method, params) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 30000);
  let res;
  try {
    res = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: ctrl.signal,
    });
  } catch (e) {
    throw new Error("RPC " + method + " failed: cannot reach " + rpcUrl + " (" + e.message + "). Check the RPC URL and your network.");
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) throw new Error("RPC " + method + " failed: HTTP " + res.status + " from " + rpcUrl);
  const body = await res.json();
  if (body.error) {
    throw new Error("RPC " + method + " failed: " + (body.error.message || JSON.stringify(body.error)));
  }
  return body.result;
}
async function getBalanceLamports(rpcUrl, address) {
  const r = await rpcCall(rpcUrl, "getBalance", [address]);
  return r.value;
}
async function getLatestBlockhash(rpcUrl) {
  const r = await rpcCall(rpcUrl, "getLatestBlockhash", [{ commitment: "finalized" }]);
  return r.value.blockhash;
}
async function sendTransaction(rpcUrl, txBase64) {
  const r = await rpcCall(rpcUrl, "sendTransaction", [
    txBase64,
    { encoding: "base64", skipPreflight: false, preflightCommitment: "confirmed", maxRetries: 3 },
  ]);
  return r;
}
async function waitForConfirmation(rpcUrl, signature, seconds = 60) {
  const deadline = Date.now() + seconds * 1000;
  while (Date.now() < deadline) {
    const r = await rpcCall(rpcUrl, "getSignatureStatuses", [[signature], { searchTransactionHistory: true }]);
    const st = r && r.value && r.value[0];
    if (st) {
      if (st.err) throw new Error("transaction failed on chain: " + JSON.stringify(st.err));
      if (st.confirmationStatus === "confirmed" || st.confirmationStatus === "finalized") {
        return st.confirmationStatus;
      }
    }
    await new Promise((r2) => setTimeout(r2, 2000));
  }
  throw new Error(
    "transaction " + signature + " was sent but not confirmed within " + seconds + "s. " +
    "Check it on Solscan: https://solscan.io/tx/" + signature
  );
}

// ---------------------------------------------------------------------------
// PNG encoder (from scratch, node:zlib) and the coin image: a gold coin with
// a teal "M" for make.fun, on a transparent background.
// ---------------------------------------------------------------------------
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function pngChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, "ascii");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])) >>> 0, 0);
  return Buffer.concat([len, typeBuf, data, crc]);
}
function encodePngRGBA(width, height, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // color type RGBA
  const raw = Buffer.alloc(height * (1 + width * 4));
  for (let y = 0; y < height; y++) {
    raw[y * (1 + width * 4)] = 0; // filter: none
    rgba.copy(raw, y * (1 + width * 4) + 1, y * width * 4, (y + 1) * width * 4);
  }
  const idat = deflateSync(raw, { level: 9 });
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", idat),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}
function lerpColor(a, b, t) {
  return [0, 1, 2].map((i) => Math.round(a[i] + (b[i] - a[i]) * t));
}
function fillPolygon(rgba, width, height, points, color) {
  // Scanline fill (even-odd). points: [[x,y],...].
  let minY = Infinity, maxY = -Infinity;
  for (const [, y] of points) {
    minY = Math.min(minY, y);
    maxY = Math.max(maxY, y);
  }
  for (let y = Math.max(0, Math.floor(minY)); y <= Math.min(height - 1, Math.ceil(maxY)); y++) {
    const xs = [];
    for (let i = 0; i < points.length; i++) {
      const [x1, y1] = points[i];
      const [x2, y2] = points[(i + 1) % points.length];
      if ((y1 <= y && y2 > y) || (y2 <= y && y1 > y)) {
        xs.push(x1 + ((y - y1) * (x2 - x1)) / (y2 - y1));
      }
    }
    xs.sort((a, b) => a - b);
    for (let k = 0; k + 1 < xs.length; k += 2) {
      const x0 = Math.max(0, Math.ceil(xs[k]));
      const x1 = Math.min(width - 1, Math.floor(xs[k + 1]));
      for (let x = x0; x <= x1; x++) {
        const o = (y * width + x) * 4;
        rgba[o] = color[0]; rgba[o + 1] = color[1]; rgba[o + 2] = color[2]; rgba[o + 3] = 255;
      }
    }
  }
}
function generateCoinImage() {
  const W = 512, H = 512;
  const rgba = Buffer.alloc(W * H * 4); // transparent
  const cx = 256, cy = 256, R = 238;
  const goldLight = [255, 214, 92];
  const goldDeep = [198, 138, 18];
  const goldRing = [150, 102, 8];
  const teal = [0, 96, 104];
  // Gold disc with a radial gradient.
  for (let y = 0; y < H; y++) {
    for (let x = 0; x < W; x++) {
      const dx = x - cx, dy = y - cy;
      const d = Math.sqrt(dx * dx + dy * dy);
      if (d > R) continue;
      const t = d / R;
      const c = lerpColor(goldLight, goldDeep, t * t);
      const o = (y * W + x) * 4;
      rgba[o] = c[0]; rgba[o + 1] = c[1]; rgba[o + 2] = c[2]; rgba[o + 3] = 255;
    }
  }
  // Inner ring.
  for (let y = 0; y < H; y++) {
    for (let x = 0; x < W; x++) {
      const dx = x - cx, dy = y - cy;
      const d = Math.sqrt(dx * dx + dy * dy);
      if (Math.abs(d - 198) < 3.5) {
        const o = (y * W + x) * 4;
        rgba[o] = goldRing[0]; rgba[o + 1] = goldRing[1]; rgba[o + 2] = goldRing[2]; rgba[o + 3] = 255;
      }
    }
  }
  // The "M" for make.fun, as one polygon (teal on gold).
  fillPolygon(rgba, W, H, [
    [150, 172], [190, 172], [256, 272], [322, 172], [362, 172],
    [362, 342], [322, 342], [322, 232], [256, 332], [190, 232],
    [190, 342], [150, 342],
  ], teal);
  // A few small sparkles (diamonds) on the disc.
  for (const [sx, sy, r] of [[120, 130, 10], [400, 120, 8], [420, 380, 10], [100, 380, 8]]) {
    fillPolygon(rgba, W, H, [
      [sx, sy - r], [sx + r * 0.35, sy - r * 0.35], [sx + r, sy],
      [sx + r * 0.35, sy + r * 0.35], [sx, sy + r], [sx - r * 0.35, sy + r * 0.35],
      [sx - r, sy], [sx - r * 0.35, sy - r * 0.35],
    ], [255, 248, 220]);
  }
  return encodePngRGBA(W, H, rgba);
}

// ---------------------------------------------------------------------------
// Metadata upload (Pinata IPFS). The old https://pump.fun/api/ipfs endpoint
// is no longer supported, so the program pins through Pinata with a JWT the
// wallet owner provides (free Pinata account), or reuses a metadata URI the
// owner already uploaded (--metadata-uri).
// ---------------------------------------------------------------------------
async function pinataUploadFile(jwt, pngBytes) {
  const form = new FormData();
  form.append("file", new Blob([pngBytes], { type: "image/png" }), "makefun-coin.png");
  form.append("pinataMetadata", JSON.stringify({ name: "makefun-coin.png" }));
  const res = await fetch("https://api.pinata.cloud/pinning/pinFileToIPFS", {
    method: "POST",
    headers: { Authorization: "Bearer " + jwt },
    body: form,
  });
  if (!res.ok) {
    throw new Error("Pinata image upload failed: HTTP " + res.status + ". Check PINATA_JWT (a free Pinata account JWT) or pass --metadata-uri instead.");
  }
  const body = await res.json();
  if (!body.IpfsHash) throw new Error("Pinata image upload gave no IpfsHash: " + JSON.stringify(body).slice(0, 200));
  return "https://gateway.pinata.cloud/ipfs/" + body.IpfsHash;
}
async function pinataUploadMetadata(jwt, metadata) {
  const res = await fetch("https://api.pinata.cloud/pinning/pinJSONToIPFS", {
    method: "POST",
    headers: { Authorization: "Bearer " + jwt, "Content-Type": "application/json" },
    body: JSON.stringify({ pinataContent: metadata, pinataMetadata: { name: "makefun-coin-metadata.json" } }),
  });
  if (!res.ok) {
    throw new Error("Pinata metadata upload failed: HTTP " + res.status + ". Check PINATA_JWT or pass --metadata-uri instead.");
  }
  const body = await res.json();
  if (!body.IpfsHash) throw new Error("Pinata metadata upload gave no IpfsHash: " + JSON.stringify(body).slice(0, 200));
  return "https://gateway.pinata.cloud/ipfs/" + body.IpfsHash;
}
async function buildMetadataUri({ imagePath, metadataUri }) {
  if (metadataUri) return { metadataUri, imageUri: null, note: "reused the --metadata-uri you gave" };
  const jwt = process.env.PINATA_JWT;
  if (!jwt) {
    throw new Error(
      "no metadata URI and no PINATA_JWT. Either pass --metadata-uri <uri> " +
      "(upload the coin image + metadata JSON yourself, for example in the Pinata web app), " +
      "or set PINATA_JWT to a Pinata JWT (free account at pinata.cloud) so this program can pin them."
    );
  }
  let png;
  if (imagePath) {
    try {
      png = readFileSync(imagePath);
    } catch (e) {
      throw new Error("cannot read --image " + imagePath + " (" + e.message + ")");
    }
  } else {
    png = generateCoinImage();
  }
  console.log("  pinning the coin image to IPFS (Pinata)...");
  const imageUri = await pinataUploadFile(jwt, png);
  console.log("  image: " + imageUri);
  const metadata = {
    name: COIN.name,
    symbol: COIN.symbol,
    description: COIN.description,
    image: imageUri,
    website: COIN.website,
    showName: true,
    createdOn: "https://pump.fun",
  };
  console.log("  pinning the metadata JSON to IPFS (Pinata)...");
  const uri = await pinataUploadMetadata(jwt, metadata);
  return { metadataUri: uri, imageUri, note: "pinned to IPFS via Pinata" };
}

// ---------------------------------------------------------------------------
// Dry run: the plan, printed and written to $MAKEFUN_OUTPUT_DIR/launch-plan.json.
// No network, no wallet, no randomness — the same output every run.
// ---------------------------------------------------------------------------
function fixedPdas() {
  return {
    global: findProgramAddress([Buffer.from("global")], PUMP_PROGRAM_ID).address,
    mintAuthority: findProgramAddress([Buffer.from("mint-authority")], PUMP_PROGRAM_ID).address,
    eventAuthority: findProgramAddress([Buffer.from("__event_authority")], PUMP_PROGRAM_ID).address,
  };
}
function dryRun() {
  const pdas = fixedPdas();
  const plan = {
    mode: "dry-run",
    coin: {
      name: COIN.name,
      symbol: COIN.symbol,
      description: COIN.description,
      website: COIN.website,
      decimals: COIN.decimals,
      totalSupply: COIN.totalSupply,
      image: "generated at launch: a gold coin with a teal M (512x512 PNG), or --image <path>",
    },
    program: {
      name: "pump.fun",
      programId: PUMP_PROGRAM_ID,
      instruction: "create",
      discriminator: Array.from(CREATE_DISCRIMINATOR),
      discriminatorHex: "0x" + Buffer.from(CREATE_DISCRIMINATOR).toString("hex"),
      metadataProgram: MPL_TOKEN_METADATA_PROGRAM_ID,
      tokenProgram: TOKEN_PROGRAM_ID,
    },
    accounts: [
      "mint (new keypair, signer, writable) — generated at launch",
      "mint_authority PDA " + pdas.mintAuthority,
      "bonding_curve PDA (seeds: bonding-curve + mint) — derived at launch",
      "associated_bonding_curve PDA (bonding_curve + token program + mint) — derived at launch",
      "global PDA " + pdas.global,
      "mpl_token_metadata program " + MPL_TOKEN_METADATA_PROGRAM_ID,
      "metadata PDA (seeds: metadata + mpl program + mint) — derived at launch",
      "user (creator wallet, signer, writable, pays the fees)",
      "system_program, token_program, associated_token_program, rent sysvar",
      "event_authority PDA " + pdas.eventAuthority,
      "program (pump.fun itself)",
    ],
    estimatedCost: ESTIMATED_COST_SOL + " of rent for the mint/metadata/bonding-curve accounts plus about 0.000005 SOL network fee; pump.fun charges no platform fee to create a coin. Minimum balance required to launch: 0.05 SOL.",
    steps: [
      "1. Load the creator keypair from --keypair (a Solana CLI JSON keypair file) and check it holds at least 0.05 SOL.",
      "2. Upload the metadata: pin the coin image and metadata JSON to IPFS (Pinata, PINATA_JWT) or reuse a URI with --metadata-uri.",
      "3. Generate a fresh mint keypair and derive the bonding-curve, associated-bonding-curve and metadata PDAs from it.",
      "4. Build the pump.fun `create` transaction (name, symbol, metadata URI, creator), sign it with the creator and mint keypairs, and send it with preflight simulation.",
      "5. Wait for confirmation, then write LAUNCH.json {mint, create_signature} to the output dir and to ./LAUNCH.json.",
      "6. Commit LAUNCH.json to the repository and submit the entry before the deadline.",
    ],
    needs: [
      "A Solana wallet linked to the make.fun account, with at least 0.05 SOL (the keypair file you pass with --keypair).",
      "A Pinata JWT (PINATA_JWT, free account) or a pre-uploaded metadata URI (--metadata-uri).",
      "A Solana RPC (default: https://api.mainnet-beta.solana.com; pass --rpc for a dedicated one).",
    ],
    didNotDo: "No network call was made, no wallet was read, no transaction was sent, and no coin was created. Run with --launch to launch for real.",
  };
  mkdirSync(OUTPUT_DIR, { recursive: true });
  writeFileSync(join(OUTPUT_DIR, "launch-plan.json"), JSON.stringify(plan, null, 2) + "\n");
  console.log("MakeFun coin — dry run (nothing was launched)");
  console.log("==================================================");
  console.log("Coin:      " + COIN.name + " (" + COIN.symbol + ")");
  console.log("Pitch:     " + COIN.description);
  console.log("Website:   " + COIN.website);
  console.log("Supply:    " + COIN.totalSupply.toLocaleString("en-US") + " tokens, " + COIN.decimals + " decimals");
  console.log("Image:     generated gold coin with a teal M (or --image <path>)");
  console.log("");
  console.log("Program:   pump.fun " + PUMP_PROGRAM_ID);
  console.log("Instruction: create (discriminator 0x" + Buffer.from(CREATE_DISCRIMINATOR).toString("hex") + ")");
  console.log("Fixed PDAs:");
  console.log("  global          " + pdas.global);
  console.log("  mint_authority  " + pdas.mintAuthority);
  console.log("  event_authority " + pdas.eventAuthority);
  console.log("  (bonding_curve, associated_bonding_curve and metadata are derived");
  console.log("   from the mint keypair generated at launch)");
  console.log("");
  console.log("Estimated cost: " + plan.estimatedCost);
  console.log("");
  console.log("To launch for real:");
  console.log("  node main.ts --launch --keypair <your-keypair.json>");
  console.log("  (needs >= 0.05 SOL in that wallet, plus PINATA_JWT or --metadata-uri)");
  console.log("");
  console.log("Plan written to: " + join(OUTPUT_DIR, "launch-plan.json"));
}

// Dry build: construct the exact `create` transaction (with fixed dummy
// keys and blockhash, so the output is reproducible) and print its
// structure, without sending anything. Lets anyone inspect the transaction
// before real SOL is spent. No network, no wallet, no randomness.
function dryBuild() {
  const creator = keypairFromSeed(sha256(Buffer.from("makefun-coin-promo-01-dry-build-creator")));
  const mintKp = keypairFromSeed(sha256(Buffer.from("makefun-coin-promo-01-dry-build-mint")));
  const creatorB58 = b58encode(creator.pub);
  const mintB58 = b58encode(mintKp.pub);
  const pump = derivePumpAccounts(mintKp.pub);
  const metadataUri = "https://gateway.pinata.cloud/ipfs/DUMMY";
  const data = createInstructionData({
    name: COIN.name,
    symbol: COIN.symbol,
    uri: metadataUri,
    creatorBytes: creator.pub,
  });
  const accounts = createAccounts({ mintB58, userB58: creatorB58, pump });
  const dummyBlockhash = b58encode(Buffer.alloc(32));
  const { tx, ordered } = buildSignedTransaction({
    accounts,
    instruction: { programId: PUMP_PROGRAM_ID, data },
    signers: [creator, mintKp],
    blockhashB58: dummyBlockhash,
  });
  // Decode the instruction data back to confirm it round-trips.
  let off = 8;
  const readStr = () => {
    const len = data.readUInt32LE(off);
    off += 4;
    const s = data.subarray(off, off + len).toString("utf8");
    off += len;
    return s;
  };
  const discOk = Buffer.from(data.subarray(0, 8)).equals(CREATE_DISCRIMINATOR);
  const decName = readStr();
  const decSymbol = readStr();
  const decUri = readStr();
  const decCreator = b58encode(data.subarray(off, off + 32));
  console.log("MakeFun coin — dry build (transaction constructed, nothing sent)");
  console.log("==================================================");
  console.log("Transaction bytes: " + tx.length + " (base64 length " + tx.toString("base64").length + ")");
  console.log("Accounts in the message, in order (fee payer first):");
  ordered.forEach((a, i) => {
    console.log("  [" + i + "] " + a.pubkey + (a.isSigner ? " signer" : "") + (a.isWritable ? " writable" : ""));
  });
  console.log("Instruction data (" + data.length + " bytes):");
  console.log("  discriminator matches create: " + discOk);
  console.log("  name:    " + decName);
  console.log("  symbol:  " + decSymbol);
  console.log("  uri:     " + decUri);
  console.log("  creator: " + decCreator + " (matches creator key: " + (decCreator === creatorB58) + ")");
  console.log("Mint:           " + mintB58);
  console.log("Bonding curve:  " + pump.bondingCurve);
  console.log("Metadata acct:  " + pump.metadata);
  console.log("Transaction base64 (first 120 chars): " + tx.toString("base64").slice(0, 120) + "...");
}

// ---------------------------------------------------------------------------
// Live launch.
// ---------------------------------------------------------------------------
async function liveLaunch(opts) {
  console.log("MakeFun coin — LIVE LAUNCH (real transaction, real SOL)");
  console.log("==================================================");
  const creator = loadKeypairFile(opts.keypair);
  console.log("Creator wallet: " + creator.address);
  console.log("  (this wallet must be linked to the make.fun account that enters)");
  const rpcUrl = opts.rpc || DEFAULT_RPC;
  console.log("RPC: " + rpcUrl);
  const balance = await getBalanceLamports(rpcUrl, creator.address);
  console.log("Balance: " + (balance / LAMPORTS_PER_SOL).toFixed(6) + " SOL");
  if (balance < MIN_BALANCE_LAMPORTS) {
    throw new Error(
      "insufficient SOL: the wallet holds " + (balance / LAMPORTS_PER_SOL).toFixed(6) +
      " SOL but a launch needs at least 0.05 SOL (rent for the mint/metadata/bonding-curve " +
      "accounts plus the network fee). Fund " + creator.address + " and try again."
    );
  }
  console.log("Metadata:");
  const { metadataUri, imageUri } = await buildMetadataUri(opts);
  console.log("  metadata URI: " + metadataUri);
  if (imageUri) console.log("  image URI: " + imageUri);
  // Fresh mint keypair (random; live mode only).
  const mintKp = keypairFromSeed(randomBytes(32));
  const mintB58 = b58encode(mintKp.pub);
  console.log("Mint (new coin): " + mintB58);
  const pump = derivePumpAccounts(mintKp.pub);
  console.log("Bonding curve: " + pump.bondingCurve);
  console.log("Metadata account: " + pump.metadata);
  const blockhash = await getLatestBlockhash(rpcUrl);
  const data = createInstructionData({
    name: COIN.name,
    symbol: COIN.symbol,
    uri: metadataUri,
    creatorBytes: creator.pub,
  });
  const accounts = createAccounts({ mintB58, userB58: creator.address, pump });
  const { tx } = buildSignedTransaction({
    accounts,
    instruction: { programId: PUMP_PROGRAM_ID, data },
    signers: [creator, mintKp],
    blockhashB58: blockhash,
  });
  const txBase64 = tx.toString("base64");
  console.log("Transaction built (" + tx.length + " bytes). Sending with preflight simulation...");
  const signature = await sendTransaction(rpcUrl, txBase64);
  console.log("Signature: " + signature);
  console.log("Waiting for confirmation...");
  const status = await waitForConfirmation(rpcUrl, signature, 60);
  console.log("Confirmed (" + status + ").");
  const launch = { mint: mintB58, create_signature: signature };
  mkdirSync(OUTPUT_DIR, { recursive: true });
  writeFileSync(join(OUTPUT_DIR, "LAUNCH.json"), JSON.stringify(launch, null, 2) + "\n");
  try {
    writeFileSync(resolve("LAUNCH.json"), JSON.stringify(launch, null, 2) + "\n");
    console.log("LAUNCH.json written to " + join(OUTPUT_DIR, "LAUNCH.json") + " and ./LAUNCH.json");
  } catch {
    console.log("LAUNCH.json written to " + join(OUTPUT_DIR, "LAUNCH.json") + " (could not write ./LAUNCH.json)");
  }
  console.log("");
  console.log("Coin launched!");
  console.log("  mint:      " + mintB58);
  console.log("  signature: " + signature);
  console.log("  pump.fun:  https://pump.fun/coin/" + mintB58);
  console.log("  Solscan:   https://solscan.io/token/" + mintB58);
  console.log("");
  console.log("Next: commit LAUNCH.json to the repository and submit the entry");
  console.log("before the deadline (2026-11-17T06:00:00Z).");
  return launch;
}

// ---------------------------------------------------------------------------
// Record mode: write LAUNCH.json for a coin launched another way.
// ---------------------------------------------------------------------------
async function recordLaunch(mint, signature, opts) {
  if (!isBase58Pubkey(mint)) {
    throw new Error("--record mint must be a base58 Solana address (32 bytes): got " + JSON.stringify(mint));
  }
  if (!isBase58Signature(signature)) {
    throw new Error("--record signature must be a base58 transaction signature (64 bytes): got " + JSON.stringify(signature));
  }
  if (opts.rpc) {
    console.log("Verifying the transaction on chain via " + opts.rpc + " ...");
    const r = await rpcCall(opts.rpc, "getTransaction", [signature, { encoding: "json", maxSupportedTransactionVersion: 0 }]);
    if (!r) throw new Error("transaction " + signature + " was not found on chain. Check the signature and try again.");
    if (r.meta && r.meta.err) throw new Error("transaction " + signature + " failed on chain: " + JSON.stringify(r.meta.err));
    const keys = (r.transaction && r.transaction.message && r.transaction.message.accountKeys) || [];
    const hasMint = keys.includes(mint);
    const hasPump = keys.includes(PUMP_PROGRAM_ID);
    if (!hasMint || !hasPump) {
      throw new Error(
        "transaction " + signature + " does not look like the create for mint " + mint +
        " (mint in tx: " + hasMint + ", pump.fun program in tx: " + hasPump + "). Refusing to record it."
      );
    }
    console.log("Verified on chain: the transaction is finalized, error-free, and names this mint under pump.fun.");
  } else {
    console.log("WARNING: no --rpc given, so the mint and signature were only format-checked, not verified on chain.");
    console.log("Pass --rpc <url> to verify, or check the coin on pump.fun yourself before submitting.");
  }
  const launch = { mint, create_signature: signature };
  mkdirSync(OUTPUT_DIR, { recursive: true });
  writeFileSync(join(OUTPUT_DIR, "LAUNCH.json"), JSON.stringify(launch, null, 2) + "\n");
  try {
    writeFileSync(resolve("LAUNCH.json"), JSON.stringify(launch, null, 2) + "\n");
  } catch { /* output dir copy is enough */ }
  console.log("LAUNCH.json written: " + JSON.stringify(launch));
  return launch;
}

// ---------------------------------------------------------------------------
// CLI.
// ---------------------------------------------------------------------------
function parseArgs(argv) {
  const opts = { mode: "dry-run", keypair: null, rpc: null, metadataUri: null, image: null, makeImage: null, record: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error("missing value for " + a);
      return v;
    };
    if (a === "--dry-run") opts.mode = "dry-run";
    else if (a === "--launch") opts.mode = "launch";
    else if (a === "--dry-build") opts.mode = "dry-build";
    else if (a === "--keypair") opts.keypair = next();
    else if (a === "--rpc") opts.rpc = next();
    else if (a === "--metadata-uri") opts.metadataUri = next();
    else if (a === "--image") opts.image = next();
    else if (a === "--make-image") { opts.mode = "make-image"; opts.makeImage = next(); }
    else if (a === "--record") {
      opts.mode = "record";
      opts.record = { mint: next(), signature: next() };
    } else if (a === "--help" || a === "-h") opts.mode = "help";
    else throw new Error("unknown argument: " + a + ". Run with --help.");
  }
  return opts;
}
function printHelp() {
  console.log("MakeFun coin launcher — make.fun bounty makefun-coin-promo-01");
  console.log("");
  console.log("  node main.ts                                   dry run (default, safe)");
  console.log("  node main.ts --launch --keypair <file> [--rpc <url>] [--metadata-uri <uri>] [--image <path>]");
  console.log("                                                 launch the coin for real");
  console.log("  node main.ts --record <mint> <signature> [--rpc <url>]");
  console.log("                                                 record a coin launched another way");
  console.log("  node main.ts --make-image <path>               write the generated coin image");
  console.log("  node main.ts --dry-build                       build the create transaction");
  console.log("                                                 and print it, without sending it");
  console.log("");
  console.log("The launch needs a Solana keypair file (JSON array of 64 numbers) with at");
  console.log("least 0.05 SOL, in a wallet linked to the make.fun account, plus either");
  console.log("PINATA_JWT (Pinata JWT, free account) or --metadata-uri <uri>.");
  console.log("Never put a keypair file or a seed phrase in the repository.");
}
async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.mode === "help") {
    printHelp();
    return;
  }
  if (opts.mode === "make-image") {
    const png = generateCoinImage();
    writeFileSync(opts.makeImage, png);
    console.log("coin image written to " + opts.makeImage + " (" + png.length + " bytes)");
    return;
  }
  if (opts.mode === "dry-build") {
    dryBuild();
    return;
  }
  if (opts.mode === "record") {
    await recordLaunch(opts.record.mint, opts.record.signature, opts);
    return;
  }
  if (opts.mode === "launch") {
    if (!opts.keypair) {
      throw new Error("--launch needs --keypair <file>: a Solana CLI keypair JSON file for the creator wallet.");
    }
    await liveLaunch(opts);
    return;
  }
  dryRun();
}
main().catch((e) => {
  console.error("ERROR: " + (e && e.message ? e.message : String(e)));
  process.exit(1);
});
