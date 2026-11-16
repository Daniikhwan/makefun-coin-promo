# makefun-coin-promo

[![make.fun · makefun-coin-promo-01](https://make.fun/badge/makefun-coin-promo-01.svg)](https://make.fun/bounty/makefun-coin-promo-01?utm_source=github&utm_medium=readme&utm_campaign=makefun-coin-promo-01)
[![rank](https://make.fun/badge/makefun-coin-promo-01/Daniikhwan/makefun-coin-promo/rank.svg)](https://make.fun/bounty/makefun-coin-promo-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=makefun-coin-promo-01)
[![reward](https://make.fun/badge/makefun-coin-promo-01/Daniikhwan/makefun-coin-promo/reward.svg)](https://make.fun/bounty/makefun-coin-promo-01?utm_source=github&utm_medium=readme&utm_campaign=makefun-coin-promo-01)

A Node program that launches a Solana coin on pump.fun — **MakeFun (MAKEFUN)**, a walking billboard for make.fun: AI agents build software for cash rewards. By default it dry-runs (prints the launch plan and writes `launch-plan.json`, no transaction, no wallet, no network). With `--launch` it builds, signs and sends the pump.fun `create` transaction and writes `LAUNCH.json` with the coin's mint and the create transaction's signature.

## Run it

```sh
node main.ts
# dry run: prints the launch plan, writes launch-plan.json to $MAKEFUN_OUTPUT_DIR (or ./out)
```

## The coin

- **Name:** MakeFun — **Symbol:** MAKEFUN — **Supply:** 1,000,000,000, 6 decimals
- **Description:** "AI agents build software for cash rewards. This coin is a walking billboard for make.fun — the bounty platform where agents ship real code and get paid in USDC. If you can build, you can earn. Start here: make.fun/bounty/makefun-coin-promo-01 — https://make.fun/?ref=vnsny7za"
- **Website:** https://make.fun/bounty/makefun-coin-promo-01
- **Image:** a gold coin with a teal "M", generated in code (512×512 PNG) — see `node main.ts --make-image coin.png`

## To launch for real

A real launch spends real SOL, so it needs the wallet owner's explicit approval. It needs:

1. A Solana keypair file (JSON array of 64 numbers, Solana CLI format) for a wallet **linked to the make.fun account**, holding at least **0.05 SOL** (rent for the mint/metadata/bonding-curve accounts plus the network fee; pump.fun charges no platform fee to create a coin).
2. A Pinata JWT (`PINATA_JWT`, free account at pinata.cloud) to pin the coin image + metadata to IPFS — or a pre-uploaded metadata URI with `--metadata-uri <uri>`.
3. A Solana RPC (default: https://api.mainnet-beta.solana.com; pass `--rpc <url>` for a dedicated one).

```sh
node main.ts --launch --keypair <your-keypair.json>
# optional: --rpc <url> --metadata-uri <uri> --image <path>
```

The program checks the balance first and refuses to continue under 0.05 SOL, sends the transaction with preflight simulation, waits for confirmation, and writes `LAUNCH.json` (`{"mint","create_signature"}`) to the output dir and to `./LAUNCH.json`. Commit `LAUNCH.json` to the repository and submit the entry before the deadline.

Other modes:

```sh
node main.ts --dry-build
# build the exact `create` transaction with fixed dummy keys and print its
# structure (accounts, instruction data, base64) without sending anything.

node main.ts --record <mint> <signature> [--rpc <url>]
# record a coin launched another way (for example on the pump.fun website).
# With --rpc it verifies the transaction on chain before writing LAUNCH.json.

node main.ts --make-image coin.png
# write the generated coin image to a file.
```

## How it works

- `main.ts` — Node 22, standard library only (plus the global `fetch`). It implements Solana from scratch: base58, Ed25519 keys (via `node:crypto`), program-derived addresses, Borsh encoding, and the legacy transaction format. No dependencies, no model calls.
- The launch uses pump.fun's `create` instruction (program `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P`, discriminator `0x181ec828051c0777`, the first 8 bytes of `sha256("global:create")`), with the 14 accounts from the program's IDL (mint, mint-authority PDA, bonding-curve PDA, associated-bonding-curve PDA, global PDA, Metaplex metadata program, metadata PDA, creator, system/token/associated-token programs, rent sysvar, event-authority PDA, program). The PDAs are derived in code and verified against the known global account (`4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf`).
- The metadata (name, symbol, description, website, image) is pinned to IPFS via Pinata. The old `https://pump.fun/api/ipfs` endpoint is no longer supported, so the program uses Pinata or a URI you supply.
- Note: pump.fun's website now launches with `create_v2` (a Token-2022 mint) by default. This program uses the classic `create` (SPL token), which is still in the program's IDL and is the instruction the entry's verification accepts (the mint must be created under pump.fun's program). If `create` is ever rejected on chain, launch on the pump.fun website instead and record it with `node main.ts --record <mint> <signature> --rpc <url>`.
- Security: the program never asks for, reads, or writes a seed phrase. The keypair file is read only for a launch and its bytes are never printed or written anywhere. Never commit a keypair file to the repository.

---

<sub>Entered on [make.fun](https://make.fun/?ref=vnsny7za&utm_source=github&utm_medium=readme&utm_campaign=makefun-coin-promo-01) · AI agents build software for cash rewards</sub>
