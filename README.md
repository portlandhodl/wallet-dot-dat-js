# wallet-dot-dat-js

Bitcoin Core `wallet.dat` (SQLite descriptor wallet) exporter for JavaScript.

Builds a complete descriptor-wallet database **byte-by-byte** in the exact
format Bitcoin Core 28.x writes for `createwallet` + `importdescriptors` —
verified byte-for-byte against Bitcoin Core v28.3.0 on regtest, and the
generated files load (`loadwallet`) and sign/spend in `bitcoind`.

- **Zero dependencies, no I/O, no network.** Pure byte transformation;
  all crypto (SHA-256, descriptor checksums, base58check, BIP32 public
  derivation, secp256k1) is injected by the caller.
- Includes a minimal **SQLite 3 database file writer** (usable standalone via
  `wallet-dot-dat-js/sqlite-writer`) — 4096-byte pages, table/index b-trees,
  automatic `BLOB PRIMARY KEY` index.
- Watch-only or **signing** exports: with private material included, accounts
  get DER-encoded `walletdescriptorkey` records and the wallet drops the
  `disable-private-keys` flag.

Extracted from [EntropyLab](https://github.com/portlandhodl/entropylab).

## Install

```sh
npm install wallet-dot-dat-js
```

## Usage

```js
import { buildWalletDat, walletDatFilename } from "wallet-dot-dat-js";

const wallet = {
  kind: "hd",
  network: "mainnet", // "mainnet" | "testnet" | "regtest"
  accounts: [
    {
      def: { id: "bip84" }, // "bip44" | "bip49" | "bip84" | "bip86"
      receiveDescriptor: "wpkh([fingerprint/84'/0'/0']xpub.../0/*)#checksum",
      changeDescriptor: "wpkh([fingerprint/84'/0'/0']xpub.../1/*)#checksum",
      // optional, needed only for signing exports:
      receiveDescriptorPriv: "wpkh([fingerprint/84'/0'/0']xprv.../0/*)#checksum",
      changeDescriptorPriv: "wpkh([fingerprint/84'/0'/0']xprv.../1/*)#checksum",
    },
  ],
};

const deps = {
  sha256: (bytes) => /* Uint8Array(32) */,
  checksum: (descriptorBody) => /* 8-char Bitcoin Core descriptor checksum */,
  base58Decode: (xprv) => /* base58check-decoded 78-byte payload */,
  deriveBranchBody: (xpub, branch) => /* 74-byte branch xpub body (BIP32 public derive) */,
  publicKeyForPrivate: (secret32) => /* 33-byte compressed secp256k1 pubkey */,
};

const includePrivate = false; // watch-only
const bytes = buildWalletDat(wallet, includePrivate, deps);
// bytes is a Uint8Array holding a complete SQLite database file.
// Suggested filename: walletDatFilename(includePrivate)
```

`test/wallet-export.test.mjs` contains a complete, dependency-free reference
implementation of every `deps` function (BigInt + `node:crypto` only) that you
can adapt, or wire up your own (noble/scure, etc.).

## API

### `buildWalletDat(wallet, includePrivate, deps, creationTime?) → Uint8Array`

The complete `wallet.dat` file bytes. `creationTime` defaults to the current
unix time; descriptor records store it as each descriptor's creation time.

### `buildWalletRecords(wallet, includePrivate, deps, creationTime) → [[key, value], ...]`

The raw key/value rows of the wallet's `main` table, if you want to inspect or
embed them yourself.

### `hasDescriptors(wallet) → boolean`

True when the wallet shape contains at least one exportable HD account
descriptor pair.

### `walletDatFilename(includePrivate?) → string`

`"watch-only-wallet.dat"` or `"private-wallet-secrets.dat"`.

### `walletDatButtonLabel(includePrivate?) → string`

UI label announcing which variant is being downloaded.

### `walletDescriptorUnits(wallet, includePrivate) → Array`

The flattened per-branch descriptor export units (receive + change for each
account/script type).

### `wallet-dot-dat-js/sqlite-writer`

`createDatabase({ applicationId, tables })`, plus the low-level `encodeRecord`,
`varint`, `bytewiseCompare`, and `PAGE_SIZE`. See the module header for the
table schema format.

## Injected crypto interface

| Function | Input | Output |
| --- | --- | --- |
| `sha256` | `Uint8Array` | 32-byte digest |
| `checksum` | descriptor body (no `#...`) | 8-char checksum (Bitcoin Core `doc/descriptors.md` algorithm) |
| `base58Decode` | extended private key string | base58check payload, 78 bytes |
| `deriveBranchBody` | account xpub string, branch `0`/`1` | 74-byte branch xpub body (no version bytes) |
| `publicKeyForPrivate` | 32-byte secret | 33-byte compressed pubkey |

## How it works

Record layout written to the `main` table (Bitcoin Core 28.x):

- `version` / `minversion` / `flags` — wallet metadata; flags are
  `DESCRIPTORS | BLANK`, plus `DISABLE_PRIVATE_KEYS` for watch-only exports.
- `bestblock` / `bestblock_nomerkle` — fresh wallets sit on the genesis block.
- `walletdescriptor <id>` — public descriptor string, creation time,
  `next_index`, `range_start`, `range_end`.
- `walletdescriptorcache <id> <pos 0>` — 74-byte branch xpub.
- `walletdescriptorkey <id> <pubkey>` — DER private key + key hash
  (signing exports only).
- `activeexternalspk` / `activeinternalspk <type>` — descriptor id
  (`pkh=0, sh(wpkh)=1, wpkh=2, tr=3`).

## Security

- The module never performs I/O or network access and never derives keys on
  its own; secrets pass through only as the byte material you inject.
- Signing exports contain private keys. Handle the output like a seed phrase.

## Tests

```sh
npm test
```

The suites rebuild ground-truth `main`-table rows captured from Bitcoin Core
v28.3.0 (`createwallet` + `importdescriptors` on regtest) using an independent
reference implementation of the crypto, and verify the generated database
files with Python's `sqlite3` (the real SQLite C library): `PRAGMA
integrity_check`, schema readback, and full row dumps.

## License

MIT
