// Tests for src/wallet-export.js (Bitcoin Core wallet.dat export) using
// Node's built-in test runner.
//
// The gold standard: REF_WATCH_ONLY_RECORDS / REF_PRIVATE_RECORDS in
// wallet-export-reference.mjs are the exact rows of wallet.dat `main` tables
// produced by Bitcoin Core v28.3.0 (regtest) via createwallet +
// importdescriptors of the reference descriptors. The tests rebuild those
// rows with the module and an independent, dependency-free reference
// implementation of the crypto (secp256k1/BIP32/checksums over BigInt and
// node:crypto — see wallet-export-harness.mjs), then verify the generated
// database files with Python's sqlite3 (the real SQLite C library).
//
// The final section automates the end-to-end check: where bitcoind is
// installed, every chain must load the generated wallet.dat and hand out its
// own address form.
//
// Run with `npm test` or `npm run test:wallet-export`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:net";
import {
  buildWalletDat,
  buildWalletRecords,
  hasDescriptors,
  walletDatButtonLabel,
  walletDatFilename,
} from "../src/index.js";
import {
  REF_ACCOUNT_TPUB,
  REF_CREATION_TIME,
  REF_PRIVATE_DESCRIPTORS,
  REF_PRIVATE_RECORDS,
  REF_PUBLIC_DESCRIPTORS,
  REF_WATCH_ONLY_RECORDS,
} from "./wallet-export-reference.mjs";
import {
  PYTHON_SQLITE,
  asMap,
  b58checkDecode,
  b58checkEncode,
  bytesToHex,
  deps,
  deriveBranchBody,
  descriptorChecksum,
  hexToBytes,
  moduleRecords,
  publicKeyForPrivate,
  read,
  sha256,
  sqliteReadBack,
} from "./wallet-export-harness.mjs";

const sqliteSrc = read("src/sqlite-writer.js");
const walletSrc = read("src/wallet-export.js");

// --- reference wallets ------------------------------------------------------

// refD descriptors all share one account key (m/44'/1'/0'); its public form:
const publicFormOf = (privateDescriptor) => {
  const body = privateDescriptor
    .slice(0, privateDescriptor.lastIndexOf("#"))
    .replace(/tprv[1-9A-HJ-NP-Za-km-z]{90,}/, REF_ACCOUNT_TPUB);
  return `${body}#${descriptorChecksum(body)}`;
};
const REF_PRIVATE_PUBLIC_FORMS = REF_PRIVATE_DESCRIPTORS.map(publicFormOf);

const SCRIPT_DEFS = [
  { id: "bip44", bip: "BIP44", label: "Legacy", script: "p2pkh" },
  { id: "bip49", bip: "BIP49", label: "Nested SegWit", script: "p2sh-p2wpkh" },
  { id: "bip86", bip: "BIP86", label: "Taproot", script: "p2tr" },
  { id: "bip84", bip: "BIP84", label: "Native SegWit", script: "p2wpkh" },
];
const makeAccounts = (publics, privates) =>
  SCRIPT_DEFS.map((def, i) => ({
    def,
    accountPath: `m/${def.id.slice(3)}'/1'/0'`,
    receiveDescriptor: publics[i * 2],
    changeDescriptor: publics[i * 2 + 1],
    receiveDescriptorPriv: privates[i * 2],
    changeDescriptorPriv: privates[i * 2 + 1],
  }));

const WATCH_ONLY_WALLET = {
  kind: "hd",
  network: "regtest",
  accounts: makeAccounts(REF_PUBLIC_DESCRIPTORS, new Array(8).fill(null)),
};
const PRIVATE_WALLET = {
  kind: "hd",
  network: "regtest",
  accounts: makeAccounts(REF_PRIVATE_PUBLIC_FORMS, REF_PRIVATE_DESCRIPTORS),
};

// --- tests ------------------------------------------------------------------

test("never generates network traffic", () => {
  for (const source of [sqliteSrc, walletSrc]) {
    assert.doesNotMatch(source, /\bfetch\b|XMLHttpRequest|WebSocket|RTCPeerConnection|sendBeacon|WebTransport/);
  }
});

test("reference implementations agree with the fixture", () => {
  // every fixture descriptor carries the checksum its body must produce
  for (const descriptor of [...REF_PUBLIC_DESCRIPTORS, ...REF_PRIVATE_DESCRIPTORS]) {
    const [body, checksum] = descriptor.split("#");
    assert.equal(descriptorChecksum(body), checksum, `checksum mismatch: ${descriptor.slice(0, 40)}`);
  }
  // account branch-0 cache body as Core wrote it in refB2/refD
  const cache = REF_WATCH_ONLY_RECORDS.find(([key]) => key.startsWith("15" + "77616c6c657464657363726970746f726361636865"));
  const body = deriveBranchBody(REF_ACCOUNT_TPUB, 0);
  assert.equal("4a" + bytesToHex(body), cache[1]);
  // secp256k1 generator sanity
  assert.equal(
    bytesToHex(publicKeyForPrivate(Uint8Array.from([...new Array(31).fill(0), 1]))),
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  );
});

test("watch-only records are byte-identical to a Bitcoin Core wallet", () => {
  const mine = moduleRecords(WATCH_ONLY_WALLET, false, REF_CREATION_TIME);
  const reference = asMap(REF_WATCH_ONLY_RECORDS);
  assert.equal(mine.size, reference.size);
  for (const [key, value] of reference) {
    assert.ok(mine.has(key), `missing record ${key.slice(0, 60)}`);
    assert.equal(mine.get(key), value, `record value mismatch at ${key.slice(0, 60)}`);
  }
  // no private-key records in a watch-only export
  assert.ok(![...mine.keys()].some((key) => key.includes("77616c6c657464657363726970746f726b6579")));
  // flags = DESCRIPTORS | BLANK | DISABLE_PRIVATE_KEYS
  assert.equal(mine.get("05666c616773"), "0000000007000000");
});

test("private records are byte-identical to a Bitcoin Core wallet", () => {
  const mine = moduleRecords(PRIVATE_WALLET, true, REF_CREATION_TIME);
  const reference = asMap(REF_PRIVATE_RECORDS);
  assert.equal(mine.size, reference.size);
  for (const [key, value] of reference) {
    assert.ok(mine.has(key), `missing record ${key.slice(0, 60)}`);
    assert.equal(mine.get(key), value, `record value mismatch at ${key.slice(0, 60)}`);
  }
  // 8 descriptorkey records, one per descriptor; flags = DESCRIPTORS | BLANK
  const keyRecords = [...mine.keys()].filter((key) => key.includes("77616c6c657464657363726970746f726b6579"));
  assert.equal(keyRecords.length, 8);
  assert.equal(mine.get("05666c616773"), "0000000006000000");
});

test("accounts without private material stay watch-only in a private export", () => {
  const watchOnly = moduleRecords(WATCH_ONLY_WALLET, false, REF_CREATION_TIME);
  const fallback = moduleRecords(WATCH_ONLY_WALLET, true, REF_CREATION_TIME);
  assert.deepEqual([...fallback.keys()].sort(), [...watchOnly.keys()].sort());
  for (const key of watchOnly.keys()) assert.equal(fallback.get(key), watchOnly.get(key));
});

// Regression: the h->' compat rewrite must stay inside the [origin] segment.
// About 1 in 375 account xpubs end in a digit followed by the base58 letter
// "h"; a body-wide rewrite corrupted that xpub, and Bitcoin Core refused to
// load the wallet ("descriptor ID calculated by the wallet differs from the
// one in DB"). Both xpubs below are real m/84'/0'/0' account keys with that
// ending, so the old code path is exercised exactly.
const XPUB_TAIL_4H = "xpub6DGDSTSv42ve3BBRALC4UVi3LdaoQjA9R2yV9RSDojTRKQTK5Jk73WKqm6v392eeF3Lxawf8gHiBpD5xBDx7HYvbkLoZ6e1Emu9fvW2M24h";
const XPUB_TAIL_2H = "xpub6ChZ8GTJVLpepi3oLPQUHRx6H7RkwQ6bsoqvSfwTw5jZuRithtrc75Tfq7H3sa8bXkA9d35K3CdJDY5B2aTFmdFEp19AGWT7XTXDVFvCn2h";

const DESCRIPTOR_PREFIX = "10" + "77616c6c657464657363726970746f72"; // length-prefixed "walletdescriptor"
const descriptorIds = (records) =>
  [...records.keys()].filter((key) => key.startsWith(DESCRIPTOR_PREFIX)).map((key) => key.slice(DESCRIPTOR_PREFIX.length));
const digitHWallet = (descriptorFor) => ({
  kind: "hd",
  network: "mainnet",
  accounts: [{
    def: { id: "bip84" },
    receiveDescriptor: descriptorFor(XPUB_TAIL_4H),
    changeDescriptor: descriptorFor(XPUB_TAIL_2H),
  }],
});

test("descriptor ids keep account xpubs ending in <digit>h byte-identical", () => {
  const descriptorFor = (xpub) => {
    const body = `wpkh([00000000/84h/0h/0h]${xpub}/0/*)`;
    return `${body}#${descriptorChecksum(body)}`;
  };
  const records = moduleRecords(digitHWallet(descriptorFor), false, REF_CREATION_TIME);
  const ids = descriptorIds(records);
  assert.equal(ids.length, 2);
  for (const xpub of [XPUB_TAIL_4H, XPUB_TAIL_2H]) {
    // What Core computes at load: origin steps rendered with ', key material
    // (including its trailing "h") re-encoded untouched.
    const compat = `wpkh([00000000/84'/0'/0']${xpub}/0/*)`;
    const expectedId = bytesToHex(sha256(new TextEncoder().encode(`${compat}#${descriptorChecksum(compat)}`)));
    assert.ok(ids.includes(expectedId), `record id for ...${xpub.slice(-12)} must match Core's DescriptorID`);
  }
  // The stored descriptor string keeps the original xpub text as well.
  const storedValues = ids.map((id) => Buffer.from(records.get(DESCRIPTOR_PREFIX + id), "hex").toString());
  for (const xpub of [XPUB_TAIL_4H, XPUB_TAIL_2H]) {
    assert.ok(storedValues.some((value) => value.includes(xpub)), `stored descriptor keeps ...${xpub.slice(-12)} verbatim`);
  }
});

test("origin-less descriptors keep a <digit>h xpub byte-identical", () => {
  // Imported account keys export without a key origin. With nothing to
  // rewrite, the compat form is the body itself — a body-wide rewrite
  // corrupted these xpubs just the same.
  const descriptorFor = (xpub) => {
    const body = `wpkh(${xpub}/0/*)`;
    return `${body}#${descriptorChecksum(body)}`;
  };
  const records = moduleRecords(digitHWallet(descriptorFor), false, REF_CREATION_TIME);
  const ids = descriptorIds(records);
  assert.equal(ids.length, 2);
  for (const xpub of [XPUB_TAIL_4H, XPUB_TAIL_2H]) {
    const body = `wpkh(${xpub}/0/*)`;
    const expectedId = bytesToHex(sha256(new TextEncoder().encode(`${body}#${descriptorChecksum(body)}`)));
    assert.ok(ids.includes(expectedId), `record id for origin-less ...${xpub.slice(-12)} must hash the unchanged body`);
  }
});

test("descriptor range records mirror the address rows like Core's importdescriptors", () => {
  // Core's importdescriptors stores range_start / range_end (exclusive) /
  // next_index; the export covers the shown indexes plus Core's 1000-key
  // lookahead, clamped to the BIP32 index space.
  const descriptorFor = (xpub, branch) => {
    const body = `wpkh([00000000/84h/0h/0h]${xpub}/${branch}/*)`;
    return `${body}#${descriptorChecksum(body)}`;
  };
  const wallet = {
    kind: "hd",
    network: "mainnet",
    accounts: [{
      def: { id: "bip84" },
      receiveDescriptor: descriptorFor(XPUB_TAIL_4H, 0),
      changeDescriptor: descriptorFor(XPUB_TAIL_2H, 1),
      addressBranches: [
        { branch: 0, rows: [{ index: 3 }, { index: 17 }, { index: "ignored" }, { index: -1 }] },
        { branch: 1, rows: [{ index: 0x7fffffff }] },
      ],
    }],
  };
  const records = moduleRecords(wallet, false, REF_CREATION_TIME);
  const ids = descriptorIds(records);
  assert.equal(ids.length, 2);
  const ranges = ids.map((id) => {
    const value = Buffer.from(records.get(DESCRIPTOR_PREFIX + id), "hex");
    const textEnd = 1 + value[0];
    return {
      nextIndex: value.readUInt32LE(textEnd + 8),
      rangeStart: value.readUInt32LE(textEnd + 12),
      rangeEnd: value.readUInt32LE(textEnd + 16),
    };
  });
  // receive branch: shown 3..17 -> range [3, 1017], next 18
  assert.deepEqual(ranges.find((r) => r.rangeStart === 3), { nextIndex: 18, rangeStart: 3, rangeEnd: 1017 });
  // change branch: the BIP32 max index clamps next_index and the lookahead
  assert.deepEqual(ranges.find((r) => r.rangeStart === 0x7fffffff), { nextIndex: 0x7fffffff, rangeStart: 0x7fffffff, rangeEnd: 0x7fffffff });
  // no rows at all -> Core's default [0, 1000) window with next 0
  const bare = moduleRecords(digitHWallet((xpub) => descriptorFor(xpub, 0)), false, REF_CREATION_TIME);
  for (const id of descriptorIds(bare)) {
    const value = Buffer.from(bare.get(DESCRIPTOR_PREFIX + id), "hex");
    const textEnd = 1 + value[0];
    assert.equal(value.readUInt32LE(textEnd + 8), 0);
    assert.equal(value.readUInt32LE(textEnd + 12), 0);
    assert.equal(value.readUInt32LE(textEnd + 16), 1000);
  }
  // the legacy receive/change row arrays feed the same records
  const legacy = {
    ...wallet,
    accounts: [{ ...wallet.accounts[0], addressBranches: undefined, receive: [{ index: 5 }], change: [{ index: 9 }] }],
  };
  const legacyRecords = moduleRecords(legacy, false, REF_CREATION_TIME);
  const legacyRanges = descriptorIds(legacyRecords).map((id) => {
    const value = Buffer.from(legacyRecords.get(DESCRIPTOR_PREFIX + id), "hex");
    const textEnd = 1 + value[0];
    return { nextIndex: value.readUInt32LE(textEnd + 8), rangeStart: value.readUInt32LE(textEnd + 12), rangeEnd: value.readUInt32LE(textEnd + 16) };
  });
  assert.deepEqual(legacyRanges.find((r) => r.rangeStart === 5), { nextIndex: 6, rangeStart: 5, rangeEnd: 1005 });
  assert.deepEqual(legacyRanges.find((r) => r.rangeStart === 9), { nextIndex: 10, rangeStart: 9, rangeEnd: 1009 });
});

test("generated watch-only wallet.dat verifies with real SQLite", { skip: !PYTHON_SQLITE }, () => {
  const bytes = buildWalletDat(WATCH_ONLY_WALLET, false, deps, REF_CREATION_TIME);
  assert.equal(new TextDecoder().decode(bytes.subarray(0, 15)), "SQLite format 3");
  const report = sqliteReadBack(bytes);
  assert.equal(report.integrity, "ok");
  assert.equal(report.app_id, 0xfabfb5da); // regtest magic
  assert.equal(report.user_version, 0);
  assert.deepEqual(asMap(report.rows), asMap(REF_WATCH_ONLY_RECORDS));
});

test("generated private wallet.dat verifies with real SQLite", { skip: !PYTHON_SQLITE }, () => {
  const bytes = buildWalletDat(PRIVATE_WALLET, true, deps, REF_CREATION_TIME);
  const report = sqliteReadBack(bytes);
  assert.equal(report.integrity, "ok");
  assert.deepEqual(asMap(report.rows), asMap(REF_PRIVATE_RECORDS));
});

test("network selects the application id and best-block locator", () => {
  const expected = {
    mainnet: { magic: "f9beb4d9", genesis: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" },
    testnet: { magic: "0b110907", genesis: "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943" },
    signet: { magic: "0a03cf40", genesis: "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6" },
    regtest: { magic: "fabfb5da", genesis: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206" },
  };
  const bestblockKey = "12" + "62657374626c6f636b5f6e6f6d65726b6c65"; // "bestblock_nomerkle"
  for (const [network, { magic, genesis }] of Object.entries(expected)) {
    const wallet = { ...WATCH_ONLY_WALLET, network };
    const bytes = buildWalletDat(wallet, false, deps, REF_CREATION_TIME);
    assert.equal(bytesToHex(bytes.subarray(68, 72)), magic, `${network} application id`);
    const locator = moduleRecords(wallet, false, REF_CREATION_TIME).get(bestblockKey);
    assert.ok(locator.endsWith(bytesToHex(hexToBytes(genesis).reverse())), `${network} bestblock locator should name its genesis block`);
  }
  assert.throws(() => buildWalletRecords({ ...WATCH_ONLY_WALLET, network: "mutinynet" }, false, deps, REF_CREATION_TIME), /unknown network/);
});

test("button gating: only HD wallets with descriptors", () => {
  assert.equal(hasDescriptors(null), false);
  assert.equal(hasDescriptors({}), false);
  assert.equal(hasDescriptors({ kind: "single", wifCompressed: "L..." }), false);
  assert.equal(hasDescriptors({ kind: "msig", receiveDescriptor: "wsh(...)#x", changeDescriptor: "wsh(...)#y" }), false);
  assert.equal(hasDescriptors({ kind: "hd", accounts: [] }), false);
  assert.equal(hasDescriptors(WATCH_ONLY_WALLET), true);
});

test("filename announces watch-only vs secrets", () => {
  assert.equal(walletDatFilename(false), "watch-only-wallet.dat");
  assert.equal(walletDatFilename(true), "private-wallet-secrets.dat");
  assert.equal(walletDatFilename(), "watch-only-wallet.dat");
});

test("button label follows the reveal state", () => {
  assert.equal(walletDatButtonLabel(false), "Download watch-only wallet.dat");
  const shown = walletDatButtonLabel(true);
  assert.match(shown, /secrets/i);
  assert.match(shown, /xprv/i);
  assert.match(shown, /\.dat/);
});

// --- Bitcoin Core integration (skipped where bitcoind is not installed) ----
//
// For every chain, a fresh bitcoind on that chain must load the generated
// wallet.dat, and the signing variant must hand out the chain's own address
// form — including regtest's bcrt1… — because the SQLite application id and
// the bestblock locator are chain-specific. A file carrying another chain's
// metadata must be refused. Run it where Bitcoin Core is installed (verified
// with v31.1.0).
const BITCOIND = (() => {
  const daemon = spawnSync("bitcoind", ["--version"], { stdio: "pipe" });
  const cli = spawnSync("bitcoin-cli", ["--version"], { stdio: "pipe" });
  return daemon.status === 0 && cli.status === 0;
})();

// Re-version every extended key in a descriptor (tpub<->xpub and tprv<->xprv
// payloads have the same layout) and re-checksum it — what a caller does when
// the mainnet family re-labels the same key material.
const reversionDescriptor = (descriptor, publicVersion, privateVersion) => {
  const body = descriptor
    .slice(0, descriptor.lastIndexOf("#"))
    .replace(/[txyzuv](?:prv|pub)[1-9A-HJ-NP-Za-km-z]{90,}/g, (key) => {
      const raw = b58checkDecode(key).slice();
      const version = key.slice(1, 4) === "prv" ? privateVersion : publicVersion;
      raw[0] = (version >>> 24) & 255;
      raw[1] = (version >>> 16) & 255;
      raw[2] = (version >>> 8) & 255;
      raw[3] = version & 255;
      return b58checkEncode(raw);
    });
  return `${body}#${descriptorChecksum(body)}`;
};

const CHAIN_FIXTURES = {
  mainnet: { flag: "", subdir: ".", bech32Prefix: "bc1q" },
  testnet: { flag: "-testnet", subdir: "testnet3", bech32Prefix: "tb1q" },
  signet: { flag: "-signet", subdir: "signet", bech32Prefix: "tb1q" },
  regtest: { flag: "-regtest", subdir: "regtest", bech32Prefix: "bcrt1q" },
};

// The wallet the caller exports for each chain: the reference key material,
// versioned the way that chain's encoding family versions it.
const chainWallets = (network) => {
  const toMainnet = (descriptor) => reversionDescriptor(descriptor, 0x0488b21e, 0x0488ade4);
  const asChain = (descriptors) => descriptors.map((d) => (network === "mainnet" ? toMainnet(d) : d));
  return {
    watch: { kind: "hd", network, accounts: makeAccounts(asChain(REF_PUBLIC_DESCRIPTORS), new Array(8).fill(null)) },
    priv: { kind: "hd", network, accounts: makeAccounts(asChain(REF_PRIVATE_PUBLIC_FORMS), asChain(REF_PRIVATE_DESCRIPTORS)) },
  };
};

// An OS-assigned localhost port keeps parallel or repeated runs from
// colliding with a real node.
const freePort = () =>
  new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });

const sleepSync = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

// Boots a fresh node for the chain, runs `body(cli)` where
// cli(...rpcArgs) returns the parsed JSON result (asserting success), and
// always shuts the node down again.
const withChainNode = async (network, body) => {
  const fixture = CHAIN_FIXTURES[network];
  const port = await freePort();
  const datadir = mkdtempSync(join(tmpdir(), `wallet-dot-dat-js-bitcoind-${network}-`));
  const flagArgs = fixture.flag ? [fixture.flag] : [];
  const cliArgs = [...flagArgs, `-datadir=${datadir}`, "-rpcuser=el", "-rpcpassword=el", `-rpcport=${port}`];
  const cli = (args, { check = true } = {}) => {
    const run = spawnSync("bitcoin-cli", [...cliArgs, ...args], { encoding: "utf8", maxBuffer: 1 << 22 });
    if (check && run.status !== 0) throw new Error(`bitcoin-cli ${args[0]} failed on ${network}: ${run.stderr.trim()}`);
    return run;
  };
  try {
    spawnSync("bitcoind", [...flagArgs, `-datadir=${datadir}`, "-listen=0", "-connect=0", "-server", "-rpcuser=el", "-rpcpassword=el", `-rpcport=${port}`, "-daemon"], { stdio: "pipe" });
    cli(["-rpcwait", "getblockchaininfo"]);
    await body((args, options) => cli(args, options), join(datadir, fixture.subdir, "wallets"));
  } finally {
    spawnSync("bitcoin-cli", [...cliArgs, "stop"], { stdio: "pipe" });
    // stop returns before the process exits; wait for the RPC to go quiet so
    // the datadir removal cannot race a late flush.
    for (let waited = 0; waited < 300; waited++) {
      if (cli(["getblockchaininfo"], { check: false }).status !== 0) break;
      sleepSync(100);
    }
    rmSync(datadir, { recursive: true, force: true });
  }
};

for (const network of Object.keys(CHAIN_FIXTURES)) {
  test(`bitcoind on ${network} loads the generated wallet.dat`, { skip: !BITCOIND, timeout: 120000 }, async () => {
    const wallets = chainWallets(network);
    const watchBytes = buildWalletDat(wallets.watch, false, deps, 0);
    const privBytes = buildWalletDat(wallets.priv, true, deps, 0);
    await withChainNode(network, (cli, walletsDir) => {
      for (const [name, bytes] of [["js-watch", watchBytes], ["js-priv", privBytes]]) {
        mkdirSync(join(walletsDir, name), { recursive: true });
        writeFileSync(join(walletsDir, name, "wallet.dat"), bytes);
        assert.equal(JSON.parse(cli(["loadwallet", name]).stdout).name, name, `${network} refused its ${name} wallet`);
      }
      const watchInfo = JSON.parse(cli(["-rpcwallet=js-watch", "getwalletinfo"]).stdout);
      assert.equal(watchInfo.format, "sqlite");
      assert.equal(watchInfo.descriptors, true);
      assert.equal(watchInfo.private_keys_enabled, false);
      const privInfo = JSON.parse(cli(["-rpcwallet=js-priv", "getwalletinfo"]).stdout);
      assert.equal(privInfo.private_keys_enabled, true);
      // The signing wallet hands out the chain's own SegWit address: bc1q… on
      // mainnet, tb1q… on testnet AND signet, bcrt1q… on regtest.
      const address = cli(["-rpcwallet=js-priv", "getnewaddress", "", "bech32"]).stdout.trim();
      assert.ok(address.startsWith(CHAIN_FIXTURES[network].bech32Prefix), `${network} address ${address} has the wrong HRP`);
      if (network === "regtest") {
        // A file built with another chain's metadata is not a regtest wallet
        // and must be refused (Core's application-id check).
        mkdirSync(join(walletsDir, "js-wrong"), { recursive: true });
        writeFileSync(join(walletsDir, "js-wrong", "wallet.dat"), buildWalletDat(chainWallets("testnet").watch, false, deps, 0));
        assert.notEqual(cli(["loadwallet", "js-wrong"], { check: false }).status, 0, "a testnet-magic wallet loaded on regtest");
      }
    });
  });
}
