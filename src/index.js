// wallet-dot-dat-js — Bitcoin Core wallet.dat (SQLite descriptor wallet)
// exporter. Pure byte transformation: no I/O, no network, zero dependencies;
// crypto is injected by the caller.
export {
  createDatabase,
  encodeRecord,
  varint,
  bytewiseCompare,
  PAGE_SIZE,
} from "./sqlite-writer.js";
export {
  walletDescriptorUnits,
  hasDescriptors,
  buildWalletRecords,
  buildWalletDat,
  walletDatFilename,
  walletDatButtonLabel,
} from "./wallet-export.js";
