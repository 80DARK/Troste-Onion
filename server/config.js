import path from "node:path";
import { fileURLToPath } from "node:url";

const projectDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function readPort(name, fallback) {
  const value = Number.parseInt(process.env[name] || String(fallback), 10);
  if (!Number.isInteger(value) || value < 1024 || value > 65535) {
    throw new Error(`${name} debe ser un puerto entre 1024 y 65535.`);
  }
  return value;
}

export const config = Object.freeze({
  projectDir,
  uiHost: "127.0.0.1",
  uiPort: readPort("TROSTE_UI_PORT", 8741),
  onionHost: "127.0.0.1",
  onionPort: readPort("TROSTE_ONION_PORT", 8742),
  socksHost: "127.0.0.1",
  socksPort: readPort("TOR_SOCKS_PORT", 9060),
  dataDir: path.resolve(process.env.TROSTE_DATA_DIR || path.join(projectDir, "data")),
  torBinary: String(process.env.TOR_BINARY || "").trim(),
  manageTor: !/^(0|false|no)$/i.test(String(process.env.TROSTE_MANAGE_TOR || "true")),
  externalOnionAddress: String(process.env.TROSTE_ONION_ADDRESS || "").trim().toLowerCase(),
  maxStoredPayloadBytes: 96 * 1024,
  maxRemoteBodyBytes: 2048,
  maxLocalBodyBytes: 128 * 1024,
  resolveTimeoutMs: 45_000,
  nodeTtlMs: 90 * 24 * 60 * 60 * 1000
});

if (new Set([config.uiPort, config.onionPort, config.socksPort]).size !== 3) {
  throw new Error("Los puertos de interfaz, Onion y SOCKS deben ser distintos.");
}
