import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export const ONION_PATTERN = /^[a-z2-7]{56}\.onion$/;
export const BASE64URL_SECRET_PATTERN = /^[A-Za-z0-9_-]{43}$/;
export const SHA256_PATTERN = /^[a-f0-9]{64}$/;

export function isV3OnionAddress(value) {
  const address = String(value || "").toLowerCase();
  if (!ONION_PATTERN.test(address)) return false;
  const decoded = decodeBase32(address.slice(0, -6));
  if (!decoded || decoded.length !== 35 || decoded[34] !== 3) return false;
  const publicKey = decoded.subarray(0, 32);
  const expected = createHash("sha3-256")
    .update(Buffer.from(".onion checksum", "ascii"))
    .update(publicKey)
    .update(Buffer.from([3]))
    .digest()
    .subarray(0, 2);
  return timingSafeEqual(decoded.subarray(32, 34), expected);
}

export function hashRouteSecret(nodeId, secret) {
  return createHash("sha256")
    .update(`troste-onion-secret-v1:${nodeId}:${secret}`, "utf8")
    .digest("hex");
}

export function safeHexEqual(left, right) {
  if (!SHA256_PATTERN.test(left || "") || !SHA256_PATTERN.test(right || "")) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

export function isRoutePayload(value, maxBytes) {
  if (!value || value.version !== 1 || value.cryptoSuite !== "HKDF-SHA256+AES-256-GCM") return false;
  if (!/^[A-Za-z0-9_-]{22}$/.test(value.salt || "")) return false;
  if (!/^[A-Za-z0-9_-]{16}$/.test(value.iv || "")) return false;
  if (!/^[A-Za-z0-9_-]{24,}$/.test(value.ciphertext || "")) return false;
  return Buffer.byteLength(JSON.stringify(value), "utf8") <= maxBytes;
}

export function randomSocksCredential() {
  return randomBytes(18).toString("base64url");
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function decodeBase32(value) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  const output = [];
  let bits = 0;
  let accumulator = 0;
  for (const character of value) {
    const digit = alphabet.indexOf(character);
    if (digit < 0) return null;
    accumulator = (accumulator << 5) | digit;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      output.push((accumulator >>> bits) & 0xff);
      accumulator &= (1 << bits) - 1;
    }
  }
  return Buffer.from(output);
}

export function privateHeaders(extra = {}) {
  return {
    "Cache-Control": "no-store, max-age=0",
    Pragma: "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Resource-Policy": "same-origin",
    ...extra
  };
}
