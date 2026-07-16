import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { hashRouteSecret, isV3OnionAddress } from "../server/security.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("panel local y puerto Onion mantienen permisos separados", async (t) => {
  const [uiPort, onionPort, socksPort] = await threeFreePorts();
  const dataDir = await mkdtemp(path.join(os.tmpdir(), "troste-integration-"));
  const onionAddress = makeV3OnionAddress(randomBytes(32));
  const child = spawn(process.execPath, ["server/main.js"], {
    cwd: root,
    windowsHide: true,
    env: {
      ...process.env,
      TROSTE_UI_PORT: String(uiPort),
      TROSTE_ONION_PORT: String(onionPort),
      TOR_SOCKS_PORT: String(socksPort),
      TROSTE_DATA_DIR: dataDir,
      TROSTE_MAX_ACTIVE_NODES: "1",
      TROSTE_MANAGE_TOR: "false",
      TROSTE_ONION_ADDRESS: onionAddress
    },
    stdio: ["ignore", "pipe", "pipe"]
  });
  t.after(async () => {
    child.kill("SIGTERM");
    await Promise.race([new Promise((resolve) => child.once("exit", resolve)), new Promise((resolve) => setTimeout(resolve, 3000))]);
    await rm(dataDir, { recursive: true, force: true });
  });
  await waitForOutput(child, "Troste Onion:");

  const local = `http://127.0.0.1:${uiPort}`;
  const remote = `http://127.0.0.1:${onionPort}`;
  const localHeaders = {
    "X-Troste-Local": "1",
    Origin: local,
    "Content-Type": "application/json"
  };
  const statusResponse = await fetch(`${local}/api/status`, { headers: { "X-Troste-Local": "1", Origin: local } });
  assert.equal(statusResponse.status, 200);
  assert.match(statusResponse.headers.get("permissions-policy"), /camera=\(\)/);
  assert.equal((await statusResponse.json()).onionAddress, onionAddress);

  assert.equal((await fetch(`${local}/api/status`)).status, 403);
  assert.equal((await fetch(`${local}/package.json`)).status, 404);
  assert.equal((await fetch(`${local}/..%2Fpackage.json`)).status, 404);
  assert.equal((await fetch(`${remote}/api/status`)).status, 404);
  assert.equal((await fetch(`${remote}/api/nodes`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })).status, 404);

  const nodeId = randomUUID();
  const secret = randomBytes(32).toString("base64url");
  const payload = {
    version: 1,
    cryptoSuite: "HKDF-SHA256+AES-256-GCM",
    salt: randomBytes(16).toString("base64url"),
    iv: randomBytes(12).toString("base64url"),
    ciphertext: randomBytes(64).toString("base64url")
  };
  const published = await fetch(`${local}/api/nodes`, {
    method: "POST",
    headers: localHeaders,
    body: JSON.stringify({
      nodeId,
      secretHash: hashRouteSecret(nodeId, secret),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      payload
    })
  });
  assert.equal(published.status, 201);

  const fullNodeId = randomUUID();
  const storeFull = await fetch(`${local}/api/nodes`, {
    method: "POST",
    headers: localHeaders,
    body: JSON.stringify({
      nodeId: fullNodeId,
      secretHash: hashRouteSecret(fullNodeId, randomBytes(32).toString("base64url")),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      payload
    })
  });
  assert.equal(storeFull.status, 507);
  assert.equal((await storeFull.json()).code, "STORE_FULL");

  const resolved = await fetch(`${remote}/v1/letters/${nodeId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ secret })
  });
  assert.equal(resolved.status, 200);
  assert.deepEqual((await resolved.json()).payload, payload);

  const rejected = await fetch(`${remote}/v1/letters/${nodeId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ secret: randomBytes(32).toString("base64url") })
  });
  assert.equal(rejected.status, 404);

  const revoked = await fetch(`${local}/api/nodes/${nodeId}`, {
    method: "DELETE",
    headers: localHeaders,
    body: JSON.stringify({ secret })
  });
  assert.equal(revoked.status, 204);
  const afterRevoke = await fetch(`${remote}/v1/letters/${nodeId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ secret })
  });
  assert.equal(afterRevoke.status, 404);
});

test("una direccion v3 exige checksum y version validos", () => {
  const address = makeV3OnionAddress(randomBytes(32));
  assert.equal(isV3OnionAddress(address), true);
  assert.equal(isV3OnionAddress(`${address[0] === "a" ? "b" : "a"}${address.slice(1)}`), false);
  assert.equal(isV3OnionAddress(`${"a".repeat(56)}.onion`), false);
});

function makeV3OnionAddress(publicKey) {
  const version = Buffer.from([3]);
  const checksum = createHash("sha3-256")
    .update(Buffer.from(".onion checksum", "ascii"))
    .update(publicKey)
    .update(version)
    .digest()
    .subarray(0, 2);
  return `${encodeBase32(Buffer.concat([publicKey, checksum, version]))}.onion`;
}

function encodeBase32(bytes) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let output = "";
  let bits = 0;
  let accumulator = 0;
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += alphabet[(accumulator >>> bits) & 31];
      accumulator &= (1 << bits) - 1;
    }
  }
  if (bits) output += alphabet[(accumulator << (5 - bits)) & 31];
  return output;
}

async function threeFreePorts() {
  const ports = [];
  while (ports.length < 3) {
    const port = await freePort();
    if (!ports.includes(port)) ports.push(port);
  }
  return ports;
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

function waitForOutput(child, needle) {
  return new Promise((resolve, reject) => {
    let output = "";
    const timeout = setTimeout(() => reject(new Error(`El servidor no inicio. Salida: ${output}`)), 8000);
    const onData = (chunk) => {
      output += chunk.toString();
      if (!output.includes(needle)) return;
      clearTimeout(timeout);
      child.stdout.off("data", onData);
      child.stderr.off("data", onData);
      resolve();
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.once("exit", (code) => {
      clearTimeout(timeout);
      reject(new Error(`El servidor termino antes de iniciar (${code}). Salida: ${output}`));
    });
  });
}
