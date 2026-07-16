import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { randomBytes, randomUUID } from "node:crypto";
import { LetterStore } from "../server/store.js";
import { hashRouteSecret } from "../server/security.js";

function fakePayload() {
  return {
    version: 1,
    cryptoSuite: "HKDF-SHA256+AES-256-GCM",
    salt: randomBytes(16).toString("base64url"),
    iv: randomBytes(12).toString("base64url"),
    ciphertext: randomBytes(48).toString("base64url")
  };
}

test("el almacen resuelve por secreto exacto y permite revocar", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "troste-store-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new LetterStore({ directory, maxPayloadBytes: 96 * 1024, maxTtlMs: 90 * 24 * 60 * 60 * 1000 });
  await store.init();
  const nodeId = randomUUID();
  const secret = randomBytes(32).toString("base64url");
  const secretHash = hashRouteSecret(nodeId, secret);
  await store.create({
    nodeId,
    secretHash,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    payload: fakePayload()
  });

  assert.equal(await store.count(), 1);
  assert.equal((await store.resolve(nodeId, secretHash)).nodeId, nodeId);
  assert.equal(await store.resolve(nodeId, hashRouteSecret(nodeId, "A".repeat(43))), null);
  assert.equal(await store.remove(nodeId), true);
  assert.equal(await store.resolve(nodeId, secretHash), null);
});

test("el almacen rechaza vencimientos y paquetes no cifrados", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "troste-store-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new LetterStore({ directory, maxPayloadBytes: 4096, maxTtlMs: 60_000 });
  await store.init();
  const nodeId = randomUUID();
  const secret = randomBytes(32).toString("base64url");
  await assert.rejects(() => store.create({
    nodeId,
    secretHash: hashRouteSecret(nodeId, secret),
    expiresAt: new Date(Date.now() - 1000).toISOString(),
    payload: fakePayload()
  }), /Vencimiento/);
  await assert.rejects(() => store.create({
    nodeId,
    secretHash: hashRouteSecret(nodeId, secret),
    expiresAt: new Date(Date.now() + 30_000).toISOString(),
    payload: { plaintext: "hola" }
  }), /Paquete cifrado/);
});

test("la limpieza elimina archivos de nodo corruptos", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "troste-store-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new LetterStore({ directory, maxPayloadBytes: 4096, maxTtlMs: 60_000 });
  await store.init();
  const nodeId = randomUUID();
  await writeFile(path.join(directory, `${nodeId}.json`), "{nodo-roto", "utf8");

  assert.equal(await store.cleanupExpired(), 1);
  assert.equal(await store.count(), 0);
});

test("el almacen aplica cuotas y recupera capacidad al revocar", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "troste-store-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new LetterStore({
    directory,
    maxPayloadBytes: 4096,
    maxTtlMs: 60_000,
    maxActiveNodes: 1,
    maxTotalBytes: 1024 * 1024
  });
  await store.init();
  const firstId = randomUUID();
  const secondId = randomUUID();
  const expiresAt = new Date(Date.now() + 30_000).toISOString();
  await store.create({
    nodeId: firstId,
    secretHash: hashRouteSecret(firstId, randomBytes(32).toString("base64url")),
    expiresAt,
    payload: fakePayload()
  });

  await assert.rejects(() => store.create({
    nodeId: secondId,
    secretHash: hashRouteSecret(secondId, randomBytes(32).toString("base64url")),
    expiresAt,
    payload: fakePayload()
  }), (error) => error.code === "STORE_FULL");
  assert.equal(store.usage().activeNodes, 1);

  assert.equal(await store.remove(firstId), true);
  await store.create({
    nodeId: secondId,
    secretHash: hashRouteSecret(secondId, randomBytes(32).toString("base64url")),
    expiresAt,
    payload: fakePayload()
  });
  assert.equal(await store.count(), 1);
});

test("dos publicaciones concurrentes no sobrescriben el mismo nodo", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "troste-store-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new LetterStore({ directory, maxPayloadBytes: 4096, maxTtlMs: 60_000 });
  await store.init();
  const nodeId = randomUUID();
  const expiresAt = new Date(Date.now() + 30_000).toISOString();
  const records = [randomBytes(32), randomBytes(32)].map((secret) => ({
    nodeId,
    secretHash: hashRouteSecret(nodeId, secret.toString("base64url")),
    expiresAt,
    payload: fakePayload()
  }));

  const results = await Promise.allSettled(records.map((record) => store.create(record)));
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  const rejected = results.find((result) => result.status === "rejected");
  assert.equal(rejected.reason.code, "NODE_EXISTS");
  assert.equal(await store.count(), 1);
});

test("el almacen rechaza un nodo que supera la cuota total", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "troste-store-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new LetterStore({
    directory,
    maxPayloadBytes: 4096,
    maxTtlMs: 60_000,
    maxActiveNodes: 10,
    maxTotalBytes: 1
  });
  await store.init();
  const nodeId = randomUUID();
  await assert.rejects(() => store.create({
    nodeId,
    secretHash: hashRouteSecret(nodeId, randomBytes(32).toString("base64url")),
    expiresAt: new Date(Date.now() + 30_000).toISOString(),
    payload: fakePayload()
  }), (error) => error.code === "STORE_FULL");
  assert.equal(await store.count(), 0);
});
