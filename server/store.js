import { link, mkdir, open, readFile, readdir, stat, unlink } from "node:fs/promises";
import path from "node:path";
import { isRoutePayload, safeHexEqual, SHA256_PATTERN, UUID_PATTERN } from "./security.js";

export class LetterStore {
  constructor({ directory, maxPayloadBytes, maxTtlMs, maxActiveNodes = 500, maxTotalBytes = 64 * 1024 * 1024 }) {
    this.directory = directory;
    this.maxPayloadBytes = maxPayloadBytes;
    this.maxTtlMs = maxTtlMs;
    this.maxActiveNodes = maxActiveNodes;
    this.maxTotalBytes = maxTotalBytes;
    this.activeNodes = 0;
    this.totalBytes = 0;
    this.mutationQueue = Promise.resolve();
  }

  async init() {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    await this.cleanupExpired();
  }

  filePath(nodeId) {
    if (!UUID_PATTERN.test(nodeId || "")) throw storeError("INVALID_NODE", "Identificador de carta invalido.");
    return path.join(this.directory, `${nodeId.toLowerCase()}.json`);
  }

  validateRecord(record) {
    const expiresAtMs = Date.parse(record?.expiresAt);
    const now = Date.now();
    if (!UUID_PATTERN.test(record?.nodeId || "")) throw storeError("INVALID_NODE", "Identificador de carta invalido.");
    if (!SHA256_PATTERN.test(record?.secretHash || "")) throw storeError("INVALID_SECRET_HASH", "Hash de ruta invalido.");
    if (!Number.isFinite(expiresAtMs) || expiresAtMs <= now || expiresAtMs > now + this.maxTtlMs + 60_000) {
      throw storeError("INVALID_EXPIRATION", "Vencimiento de carta invalido.");
    }
    if (!isRoutePayload(record?.payload, this.maxPayloadBytes)) {
      throw storeError("INVALID_PAYLOAD", "Paquete cifrado invalido.");
    }
  }

  async create(record) {
    this.validateRecord(record);
    const normalized = {
      version: 1,
      nodeId: record.nodeId.toLowerCase(),
      secretHash: record.secretHash,
      expiresAt: new Date(record.expiresAt).toISOString(),
      payload: record.payload
    };
    const serialized = JSON.stringify(normalized);
    const storedBytes = Buffer.byteLength(serialized, "utf8");

    return this.mutate(async () => {
      if (this.activeNodes >= this.maxActiveNodes || this.totalBytes + storedBytes > this.maxTotalBytes) {
        throw storeError("STORE_FULL", "La caja alcanzo su capacidad local. Revoca cartas antes de guardar otra.");
      }

      const target = this.filePath(normalized.nodeId);
      const temporary = `${target}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`;
      const handle = await open(temporary, "wx", 0o600);
      try {
        await handle.writeFile(serialized, "utf8");
        await handle.sync();
      } finally {
        await handle.close();
      }

      try {
        await link(temporary, target);
      } catch (error) {
        await unlink(temporary).catch(() => {});
        if (error.code === "EEXIST") throw storeError("NODE_EXISTS", "Ese identificador ya existe.");
        throw error;
      }
      await unlink(temporary).catch(() => {});
      this.activeNodes += 1;
      this.totalBytes += storedBytes;
      return normalized;
    });
  }

  async read(nodeId) {
    try {
      const record = JSON.parse(await readFile(this.filePath(nodeId), "utf8"));
      if (record?.nodeId !== nodeId.toLowerCase() || !isRoutePayload(record.payload, this.maxPayloadBytes)) {
        throw storeError("CORRUPT_NODE", "El nodo almacenado esta danado.");
      }
      if (Date.parse(record.expiresAt) <= Date.now()) {
        await this.remove(nodeId);
        return null;
      }
      return record;
    } catch (error) {
      if (error.code === "ENOENT" || error instanceof SyntaxError) return null;
      throw error;
    }
  }

  async resolve(nodeId, secretHash) {
    const record = await this.read(nodeId);
    return record && safeHexEqual(record.secretHash, secretHash) ? record : null;
  }

  async remove(nodeId) {
    return this.mutate(async () => {
      const target = this.filePath(nodeId);
      try {
        const details = await stat(target);
        await unlink(target);
        this.activeNodes = Math.max(0, this.activeNodes - 1);
        this.totalBytes = Math.max(0, this.totalBytes - details.size);
        return true;
      } catch (error) {
        if (error.code === "ENOENT") return false;
        throw error;
      }
    });
  }

  async count() {
    return this.activeNodes;
  }

  usage() {
    return {
      activeNodes: this.activeNodes,
      maxActiveNodes: this.maxActiveNodes,
      totalBytes: this.totalBytes,
      maxTotalBytes: this.maxTotalBytes
    };
  }

  async cleanupExpired() {
    return this.mutate(async () => {
      const names = await readdir(this.directory).catch(() => []);
      let removed = 0;
      let processed = 0;
      for (const name of names) {
        if (!/^[0-9a-f-]{36}\.json$/.test(name)) continue;
        const target = path.join(this.directory, name);
        try {
          const record = JSON.parse(await readFile(target, "utf8"));
          const isExpired = !Number.isFinite(Date.parse(record?.expiresAt)) || Date.parse(record.expiresAt) <= Date.now();
          const isCorrupt = record?.nodeId !== name.slice(0, -5) || !isRoutePayload(record?.payload, this.maxPayloadBytes);
          if (isExpired || isCorrupt) {
            await unlink(target);
            removed += 1;
          }
        } catch {
          await unlink(target).catch(() => {});
          removed += 1;
        }
        processed += 1;
        if (processed % 50 === 0) await new Promise((resolve) => setImmediate(resolve));
      }
      await this.refreshUsage();
      return removed;
    });
  }

  mutate(operation) {
    const pending = this.mutationQueue.then(operation, operation);
    this.mutationQueue = pending.catch(() => {});
    return pending;
  }

  async refreshUsage() {
    const names = await readdir(this.directory).catch(() => []);
    const sizes = await Promise.all(names
      .filter((name) => /^[0-9a-f-]{36}\.json$/.test(name))
      .map((name) => stat(path.join(this.directory, name)).then((details) => details.size).catch(() => 0)));
    this.activeNodes = sizes.filter((size) => size > 0).length;
    this.totalBytes = sizes.reduce((total, size) => total + size, 0);
  }
}

function storeError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}
