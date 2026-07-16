import { constants as fsConstants } from "node:fs";
import { access, mkdir, open, readFile, readdir, rename, unlink } from "node:fs/promises";
import path from "node:path";
import { isRoutePayload, safeHexEqual, SHA256_PATTERN, UUID_PATTERN } from "./security.js";

export class LetterStore {
  constructor({ directory, maxPayloadBytes, maxTtlMs }) {
    this.directory = directory;
    this.maxPayloadBytes = maxPayloadBytes;
    this.maxTtlMs = maxTtlMs;
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
    const target = this.filePath(normalized.nodeId);
    const temporary = `${target}.${process.pid}.${Date.now()}.tmp`;
    const handle = await open(temporary, "wx", 0o600);
    try {
      await handle.writeFile(JSON.stringify(normalized), "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      await access(target, fsConstants.F_OK);
      await unlink(temporary).catch(() => {});
      throw storeError("NODE_EXISTS", "Ese identificador ya existe.");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    await rename(temporary, target);
    return normalized;
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
    try {
      await unlink(this.filePath(nodeId));
      return true;
    } catch (error) {
      if (error.code === "ENOENT") return false;
      throw error;
    }
  }

  async count() {
    const names = await readdir(this.directory);
    return names.filter((name) => /^[0-9a-f-]{36}\.json$/.test(name)).length;
  }

  async cleanupExpired() {
    const names = await readdir(this.directory).catch(() => []);
    let removed = 0;
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
    }
    return removed;
  }
}

function storeError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}
