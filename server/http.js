import { privateHeaders } from "./security.js";

export async function readJson(req, maxBytes) {
  const contentType = String(req.headers["content-type"] || "").split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/json") throw httpError(415, "UNSUPPORTED_MEDIA", "Se esperaba application/json.");
  const declared = Number.parseInt(req.headers["content-length"] || "0", 10);
  if (Number.isFinite(declared) && declared > maxBytes) throw httpError(413, "PAYLOAD_TOO_LARGE", "Solicitud demasiado grande.");
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw httpError(413, "PAYLOAD_TOO_LARGE", "Solicitud demasiado grande.");
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
  } catch {
    throw httpError(400, "INVALID_JSON", "JSON invalido.");
  }
}

export function sendJson(res, status, value, extraHeaders = {}) {
  const body = Buffer.from(JSON.stringify(value), "utf8");
  res.writeHead(status, privateHeaders({
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": body.length,
    ...extraHeaders
  }));
  res.end(body);
}

export function sendEmpty(res, status = 204) {
  res.writeHead(status, privateHeaders());
  res.end();
}

export function httpError(status, code, message) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
}

export class SlidingWindowLimiter {
  constructor({ max, windowMs }) {
    this.max = max;
    this.windowMs = windowMs;
    this.attempts = [];
  }

  consume(now = Date.now()) {
    this.attempts = this.attempts.filter((time) => now - time < this.windowMs);
    if (this.attempts.length >= this.max) return false;
    this.attempts.push(now);
    return true;
  }
}
