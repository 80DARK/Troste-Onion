import path from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";

const projectDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const envPath = path.join(projectDir, ".env");
if (existsSync(envPath) && typeof process.loadEnvFile === "function") process.loadEnvFile(envPath);

const [{ createServer }, { readFile }, { config }, { LetterStore }, { TorManager }, { OnionClient }, httpTools, security] = await Promise.all([
  import("node:http"),
  import("node:fs/promises"),
  import("./config.js"),
  import("./store.js"),
  import("./tor-manager.js"),
  import("./onion-client.js"),
  import("./http.js"),
  import("./security.js")
]);

const { httpError, readJson, sendEmpty, sendJson, SlidingWindowLimiter } = httpTools;
const { BASE64URL_SECRET_PATTERN, hashRouteSecret, isRoutePayload, privateHeaders, sleep, UUID_PATTERN } = security;
const store = new LetterStore({
  directory: path.join(config.dataDir, "nodes"),
  maxPayloadBytes: config.maxStoredPayloadBytes,
  maxTtlMs: config.nodeTtlMs
});
const tor = new TorManager(config);
const onionClient = new OnionClient({
  socksHost: config.socksHost,
  socksPort: config.socksPort,
  timeoutMs: config.resolveTimeoutMs,
  maxResponseBytes: config.maxStoredPayloadBytes + 4096
});
const remoteLimiter = new SlidingWindowLimiter({ max: 120, windowMs: 60_000 });
const localResolveLimiter = new SlidingWindowLimiter({ max: 30, windowMs: 60_000 });
let remoteInFlight = 0;

await store.init();

const onionServer = createServer((req, res) => {
  handleOnionRequest(req, res).catch((error) => handleError(res, error, false));
});
const uiServer = createServer((req, res) => {
  handleLocalRequest(req, res).catch((error) => handleError(res, error, true));
});

onionServer.requestTimeout = 20_000;
onionServer.headersTimeout = 8_000;
onionServer.keepAliveTimeout = 1_000;
uiServer.requestTimeout = 55_000;
uiServer.headersTimeout = 10_000;

await Promise.all([
  listen(onionServer, config.onionPort, config.onionHost),
  listen(uiServer, config.uiPort, config.uiHost)
]);
await tor.start();

const cleanupTimer = setInterval(() => store.cleanupExpired().catch(() => {}), 60 * 60 * 1000);
cleanupTimer.unref();

console.log(`Troste Onion: http://${config.uiHost}:${config.uiPort}`);
console.log(`Entrega local: ${config.onionHost}:${config.onionPort} (solo Tor)`);
console.log(tor.getStatus().message);

let shuttingDown = false;
async function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  clearInterval(cleanupTimer);
  await Promise.all([closeServer(uiServer), closeServer(onionServer), tor.stop()]);
}

process.once("SIGINT", () => shutdown().finally(() => process.exit(0)));
process.once("SIGTERM", () => shutdown().finally(() => process.exit(0)));

async function handleLocalRequest(req, res) {
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
  if (!url.pathname.startsWith("/api/")) {
    await serveStatic(req, res, url.pathname);
    return;
  }
  assertLocalRequest(req);

  if (req.method === "GET" && url.pathname === "/api/status") {
    const torStatus = tor.getStatus();
    sendJson(res, 200, {
      service: "troste-onion",
      version: 1,
      onionAddress: torStatus.onionAddress,
      nodeCount: await store.count(),
      tor: {
        state: torStatus.state,
        progress: torStatus.progress,
        message: torStatus.message
      }
    });
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/nodes") {
    const body = await readJson(req, config.maxLocalBodyBytes);
    if (!UUID_PATTERN.test(body.nodeId || "") || !/^[a-f0-9]{64}$/.test(body.secretHash || "")) {
      throw httpError(400, "INVALID_NODE", "Identificador o hash de ruta invalido.");
    }
    if (!isRoutePayload(body.payload, config.maxStoredPayloadBytes)) {
      throw httpError(400, "INVALID_PAYLOAD", "Paquete cifrado invalido.");
    }
    await store.create({
      nodeId: body.nodeId,
      secretHash: body.secretHash,
      expiresAt: body.expiresAt,
      payload: body.payload
    });
    sendJson(res, 201, { stored: true, nodeId: body.nodeId });
    return;
  }

  const deleteMatch = req.method === "DELETE" && url.pathname.match(/^\/api\/nodes\/([0-9a-f-]{36})$/i);
  if (deleteMatch) {
    const nodeId = deleteMatch[1].toLowerCase();
    const body = await readJson(req, 1024);
    if (!BASE64URL_SECRET_PATTERN.test(body.secret || "")) throw httpError(404, "LETTER_NOT_FOUND", "Carta no encontrada.");
    const record = await store.resolve(nodeId, hashRouteSecret(nodeId, body.secret));
    if (!record) throw httpError(404, "LETTER_NOT_FOUND", "Carta no encontrada.");
    await store.remove(nodeId);
    sendEmpty(res);
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/resolve") {
    if (!localResolveLimiter.consume()) throw httpError(429, "RATE_LIMITED", "Demasiadas consultas locales.");
    const torStatus = tor.getStatus();
    if (torStatus.state !== "ready") throw httpError(503, "TOR_NOT_READY", torStatus.message);
    const body = await readJson(req, 2048);
    const payload = await onionClient.resolve({
      onionAddress: String(body.onionAddress || "").toLowerCase(),
      nodeId: String(body.nodeId || "").toLowerCase(),
      secret: body.secret
    });
    if (!isRoutePayload(payload.payload, config.maxStoredPayloadBytes)) {
      throw httpError(502, "INVALID_RESPONSE", "El buzon Onion devolvio un paquete invalido.");
    }
    sendJson(res, 200, { payload: payload.payload });
    return;
  }

  throw httpError(404, "NOT_FOUND", "Ruta local inexistente.");
}

async function handleOnionRequest(req, res) {
  const url = new URL(req.url || "/", "http://onion.invalid");
  const match = req.method === "POST" && url.pathname.match(/^\/v1\/letters\/([0-9a-f-]{36})$/i);
  if (!match) throw httpError(404, "LETTER_NOT_FOUND", "Carta no encontrada.");
  if (!remoteLimiter.consume() || remoteInFlight >= 16) throw httpError(429, "RATE_LIMITED", "Buzon ocupado.");
  remoteInFlight += 1;
  try {
    const nodeId = match[1].toLowerCase();
    const body = await readJson(req, config.maxRemoteBodyBytes);
    if (!UUID_PATTERN.test(nodeId) || !BASE64URL_SECRET_PATTERN.test(body.secret || "")) {
      await sleep(40 + Math.floor(Math.random() * 80));
      throw httpError(404, "LETTER_NOT_FOUND", "Carta no encontrada.");
    }
    const record = await store.resolve(nodeId, hashRouteSecret(nodeId, body.secret));
    if (!record) {
      await sleep(40 + Math.floor(Math.random() * 80));
      throw httpError(404, "LETTER_NOT_FOUND", "Carta no encontrada.");
    }
    sendJson(res, 200, { payload: record.payload }, {
      "Cross-Origin-Resource-Policy": "same-site",
      Connection: "close"
    });
  } finally {
    remoteInFlight -= 1;
  }
}

function assertLocalRequest(req) {
  const allowedHosts = new Set([`${config.uiHost}:${config.uiPort}`, `localhost:${config.uiPort}`]);
  if (!allowedHosts.has(String(req.headers.host || "").toLowerCase())) {
    throw httpError(403, "LOCAL_ONLY", "Host local no permitido.");
  }
  if (req.headers["x-troste-local"] !== "1") {
    throw httpError(403, "LOCAL_ONLY", "Falta la marca de solicitud local.");
  }
  const origin = String(req.headers.origin || "");
  if (origin && !new Set([`http://${config.uiHost}:${config.uiPort}`, `http://localhost:${config.uiPort}`]).has(origin)) {
    throw httpError(403, "LOCAL_ONLY", "Origen local no permitido.");
  }
  const fetchSite = String(req.headers["sec-fetch-site"] || "");
  if (fetchSite && fetchSite !== "same-origin" && fetchSite !== "none") {
    throw httpError(403, "LOCAL_ONLY", "Solicitud entre sitios rechazada.");
  }
}

async function serveStatic(req, res, pathname) {
  if (req.method !== "GET" && req.method !== "HEAD") throw httpError(405, "METHOD_NOT_ALLOWED", "Metodo no permitido.");
  const files = new Map([
    ["/", ["index.html", "text/html; charset=utf-8"]],
    ["/index.html", ["index.html", "text/html; charset=utf-8"]],
    ["/styles.css", ["styles.css", "text/css; charset=utf-8"]],
    ["/app.js", ["app.js", "text/javascript; charset=utf-8"]]
  ]);
  const entry = files.get(pathname);
  if (!entry) throw httpError(404, "NOT_FOUND", "Archivo inexistente.");
  const body = await readFile(path.join(config.projectDir, entry[0]));
  res.writeHead(200, privateHeaders({
    "Content-Type": entry[1],
    "Content-Length": body.length,
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin"
  }));
  res.end(req.method === "HEAD" ? undefined : body);
}

function handleError(res, error, local) {
  if (res.headersSent) {
    res.destroy();
    return;
  }
  const status = Number.isInteger(error.status) ? error.status : mapErrorStatus(error.code);
  const code = error.code || "INTERNAL_ERROR";
  const message = status >= 500 && !local ? "Buzon no disponible." : error.message || "Error interno.";
  if (status >= 500) console.error(`[${code}] ${error.message}`);
  sendJson(res, status, { error: message, code });
}

function mapErrorStatus(code) {
  if (code === "NODE_EXISTS") return 409;
  if (code === "ONION_UNREACHABLE" || code === "INVALID_RESPONSE") return 502;
  if (code === "INVALID_CODE") return 400;
  return 500;
}

function listen(server, port, host) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
}

function closeServer(server) {
  return new Promise((resolve) => server.close(() => resolve()));
}
