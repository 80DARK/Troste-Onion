import http from "node:http";
import { SocksProxyAgent } from "socks-proxy-agent";
import { BASE64URL_SECRET_PATTERN, isV3OnionAddress, randomSocksCredential, UUID_PATTERN } from "./security.js";

export class OnionClient {
  constructor({ socksHost, socksPort, timeoutMs, maxResponseBytes }) {
    this.socksHost = socksHost;
    this.socksPort = socksPort;
    this.timeoutMs = timeoutMs;
    this.maxResponseBytes = maxResponseBytes;
  }

  async resolve({ onionAddress, nodeId, secret }) {
    if (!isV3OnionAddress(onionAddress) || !UUID_PATTERN.test(nodeId || "") || !BASE64URL_SECRET_PATTERN.test(secret || "")) {
      throw clientError("INVALID_CODE", "Codigo Onion invalido.");
    }
    const credential = randomSocksCredential();
    const proxy = `socks5h://${credential}:${credential}@${this.socksHost}:${this.socksPort}`;
    const agent = new SocksProxyAgent(proxy);
    const body = Buffer.from(JSON.stringify({ secret }), "utf8");

    return new Promise((resolve, reject) => {
      const req = http.request({
        protocol: "http:",
        hostname: onionAddress,
        port: 80,
        path: `/v1/letters/${nodeId}`,
        method: "POST",
        agent,
        headers: {
          Host: onionAddress,
          "Content-Type": "application/json",
          "Content-Length": body.length,
          Accept: "application/json",
          "User-Agent": "Troste-Onion/1",
          Connection: "close"
        },
        timeout: this.timeoutMs
      }, (res) => {
        const chunks = [];
        let size = 0;
        res.on("data", (chunk) => {
          size += chunk.length;
          if (size > this.maxResponseBytes) {
            req.destroy(clientError("INVALID_RESPONSE", "El buzon devolvio demasiado contenido."));
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => {
          let payload;
          try {
            payload = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
          } catch {
            reject(clientError("INVALID_RESPONSE", "El buzon devolvio una respuesta invalida."));
            return;
          }
          if (res.statusCode !== 200) {
            reject(clientError(payload.code === "RATE_LIMITED" ? "RATE_LIMITED" : "LETTER_NOT_FOUND", "Carta no encontrada o no disponible."));
            return;
          }
          resolve(payload);
        });
      });
      req.on("timeout", () => req.destroy(clientError("ONION_UNREACHABLE", "La ruta Onion agoto el tiempo de espera.")));
      req.on("error", (error) => {
        const publicCodes = new Set(["INVALID_CODE", "INVALID_RESPONSE", "ONION_UNREACHABLE", "LETTER_NOT_FOUND", "RATE_LIMITED"]);
        reject(publicCodes.has(error.code) ? error : clientError("ONION_UNREACHABLE", "No se pudo alcanzar el buzon Onion."));
      });
      req.end(body);
    });
  }
}

function clientError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}
