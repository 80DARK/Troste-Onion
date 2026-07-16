import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (name) => fs.readFileSync(path.join(root, name), "utf8");

test("la superficie publicada mantiene el protocolo Onion minimo", () => {
  const app = read("app.js");
  const html = read("index.html");
  const main = read("server/main.js");
  const tor = read("server/tor-manager.js");
  const gitignore = read(".gitignore");

  assert(!/supabase/i.test(app + html + main));
  assert(html.includes("TROSTE-ONION1:direccion:id:secreto"));
  assert(!html.toLowerCase().includes("qr"));
  assert(app.includes("ECDH-P256+HKDF-SHA256+AES-256-GCM"));
  assert(app.includes("HKDF-SHA256+AES-256-GCM"));
  assert(app.includes("VAULT_KDF_ITERATIONS = 600000"));
  assert(app.includes("await publishNodeToOnion(node)"));
  assert(app.indexOf("await publishNodeToOnion(node)") < app.indexOf("await playSealAnimation(recipient.publicIdentity.name)"));
  assert(main.includes('config.onionHost:') === false);
  assert(main.includes("listen(onionServer, config.onionPort, config.onionHost)"));
  assert(main.includes("listen(uiServer, config.uiPort, config.uiHost)"));
  assert(main.includes('url.pathname.match(/^\\/v1\\/letters\\/'));
  assert(!main.includes('GET" && url.pathname === "/v1/'));
  assert(main.includes('req.headers["x-troste-local"] !== "1"'));
  assert(main.includes('"Cross-Origin-Opener-Policy": "same-origin"'));
  assert(tor.includes("HiddenServiceVersion 3"));
  assert(tor.includes("IsolateSOCKSAuth"));
  assert(tor.includes("SafeLogging 1"));
  assert(gitignore.includes("data/"));
  assert(gitignore.includes("vendor/tor/"));
});
