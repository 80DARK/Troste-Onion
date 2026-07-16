import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import vm from "node:vm";
import { webcrypto } from "node:crypto";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function fakeElement() {
  return {
    value: "",
    textContent: "",
    innerHTML: "",
    hidden: false,
    disabled: false,
    width: 420,
    height: 420,
    dataset: {},
    style: {},
    className: "",
    classList: { add() {}, remove() {}, toggle() {} },
    addEventListener() {},
    setAttribute() {},
    remove() {},
    select() {},
    focus() {},
    scrollIntoView() {},
    querySelector: () => fakeElement(),
    getContext: () => ({
      fillRect() {}, fillText() {}, beginPath() {}, arc() {}, fill() {}, clearRect() {}, setTransform() {}
    })
  };
}

const context = {
  console,
  TextEncoder,
  TextDecoder,
  Uint8Array,
  ArrayBuffer,
  Math,
  JSON,
  Date,
  Intl,
  Blob,
  crypto: webcrypto,
  navigator: { clipboard: { writeText: async () => {}, readText: async () => "" } },
  document: {
    querySelector: () => fakeElement(),
    querySelectorAll: () => [],
    createElement: () => fakeElement(),
    addEventListener() {},
    execCommand: () => true,
    body: { appendChild() {} }
  },
  window: {
    addEventListener() {},
    matchMedia: () => ({ matches: false }),
    innerWidth: 1200,
    innerHeight: 800,
    devicePixelRatio: 1
  },
  location: new URL("http://127.0.0.1:8741/"),
  history: { replaceState() {} },
  localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
  fetch: async () => ({ ok: false, json: async () => ({}) }),
  requestAnimationFrame() {},
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
  btoa: (value) => Buffer.from(value, "binary").toString("base64"),
  atob: (value) => Buffer.from(value, "base64").toString("binary")
};
context.window.crypto = webcrypto;
context.window.location = context.location;
vm.createContext(context);

let source = fs.readFileSync(path.join(root, "app.js"), "utf8");
source = source.replace(/init\(\)\.catch\(\(error\) => \{[\s\S]*?\n\}\);\n/, "");
source += `
this.__trosteTest = {
  compactPublicJwk,
  fingerprintPublicIdentity,
  createSealedNode,
  decryptNode,
  verifyNodeSignature,
  encryptRouteNode,
  decryptRouteNode,
  formatLetterCode,
  parseLetterCode,
  hashCodeSecret,
  state
};
`;
vm.runInContext(source, context);
const api = context.__trosteTest;

async function makeIdentity(name) {
  const encryptionPair = await webcrypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const signingPair = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const publicIdentity = {
    type: "troste-public-identity",
    version: 1,
    name,
    encryptionPublicJwk: api.compactPublicJwk(await webcrypto.subtle.exportKey("jwk", encryptionPair.publicKey)),
    signingPublicJwk: api.compactPublicJwk(await webcrypto.subtle.exportKey("jwk", signingPair.publicKey))
  };
  publicIdentity.fingerprint = await api.fingerprintPublicIdentity(publicIdentity);
  return {
    fingerprint: publicIdentity.fingerprint,
    name,
    publicIdentity,
    encryptionPrivateJwk: await webcrypto.subtle.exportKey("jwk", encryptionPair.privateKey),
    signingPrivateJwk: await webcrypto.subtle.exportKey("jwk", signingPair.privateKey)
  };
}

test("la carta conserva cifrado, firma y doble sobre Onion", async () => {
  const alice = await makeIdentity("Alice");
  const bob = await makeIdentity("Bob");
  api.state.activeIdentity = alice;
  api.state.contacts = [
    { fingerprint: alice.fingerprint, publicIdentity: alice.publicIdentity },
    { fingerprint: bob.fingerprint, publicIdentity: bob.publicIdentity }
  ];
  api.state.onion.address = `${"a".repeat(56)}.onion`;

  const node = await api.createSealedNode({
    recipient: { fingerprint: bob.fingerprint, publicIdentity: bob.publicIdentity },
    title: "Prueba",
    mood: "secreto",
    body: "Esta carta no debe quedar en claro.",
    dateline: "Lima, 15 de julio de 2026",
    salutation: "A la atencion de Bob:",
    closing: "Con afecto,",
    signoff: "Alice"
  });

  assert.equal(node.codeSecret.length, 43);
  assert.equal(node.codeHash, await api.hashCodeSecret(node.nodeId, node.codeSecret));
  assert(!JSON.stringify(node).includes("Esta carta no debe quedar en claro."));

  const routePayload = await api.encryptRouteNode(node, node.codeSecret);
  assert(!JSON.stringify(routePayload).includes(node.envelope.ciphertext));
  const routedNode = await api.decryptRouteNode(routePayload, node.nodeId, node.codeSecret);
  assert.equal(routedNode.nodeId, node.nodeId);
  await assert.rejects(() => api.decryptRouteNode(routePayload, node.nodeId, "B".repeat(43)));

  const tamperedRoute = structuredClone(routePayload);
  tamperedRoute.ciphertext = `${tamperedRoute.ciphertext[0] === "A" ? "B" : "A"}${tamperedRoute.ciphertext.slice(1)}`;
  await assert.rejects(() => api.decryptRouteNode(tamperedRoute, node.nodeId, node.codeSecret));

  const opened = await api.decryptNode(routedNode, bob);
  assert.equal(opened.body, "Esta carta no debe quedar en claro.");
  await assert.rejects(() => api.decryptNode(routedNode, alice));
  assert.equal((await api.verifyNodeSignature(routedNode)).valid, true);

  const tamperedLetter = structuredClone(routedNode);
  tamperedLetter.envelope.signature = `${tamperedLetter.envelope.signature[0] === "A" ? "B" : "A"}${tamperedLetter.envelope.signature.slice(1)}`;
  assert.equal((await api.verifyNodeSignature(tamperedLetter)).valid, false);

  const code = api.formatLetterCode(node);
  const parsed = api.parseLetterCode(code);
  assert.equal(parsed.onionAddress, node.onionAddress);
  assert.equal(parsed.nodeId, node.nodeId);
  assert.equal(parsed.codeSecret, node.codeSecret);
});
