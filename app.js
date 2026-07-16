const PUBLIC_IDENTITY_TYPE = "troste-public-identity";
const LETTER_CODE_PREFIX = "TROSTE-ONION1:";
const CRYPTO_SUITE = "ECDH-P256+HKDF-SHA256+AES-256-GCM";
const SIGNATURE_SUITE = "ECDSA-P256-SHA256";
const ROUTE_CRYPTO_SUITE = "HKDF-SHA256+AES-256-GCM";
const LOCAL_KEYRING_KEY = "troste.onion.keyring.v1";
const LOCAL_VAULT_KEY = "troste.onion.keyringVault.v1";
const LOCAL_OUTBOX_KEY = "troste.onion.outbox.v1";
const LOCAL_OUTBOX_VAULT_KEY = "troste.onion.outboxVault.v1";
const LOCAL_RESOLVE_LIMIT_KEY = "troste.onion.resolveLimit.v1";
const NODE_TTL_DAYS = 90;
const VAULT_KDF_ITERATIONS = 600000;
const MIN_VAULT_PHRASE_LENGTH = 12;
const MAX_LETTER_BYTES = 32 * 1024;
const MAX_ENVELOPE_BYTES = 60 * 1024;
const MAX_ROUTE_PAYLOAD_BYTES = 96 * 1024;
const MAX_PUBLIC_IDENTITY_BYTES = 12 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const els = {
  runtimeStatus: document.querySelector("#runtime-status"),
  backendStatus: document.querySelector("#backend-status"),
  menuToggle: document.querySelector("#menu-toggle"),
  sectionTabs: document.querySelector(".section-tabs"),
  sectionButtons: Array.from(document.querySelectorAll("[data-section-target]")),
  sectionPanels: Array.from(document.querySelectorAll("[data-section]")),
  identityForm: document.querySelector("#identity-form"),
  identityName: document.querySelector("#identity-name"),
  identityPassphrase: document.querySelector("#identity-passphrase"),
  identityPassphraseField: document.querySelector("#identity-passphrase-field"),
  identityCount: document.querySelector("#identity-count"),
  identityList: document.querySelector("#identity-list"),
  publicIdentity: document.querySelector("#public-identity"),
  onionNodeDetail: document.querySelector("#onion-node-detail"),
  onionAddress: document.querySelector("#onion-address"),
  copyPublic: document.querySelector("#copy-public"),
  downloadBackup: document.querySelector("#download-backup"),
  contactInput: document.querySelector("#contact-input"),
  importContact: document.querySelector("#import-contact"),
  pasteContact: document.querySelector("#paste-contact"),
  contactCount: document.querySelector("#contact-count"),
  contactList: document.querySelector("#contact-list"),
  letterForm: document.querySelector("#letter-form"),
  letterSenderName: document.querySelector("#letter-sender-name"),
  letterSenderId: document.querySelector("#letter-sender-id"),
  letterRecipient: document.querySelector("#letter-recipient"),
  letterDateline: document.querySelector("#letter-dateline"),
  letterMood: document.querySelector("#letter-mood"),
  letterTitle: document.querySelector("#letter-title"),
  letterSalutation: document.querySelector("#letter-salutation"),
  letterBody: document.querySelector("#letter-body"),
  letterClosing: document.querySelector("#letter-closing"),
  letterSignature: document.querySelector("#letter-signature"),
  letterMeter: document.querySelector("#letter-meter"),
  letterPaperStage: document.querySelector("#letter-paper-stage"),
  letterPaper: document.querySelector("#letter-paper"),
  letterActions: document.querySelector("#letter-actions"),
  sealedOutput: document.querySelector("#sealed-output"),
  sealedCode: document.querySelector("#sealed-code"),
  copyCode: document.querySelector("#copy-code"),
  writeAnother: document.querySelector("#write-another"),
  nodeCount: document.querySelector("#node-count"),
  nodeSource: document.querySelector("#node-source"),
  nodeList: document.querySelector("#node-list"),
  vaultStatus: document.querySelector("#vault-status"),
  vaultPin: document.querySelector("#vault-pin"),
  vaultEnable: document.querySelector("#vault-enable"),
  vaultUnlock: document.querySelector("#vault-unlock"),
  vaultLock: document.querySelector("#vault-lock"),
  backupRestore: document.querySelector("#backup-restore"),
  backupFile: document.querySelector("#backup-file"),
  securityChecklist: document.querySelector("#security-checklist"),
  openForm: document.querySelector("#open-form"),
  openCode: document.querySelector("#open-code"),
  openStatus: document.querySelector("#open-status"),
  readBadge: document.querySelector("#read-badge"),
  openedLetter: document.querySelector("#opened-letter"),
  sealAnimation: document.querySelector("#seal-animation"),
  sealAnimationSkip: document.querySelector("#seal-animation-skip"),
  sealAnimationRecipient: document.querySelector("#seal-animation-recipient"),
  sealAnimationStatus: document.querySelector("#seal-animation-status"),
  toast: document.querySelector("#toast"),
  sky: document.querySelector("#sky")
};

const state = {
  identities: [],
  contacts: [],
  nodes: [],
  activeIdentity: null,
  lastCreatedCode: "",
  vault: {
    enabled: false,
    locked: false,
    message: "Llavero local sin PIN."
  },
  onion: {
    available: false,
    torReady: false,
    address: "",
    nodeCount: 0,
    message: "Nodo local no verificado."
  }
};

let toastTimer = null;
let skyStars = [];
let skyAnimationEnabled = window.matchMedia("(min-width: 761px) and (prefers-reduced-motion: no-preference)").matches;
let skyFrameActive = false;
let unlockedKeyring = null;
let vaultKey = null;
let vaultRecord = null;
let sealingLetter = false;
let sealAnimationTimer = null;
let sealAnimationStatusTimers = [];
let sealAnimationResolve = null;
const skyCtx = els.sky.getContext("2d");

init().catch((error) => {
  console.error(error);
  setRuntime("No se pudo iniciar la caja fuerte.");
  showToast(error.message || "Algo se rompio al iniciar.");
});

async function init() {
  if (!window.crypto?.subtle) {
    throw new Error("Web Crypto no esta disponible. Abre la app en un contexto seguro o servidor local.");
  }

  bindEvents();
  if (skyAnimationEnabled) {
    resizeSky();
    seedSky();
    drawSky();
  } else {
    els.sky.hidden = true;
  }

  await refreshState();
  await checkOnionNode();
  setRuntime(
    state.vault.locked
      ? "Caja local bloqueada. Abrela en Seguridad."
      : state.identities.length && !state.vault.enabled
        ? "Protege tus llaves antiguas en Seguridad."
      : state.onion.torReady
        ? "Llaves locales + ruta Onion lista."
        : "Llaves locales listas. Tor pendiente."
  );
  renderAll();

  const initialCode = getInitialCodeFromUrl();
  if (initialCode) {
    setActiveSection("search");
    els.openCode.value = initialCode;
    setOpenStatus("warn", "Codigo recibido. Activa la identidad destinataria y busca la carta.");
    if (state.activeIdentity) {
      await openCode(initialCode);
    }
  }
}

function bindEvents() {
  els.sectionTabs.addEventListener("click", handleSectionClick);
  els.menuToggle.addEventListener("click", toggleMenu);
  document.addEventListener("click", closeMenuFromOutside);
  els.identityForm.addEventListener("submit", createIdentity);
  els.copyPublic.addEventListener("click", () => copyActivePublicIdentity());
  els.downloadBackup.addEventListener("click", downloadActiveBackup);
  els.importContact.addEventListener("click", importContactFromInput);
  els.pasteContact.addEventListener("click", pasteContactText);
  els.letterForm.addEventListener("submit", sealLetter);
  els.letterForm.addEventListener("reset", () => {
    setTimeout(() => {
      [els.letterDateline, els.letterSalutation, els.letterClosing, els.letterSignature].forEach((field) => {
        field.dataset.autofill = "true";
      });
      syncFormalLetterContext();
      updateLetterMeter();
    }, 0);
  });
  els.letterRecipient.addEventListener("change", () => {
    syncFormalLetterContext();
    updateLetterMeter();
  });
  [els.letterDateline, els.letterSalutation, els.letterClosing, els.letterSignature].forEach((field) => {
    field.addEventListener("input", () => {
      field.dataset.autofill = "false";
      updateLetterMeter();
    });
  });
  [els.letterTitle, els.letterBody].forEach((field) => field.addEventListener("input", updateLetterMeter));
  els.letterMood.addEventListener("change", updateLetterMeter);
  els.copyCode.addEventListener("click", () => copyText(els.sealedCode.value));
  els.writeAnother.addEventListener("click", writeAnotherLetter);
  els.openForm.addEventListener("submit", (event) => {
    event.preventDefault();
    openCode(els.openCode.value);
  });
  els.sealAnimationSkip.addEventListener("click", finishSealAnimation);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !els.sealAnimation.hidden) finishSealAnimation();
  });

  els.identityList.addEventListener("click", handleIdentityAction);
  els.contactList.addEventListener("click", handleContactAction);
  els.nodeList.addEventListener("click", handleNodeAction);
  els.vaultEnable.addEventListener("click", enableVaultFromPin);
  els.vaultUnlock.addEventListener("click", unlockVaultFromPin);
  els.vaultLock.addEventListener("click", lockVault);
  els.backupRestore.addEventListener("click", () => els.backupFile.click());
  els.backupFile.addEventListener("change", restoreEncryptedBackup);
  window.addEventListener("online", () => checkOnionNode());
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") checkOnionNode();
  });
  window.addEventListener("resize", () => {
    skyAnimationEnabled = window.matchMedia("(min-width: 761px) and (prefers-reduced-motion: no-preference)").matches;
    els.sky.hidden = !skyAnimationEnabled;
    if (skyAnimationEnabled) {
      resizeSky();
      seedSky();
      if (!skyFrameActive) drawSky();
    }
  });
}

function handleSectionClick(event) {
  const button = event.target.closest("[data-section-target]");
  if (!button) return;
  setActiveSection(button.dataset.sectionTarget);
  closeMenu();
}

function setActiveSection(section) {
  els.sectionButtons.forEach((button) => {
    button.classList.toggle("active", button.dataset.sectionTarget === section);
  });
  els.sectionPanels.forEach((panel) => {
    panel.classList.toggle("active-section", panel.dataset.section === section);
  });
}

function toggleMenu(event) {
  event.stopPropagation();
  const open = !els.sectionTabs.classList.contains("open");
  els.sectionTabs.classList.toggle("open", open);
  els.menuToggle.setAttribute("aria-expanded", String(open));
  els.menuToggle.setAttribute("aria-label", open ? "Cerrar menu" : "Abrir menu");
}

function closeMenu() {
  els.sectionTabs.classList.remove("open");
  els.menuToggle.setAttribute("aria-expanded", "false");
  els.menuToggle.setAttribute("aria-label", "Abrir menu");
}

function closeMenuFromOutside(event) {
  if (els.sectionTabs.contains(event.target) || els.menuToggle.contains(event.target)) return;
  closeMenu();
}

async function refreshState() {
  const keyring = loadKeyring();
  const outbox = await loadOutbox();
  const identities = keyring.identities || [];
  const contacts = keyring.contacts || [];
  state.identities = identities.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  state.contacts = contacts.sort((a, b) => a.publicIdentity.name.localeCompare(b.publicIdentity.name));
  state.nodes = outbox.sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""));
  state.activeIdentity =
    state.identities.find((identity) => identity.active) || state.identities[0] || null;

  if (state.activeIdentity && !state.activeIdentity.active) {
    await setActiveIdentity(state.activeIdentity.fingerprint, false);
  }
}

function loadKeyring() {
  vaultRecord = readVaultRecord();
  if (vaultRecord && !unlockedKeyring) {
    state.vault = {
      enabled: true,
      locked: true,
      message: "Llavero protegido. Ingresa tu PIN para usar tus llaves."
    };
    return { identities: [], contacts: [] };
  }
  if (vaultRecord && unlockedKeyring) {
    state.vault = {
      enabled: true,
      locked: false,
      message: "Llavero protegido con PIN y desbloqueado en esta sesion."
    };
    return normalizeKeyring(unlockedKeyring);
  }

  try {
    const parsed = JSON.parse(localStorage.getItem(LOCAL_KEYRING_KEY));
    state.vault = {
      enabled: false,
      locked: false,
      message: "Llavero local sin PIN. Puedes protegerlo en Seguridad."
    };
    return normalizeKeyring(parsed);
  } catch {
    state.vault = {
      enabled: false,
      locked: false,
      message: "Llavero local sin PIN."
    };
    return { identities: [], contacts: [] };
  }
}

function normalizeKeyring(value) {
  return {
    identities: Array.isArray(value?.identities) ? value.identities : [],
    contacts: Array.isArray(value?.contacts) ? value.contacts : []
  };
}

async function saveKeyring() {
  const keyring = {
    identities: state.identities,
    contacts: state.contacts
  };

  if (state.vault.enabled) {
    if (!vaultKey) throw new Error("Vault bloqueado.");
    unlockedKeyring = keyring;
    vaultRecord = await encryptVaultPayload(keyring);
    localStorage.setItem(LOCAL_VAULT_KEY, JSON.stringify(vaultRecord));
    localStorage.removeItem(LOCAL_KEYRING_KEY);
    return;
  }

  localStorage.setItem(LOCAL_KEYRING_KEY, JSON.stringify(keyring));
}

function readVaultRecord() {
  try {
    const parsed = JSON.parse(localStorage.getItem(LOCAL_VAULT_KEY));
    if (parsed?.type !== "troste-keyring-vault" || parsed.version !== 1) return null;
    return parsed;
  } catch {
    return null;
  }
}

async function enableVaultFromPin() {
  const pin = els.vaultPin.value.trim();
  if (pin.length < MIN_VAULT_PHRASE_LENGTH) {
    showToast(`Usa una frase de al menos ${MIN_VAULT_PHRASE_LENGTH} caracteres.`);
    return;
  }
  await enableVault(pin, { announce: true });
}

async function enableVault(pin, { announce = false } = {}) {
  try {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    vaultKey = await deriveVaultKey(pin, salt);
    vaultRecord = {
      type: "troste-keyring-vault",
      version: 1,
      kdf: "PBKDF2-SHA256",
      iterations: VAULT_KDF_ITERATIONS,
      salt: bytesToBase64url(salt)
    };
    state.vault = {
      enabled: true,
      locked: false,
      message: "Llavero protegido con PIN y desbloqueado en esta sesion."
    };
    await saveKeyring();
    await saveOutbox();
    els.vaultPin.value = "";
    await refreshState();
    renderAll();
    if (announce) showToast("Caja protegida. Tus llaves y cartas locales quedaron cifradas.");
    return true;
  } catch (error) {
    showToast(error.message || "No se pudo activar el vault.");
    return false;
  }
}

async function unlockVaultFromPin() {
  const pin = els.vaultPin.value.trim();
  const record = readVaultRecord();
  if (!record) {
    showToast("No hay vault cifrado todavia.");
    return;
  }
  if (!pin) {
    showToast("Ingresa tu PIN para desbloquear.");
    return;
  }

  try {
    const salt = base64urlToBytes(record.salt);
    const key = await deriveVaultKey(pin, salt, record.iterations || VAULT_KDF_ITERATIONS);
    const clear = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64urlToBytes(record.iv) },
      key,
      base64urlToBytes(record.ciphertext)
    );
    unlockedKeyring = normalizeKeyring(JSON.parse(decoder.decode(clear)));
    vaultKey = key;
    vaultRecord = record;
    state.vault = {
      enabled: true,
      locked: false,
      message: "Llavero protegido con PIN y desbloqueado en esta sesion."
    };
    els.vaultPin.value = "";
    await refreshState();
    await saveOutbox();
    renderAll();
    showToast("Llavero desbloqueado.");
  } catch (error) {
    console.warn(error);
    showToast("PIN incorrecto o vault danado.");
  }
}

async function lockVault() {
  if (!state.vault.enabled) {
    showToast("Primero activa el vault con PIN.");
    return;
  }
  unlockedKeyring = null;
  vaultKey = null;
  await refreshState();
  renderAll();
  hideOpenedLetter();
  showToast("Llavero bloqueado en esta sesion.");
}

async function deriveVaultKey(pin, salt, iterations = VAULT_KDF_ITERATIONS) {
  const baseKey = await crypto.subtle.importKey("raw", encoder.encode(pin), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptVaultPayload(keyring) {
  const current = vaultRecord || {};
  const salt = current.salt ? base64urlToBytes(current.salt) : crypto.getRandomValues(new Uint8Array(16));
  if (!vaultKey) {
    throw new Error("Vault bloqueado.");
  }
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    vaultKey,
    encoder.encode(JSON.stringify(keyring))
  );
  return {
    type: "troste-keyring-vault",
    version: 1,
    kdf: "PBKDF2-SHA256",
    iterations: current.iterations || VAULT_KDF_ITERATIONS,
    salt: bytesToBase64url(salt),
    iv: bytesToBase64url(iv),
    ciphertext: bytesToBase64url(ciphertext)
  };
}

async function loadOutbox() {
  if (vaultRecord) {
    if (!vaultKey) return [];
    try {
      const record = JSON.parse(localStorage.getItem(LOCAL_OUTBOX_VAULT_KEY));
      if (record?.type === "troste-outbox-vault" && record.version === 1) {
        const clear = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: base64urlToBytes(record.iv) },
          vaultKey,
          base64urlToBytes(record.ciphertext)
        );
        const parsed = JSON.parse(decoder.decode(clear));
        return normalizeOutboxNodes(parsed?.nodes);
      }
    } catch (error) {
      console.warn("No se pudo abrir la bandeja cifrada", error);
      return [];
    }
  }

  try {
    const parsed = JSON.parse(localStorage.getItem(LOCAL_OUTBOX_KEY));
    return normalizeOutboxNodes(parsed?.nodes);
  } catch {
    return [];
  }
}

function normalizeOutboxNodes(nodes) {
  return Array.isArray(nodes)
    ? nodes.filter((node) => isLocalOutboxNode(node))
    : [];
}

async function saveOutbox() {
  if (state.vault.enabled) {
    if (!vaultKey) throw new Error("Vault bloqueado.");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      vaultKey,
      encoder.encode(JSON.stringify({ version: 1, nodes: state.nodes }))
    );
    localStorage.setItem(
      LOCAL_OUTBOX_VAULT_KEY,
      JSON.stringify({
        type: "troste-outbox-vault",
        version: 1,
        iv: bytesToBase64url(iv),
        ciphertext: bytesToBase64url(ciphertext)
      })
    );
    localStorage.removeItem(LOCAL_OUTBOX_KEY);
    return;
  }

  localStorage.setItem(
    LOCAL_OUTBOX_KEY,
    JSON.stringify({
      version: 1,
      nodes: state.nodes
    })
  );
}

function isLocalOutboxNode(node) {
  return Boolean(
    node &&
      typeof node.nodeId === "string" &&
      isOnionAddress(node.onionAddress) &&
      typeof node.codeSecret === "string" &&
      typeof node.codeHash === "string" &&
      typeof node.expiresAt === "string" &&
      typeof node.recipientKeyHash === "string" &&
      typeof node.senderKeyHash === "string" &&
      node.envelope
  );
}

async function rememberOutboxNode(node) {
  state.nodes = [node, ...state.nodes.filter((item) => item.nodeId !== node.nodeId)].slice(0, 80);
  await saveOutbox();
}

function findLocalOutboxNode(nodeId) {
  return state.nodes.find(
    (node) =>
      node.nodeId === nodeId &&
      node.envelope &&
      node.status !== "revoked" &&
      Date.parse(node.expiresAt) > Date.now()
  ) || null;
}

function upsertContact(contact) {
  const index = state.contacts.findIndex((item) => item.fingerprint === contact.fingerprint);
  if (index >= 0) {
    state.contacts[index] = { ...state.contacts[index], ...contact };
  } else {
    state.contacts.push(contact);
  }
}

async function checkOnionNode() {
  try {
    const status = await localApi("/api/status", { method: "GET" });
    state.onion = {
      available: true,
      torReady: status.tor?.state === "ready" && isOnionAddress(status.onionAddress),
      address: isOnionAddress(status.onionAddress) ? status.onionAddress : "",
      nodeCount: Number.isInteger(status.nodeCount) ? status.nodeCount : 0,
      message: String(status.tor?.message || "Daemon local conectado.")
    };
  } catch (error) {
    state.onion = {
      available: false,
      torReady: false,
      address: "",
      nodeCount: 0,
      message: `Daemon pendiente: ${error.message}`
    };
  }
  renderBackendStatus();
  return state.onion;
}

async function localApi(path, { method = "POST", body } = {}) {
  const response = await fetch(path, {
    method,
    credentials: "same-origin",
    cache: "no-store",
    headers: body === undefined
      ? { "X-Troste-Local": "1" }
      : { "Content-Type": "application/json", "X-Troste-Local": "1" },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.error || `El nodo local respondio ${response.status}.`);
    error.code = payload.code || "LOCAL_NODE_ERROR";
    throw error;
  }
  return payload;
}

async function publishNodeToOnion(node) {
  if (!state.onion.torReady || !isOnionAddress(state.onion.address)) {
    throw new Error(state.onion.message || "Tor aun no termino de abrir la ruta Onion.");
  }
  const routePayload = await encryptRouteNode(node, node.codeSecret);
  await localApi("/api/nodes", {
    body: {
      nodeId: node.nodeId,
      secretHash: node.codeHash,
      expiresAt: node.expiresAt,
      payload: routePayload
    }
  });
  state.onion.nodeCount += 1;
  return routePayload;
}

async function fetchNodeFromOnion(code) {
  return localApi("/api/resolve", {
    body: {
      onionAddress: code.onionAddress,
      nodeId: code.nodeId,
      secret: code.codeSecret
    }
  });
}

async function createIdentity(event) {
  event.preventDefault();
  const name = els.identityName.value.trim() || "sin nombre";

  if (state.vault.enabled && state.vault.locked) {
    showToast("Desbloquea tu caja antes de crear otra identidad.");
    setActiveSection("security");
    return;
  }
  if (!state.vault.enabled) {
    const phrase = els.identityPassphrase.value.trim();
    if (phrase.length < MIN_VAULT_PHRASE_LENGTH) {
      showToast(`Protege tu identidad con una frase de al menos ${MIN_VAULT_PHRASE_LENGTH} caracteres.`);
      els.identityPassphrase.focus();
      return;
    }
    const enabled = await enableVault(phrase);
    if (!enabled) return;
  }

  setRuntime("Forjando llaves locales...");

  try {
    const encryptionPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );
    const signingPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );

    const encryptionPublicJwk = compactPublicJwk(await crypto.subtle.exportKey("jwk", encryptionPair.publicKey));
    const signingPublicJwk = compactPublicJwk(await crypto.subtle.exportKey("jwk", signingPair.publicKey));
    const publicIdentity = {
      type: PUBLIC_IDENTITY_TYPE,
      version: 1,
      name,
      encryptionPublicJwk,
      signingPublicJwk
    };
    publicIdentity.fingerprint = await fingerprintPublicIdentity(publicIdentity);

    const record = {
      fingerprint: publicIdentity.fingerprint,
      name,
      active: true,
      createdAt: new Date().toISOString(),
      publicIdentity,
      encryptionPrivateJwk: await crypto.subtle.exportKey("jwk", encryptionPair.privateKey),
      signingPrivateJwk: await crypto.subtle.exportKey("jwk", signingPair.privateKey)
    };

    state.identities = state.identities.map((identity) => ({ ...identity, active: false }));
    state.identities.unshift(record);
    upsertContact({
      fingerprint: publicIdentity.fingerprint,
      publicIdentity,
      importedAt: new Date().toISOString(),
      self: true
    });
    await saveKeyring();

    els.identityName.value = "";
    els.identityPassphrase.value = "";
    await refreshState();
    renderAll();
    setRuntime("Identidad activa lista.");
    showToast("Identidad lista. Tu llave privada quedo cifrada en esta caja.");
  } catch (error) {
    setRuntime("No se pudo crear la identidad.");
    showToast(error.message || "No se pudo crear la identidad.");
  }
}

async function setActiveIdentity(fingerprint, refresh = true) {
  state.identities = state.identities.map((identity) => ({
    ...identity,
    active: identity.fingerprint === fingerprint
  }));
  await saveKeyring();
  if (refresh) {
    await refreshState();
    renderAll();
  }
}

async function handleIdentityAction(event) {
  const button = event.target.closest("button");
  if (!button) return;
  const fingerprint = button.dataset.fingerprint;
  const identity = state.identities.find((item) => item.fingerprint === fingerprint);
  if (!identity) return;

  if (button.dataset.action === "activate") {
    await setActiveIdentity(fingerprint);
    showToast(`Identidad activa: ${identity.name}`);
  }

  if (button.dataset.action === "copy") {
    await copyText(JSON.stringify(identity.publicIdentity, null, 2));
    showToast("Identidad publica copiada.");
  }
}

async function importContactFromInput() {
  const text = els.contactInput.value.trim();
  if (!text) {
    showToast("Pega una identidad publica primero.");
    return;
  }

  try {
    const publicIdentity = await normalizeAndValidatePublicIdentity(text);
    await savePublicIdentityAsContact(publicIdentity);
    els.contactInput.value = "";
    showToast(`Contacto importado: ${publicIdentity.name}`);
  } catch (error) {
    showToast(error.message || "No pude importar esa identidad.");
  }
}

async function savePublicIdentityAsContact(publicIdentity) {
  upsertContact({
    fingerprint: publicIdentity.fingerprint,
    publicIdentity,
    importedAt: new Date().toISOString(),
    self: state.identities.some((identity) => identity.fingerprint === publicIdentity.fingerprint)
  });
  await saveKeyring();
  await refreshState();
  renderAll();
}

async function pasteContactText() {
  try {
    els.contactInput.value = await navigator.clipboard.readText();
    showToast("Texto pegado.");
  } catch {
    els.contactInput.focus();
    showToast("Tu navegador no dejo leer el portapapeles. Pegalo manualmente.");
  }
}


async function handleContactAction(event) {
  const button = event.target.closest("button");
  if (!button) return;
  const fingerprint = button.dataset.fingerprint;
  const contact = state.contacts.find((item) => item.fingerprint === fingerprint);
  if (!contact) return;

  if (button.dataset.action === "copy") {
    await copyText(JSON.stringify(contact.publicIdentity, null, 2));
    showToast("Identidad publica copiada.");
  }

  if (button.dataset.action === "remove") {
    state.contacts = state.contacts.filter((item) => item.fingerprint !== fingerprint);
    await saveKeyring();
    await refreshState();
    renderAll();
    showToast("Contacto removido.");
  }
}

function syncFormalLetterContext() {
  const sender = state.activeIdentity;
  const recipient = state.contacts.find((contact) => contact.fingerprint === els.letterRecipient.value);
  els.letterSenderName.textContent = sender?.name || "Sin identidad activa";
  els.letterSenderId.textContent = sender ? `Sello ${shortFingerprint(sender.fingerprint)}` : "Sello local pendiente";

  setFormalAutofill(els.letterDateline, formatFormalDateline(new Date()));
  setFormalAutofill(
    els.letterSalutation,
    recipient ? `A la atencion de ${recipient.publicIdentity.name}:` : "A quien corresponda:"
  );
  setFormalAutofill(els.letterClosing, "Con afecto,");
  setFormalAutofill(els.letterSignature, sender?.name || "");
}

function setFormalAutofill(field, value) {
  if (field.dataset.autofill === "false") return;
  field.value = value;
  field.dataset.autofill = "true";
}

function formatFormalDateline(date) {
  const formatted = new Intl.DateTimeFormat("es-PE", {
    day: "numeric",
    month: "long",
    year: "numeric"
  }).format(date);
  return `Lima, ${formatted}`;
}

function getLetterDraft(recipient) {
  return {
    title: els.letterTitle.value.trim() || "Carta sin titulo",
    mood: els.letterMood.value,
    body: els.letterBody.value,
    dateline: els.letterDateline.value.trim() || formatFormalDateline(new Date()),
    salutation: els.letterSalutation.value.trim() || `A la atencion de ${recipient.publicIdentity.name}:`,
    closing: els.letterClosing.value.trim() || "Con afecto,",
    signoff: els.letterSignature.value.trim() || state.activeIdentity?.name || "Remitente"
  };
}

function playSealAnimation(recipientName) {
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    completeLetterDispatch();
    return Promise.resolve();
  }
  if (sealAnimationResolve) finishSealAnimation();

  els.letterPaperStage.hidden = false;
  els.letterActions.hidden = true;
  els.sealedOutput.hidden = true;
  els.sealAnimationRecipient.textContent = `Para ${recipientName}`;
  els.sealAnimationStatus.textContent = "Doblando la carta...";
  els.sealAnimation.hidden = false;
  els.sealAnimation.classList.remove("is-running");
  els.letterPaperStage.classList.remove("is-sealing");
  els.letterPaperStage.scrollIntoView({ block: "start", behavior: "smooth" });
  void els.letterPaperStage.offsetWidth;
  els.letterPaperStage.classList.add("is-sealing");
  els.sealAnimation.classList.add("is-running");

  const statuses = [
    [900, "Plegando la hoja..."],
    [1600, "Cerrando el sobre..."],
    [2300, "Presionando el sello de cera..."],
    [3150, "Rumbo al buzon..."],
    [4050, "Carta despachada."]
  ];
  sealAnimationStatusTimers = statuses.map(([delay, message]) =>
    setTimeout(() => {
      els.sealAnimationStatus.textContent = message;
    }, delay)
  );

  return new Promise((resolve) => {
    sealAnimationResolve = resolve;
    sealAnimationTimer = setTimeout(finishSealAnimation, 4500);
  });
}

function finishSealAnimation() {
  if (sealAnimationTimer !== null) {
    clearTimeout(sealAnimationTimer);
    sealAnimationTimer = null;
  }
  sealAnimationStatusTimers.forEach((timer) => clearTimeout(timer));
  sealAnimationStatusTimers = [];
  els.sealAnimation.classList.remove("is-running");
  els.sealAnimation.hidden = true;
  els.letterPaperStage.classList.remove("is-sealing");
  completeLetterDispatch();
  const resolve = sealAnimationResolve;
  sealAnimationResolve = null;
  if (resolve) resolve();
}

function completeLetterDispatch() {
  els.letterPaperStage.hidden = true;
  els.letterActions.hidden = true;
  els.sealedOutput.hidden = false;
}

function writeAnotherLetter() {
  if (sealingLetter) return;
  els.sealedOutput.hidden = true;
  els.sealedCode.value = "";
  els.letterPaperStage.hidden = false;
  els.letterActions.hidden = false;
  state.lastCreatedCode = "";
  els.letterForm.reset();
  setRuntime("Hoja nueva lista.");
  requestAnimationFrame(() => {
    els.letterPaperStage.scrollIntoView({ block: "start", behavior: "smooth" });
    els.letterTitle.focus({ preventScroll: true });
  });
}

async function sealLetter(event) {
  event.preventDefault();
  if (sealingLetter) return;
  if (!state.vault.enabled) {
    showToast("Protege primero tus llaves en Seguridad.");
    setActiveSection("security");
    return;
  }
  if (!state.activeIdentity) {
    showToast("Primero crea una identidad local.");
    return;
  }

  const recipient = state.contacts.find((contact) => contact.fingerprint === els.letterRecipient.value);
  if (!recipient) {
    showToast("Importa o elige una llave de destino.");
    return;
  }

  const draft = getLetterDraft(recipient);
  if (!draft.body.trim()) {
    els.letterBody.focus();
    showToast("Una carta vacia no tiene sobre, mi king.");
    return;
  }
  const estimatedPayloadBytes = encoder.encode(
    JSON.stringify({
      ...draft,
      senderName: state.activeIdentity.name,
      recipientName: recipient.publicIdentity.name
    })
  ).byteLength;
  if (estimatedPayloadBytes > MAX_LETTER_BYTES) {
    showToast(`La carta supera ${formatBytes(MAX_LETTER_BYTES)}. Recortala un poco para entregarla con seguridad.`);
    return;
  }

  setRuntime("Sellando carta...");
  const sealButton = els.letterForm.querySelector('button[type="submit"]');
  sealingLetter = true;
  if (sealButton) sealButton.disabled = true;
  try {
    const node = await createSealedNode({
      recipient,
      ...draft
    });

    if (!state.onion.torReady) {
      await checkOnionNode();
    }
    if (!state.onion.torReady) {
      throw new Error(state.onion.message || "Tor aun no esta listo.");
    }

    node.onionAddress = state.onion.address;
    const code = formatLetterCode(node);
    await publishNodeToOnion(node);
    await rememberOutboxNode(node);
    state.lastCreatedCode = code;
    await refreshState();
    renderAll();

    els.sealedCode.value = code;
    await playSealAnimation(recipient.publicIdentity.name);
    setRuntime("Carta sellada en tu nodo Onion.");
    showToast("Carta sellada. Tu daemon custodia un sobre doblemente cifrado.");
  } catch (error) {
    if (!els.sealAnimation.hidden) finishSealAnimation();
    setRuntime("No se pudo sellar la carta.");
    showToast(error.message || "No se pudo dejar la carta disponible.");
  } finally {
    sealingLetter = false;
    if (sealButton) sealButton.disabled = false;
  }
}

async function createSealedNode({
  recipient,
  title,
  mood,
  body,
  dateline = "",
  salutation = "",
  closing = "",
  signoff = ""
}) {
  const nodeId = crypto.randomUUID();
  const codeSecret = createCodeSecret();
  const codeHash = await hashCodeSecret(nodeId, codeSecret);
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + NODE_TTL_DAYS * 24 * 60 * 60 * 1000).toISOString();
  const sender = state.activeIdentity;
  const payload = {
    title,
    body,
    mood,
    createdAt,
    senderName: sender.name,
    recipientName: recipient.publicIdentity.name,
    dateline: dateline || formatFormalDateline(new Date(createdAt)),
    salutation: salutation || `A la atencion de ${recipient.publicIdentity.name}:`,
    closing: closing || "Con afecto,",
    signoff: signoff || sender.name
  };
  if (encoder.encode(JSON.stringify(payload)).byteLength > MAX_LETTER_BYTES) {
    throw new Error(`La carta supera el limite seguro de ${formatBytes(MAX_LETTER_BYTES)}.`);
  }

  const recipientPublicKey = await crypto.subtle.importKey(
    "jwk",
    recipient.publicIdentity.encryptionPublicJwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
  const ephemeralPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: recipientPublicKey },
    ephemeralPair.privateKey,
    256
  );
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await deriveAesKey(sharedBits, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    encoder.encode(JSON.stringify(payload))
  );

  const node = {
    nodeId,
    version: 1,
    status: "available",
    codeSecret,
    codeHash,
    onionAddress: state.onion.address,
    createdAt,
    expiresAt,
    readCount: 0,
    recipientKeyHash: recipient.fingerprint,
    senderKeyHash: sender.fingerprint,
    localMeta: {
      title,
      recipientName: recipient.publicIdentity.name,
      mood,
      sentAt: createdAt
    },
    envelope: {
      cryptoSuite: CRYPTO_SUITE,
      ephemeralPublicJwk: compactPublicJwk(await crypto.subtle.exportKey("jwk", ephemeralPair.publicKey)),
      salt: bytesToBase64url(salt),
      iv: bytesToBase64url(iv),
      ciphertext: bytesToBase64url(ciphertext),
      signatureSuite: SIGNATURE_SUITE,
      senderPublicIdentity: sender.publicIdentity
    }
  };

  const signingPrivateKey = await crypto.subtle.importKey(
    "jwk",
    sender.signingPrivateJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    signingPrivateKey,
    encoder.encode(signatureMaterial(node))
  );
  node.envelope.signature = bytesToBase64url(signature);
  if (envelopeByteLength(node.envelope) > MAX_ENVELOPE_BYTES) {
    throw new Error("El sobre cifrado quedo demasiado grande para el canal seguro.");
  }
  return node;
}

function createCodeSecret() {
  const random = new Uint8Array(32);
  crypto.getRandomValues(random);
  return bytesToBase64url(random);
}

async function openCode(rawCode) {
  const parsedCode = parseLetterCode(rawCode);
  if (!parsedCode) {
    setOpenStatus("warn", "Codigo invalido. Debe comenzar con TROSTE-ONION1: y contener direccion, id y secreto.");
    return;
  }
  if (!state.vault.enabled) {
    setOpenStatus("warn", "Protege primero tus llaves en Seguridad antes de abrir cartas.");
    setActiveSection("security");
    return;
  }

  els.openCode.value = formatLetterCode(parsedCode);
  if (!state.onion.available) {
    await checkOnionNode();
  }
  if (!state.onion.available) {
    setOpenStatus("bad", state.onion.message || "El daemon local no esta disponible.");
    return;
  }

  if (!state.activeIdentity) {
    setOpenStatus("warn", "Crea o activa una identidad local antes de abrir cartas.");
    return;
  }

  setOpenStatus("warn", "Trazando una ruta privada por Tor...");
  let sealedNode;
  try {
    if (!consumeResolveBudget()) {
      setOpenStatus("bad", "Demasiados intentos seguidos. Espera un minuto antes de buscar otra carta.");
      return;
    }
    const response = await fetchNodeFromOnion(parsedCode);
    sealedNode = await decryptRouteNode(response.payload, parsedCode.nodeId, parsedCode.codeSecret);
  } catch (error) {
    console.error(error);
    setOpenStatus("bad", onionResolveError(error));
    hideOpenedLetter();
    return;
  }

  if (sealedNode.recipientKeyHash !== state.activeIdentity.fingerprint) {
    setOpenStatus("bad", "No eres destinatario de esta carta.");
    hideOpenedLetter();
    return;
  }

  try {
    const letter = await decryptNode(sealedNode, state.activeIdentity);
    const signatureState = await verifyNodeSignature(sealedNode);
    if (!signatureState.valid) {
      setOpenStatus("bad", "Sobre alterado: la firma no coincide.");
      hideOpenedLetter();
      return;
    }

    await refreshState();
    renderAll();

    const statusClass = signatureState.known ? "good" : "warn";
    const statusText = signatureState.known
      ? "Abierta. Firma valida."
      : "Abierta. Firma valida, remitente no importado.";
    setOpenStatus(statusClass, statusText);
    renderOpenedLetter(letter, sealedNode, signatureState);
  } catch (error) {
    console.error(error);
    setOpenStatus("bad", "Sobre alterado o llave incompatible. No se pudo descifrar.");
    hideOpenedLetter();
  }
}

function onionResolveError(error) {
  if (error?.code === "TOR_NOT_READY") return "Tor aun no esta listo en este equipo.";
  if (error?.code === "ONION_UNREACHABLE") return "El buzon Onion no respondio. Puede estar apagado o Tor puede seguir construyendo la ruta.";
  if (error?.code === "LETTER_NOT_FOUND") return "Carta no encontrada, vencida o codigo secreto incorrecto.";
  if (error?.code === "RATE_LIMITED") return "El buzon freno los intentos. Espera un momento y vuelve a probar.";
  return error?.message || "No se pudo llegar al buzon Onion.";
}

async function encryptRouteNode(node, codeSecret) {
  const routeNode = {
    nodeId: node.nodeId,
    version: node.version,
    status: "available",
    createdAt: node.createdAt,
    expiresAt: node.expiresAt,
    recipientKeyHash: node.recipientKeyHash,
    senderKeyHash: node.senderKeyHash,
    envelope: node.envelope
  };
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveRouteKey(codeSecret, node.nodeId, salt);
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: routeAdditionalData(node.nodeId),
      tagLength: 128
    },
    key,
    encoder.encode(JSON.stringify(routeNode))
  );
  const payload = {
    version: 1,
    cryptoSuite: ROUTE_CRYPTO_SUITE,
    salt: bytesToBase64url(salt),
    iv: bytesToBase64url(iv),
    ciphertext: bytesToBase64url(ciphertext)
  };
  if (encoder.encode(JSON.stringify(payload)).byteLength > MAX_ROUTE_PAYLOAD_BYTES) {
    throw new Error("El paquete Onion supera el limite seguro del nodo.");
  }
  return payload;
}

async function decryptRouteNode(payload, nodeId, codeSecret) {
  if (!isRoutePayload(payload)) {
    throw new Error("El buzon devolvio un paquete Onion invalido.");
  }
  const salt = base64urlToBytes(payload.salt);
  const iv = base64urlToBytes(payload.iv);
  const key = await deriveRouteKey(codeSecret, nodeId, salt);
  const clear = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: routeAdditionalData(nodeId),
      tagLength: 128
    },
    key,
    base64urlToBytes(payload.ciphertext)
  );
  const node = JSON.parse(decoder.decode(clear));
  if (
    node?.nodeId !== nodeId ||
    node.version !== 1 ||
    node.status !== "available" ||
    !isPublicFingerprint(node.recipientKeyHash) ||
    !isPublicFingerprint(node.senderKeyHash) ||
    !isEnvelopeShape(node.envelope) ||
    !Number.isFinite(Date.parse(node.createdAt)) ||
    !Number.isFinite(Date.parse(node.expiresAt))
  ) {
    throw new Error("El contenido del paquete Onion no tiene un formato valido.");
  }
  if (Date.parse(node.expiresAt) <= Date.now()) {
    throw new Error("Esta carta vencio y ya no debe entregarse.");
  }
  return node;
}

async function deriveRouteKey(codeSecret, nodeId, salt) {
  if (!isSafeBase64url(codeSecret, 43, 43)) {
    throw new Error("El secreto de ruta no tiene un formato valido.");
  }
  const source = await crypto.subtle.importKey(
    "raw",
    base64urlToBytes(codeSecret),
    "HKDF",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: encoder.encode(`troste-onion-route-key-v1:${nodeId}`)
    },
    source,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function routeAdditionalData(nodeId) {
  return encoder.encode(`troste-onion-route-envelope-v1:${nodeId}`);
}

function isRoutePayload(payload) {
  if (!payload || payload.version !== 1 || payload.cryptoSuite !== ROUTE_CRYPTO_SUITE) return false;
  if (!isSafeBase64url(payload.salt, 22, 22) || !isSafeBase64url(payload.iv, 16, 16)) return false;
  if (!isSafeBase64url(payload.ciphertext, 24, Math.ceil(MAX_ROUTE_PAYLOAD_BYTES * 4 / 3))) return false;
  return encoder.encode(JSON.stringify(payload)).byteLength <= MAX_ROUTE_PAYLOAD_BYTES;
}

function isEnvelopeShape(envelope) {
  return Boolean(
    envelope &&
      envelope.cryptoSuite === CRYPTO_SUITE &&
      envelope.signatureSuite === SIGNATURE_SUITE &&
      envelope.ephemeralPublicJwk &&
      envelope.salt &&
      envelope.iv &&
      envelope.ciphertext &&
      envelope.signature &&
      envelope.senderPublicIdentity &&
      isSafeBase64url(envelope.salt, 16, 64) &&
      isSafeBase64url(envelope.iv, 12, 32) &&
      isSafeBase64url(envelope.ciphertext, 17, MAX_ENVELOPE_BYTES) &&
      isSafeBase64url(envelope.signature, 48, 160)
  );
}

async function decryptNode(node, identity) {
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    identity.encryptionPrivateJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"]
  );
  const ephemeralPublicKey = await crypto.subtle.importKey(
    "jwk",
    node.envelope.ephemeralPublicJwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: ephemeralPublicKey },
    privateKey,
    256
  );
  const aesKey = await deriveAesKey(sharedBits, base64urlToBytes(node.envelope.salt));
  const clear = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64urlToBytes(node.envelope.iv) },
    aesKey,
    base64urlToBytes(node.envelope.ciphertext)
  );
  return JSON.parse(decoder.decode(clear));
}

async function verifyNodeSignature(node) {
  const senderIdentity = await normalizePublicIdentityObject(node.envelope.senderPublicIdentity);
  const senderFingerprint = await fingerprintPublicIdentity(senderIdentity);
  if (senderFingerprint !== node.senderKeyHash) {
    return { valid: false, known: false, senderFingerprint };
  }

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    senderIdentity.signingPublicJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    base64urlToBytes(node.envelope.signature),
    encoder.encode(signatureMaterial(node))
  );
  return {
    valid,
    known: state.contacts.some((contact) => contact.fingerprint === senderFingerprint),
    senderFingerprint,
    senderName: senderIdentity.name
  };
}

function signatureMaterial(node) {
  const envelope = { ...node.envelope };
  delete envelope.signature;
  return stableStringify({
    nodeId: node.nodeId,
    version: node.version,
    recipientKeyHash: node.recipientKeyHash,
    senderKeyHash: node.senderKeyHash,
    envelope
  });
}

async function deriveAesKey(sharedBits, salt) {
  const hkdfKey = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: encoder.encode("troste-letter-v1")
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function normalizeAndValidatePublicIdentity(text) {
  if (encoder.encode(String(text || "")).byteLength > MAX_PUBLIC_IDENTITY_BYTES) {
    throw new Error("Ese sello publico es demasiado grande.");
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("Ese texto no es JSON valido.");
  }
  return normalizePublicIdentityObject(parsed);
}

async function normalizePublicIdentityObject(value) {
  if (!value || value.type !== PUBLIC_IDENTITY_TYPE || value.version !== 1) {
    throw new Error("No es una identidad publica Troste v1.");
  }

  const normalized = {
    type: PUBLIC_IDENTITY_TYPE,
    version: 1,
    name: String(value.name || "sin nombre").slice(0, 80),
    encryptionPublicJwk: compactPublicJwk(value.encryptionPublicJwk),
    signingPublicJwk: compactPublicJwk(value.signingPublicJwk)
  };
  if (encoder.encode(JSON.stringify(normalized)).byteLength > MAX_PUBLIC_IDENTITY_BYTES) {
    throw new Error("Ese sello publico es demasiado grande.");
  }

  await crypto.subtle.importKey(
    "jwk",
    normalized.encryptionPublicJwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
  await crypto.subtle.importKey(
    "jwk",
    normalized.signingPublicJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );

  normalized.fingerprint = await fingerprintPublicIdentity(normalized);
  if (value.fingerprint && value.fingerprint !== normalized.fingerprint) {
    throw new Error("La huella de esa identidad no coincide.");
  }
  return normalized;
}

function compactPublicJwk(jwk) {
  if (
    !jwk ||
    jwk.kty !== "EC" ||
    jwk.crv !== "P-256" ||
    !isSafeBase64url(jwk.x, 43, 43) ||
    !isSafeBase64url(jwk.y, 43, 43)
  ) {
    throw new Error("La llave publica debe ser EC P-256.");
  }
  return {
    kty: "EC",
    crv: "P-256",
    x: jwk.x,
    y: jwk.y
  };
}

async function fingerprintPublicIdentity(identity) {
  const material = {
    type: PUBLIC_IDENTITY_TYPE,
    version: 1,
    encryptionPublicJwk: compactPublicJwk(identity.encryptionPublicJwk),
    signingPublicJwk: compactPublicJwk(identity.signingPublicJwk)
  };
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(stableStringify(material)));
  return bytesToBase64url(digest);
}

async function hashCodeSecret(nodeId, codeSecret) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(`troste-onion-secret-v1:${nodeId}:${codeSecret}`)
  );
  return bytesToHex(digest);
}

function renderAll() {
  renderBackendStatus();
  renderIdentities();
  renderContacts();
  renderRecipientOptions();
  syncFormalLetterContext();
  renderNodes();
  renderSecurity();
  updateLetterMeter();
}

function renderBackendStatus() {
  els.backendStatus.textContent = state.onion.torReady
    ? "Nodo Onion: listo"
    : state.onion.available
      ? "Nodo Onion: iniciando"
      : "Nodo Onion: pendiente";
  els.backendStatus.classList.toggle("online", state.onion.torReady);
  els.backendStatus.classList.toggle("offline", !state.onion.torReady);
  els.nodeSource.textContent = state.onion.available
    ? `El daemon local custodia ${state.onion.nodeCount} ${state.onion.nodeCount === 1 ? "sobre" : "sobres"} doblemente cifrados; el historial sigue dentro de tu vault.`
    : `${state.onion.message} El historial permanece en tu caja local.`;
  els.onionAddress.textContent = state.onion.address || "pendiente";
  els.onionNodeDetail.textContent = state.onion.torReady
    ? "Ruta publicada. Cambiar de red o IP no cambia esta direccion."
    : state.onion.message;
}

function renderIdentities() {
  els.identityCount.textContent = state.identities.length;
  els.copyPublic.disabled = !state.activeIdentity;
  els.downloadBackup.disabled = !state.activeIdentity || !state.vault.enabled || state.vault.locked;
  els.identityPassphraseField.hidden = state.vault.enabled;
  els.identityName.disabled = state.vault.locked;
  const createButton = els.identityForm.querySelector('button[type="submit"]');
  if (createButton) createButton.disabled = state.vault.locked;

  if (!state.identities.length) {
    els.identityList.innerHTML = state.vault.locked
      ? '<div class="empty">Tu caja esta cerrada. Desbloqueala en Seguridad para ver tus identidades.</div>'
      : '<div class="empty">Crea tu primera identidad para abrir y sellar cartas.</div>';
    els.publicIdentity.value = "";
    return;
  }

  els.identityList.innerHTML = state.identities
    .map((identity) => {
      const active = identity.fingerprint === state.activeIdentity?.fingerprint;
      return `
        <article class="stack-card ${active ? "active" : ""}">
          <div class="card-row">
            <div>
              <h3>${escapeHtml(identity.name)} ${active ? '<span class="meta-chip">activa</span>' : ""}</h3>
              <p class="fingerprint">${shortFingerprint(identity.fingerprint)}</p>
            </div>
            <div class="card-actions">
              <button type="button" data-action="activate" data-fingerprint="${identity.fingerprint}" ${active ? "disabled" : ""}>Activar</button>
              <button type="button" data-action="copy" data-fingerprint="${identity.fingerprint}">Copiar</button>
            </div>
          </div>
        </article>
      `;
    })
    .join("");

  els.publicIdentity.value = JSON.stringify(state.activeIdentity.publicIdentity, null, 2);
}

function renderContacts() {
  els.contactCount.textContent = state.contacts.length;
  if (!state.contacts.length) {
    els.contactList.innerHTML = '<div class="empty">Importa una identidad publica o crea una identidad local.</div>';
    return;
  }

  els.contactList.innerHTML = state.contacts
    .map((contact) => `
      <article class="stack-card">
        <div class="card-row">
          <div>
            <h3>${escapeHtml(contact.publicIdentity.name)} ${contact.self ? '<span class="meta-chip">yo</span>' : ""}</h3>
            <p class="fingerprint">${shortFingerprint(contact.fingerprint)}</p>
          </div>
          <div class="card-actions">
            <button type="button" data-action="copy" data-fingerprint="${contact.fingerprint}">Copiar</button>
            <button type="button" data-action="remove" data-fingerprint="${contact.fingerprint}">Quitar</button>
          </div>
        </div>
      </article>
    `)
    .join("");
}

function renderRecipientOptions() {
  const selectedRecipient = els.letterRecipient.value;
  if (!state.contacts.length) {
    els.letterRecipient.innerHTML = '<option value="">sin contactos</option>';
    els.letterRecipient.disabled = true;
    return;
  }
  els.letterRecipient.disabled = false;
  els.letterRecipient.innerHTML = state.contacts
    .map(
      (contact) =>
        `<option value="${contact.fingerprint}">${escapeHtml(contact.publicIdentity.name)} - ${shortFingerprint(contact.fingerprint)}</option>`
    )
    .join("");
  if (state.contacts.some((contact) => contact.fingerprint === selectedRecipient)) {
    els.letterRecipient.value = selectedRecipient;
  }
}

function renderNodes() {
  els.nodeCount.textContent = state.nodes.length;
  if (!state.nodes.length) {
    els.nodeList.innerHTML = '<div class="empty">Aun no has despachado cartas desde esta caja.</div>';
    return;
  }

  els.nodeList.innerHTML = state.nodes
    .map((node) => {
      const code = formatLetterCode(node);
      const expired = Date.parse(node.expiresAt) <= Date.now();
      const revoked = node.status === "revoked";
      const available = !expired && !revoked;
      const status = revoked ? "revoked" : expired ? "expired" : "available";
      const statusText = revoked
        ? "Direccion revocada"
        : expired
          ? "Direccion vencida"
          : state.onion.torReady && node.onionAddress === state.onion.address
            ? "Disponible en tu buzon Onion"
            : "Guardada; el daemon debe estar encendido para entregarla";
      const title = node.localMeta?.title || "Carta sellada";
      const recipientName = node.localMeta?.recipientName || shortFingerprint(node.recipientKeyHash);
      const mood = node.localMeta?.mood || "sello privado";
      return `
        <article class="stack-card history-card ${status}">
          <div class="card-row">
            <div>
              <h3>${escapeHtml(title)}</h3>
              <p class="history-route">Para ${escapeHtml(recipientName)} &middot; ${escapeHtml(mood)}</p>
              <p>Enviada ${formatDate(node.localMeta?.sentAt || node.createdAt)} &middot; vence ${formatDate(node.expiresAt)}</p>
              <p class="history-status">${statusText}</p>
            </div>
            <div class="card-actions">
              ${available ? `<button type="button" data-action="copy" data-code="${escapeHtml(code)}">Copiar codigo</button>` : ""}
              ${available ? `<button type="button" data-action="revoke" data-node-id="${node.nodeId}">Revocar</button>` : ""}
              ${available ? "" : `<button type="button" data-action="forget" data-node-id="${node.nodeId}">Eliminar del historial</button>`}
            </div>
          </div>
        </article>
      `;
    })
    .join("");
}

function renderSecurity() {
  const vaultReady = state.vault.enabled && !state.vault.locked;
  els.vaultStatus.textContent = state.vault.message;
  els.vaultStatus.className = `open-status ${vaultReady ? "good" : state.vault.enabled ? "warn" : "warn"}`;
  els.vaultEnable.disabled = state.vault.enabled || state.vault.locked;
  els.vaultUnlock.disabled = !state.vault.enabled || !state.vault.locked;
  els.vaultLock.disabled = !vaultReady;

  const checks = [
    ["Sin directorio central", "El codigo lleva una direccion Onion v3 autocertificada; no existe una tabla global que enumerar."],
    ["Doble sobre", "La carta se cifra para el destinatario y el paquete almacenado vuelve a cifrarse con el secreto del codigo."],
    ["Secreto ausente", "El daemon guarda un hash del secreto, nunca el secreto que abre la capa de ruta."],
    ["Firma del remitente", "ECDSA permite detectar una carta alterada y reconocer un contacto conocido."],
    [vaultReady ? "Vault desbloqueado" : state.vault.enabled ? "Vault bloqueado" : "Vault pendiente", state.vault.message],
    ["Superficie local", "El panel escucha solo en loopback y el puerto Onion expone un protocolo minimo, sin listado ni escritura remota."],
    ["Caducidad", "El daemon elimina sobres vencidos automaticamente despues de 90 dias."],
    ["Ruta privada", "Tor oculta la IP del buzon y cifra de extremo a extremo la conexion con el Onion Service."]
  ];

  els.securityChecklist.innerHTML = checks
    .map(
      ([title, text]) => `
        <article class="stack-card">
          <h3>${escapeHtml(title)}</h3>
          <p>${escapeHtml(text)}</p>
        </article>
      `
    )
    .join("");
}

function renderOpenedLetter(letter, node, signatureState) {
  els.openedLetter.hidden = false;
  const senderName = letter.signoff || signatureState.senderName || "Remitente desconocido";
  const recipientName = letter.recipientName || state.activeIdentity?.name || "Destinatario";
  els.openedLetter.innerHTML = `
    <header class="opened-letterhead">
      <div>
        <p>Troste</p>
        <h3>Correspondencia privada</h3>
      </div>
      <span>${escapeHtml(letter.mood || "sin sello")}</span>
    </header>
    <div class="opened-routing">
      <div><span>Remitente</span><strong>${escapeHtml(senderName)}</strong></div>
      <div><span>Destinatario</span><strong>${escapeHtml(recipientName)}</strong></div>
      <p>${escapeHtml(letter.dateline || formatDate(letter.createdAt || node.createdAt))}</p>
    </div>
    <p class="opened-subject"><span>Asunto</span>${escapeHtml(letter.title || "Carta sin titulo")}</p>
    <p class="opened-salutation">${escapeHtml(letter.salutation || `A la atencion de ${recipientName}:`)}</p>
    <div class="letter-body">${escapeHtml(letter.body || "")}</div>
    <div class="opened-closing">
      <p>${escapeHtml(letter.closing || "Con afecto,")}</p>
      <strong>${escapeHtml(senderName)}</strong>
    </div>
    <footer class="opened-proof">
      <span>${signatureState.known ? "Firma valida" : "Firma desconocida"}</span>
      <code>${shortFingerprint(signatureState.senderFingerprint)}</code>
    </footer>
  `;
}

function hideOpenedLetter() {
  els.openedLetter.hidden = true;
  els.openedLetter.innerHTML = "";
}

function setOpenStatus(kind, message) {
  els.openStatus.className = `open-status ${kind}`;
  els.openStatus.textContent = message;
  els.readBadge.textContent = kind === "good" ? "abierta" : kind === "bad" ? "bloqueada" : "revision";
}

function setRuntime(message) {
  els.runtimeStatus.textContent = message;
}

function updateLetterMeter() {
  const words = countWords(els.letterBody.value);
  const bytes = encoder.encode(
    JSON.stringify({
      title: els.letterTitle.value,
      body: els.letterBody.value,
      mood: els.letterMood.value,
      dateline: els.letterDateline.value,
      salutation: els.letterSalutation.value,
      closing: els.letterClosing.value,
      signoff: els.letterSignature.value
    })
  ).byteLength;
  els.letterMeter.textContent = `${words} ${words === 1 ? "palabra" : "palabras"} · ${formatBytes(bytes)}`;
  els.letterMeter.classList.toggle("limit-near", bytes > MAX_LETTER_BYTES * 0.85);
}

async function handleNodeAction(event) {
  const button = event.target.closest("button");
  if (!button) return;
  const code = button.dataset.code;
  if (button.dataset.action === "copy") {
    copyText(code);
    showToast("Codigo copiado.");
  }
  if (button.dataset.action === "revoke") {
    await revokeOutboxNode(button.dataset.nodeId);
  }
  if (button.dataset.action === "forget") {
    await forgetHistoryNode(button.dataset.nodeId);
  }
}

async function revokeOutboxNode(nodeId) {
  const node = state.nodes.find((item) => item.nodeId === nodeId);
  if (!node) return;
  if (!window.confirm("Esta direccion dejara de entregar la carta. La constancia permanecera en tu historial local.")) return;

  try {
    await localApi(`/api/nodes/${encodeURIComponent(node.nodeId)}`, {
      method: "DELETE",
      body: { secret: node.codeSecret }
    });
    state.nodes = state.nodes.map((item) =>
      item.nodeId === node.nodeId
        ? { ...item, status: "revoked", revokedAt: new Date().toISOString() }
        : item
    );
    await saveOutbox();
    renderAll();
    showToast("Direccion revocada. La constancia quedo en tu historial.");
  } catch (error) {
    showToast(error.message || "No se pudo revocar la direccion.");
  }
}

async function forgetHistoryNode(nodeId) {
  const node = state.nodes.find((item) => item.nodeId === nodeId);
  if (!node) return;
  const inactive = node.status === "revoked" || Date.parse(node.expiresAt) <= Date.now();
  if (!inactive) return;
  state.nodes = state.nodes.filter((item) => item.nodeId !== nodeId);
  await saveOutbox();
  renderAll();
  showToast("Constancia eliminada del historial local.");
}

async function copyActivePublicIdentity() {
  if (!state.activeIdentity) return;
  await copyText(JSON.stringify(state.activeIdentity.publicIdentity, null, 2));
  showToast("Identidad publica copiada.");
}

async function downloadActiveBackup() {
  if (!state.activeIdentity || !state.vault.enabled || !vaultKey || !vaultRecord) {
    showToast("Desbloquea y protege tu caja antes de guardar una copia.");
    return;
  }

  try {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const payload = {
      keyring: { identities: state.identities, contacts: state.contacts },
      outbox: { version: 1, nodes: state.nodes },
      exportedAt: new Date().toISOString()
    };
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      vaultKey,
      encoder.encode(JSON.stringify(payload))
    );
    const backup = {
      type: "troste-encrypted-backup",
      version: 1,
      kdf: "PBKDF2-SHA256",
      iterations: vaultRecord.iterations || VAULT_KDF_ITERATIONS,
      salt: vaultRecord.salt,
      iv: bytesToBase64url(iv),
      ciphertext: bytesToBase64url(ciphertext)
    };
    downloadJson(
      backup,
      `troste-copia-cifrada-${shortFingerprint(state.activeIdentity.fingerprint)}.json`
    );
    showToast("Copia cifrada guardada. Se abre solo con tu frase local.");
  } catch (error) {
    showToast(error.message || "No se pudo guardar la copia cifrada.");
  }
}

function downloadJson(value, fileName) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = fileName;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 500);
}

async function restoreEncryptedBackup(event) {
  const file = event.target.files?.[0];
  event.target.value = "";
  if (!file) return;
  const phrase = els.vaultPin.value.trim();
  if (phrase.length < MIN_VAULT_PHRASE_LENGTH) {
    showToast("Escribe primero la frase de esa copia en Seguridad.");
    return;
  }
  if (file.size > 10 * 1024 * 1024) {
    showToast("Esa copia es demasiado grande para Troste Onion.");
    return;
  }
  if ((state.identities.length || state.nodes.length) && !window.confirm("La copia reemplazara tu caja local actual.")) {
    return;
  }

  try {
    const backup = JSON.parse(await file.text());
    if (
      backup?.type !== "troste-encrypted-backup" ||
      backup.version !== 1 ||
      backup.kdf !== "PBKDF2-SHA256" ||
      !Number.isInteger(backup.iterations) ||
      backup.iterations < 100000 ||
      backup.iterations > 2000000 ||
      !isSafeBase64url(backup.salt, 22, 64) ||
      !isSafeBase64url(backup.iv, 16, 32) ||
      !isSafeBase64url(backup.ciphertext, 20, 14 * 1024 * 1024)
    ) {
      throw new Error("La copia cifrada no tiene un formato valido.");
    }

    const key = await deriveVaultKey(phrase, base64urlToBytes(backup.salt), backup.iterations);
    const clear = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64urlToBytes(backup.iv) },
      key,
      base64urlToBytes(backup.ciphertext)
    );
    const payload = JSON.parse(decoder.decode(clear));
    const restoredKeyring = await validateRestoredKeyring(payload.keyring);
    const restoredNodes = normalizeOutboxNodes(payload.outbox?.nodes).slice(0, 80);

    vaultKey = key;
    vaultRecord = {
      type: "troste-keyring-vault",
      version: 1,
      kdf: "PBKDF2-SHA256",
      iterations: backup.iterations,
      salt: backup.salt
    };
    unlockedKeyring = restoredKeyring;
    state.identities = restoredKeyring.identities;
    state.contacts = restoredKeyring.contacts;
    state.nodes = restoredNodes;
    state.vault = { enabled: true, locked: false, message: "Caja restaurada y desbloqueada en esta sesion." };
    await saveKeyring();
    await saveOutbox();
    localStorage.removeItem(LOCAL_KEYRING_KEY);
    await refreshState();
    els.vaultPin.value = "";
    renderAll();
    showToast("Copia restaurada. Tu caja vuelve a estar viva.");
  } catch (error) {
    console.warn(error);
    showToast("Frase incorrecta o copia cifrada danada.");
  }
}

async function validateRestoredKeyring(value) {
  const source = normalizeKeyring(value);
  if (source.identities.length > 20 || source.contacts.length > 200) {
    throw new Error("La copia excede los limites de identidades o contactos.");
  }

  const identities = [];
  for (const record of source.identities) {
    const publicIdentity = await normalizePublicIdentityObject(record.publicIdentity);
    if (
      record.fingerprint !== publicIdentity.fingerprint ||
      record.encryptionPrivateJwk?.x !== publicIdentity.encryptionPublicJwk.x ||
      record.encryptionPrivateJwk?.y !== publicIdentity.encryptionPublicJwk.y ||
      record.signingPrivateJwk?.x !== publicIdentity.signingPublicJwk.x ||
      record.signingPrivateJwk?.y !== publicIdentity.signingPublicJwk.y
    ) {
      throw new Error("Una identidad privada no coincide con su sello publico.");
    }
    await crypto.subtle.importKey(
      "jwk",
      record.encryptionPrivateJwk,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"]
    );
    await crypto.subtle.importKey(
      "jwk",
      record.signingPrivateJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );
    identities.push({
      fingerprint: publicIdentity.fingerprint,
      name: publicIdentity.name,
      active: Boolean(record.active),
      createdAt: typeof record.createdAt === "string" ? record.createdAt : new Date().toISOString(),
      publicIdentity,
      encryptionPrivateJwk: record.encryptionPrivateJwk,
      signingPrivateJwk: record.signingPrivateJwk
    });
  }

  const contacts = [];
  for (const record of source.contacts) {
    const publicIdentity = await normalizePublicIdentityObject(record.publicIdentity);
    contacts.push({
      fingerprint: publicIdentity.fingerprint,
      publicIdentity,
      importedAt: typeof record.importedAt === "string" ? record.importedAt : new Date().toISOString(),
      self: identities.some((identity) => identity.fingerprint === publicIdentity.fingerprint)
    });
  }
  return { identities, contacts };
}

function formatLetterCode(value) {
  const onionAddress = String(value?.onionAddress || "").toLowerCase();
  const onionLabel = onionAddress.endsWith(".onion") ? onionAddress.slice(0, -6) : onionAddress;
  const nodeId = value?.nodeId || "";
  const codeSecret = value?.codeSecret || "";
  return `${LETTER_CODE_PREFIX}${onionLabel}:${nodeId}:${codeSecret}`;
}

function parseLetterCode(rawCode) {
  const clean = String(rawCode || "").trim();
  if (!clean) return null;
  const urlCode = parseCodeFromUrl(clean);
  if (urlCode) return parseLetterCode(urlCode);
  if (clean.startsWith(LETTER_CODE_PREFIX)) {
    const rest = clean.slice(LETTER_CODE_PREFIX.length);
    const [onionLabel, nodeId, codeSecret, extra] = rest.split(":");
    const onionAddress = `${String(onionLabel || "").toLowerCase().replace(/\.onion$/, "")}.onion`;
    if (!extra && isOnionAddress(onionAddress) && isUuid(nodeId) && isSafeBase64url(codeSecret, 43, 43)) {
      const code = { onionAddress, nodeId, codeSecret };
      return { ...code, code: formatLetterCode(code) };
    }
    return null;
  }
  return null;
}

function isOnionAddress(value) {
  return /^[a-z2-7]{56}\.onion$/.test(String(value || "").toLowerCase());
}

function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value || "");
}

function isSha256Hex(value) {
  return /^[a-f0-9]{64}$/.test(value || "");
}

function isPublicFingerprint(value) {
  return isSafeBase64url(value, 43, 43);
}

function isSafeBase64url(value, minLength, maxLength) {
  return (
    typeof value === "string" &&
    value.length >= minLength &&
    value.length <= maxLength &&
    /^[A-Za-z0-9_-]+$/.test(value)
  );
}

function envelopeByteLength(envelope) {
  try {
    return encoder.encode(JSON.stringify(envelope)).byteLength;
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

function parseCodeFromUrl(value) {
  try {
    const url = new URL(value, location.href);
    const queryCode = url.searchParams.get("code");
    if (queryCode) return queryCode;
    if (url.hash.startsWith("#code=")) {
      return decodeURIComponent(url.hash.slice(6));
    }
  } catch {
    return "";
  }
  return "";
}

function getInitialCodeFromUrl() {
  const queryCode = new URLSearchParams(location.search).get("code");
  if (queryCode) {
    const cleanUrl = new URL(location.href);
    cleanUrl.searchParams.delete("code");
    cleanUrl.hash = `code=${encodeURIComponent(queryCode)}`;
    history.replaceState(null, "", `${cleanUrl.pathname}${cleanUrl.search}${cleanUrl.hash}`);
    return queryCode;
  }
  if (location.hash.startsWith("#code=")) {
    return decodeURIComponent(location.hash.slice(6));
  }
  return "";
}

function buildShareTarget(code) {
  return code;
}

function consumeResolveBudget() {
  const now = Date.now();
  const windowMs = 60000;
  const maxAttempts = 8;
  try {
    const parsed = JSON.parse(localStorage.getItem(LOCAL_RESOLVE_LIMIT_KEY));
    const attempts = Array.isArray(parsed?.attempts)
      ? parsed.attempts.filter((time) => now - time < windowMs)
      : [];
    if (attempts.length >= maxAttempts) return false;
    attempts.push(now);
    localStorage.setItem(LOCAL_RESOLVE_LIMIT_KEY, JSON.stringify({ attempts }));
    return true;
  } catch {
    localStorage.setItem(LOCAL_RESOLVE_LIMIT_KEY, JSON.stringify({ attempts: [now] }));
    return true;
  }
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    area.remove();
    return true;
  }
}

function showToast(message) {
  clearTimeout(toastTimer);
  els.toast.textContent = message;
  els.toast.classList.add("show");
  toastTimer = setTimeout(() => els.toast.classList.remove("show"), 3200);
}

function countWords(text) {
  return text.trim().split(/\s+/).filter(Boolean).length;
}

function formatBytes(value) {
  const bytes = Math.max(0, Number(value) || 0);
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KB`;
}

function formatDate(value) {
  return new Intl.DateTimeFormat("es", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit"
  }).format(new Date(value));
}

function shortFingerprint(value = "") {
  return `${value.slice(0, 8)}...${value.slice(-8)}`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  return `{${Object.keys(value)
    .filter((key) => value[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
    .join(",")}}`;
}

function bytesToBase64url(input) {
  const bytes = input instanceof ArrayBuffer ? new Uint8Array(input) : new Uint8Array(input.buffer || input);
  let binary = "";
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function bytesToHex(input) {
  const bytes = input instanceof ArrayBuffer ? new Uint8Array(input) : new Uint8Array(input.buffer || input);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function base64urlToBytes(value) {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}


function resizeSky() {
  const ratio = window.devicePixelRatio || 1;
  els.sky.width = Math.floor(window.innerWidth * ratio);
  els.sky.height = Math.floor(window.innerHeight * ratio);
  els.sky.style.width = `${window.innerWidth}px`;
  els.sky.style.height = `${window.innerHeight}px`;
  skyCtx.setTransform(ratio, 0, 0, ratio, 0, 0);
}

function seedSky() {
  skyStars = Array.from({ length: 92 }, () => ({
    x: Math.random() * window.innerWidth,
    y: Math.random() * window.innerHeight,
    size: Math.random() * 1.8,
    speed: 0.08 + Math.random() * 0.18,
    drift: -0.05 + Math.random() * 0.1,
    alpha: 0.15 + Math.random() * 0.38,
    color: Math.random() > 0.5 ? "#f6eddf" : "#65c3b6"
  }));
}

function drawSky() {
  if (!skyAnimationEnabled) {
    skyFrameActive = false;
    return;
  }
  skyFrameActive = true;
  skyCtx.clearRect(0, 0, window.innerWidth, window.innerHeight);
  skyCtx.globalCompositeOperation = "lighter";

  skyStars.forEach((star) => {
    star.y -= star.speed;
    star.x += star.drift;

    if (star.y < -10) {
      star.x = Math.random() * window.innerWidth;
      star.y = window.innerHeight + Math.random() * 80;
    }

    skyCtx.beginPath();
    skyCtx.fillStyle = hexToRgba(star.color, star.alpha);
    skyCtx.shadowColor = star.color;
    skyCtx.shadowBlur = 10;
    skyCtx.arc(star.x, star.y, star.size, 0, Math.PI * 2);
    skyCtx.fill();
  });

  skyCtx.shadowBlur = 0;
  requestAnimationFrame(drawSky);
}

function hexToRgba(hex, alpha) {
  const value = hex.replace("#", "");
  const red = parseInt(value.slice(0, 2), 16);
  const green = parseInt(value.slice(2, 4), 16);
  const blue = parseInt(value.slice(4, 6), 16);
  return `rgba(${red}, ${green}, ${blue}, ${alpha})`;
}
