import { spawn } from "node:child_process";
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { isV3OnionAddress } from "./security.js";

export class TorManager {
  constructor(options) {
    this.options = options;
    this.process = null;
    this.pollTimer = null;
    this.status = {
      state: "starting",
      progress: 0,
      onionAddress: "",
      message: "Preparando Tor..."
    };
  }

  async start() {
    if (!this.options.manageTor) {
      if (!isV3OnionAddress(this.options.externalOnionAddress)) {
        this.status = {
          state: "failed",
          progress: 0,
          onionAddress: "",
          message: "TROSTE_ONION_ADDRESS es obligatorio cuando TROSTE_MANAGE_TOR=false."
        };
        return;
      }
      this.status = {
        state: "ready",
        progress: 100,
        onionAddress: this.options.externalOnionAddress,
        message: "Tor externo configurado."
      };
      return;
    }

    const binary = await findTorBinary(this.options);
    if (!binary) {
      this.status = {
        state: "missing",
        progress: 0,
        onionAddress: "",
        message: "Falta Tor Expert Bundle. Ejecuta npm run tor:install."
      };
      return;
    }

    const torDataDir = path.join(this.options.dataDir, "tor");
    const hiddenServiceDir = path.join(this.options.dataDir, "onion-service");
    const torrcPath = path.join(this.options.dataDir, "torrc");
    await mkdir(torDataDir, { recursive: true, mode: 0o700 });
    await mkdir(hiddenServiceDir, { recursive: true, mode: 0o700 });
    await writeFile(torrcPath, renderTorrc({ ...this.options, torDataDir, hiddenServiceDir }), { mode: 0o600 });

    this.status = { state: "starting", progress: 0, onionAddress: "", message: "Conectando con la red Tor..." };
    this.process = spawn(binary, ["-f", torrcPath], {
      cwd: this.options.projectDir,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"]
    });
    this.process.stdout.setEncoding("utf8");
    this.process.stderr.setEncoding("utf8");
    this.process.stdout.on("data", (chunk) => this.handleLog(chunk));
    this.process.stderr.on("data", (chunk) => this.handleLog(chunk));
    this.process.on("error", (error) => {
      this.status = { state: "failed", progress: 0, onionAddress: "", message: `Tor no pudo iniciar: ${error.message}` };
    });
    this.process.on("exit", (code) => {
      this.process = null;
      if (this.status.state !== "stopped") {
        this.status = { ...this.status, state: "failed", message: `Tor se detuvo con codigo ${code ?? "desconocido"}.` };
      }
    });

    const hostnamePath = path.join(hiddenServiceDir, "hostname");
    this.pollTimer = setInterval(() => this.readOnionAddress(hostnamePath), 700);
    this.pollTimer.unref();
    await this.readOnionAddress(hostnamePath);
  }

  handleLog(chunk) {
    for (const line of String(chunk).split(/\r?\n/)) {
      const bootstrap = line.match(/Bootstrapped\s+(\d+)%[^:]*:\s*(.+)$/i);
      if (bootstrap) {
        const progress = Number.parseInt(bootstrap[1], 10);
        this.status = {
          ...this.status,
          state: progress >= 100 && this.status.onionAddress ? "ready" : "starting",
          progress,
          message: progress >= 100
            ? (this.status.onionAddress ? "Buzon Onion publicado." : "Tor conectado; publicando el buzon Onion...")
            : `Tor ${progress}%: ${bootstrap[2]}`
        };
      }
      if (/\[warn\]/i.test(line) && !/clock skew/i.test(line)) {
        this.status = { ...this.status, message: "Tor aviso de un problema; revisa la terminal del servicio." };
      }
    }
  }

  async readOnionAddress(hostnamePath) {
    try {
      const onionAddress = (await readFile(hostnamePath, "utf8")).trim().toLowerCase();
      if (!isV3OnionAddress(onionAddress)) return;
      this.status = {
        ...this.status,
        onionAddress,
        state: this.status.progress >= 100 ? "ready" : "starting",
        message: this.status.progress >= 100 ? "Buzon Onion publicado." : this.status.message
      };
    } catch {
      // Tor crea hostname solo cuando el servicio queda inicializado.
    }
  }

  getStatus() {
    return { ...this.status };
  }

  async stop() {
    if (this.pollTimer) clearInterval(this.pollTimer);
    this.pollTimer = null;
    this.status = { ...this.status, state: "stopped", message: "Tor detenido." };
    if (!this.process) return;
    const child = this.process;
    this.process = null;
    child.kill("SIGTERM");
    await new Promise((resolve) => {
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        resolve();
      }, 4000);
      child.once("exit", () => {
        clearTimeout(timer);
        resolve();
      });
    });
  }
}

async function findTorBinary(options) {
  const executable = process.platform === "win32" ? "tor.exe" : "tor";
  const candidates = [
    options.torBinary,
    path.join(options.projectDir, "vendor", "tor", "tor", executable),
    path.join(options.projectDir, "vendor", "tor", executable),
    process.platform === "win32" ? "C:\\Program Files\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe" : "/usr/bin/tor",
    process.platform === "win32" ? "C:\\Program Files (x86)\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe" : "/usr/local/bin/tor"
  ].filter(Boolean);
  for (const candidate of candidates) {
    try {
      await access(candidate);
      return candidate;
    } catch {
      // Sigue con el siguiente lugar conocido.
    }
  }
  return null;
}

function renderTorrc(options) {
  const quote = (value) => `"${String(value).replaceAll("\\", "/").replaceAll('"', '')}"`;
  return [
    `DataDirectory ${quote(options.torDataDir)}`,
    `SocksPort ${options.socksHost}:${options.socksPort} IsolateSOCKSAuth`,
    `HiddenServiceDir ${quote(options.hiddenServiceDir)}`,
    "HiddenServiceVersion 3",
    `HiddenServicePort 80 ${options.onionHost}:${options.onionPort}`,
    "ClientOnly 1",
    "SafeLogging 1",
    "RunAsDaemon 0",
    "Log notice stdout",
    "Log warn stderr",
    ""
  ].join("\n");
}
