import { createHash } from "node:crypto";
import { createWriteStream, existsSync } from "node:fs";
import { access, mkdir, readFile, rename, rm, unlink } from "node:fs/promises";
import https from "node:https";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const VERSION = "15.0.17";
const platformKey = `${process.platform}-${process.arch}`;
const releases = {
  "win32-x64": {
    file: `tor-expert-bundle-windows-x86_64-${VERSION}.tar.gz`,
    sha256: "5f91e9426bf641dfe539dc28029088c72bed0b1d8f1c79104a0f89273cb3ebe1",
    binary: path.join("tor", "tor.exe")
  },
  "linux-x64": {
    file: `tor-expert-bundle-linux-x86_64-${VERSION}.tar.gz`,
    sha256: "4621e1573dbd6d5d6f4bb4121b37652a8b7204ae5abea600fb6b9e05e5695696",
    binary: path.join("tor", "tor")
  },
  "darwin-x64": {
    file: `tor-expert-bundle-macos-x86_64-${VERSION}.tar.gz`,
    sha256: "95243f76bcf05d6179d017c3f3e4ece7b53cc58dff1ba617b03a2fe2c8298b5b",
    binary: path.join("tor", "tor")
  },
  "darwin-arm64": {
    file: `tor-expert-bundle-macos-aarch64-${VERSION}.tar.gz`,
    sha256: "c99cf6f69740a443c7fffaf598ceb0952b3914041507c8afe11bed84a3333eb1",
    binary: path.join("tor", "tor")
  }
};

const release = releases[platformKey];
if (!release) throw new Error(`Tor automatico no esta preparado para ${platformKey}. Instala Tor manualmente y define TOR_BINARY.`);

const projectDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const vendorDir = path.join(projectDir, "vendor");
const targetDir = path.join(vendorDir, "tor");
const targetBinary = path.join(targetDir, release.binary);
if (existsSync(targetBinary)) {
  console.log(`Tor ya esta instalado en ${targetBinary}`);
  process.exit(0);
}
if (existsSync(targetDir)) {
  throw new Error("vendor/tor ya existe pero esta incompleto. Revisalo antes de volver a instalar.");
}

const archivePath = path.join(vendorDir, `${release.file}.download`);
const extractDir = path.join(vendorDir, `.tor-install-${process.pid}`);
const url = `https://dist.torproject.org/torbrowser/${VERSION}/${release.file}`;

await mkdir(vendorDir, { recursive: true });
await mkdir(extractDir, { recursive: false });

try {
  console.log(`Descargando Tor Expert Bundle ${VERSION} desde Tor Project...`);
  await download(url, archivePath);
  const digest = createHash("sha256").update(await readFile(archivePath)).digest("hex");
  if (digest !== release.sha256) {
    throw new Error(`SHA-256 inesperado. Esperado ${release.sha256}, recibido ${digest}.`);
  }
  console.log("SHA-256 verificado. Extrayendo Tor...");
  await run("tar", ["-xzf", archivePath, "-C", extractDir]);
  await access(path.join(extractDir, release.binary));
  await rename(extractDir, targetDir);
  if (process.platform !== "win32") await run("chmod", ["700", targetBinary]);
  const versionOutput = await run(targetBinary, ["--version"]);
  console.log(versionOutput.trim().split(/\r?\n/, 1)[0]);
  console.log("Tor instalado. Ya puedes ejecutar npm start.");
} finally {
  await unlink(archivePath).catch(() => {});
  if (existsSync(extractDir)) await rm(extractDir, { recursive: true, force: true });
}

function download(url, destination, redirects = 0) {
  if (redirects > 4) return Promise.reject(new Error("Demasiadas redirecciones al descargar Tor."));
  return new Promise((resolve, reject) => {
    const request = https.get(url, { headers: { "User-Agent": "Troste-Onion-Installer/1" } }, (response) => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        const next = new URL(response.headers.location, url);
        if (next.protocol !== "https:" || !next.hostname.endsWith("torproject.org")) {
          reject(new Error("Tor Project redirigio a un dominio no permitido."));
          return;
        }
        download(next.href, destination, redirects + 1).then(resolve, reject);
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error(`Tor Project respondio ${response.statusCode}.`));
        return;
      }
      const output = createWriteStream(destination, { flags: "wx", mode: 0o600 });
      response.pipe(output);
      output.on("finish", () => output.close(resolve));
      output.on("error", reject);
    });
    request.setTimeout(120_000, () => request.destroy(new Error("La descarga de Tor agoto el tiempo.")));
    request.on("error", reject);
  });
}

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    const output = [];
    const errors = [];
    child.stdout.on("data", (chunk) => output.push(chunk));
    child.stderr.on("data", (chunk) => errors.push(chunk));
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) resolve(Buffer.concat(output).toString("utf8"));
      else reject(new Error(`${command} fallo (${code}): ${Buffer.concat(errors).toString("utf8").trim()}`));
    });
  });
}
