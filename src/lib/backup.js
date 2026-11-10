// Turning a selection into a .magpie-backup.
//
// magpie's own backup writer is the CLI:
//
//   magpie backup [--sign-ins] [--no-keys] [--no-library] <file>
//
// It is the only thing that can read every provider, key, setting, profile
// and the library correctly, so this plugin runs it, then opens the file it
// wrote with the same passphrase, keeps only the sign-ins that were picked,
// and seals the result again. Everything else is carried through untouched,
// which is why the file magpie imports is a real one, not a reduced format.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { openJSON, sealJSON } from "./envelope.js";
import { loginRecID, pluginRecID } from "./core.js";

const IS_WIN = process.platform === "win32";
const CLI_NAMES = IS_WIN ? ["magpie.com", "magpie.exe", "magpie"] : ["magpie"];
const RUN_TIMEOUT = 180_000;
const OUTPUT_CAP = 64 << 10;

function exists(p) {
  try { return fs.statSync(p).isFile(); } catch { return false; }
}

// Where the magpie CLI is. A plugin is not told the binary's path, so this
// looks beside Bun (which magpie runs plugins with), in the usual install
// folders, and along PATH; the plugin option `magpieBin` wins over all.
export function findCLI(options, dir) {
  const tried = [];
  const out = [];
  const add = (p, how) => {
    if (!p) return;
    const clean = path.normalize(String(p));
    if (tried.includes(clean)) return;
    tried.push(clean);
    if (exists(clean)) out.push({ path: clean, how });
  };

  add(options && options.magpieBin, "option");
  add(process.env.MAGPIE_BIN, "MAGPIE_BIN");

  const bunDir = path.dirname(process.execPath || "");
  for (const n of CLI_NAMES) add(path.join(bunDir, n), "bun");

  if (IS_WIN) {
    const local = process.env.LOCALAPPDATA || "";
    for (const n of CLI_NAMES) {
      add(path.join(local, "Programs", "magpie", n), "install");
      add(path.join(local, "magpie", n), "install");
      add(path.join(local, "Programs", "Magpie", n), "install");
    }
  } else if (process.platform === "darwin") {
    add("/Applications/Magpie.app/Contents/MacOS/magpie", "app");
    add(path.join(os.homedir(), "Applications", "Magpie.app", "Contents", "MacOS", "magpie"), "app");
  } else {
    add("/opt/magpie/magpie", "install");       // a container or /opt install
    add("/app/magpie", "install");
    add("/usr/local/bin/magpie", "PATH");
    add("/usr/bin/magpie", "PATH");
    add("/snap/bin/magpie", "PATH");
    add(path.join(os.homedir(), ".local", "bin", "magpie"), "PATH");
    // magpie on WSL reading a Windows data folder: its own CLI is beside it
    if (String(dir || "").startsWith("/mnt/")) {
      add("/mnt/c/Users/" + (process.env.USER || "") + "/AppData/Local/Programs/magpie/magpie.com", "wsl");
    }
  }

  for (const dir of String(process.env.PATH || "").split(path.delimiter)) {
    if (!dir) continue;
    for (const n of CLI_NAMES) add(path.join(dir, n), "PATH");
  }
  return { found: out[0] || null, tried };
}

function runOnce(cli, args, cwd, pass) {
  return new Promise((resolve) => {
    let stdout = "", stderr = "", done = false;
    let child;
    try {
      child = spawn(cli, args, { cwd, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
    } catch (e) {
      return resolve({ code: -1, stdout: "", stderr: String(e && e.message || e), error: e });
    }
    const finish = (res) => { if (!done) { done = true; resolve(res); } };
    const timer = setTimeout(() => {
      try { child.kill(); } catch { /* gone */ }
      finish({ code: -1, stdout, stderr: stderr + "\n备份超时，已停止", error: new Error("timeout") });
    }, RUN_TIMEOUT);
    child.stdout.on("data", (c) => { if (stdout.length < OUTPUT_CAP) stdout += c.toString("utf8"); });
    child.stderr.on("data", (c) => { if (stderr.length < OUTPUT_CAP) stderr += c.toString("utf8"); });
    child.on("error", (e) => { clearTimeout(timer); finish({ code: -1, stdout, stderr: String(e && e.message || e), error: e }); });
    child.on("close", (code) => { clearTimeout(timer); finish({ code, stdout, stderr, error: null }); });
    try {
      child.stdin.end(pass + "\n", "utf8");
    } catch { /* the CLI may not read it */ }
  });
}

export function trimSignIns(payload, identities) {
  if (!payload || typeof payload !== "object") throw new Error("备份内容不是对象");
  const si = payload.signIns;
  if (!si) throw new Error("这个备份里没有登录信息，无法按账号裁剪");
  const logins = (Array.isArray(si.logins) ? si.logins : []).filter((l) => identities.has(loginRecID(l)));
  const plugins = {};
  for (const [key, raw] of Object.entries(si.plugins || {})) {
    if (identities.has(pluginRecID(key, raw))) plugins[key] = raw;
  }
  // Empty fields are left out, as magpie's own writer does (omitempty).
  const next = {};
  if (logins.length) next.logins = logins;
  const keys = Object.keys(plugins);
  if (keys.length) next.plugins = plugins;
  if (si.codex && identities.has(si.codex)) next.codex = si.codex;
  payload.signIns = next;
  return { logins: logins.length, plugins: keys.length, codex: !!next.codex };
}

export function signInCount(payload) {
  const si = payload && payload.signIns;
  if (!si) return { logins: 0, plugins: 0, codex: false, total: 0 };
  const logins = Array.isArray(si.logins) ? si.logins.length : 0;
  const plugins = Object.keys(si.plugins || {}).length;
  return { logins, plugins, codex: !!si.codex, total: logins + plugins };
}

function downloadsDir(options) {
  if (options && typeof options.exportDir === "string" && options.exportDir.trim()) return options.exportDir.trim();
  const home = os.homedir();
  for (const d of [path.join(home, "Downloads"), home]) {
    try { if (fs.statSync(d).isDirectory()) return d; } catch { /* next */ }
  }
  return process.cwd();
}

function freeName(dir, base, ext) {
  let name = path.join(dir, base + ext);
  for (let i = 2; fs.existsSync(name); i++) name = path.join(dir, `${base}-${i}${ext}`);
  return name;
}

function today() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

export function tilde(p) {
  const home = os.homedir();
  return home && p && p.startsWith(home) ? "~" + p.slice(home.length) : p;
}

// The whole export: CLI writes a full backup, this keeps the picked
// sign-ins and seals the file again where the user wants it.
//
// `runner` is for tests: it stands in for magpie's CLI (same arguments,
// same staged file path) so the pipeline can be checked without one.
export async function exportBackup({ dir, options, pass, keys, library, signIns, identities, runner }) {
  const opts = options || {};
  const cli = runner ? { path: "runner", how: "test" } : findCLI(opts, dir).found;
  if (!cli) {
    const e = new Error("找不到 magpie 命令行，没法生成备份（可在插件设置里把 magpieBin 指向 magpie 可执行文件）");
    e.code = "NO_CLI";
    throw e;
  }

  const work = fs.mkdtempSync(path.join(os.tmpdir(), "magpie-backup-"));
  const staged = path.join(work, "backup" + ".magpie-backup");
  const args = ["backup"];
  if (!keys) args.push("--no-keys");
  if (!library) args.push("--no-library");
  if (signIns) args.push("--sign-ins");
  args.push(staged);

  const started = Date.now();
  try {
    const res = runner ? await runner({ cli: cli.path, args, cwd: work, pass, staged })
      : await runOnce(cli.path, args, work, pass);
    if (res.code !== 0) {
      const why = (res.stderr || res.stdout || "").trim().split("\n").filter(Boolean).slice(-3).join(" ");
      const e = new Error(`magpie backup 没有成功：${why || `退出码 ${res.code}`}`);
      e.code = "CLI_FAILED";
      throw e;
    }
    if (!exists(staged)) {
      const e = new Error("magpie backup 没有写出文件");
      e.code = "CLI_FAILED";
      throw e;
    }
    const sealed = fs.readFileSync(staged);
    const payload = await openJSON(sealed, pass);
    const countsBefore = signInCount(payload);
    let counts = countsBefore;

    if (signIns) {
      counts = trimSignIns(payload, identities);
      if (!counts.logins && !counts.plugins) {
        const e = new Error("选中的账号都没有出现在备份里；换一个账号，或重新打开本页再试");
        e.code = "NOTHING_PICKED";
        throw e;
      }
    } else if (payload.signIns) {
      // no sign-ins asked for: whatever the CLI wrote, the file carries none
      delete payload.signIns;
      counts = { logins: 0, plugins: 0, codex: false };
    }

    const out = freeName(downloadsDir(opts), `magpie-${today()}`, ".magpie-backup");
    const bytes = await sealJSON(payload, pass);
    fs.writeFileSync(out, bytes, { mode: 0o600 });
    try { fs.chmodSync(out, 0o600); } catch { /* Windows ACL */ }

    return {
      path: tilde(out),
      bytes: bytes.length,
      ms: Date.now() - started,
      signIns: counts,
      signInsBefore: countsBefore,
      providers: Array.isArray(payload.providers) ? payload.providers.length : 0,
      keys: !!keys,
      library: !!library,
      app: payload.app || "",
      cli: cli.path,
    };
  } finally {
    // The staged file holds every sign-in: it never outlives the export.
    try { fs.rmSync(work, { recursive: true, force: true }); } catch { /* Windows may hold it briefly */ }
  }
}
