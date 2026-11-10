// The page's local service: 127.0.0.1 only, answers its own page only
// (Host and Origin), passphrases arrive in a POST body and are never
// logged or written, and one export runs at a time.

import fs from "node:fs";
import http from "node:http";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { catalog, safeCatalog, pick } from "./core.js";
import { exportBackup, findCLI, tilde } from "./backup.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..", "..");
const VERSION = "1.0.0";
const MAX_BODY = 1 << 20;

let running = null;
let busy = false;

// A sandboxed page has an opaque origin ("null"), so even a fetch to the
// very URL it was served from is cross-origin. The page is ours and carries
// a token only it was served with; the token, not the origin, is what keeps
// other pages out.
function cors(req, res) {
  const o = req.headers.origin;
  if (o === "null" || (o && (o === `http://127.0.0.1:${req.__abPort}` || o === `http://localhost:${req.__abPort}`))) {
    res.setHeader("Access-Control-Allow-Origin", o);
    res.setHeader("Vary", "Origin");
  }
}

function json(res, code, value) {
  const body = Buffer.from(JSON.stringify(value), "utf8");
  res.writeHead(code, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": body.length,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(body);
}

const fail = (res, code, message) => json(res, code, { error: String(message || "失败") });

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(new Error("请求太大")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

async function bodyJSON(req) {
  const text = await readBody(req);
  if (!text.trim()) return {};
  try { return JSON.parse(text); }
  catch { throw new Error("请求不是有效 JSON"); }
}

function hostOK(req, port) {
  const h = String(req.headers.host || "").toLowerCase();
  return h === `127.0.0.1:${port}` || h === `localhost:${port}`;
}

function originOK(req, port) {
  const o = req.headers.origin;
  if (o === undefined || o === "null") return true;
  return o === `http://127.0.0.1:${port}` || o === `http://localhost:${port}`;
}

function csp(port) {
  return [
    "sandbox allow-scripts",
    "default-src 'none'",
    "script-src 'unsafe-inline'",
    "style-src 'unsafe-inline'",
    `connect-src 'self' http://127.0.0.1:${port}`,
    "img-src data:",
    "base-uri 'none'",
    "form-action 'none'",
  ].join("; ");
}

function serveHTML(res, port, token) {
  let html;
  try { html = fs.readFileSync(path.join(root, "ui", "app.html"), "utf8"); }
  catch (e) { return fail(res, 500, `页面文件缺失：${e.message}`); }
  if (!html.includes("__AB_TOKEN__")) return fail(res, 500, "页面缺少令牌占位符");
  html = Buffer.from(html.replace("__AB_TOKEN__", token), "utf8");
  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": html.length,
    "Content-Security-Policy": csp(port),
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
  });
  res.end(html);
}

function accountsPayload(dir, opts) {
  const records = catalog(dir, opts);
  const migratable = records.filter((r) => r.migratable).length;
  return {
    providers: safeCatalog(records),
    counts: { accounts: records.length, migratable },
    platform: process.platform,
  };
}

export function startService({ dir, options } = {}) {
  if (running) return Promise.resolve(running);
  const magpieDir = dir || process.cwd();
  const opts = options || {};
  const wanted = Number(opts.port);
  const port = Number.isInteger(wanted) && wanted >= 1 && wanted <= 65535 ? wanted : 39872;
  const audit = [];
  // A sealed export on its way to the reader's own computer: the id in the
  // URL is the whole capability, good once, for ten minutes. It is how a
  // magpie on a server hands a backup to the browser rather than leaving it
  // in that server's Downloads folder.
  const handovers = new Map();
  const HANDOVER_TTL = 10 * 60 * 1000;
  const purgeHandovers = () => {
    const now = Date.now();
    for (const [k, v] of handovers) if (now - v.at > HANDOVER_TTL) handovers.delete(k);
  };

  const token = crypto.randomBytes(24).toString("hex");
  const server = http.createServer(async (req, res) => {
    try {
      req.__abPort = port;
      if (!hostOK(req, port)) return fail(res, 403, "这个服务只应答它自己的页面");
      if (!originOK(req, port)) return fail(res, 403, "这个服务只应答它自己的页面");
      cors(req, res);
      const url = new URL(req.url || "/", `http://127.0.0.1:${port}`);
      const p = url.pathname;
      const method = req.method || "GET";

      if (method === "OPTIONS") {
        res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.setHeader("Access-Control-Allow-Headers", "content-type, x-ab-token");
        res.setHeader("Access-Control-Max-Age", "600");
        res.writeHead(204);
        return res.end();
      }

      if (method === "GET" && (p === "/" || p === "/app.html")) return serveHTML(res, port, token);

      const handover = /^\/file\/([0-9a-f]{32})$/.exec(p);
      if (method === "GET" && handover) {
        purgeHandovers();
        const hit = handovers.get(handover[1]);
        if (!hit) return fail(res, 404, "这个下载链接已经用过或已过期，重新导出一次");
        handovers.delete(handover[1]); // one time
        res.writeHead(200, {
          "Content-Type": "application/octet-stream",
          "Content-Disposition": `attachment; filename="${hit.name}"`,
          "Content-Length": hit.data.length,
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
        });
        return res.end(hit.data);
      }

      if (p.startsWith("/api/")) {
        const given = String(req.headers["x-ab-token"] || "");
        const want = Buffer.from(token, "utf8");
        const got = Buffer.from(given, "utf8");
        if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) {
          return fail(res, 403, "这个服务只应答它自己的页面");
        }
      }

      if (method === "GET" && p === "/api/state") {
        const cli = findCLI(opts, magpieDir);
        let source = "ok", error = "";
        try { catalog(magpieDir, opts); } catch (e) { source = "error"; error = e.message; }
        return json(res, 200, {
          ok: source === "ok",
          version: VERSION,
          platform: process.platform,
          magpieDir: tilde(magpieDir),
          sourceStatus: source,
          error,
          cli: cli.found ? { path: tilde(cli.found.path), how: cli.found.how } : null,
          cliTried: cli.found ? undefined : cli.tried.slice(-6).map(tilde),
          audit: audit.slice(-10),
        });
      }

      if (method === "GET" && p === "/api/accounts") {
        return json(res, 200, accountsPayload(magpieDir, opts));
      }

      if (method === "POST" && p === "/api/reveal") {
        const body = await bodyJSON(req);
        const records = catalog(magpieDir, opts);
        const rec = records.find((r) => r.id === String(body.accountId || ""));
        if (!rec) return fail(res, 404, "没有这个账号");
        return json(res, 200, { displayName: rec.fullName });
      }

      if (method === "POST" && p === "/api/export") {
        if (busy) return fail(res, 429, "上一次导出还在进行，等它结束");
        busy = true;
        try {
          const body = await bodyJSON(req);
          const pass = String(body.passphrase || "");
          const signIns = body.signIns !== false;
          const keys = body.keys !== false;
          const library = body.library !== false;

          let identities = null;
          let pickedReport = null;
          if (signIns) {
            const records = catalog(magpieDir, opts);
            const { picked, identities: ids, excluded, providerIds } =
              pick(records, body.providerIds, body.accountIds);
            identities = ids;
            pickedReport = { accounts: picked.length, providers: providerIds, excluded };
          }

          const out = await exportBackup({
            dir: magpieDir, options: opts, pass, keys, library, signIns, identities,
            save: opts.saveOnServer !== false,
            runner: typeof opts.cliRunner === "function" ? opts.cliRunner : undefined,
          });
          const id = crypto.randomBytes(16).toString("hex");
          handovers.set(id, { data: out.data, name: out.fileName, at: Date.now() });
          delete out.data;
          audit.push({
            at: new Date().toISOString(), action: "export",
            accounts: out.signIns.total, providers: out.providers,
            keys: out.keys, library: out.library, result: "ok",
          });
          const si = out.signIns || {};
          return json(res, 200, {
            ...out,
            signIns: { ...si, total: (si.logins || 0) + (si.plugins || 0) },
            // relative to this page: the browser opens it top-level and the
            // file lands on the reader's computer, not the server's disk
            download: "file/" + id,
            savedOnServer: opts.saveOnServer !== false,
            picked: pickedReport,
          });
        } finally {
          busy = false;
        }
      }

      return fail(res, 404, "没有这个接口");
    } catch (e) {
      const code = e && e.code === "NO_CLI" ? 409 : e && e.code === "NOTHING_PICKED" ? 409 : 400;
      return fail(res, code, e && e.message ? e.message : e);
    }
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      running = { server, port, dir: magpieDir };
      console.log(`[account-backup] serving on 127.0.0.1:${port}`);
      resolve(running);
    });
  });
}

export function stopService() {
  if (!running) return;
  try { running.server.close(); } catch { /* already closed */ }
  running = null;
}
