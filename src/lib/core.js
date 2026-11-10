// The account list, read the way magpie core reads it.
//
// A page plugin cannot call magpie's Go API, but magpie hands its host
// input.directory = settings.Dir(), the folder holding logins.json,
// plugin-auth.json and providers.json. Everything here is that folder.
//
// Identity strings (agent|who) never leave this process: the picker and the
// API see an opaque, versioned id per account, computed with the same rule
// on both sides (catalog and bundle records), so a selection can be applied
// to a backup's signIns without ever naming an email.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

export const ID_PREFIX = "acb_v1_";

export const BLOCKED = {
  ROTATING: "ROTATING_REFRESH_TOKEN",
  NATIVE: "AGENT_NATIVE_LOGIN",
  HOME: "SEPARATE_AGENT_HOME",
  HIDDEN: "HIDDEN_ACCOUNT",
  RETIRED: "RETIRED_BUILTIN",
  PROXY: "PLUGIN_PROXY_RECORD",
  AMBIGUOUS: "AMBIGUOUS_IDENTITY",
  NOT_CARRIED: "NOT_CARRIED",
};

// Built-ins whose own code is gone (their plugin serves them now). A
// standalone plugin cannot read the core's Go maps, so this list is kept
// here; a newer magpie may retire more — add them with the plugin option
// `retiredProviders`.
const RETIRED = new Set([
  "zed", "kiro", "cursor", "qoder", "qoder-cn", "workbuddy", "workbuddy-ai",
  "mimo-app", "zcode", "factory", "grok", "devin", "commandcode-plan",
]);

// Vendors whose refresh token is spent once: two machines holding a copy
// would race to renew it. Extend with the option `rotatingProviders`.
const ROTATING = new Set(["minimax-code", "minimax-code-global", "qoder", "qoder-cn"]);

const NAMES = {
  claude: "Claude Code", codex: "Codex", copilot: "GitHub Copilot",
  cursor: "Cursor", grok: "Grok", devin: "Devin", kiro: "Kiro",
  zcode: "ZCode", workbuddy: "WorkBuddy", "workbuddy-ai": "WorkBuddy AI",
  "commandcode-plan": "Command Code", qoder: "Qoder", "qoder-cn": "Qoder CN",
  zed: "Zed", factory: "Factory", "mimo-app": "MiMo", "chatgpt-api": "ChatGPT API",
  gemini: "Gemini CLI", antigravity: "Antigravity", duanyan: "书生·端砚",
  sensenova: "SenseNova", raccoon: "商汤小浣熊", trae: "Trae",
  "minimax-code": "MiniMax Code", "minimax-code-global": "MiniMax Code Global",
};

const sha256 = (b) => crypto.createHash("sha256").update(b, "utf8").digest("hex");

// The id the API and the page trade. Deterministic per identity.
export function accountID(internalID) {
  return ID_PREFIX + sha256("magpie-account-backup/v1|" + internalID).slice(0, 24);
}

export function maskWho(who) {
  const s = String(who || "").trim();
  if (!s) return "（未命名）";
  const at = s.lastIndexOf("@");
  if (at > 0 && at < s.length - 1) return s[0] + "***@" + s.slice(at + 1);
  return (s.length <= 2 ? s[0] : s.slice(0, 2)) + "***";
}

const titleCase = (id) => id.split(/[-_ ]+/).filter(Boolean).map((p) => {
  const up = { ai: "AI", api: "API", cli: "CLI", cn: "CN", ide: "IDE" }[p.toLowerCase()];
  return up || p[0].toUpperCase() + p.slice(1);
}).join(" ");

export const providerOf = (key) => String(key || "").split("#")[0];

function readJSON(file, fallback) {
  let text;
  try { text = fs.readFileSync(file, "utf8"); }
  catch (e) {
    if (e.code === "ENOENT") return fallback;
    throw new Error(`${path.basename(file)} 读不出来：${e.message}`);
  }
  try { return JSON.parse(text); }
  catch (e) { throw new Error(`${path.basename(file)} 读不出来：${e.message}`); }
}

export function readAccounts(dir) {
  const logins = readJSON(path.join(dir, "logins.json"), []);
  const pluginAuth = readJSON(path.join(dir, "plugin-auth.json"), {});
  if (!Array.isArray(logins)) throw new Error("logins.json 不是账号列表");
  if (!pluginAuth || typeof pluginAuth !== "object" || Array.isArray(pluginAuth)) {
    throw new Error("plugin-auth.json 不是登录信息表");
  }
  return { logins, pluginAuth };
}

// Saved provider names (providers.json), for vendors magpie knows by name.
function savedNames(dir) {
  const out = {};
  let data;
  try { data = readJSON(path.join(dir, "providers.json"), {}); } catch { return out; }
  for (const p of (data && data.providers) || []) {
    if (p && p.id && p.name) out[p.id] = String(p.name);
  }
  return out;
}

export function providerName(id, saved) {
  const pid = String(id || "");
  return (saved && saved[pid]) || NAMES[pid] || titleCase(pid) || pid;
}

export function authWho(raw) {
  const o = raw && typeof raw === "object" ? raw : {};
  return o.accountId || (o.metadata && o.metadata.email) || o.email || "";
}

function jwtPayload(token) {
  const parts = String(token || "").split(".");
  if (parts.length < 2) return {};
  try {
    return JSON.parse(Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
  } catch { return {}; }
}

function codexWho(auth) {
  const a = auth && typeof auth === "object" ? auth : {};
  const tokens = a.tokens && typeof a.tokens === "object" ? a.tokens : {};
  const claims = jwtPayload(tokens.id_token);
  const ns = claims["https://api.openai.com/auth"] || {};
  const email = typeof claims.email === "string" ? claims.email : "";
  const ws = tokens.account_id || ns.chatgpt_account_id || "";
  return [email, ws];
}

function claudeWho(profile) {
  const p = profile && typeof profile === "object" ? profile : {};
  return [p.emailAddress || "", p.organizationUuid || ""];
}

// magpie's loginRecID: who an account of logins.json is, the same on every
// computer. Works on a savedLogin from logins.json and on one stored in a
// backup's signIns (same JSON field names).
export function loginRecID(l) {
  let who = "", org = "";
  if (l && l.agent === "claude") [who, org] = claudeWho(l.profile);
  else if (l && l.agent === "codex") [who, org] = codexWho(l.auth);
  if (who && org) return `${l.agent}|${String(who).toLowerCase()}|${org}`;
  return `${l && l.agent}|${String((l && l.user) || "").trim().toLowerCase()}`;
}

// magpie's pluginRecID, for a plugin-auth.json key and its credential.
export function pluginRecID(key, raw) {
  const who = authWho(raw);
  return who ? `plugin|${providerOf(key)}|${String(who).toLowerCase()}` : `plugin|${key}`;
}

// magpie's carried(): magpie's own copy of a sign-in — not the agent's own
// login read in place, not one kept in a folder of its own, not hidden, not
// a plugin proxy record, not a retired built-in's.
export function carried(l) {
  if (!l || typeof l !== "object") return false;
  const own = !l.home && (!l.auth || l.auth === null ||
    (typeof l.auth === "object" && Object.keys(l.auth).length === 0));
  return !own && !l.home && !l.hidden &&
    !String(l.agent || "").startsWith("plugin:") && !RETIRED.has(l.agent);
}

function credTimeBuiltin(l) {
  const a = l && l.auth && typeof l.auth === "object" ? l.auth : {};
  if (typeof a.last_refresh === "string" && !Number.isNaN(Date.parse(a.last_refresh))) {
    return new Date(a.last_refresh).toISOString();
  }
  const ms = [a.claudeAiOauth && a.claudeAiOauth.expiresAt, a.expiresAt, a.expiry_date, a.expires]
    .find((n) => typeof n === "number" && n > 0);
  if (ms) return new Date(ms).toISOString();
  if (l && typeof l.renewed === "string" && !Number.isNaN(Date.parse(l.renewed))) {
    return new Date(l.renewed).toISOString();
  }
  return "";
}

function credTimePlugin(raw) {
  const ms = raw && typeof raw.expires === "number" && raw.expires > 0 ? raw.expires : 0;
  return ms ? new Date(ms).toISOString() : "";
}

function blockedReasonOf(l, retired) {
  if (String(l.agent || "").startsWith("plugin:")) return BLOCKED.PROXY;
  if (l.home) return BLOCKED.HOME;
  if (l.hidden) return BLOCKED.HIDDEN;
  if (retired.has(l.agent)) return BLOCKED.RETIRED;
  return BLOCKED.NATIVE;
}

export function retiredProviders(options) {
  const out = new Set(RETIRED);
  for (const id of (options && options.retiredProviders) || []) out.add(String(id));
  return out;
}

export function rotatingProviders(options) {
  const out = new Set(ROTATING);
  for (const id of (options && options.rotatingProviders) || []) out.add(String(id));
  return out;
}

// Every sign-in magpie has here, migratable or not, with a reason when it
// is not. Records carry the identity string internally and never through
// the API.
export function catalog(dir, options) {
  const { logins, pluginAuth } = readAccounts(dir);
  const saved = savedNames(dir);
  const retired = retiredProviders(options);
  const rotating = rotatingProviders(options);
  const out = [];

  for (const l of logins) {
    const migratable = carried(l) && !retired.has(l.agent);
    const internalID = loginRecID(l);
    out.push({
      id: accountID(internalID),
      providerId: String(l.agent || ""),
      providerName: providerName(l.agent, saved),
      recordType: "builtin",
      displayName: maskWho(l.user),
      migratable,
      blockedReason: migratable ? "" : blockedReasonOf(l, retired),
      credentialUpdatedAt: migratable ? credTimeBuiltin(l) : "",
      internalID,
      fullName: String(l.user || ""),
      platform: "",
    });
  }

  for (const [key, raw] of Object.entries(pluginAuth)) {
    const pid = providerOf(key);
    const migratable = !rotating.has(pid);
    const internalID = pluginRecID(key, raw);
    out.push({
      id: accountID(internalID),
      providerId: pid,
      providerName: providerName(pid, saved),
      recordType: "plugin",
      displayName: maskWho(authWho(raw)),
      migratable,
      blockedReason: migratable ? "" : BLOCKED.ROTATING,
      credentialUpdatedAt: migratable ? credTimePlugin(raw) : "",
      internalID,
      fullName: authWho(raw),
      platform: "",
    });
  }

  // Two records of one identity are never guessed apart.
  const seen = new Map();
  for (const r of out) if (r.migratable) seen.set(r.internalID, (seen.get(r.internalID) || 0) + 1);
  for (const r of out) {
    if (r.migratable && seen.get(r.internalID) > 1) {
      r.migratable = false;
      r.blockedReason = BLOCKED.AMBIGUOUS;
    }
  }

  out.sort((a, b) => a.providerId.localeCompare(b.providerId) || a.id.localeCompare(b.id));
  return out;
}

// What an API answer may say: no identity strings, no credentials.
export function safeCatalog(records) {
  const groups = new Map();
  for (const r of records) {
    let g = groups.get(r.providerId);
    if (!g) {
      g = { providerId: r.providerId, providerName: r.providerName, accountCount: 0, accounts: [] };
      groups.set(r.providerId, g);
    }
    g.accountCount++;
    g.accounts.push({
      accountId: r.id,
      displayName: r.displayName,
      recordType: r.recordType,
      migratable: r.migratable,
      ...(r.blockedReason ? { blockedReason: r.blockedReason } : {}),
      ...(r.credentialUpdatedAt ? { credentialUpdatedAt: r.credentialUpdatedAt } : {}),
    });
  }
  return [...groups.values()].sort((a, b) => a.providerId.localeCompare(b.providerId));
}

// Turns provider/account ids from the page into the identities a backup's
// signIns can be matched against.
export function pick(records, providerIds, accountIds) {
  const ps = [...new Set((providerIds || []).map(String).filter(Boolean))];
  const as = [...new Set((accountIds || []).map(String).filter(Boolean))];
  if (!ps.length && !as.length) throw new Error("至少选一个供应商或一个账号");

  const knownProviders = new Set(records.map((r) => r.providerId));
  const byId = new Map(records.map((r) => [r.id, r]));
  for (const p of ps) if (!knownProviders.has(p)) throw new Error(`未知的供应商：${p}`);
  for (const a of as) if (!byId.has(a)) throw new Error(`未知的账号：${a}`);

  const wantedP = new Set(ps), wantedA = new Set(as);
  const excluded = {};
  const picked = [];
  for (const r of records) {
    if (ps.length && !wantedP.has(r.providerId)) continue;
    if (as.length && !wantedA.has(r.id)) continue;
    if (!r.migratable) {
      const why = r.blockedReason || BLOCKED.NOT_CARRIED;
      excluded[why] = (excluded[why] || 0) + 1;
      continue;
    }
    picked.push(r);
  }
  if (!picked.length) throw new Error("选中的账号都不能迁移（看每行后面的原因）");
  return {
    identities: new Set(picked.map((r) => r.internalID)),
    picked,
    excluded,
    providerIds: [...new Set(picked.map((r) => r.providerId))].sort(),
  };
}
