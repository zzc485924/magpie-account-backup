// Self-test, no magpie install needed: a fixture magpie directory, a
// fixture backup payload, and a stand-in for `magpie backup`.
//
//   node test/selftest.mjs

import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { sealJSON, openJSON } from "../src/lib/envelope.js";
import {
  catalog, safeCatalog, pick, maskWho, loginRecID, pluginRecID, accountID, BLOCKED,
} from "../src/lib/core.js";
import { trimSignIns, signInCount, findCLI } from "../src/lib/backup.js";
import { startService, stopService } from "../src/lib/server.js";

const PASS = "correct-horse-battery-staple";
const OTHER = "wrong-passphrase-123";
const tmp = (n) => fs.mkdtempSync(path.join(os.tmpdir(), `ab-${n}-`));
const writeJSON = (f, v) => {
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, JSON.stringify(v, null, 2) + "\n");
};

function jwt(payload) {
  const b = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b({ alg: "RS256", typ: "JWT" })}.${b(payload)}.sig`;
}

const codexAuth = {
  auth_mode: "chatgpt",
  tokens: {
    id_token: jwt({ email: "a@example.com", "https://api.openai.com/auth": { chatgpt_account_id: "ws-1" } }),
    account_id: "ws-1",
    access_token: "codex-access",
  },
};
const claudeAuth = { claudeAiOauth: { accessToken: "claude-access", expiresAt: 1700000000000 } };

function makeDir(name) {
  const dir = tmp(name);
  writeJSON(path.join(dir, "providers.json"), {
    providers: [{ id: "zcode", name: "ZCode" }],
    groups: [],
  });
  writeJSON(path.join(dir, "logins.json"), [
    { agent: "codex", user: "a@example.com", plan: "free", auth: codexAuth },
    { agent: "claude", user: "", profile: { emailAddress: "c@example.com", organizationUuid: "org-1" }, auth: claudeAuth },
    { agent: "kiro", user: "retired@example.com", auth: { access_token: "r" } },
    { agent: "plugin:kiro", user: "z@example.com", home: "kiro", on: true },
    { agent: "codex", user: "own@example.com" },
  ]);
  writeJSON(path.join(dir, "plugin-auth.json"), {
    zcode: { type: "api", key: "sk-1", metadata: { email: "z1@example.com" } },
    "zcode#a1": { type: "oauth", access: "za", refresh: "zr", expires: 1700000000000, accountId: "z2@example.com" },
    "minimax-code": { type: "oauth", access: "ma", refresh: "mr", accountId: "m@example.com" },
  });
  return dir;
}

function fixturePayload() {
  return {
    version: 1,
    created: new Date().toISOString(),
    app: "0.1.2862",
    keys: true,
    providers: [{ id: "zcode" }, { id: "kiro" }],
    groups: [],
    settings: { language: "zh" },
    signIns: {
      logins: [
        { id: "l1", agent: "codex", user: "a@example.com", auth: codexAuth },
        { id: "l2", agent: "claude", user: "", profile: { emailAddress: "c@example.com", organizationUuid: "org-1" }, auth: claudeAuth },
      ],
      plugins: {
        zcode: { type: "api", key: "sk-1", metadata: { email: "z1@example.com" } },
        "zcode#a1": { type: "oauth", access: "za", refresh: "zr", expires: 1700000000000, accountId: "z2@example.com" },
        "minimax-code": { type: "oauth", access: "ma", refresh: "mr", accountId: "m@example.com" },
      },
      codex: "codex|a@example.com|ws-1",
    },
  };
}

function at(port, p, body, headers = {}, token = null) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : Buffer.from(JSON.stringify(body));
    const req = http.request({
      host: "127.0.0.1", port, path: p,
      method: data ? "POST" : "GET",
      headers: {
        Host: `127.0.0.1:${port}`,
        ...(token ? { "X-AB-Token": token } : {}),
        ...(data ? { "Content-Type": "application/json", "Content-Length": data.length } : {}),
        ...headers,
      },
    }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        let parsed = null;
        try { parsed = text ? JSON.parse(text) : null; } catch { parsed = null; }
        resolve({ status: res.statusCode, data: parsed, text, cors: res.headers["access-control-allow-origin"] });
      });
    });
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

function byProvider(records, id) { return records.filter((r) => r.providerId === id); }

async function testCatalog() {
  const dir = makeDir("catalog");
  const records = catalog(dir);
  const ids = new Set(records.map((r) => r.id));
  assert.equal(ids.size, records.length, "account ids are not unique");

  const codex = byProvider(records, "codex");
  assert.equal(codex.length, 2);
  const carried = codex.find((r) => r.fullName === "a@example.com");
  assert.ok(carried.migratable, "the carried codex account isn't migratable");
  const own = codex.find((r) => r.fullName === "own@example.com");
  assert.equal(own.migratable, false);
  assert.equal(own.blockedReason, BLOCKED.NATIVE);

  const kiro = byProvider(records, "kiro");
  assert.ok(kiro.every((r) => !r.migratable), "a retired built-in was offered");
  assert.ok(kiro.some((r) => r.blockedReason === BLOCKED.RETIRED));

  const proxy = records.filter((r) => r.blockedReason === BLOCKED.PROXY);
  assert.equal(proxy.length, 1, "the plugin: proxy row isn't listed as one");

  const zcode = byProvider(records, "zcode");
  assert.equal(zcode.length, 2);
  assert.ok(zcode.every((r) => r.migratable), "zcode accounts should all be migratable");
  assert.equal(zcode[0].providerName, "ZCode", "the saved provider name wasn't used");

  const minimax = byProvider(records, "minimax-code");
  assert.equal(minimax.length, 1);
  assert.equal(minimax[0].blockedReason, BLOCKED.ROTATING);

  // nothing an API answer carries may name an identity
  const safe = JSON.stringify(safeCatalog(records));
  for (const leak of ["a@example.com", "c@example.com", "sk-1", "codex-access", "org-1"]) {
    assert.ok(!safe.includes(leak), `the API payload leaks ${leak}`);
  }

  // the id of an account is the id of the same identity in a backup
  const payload = fixturePayload();
  for (const l of payload.signIns.logins) {
    const id = accountID(loginRecID(l));
    assert.ok(ids.has(id), `a backup login has no matching account id: ${l.agent}`);
  }
  for (const [k, raw] of Object.entries(payload.signIns.plugins)) {
    const rec = records.find((r) => r.recordType === "plugin" && r.internalID === pluginRecID(k, raw));
    assert.ok(rec, `a backup plugin credential has no matching account: ${k}`);
  }
  assert.equal(maskWho("a@example.com"), "a***@example.com");
  return dir;
}

function testPickAndTrim(dir) {
  const records = catalog(dir);

  // one vendor, all of its accounts
  const z = pick(records, ["zcode"], []);
  assert.equal(z.picked.length, 2);
  assert.deepEqual(z.providerIds, ["zcode"]);

  const payload = fixturePayload();
  const counts = trimSignIns(payload, z.identities);
  assert.deepEqual(counts, { logins: 0, plugins: 2, codex: false });
  assert.equal(payload.signIns.codex, undefined, "codex stayed signed in without being picked");
  assert.deepEqual(Object.keys(payload.signIns.plugins).sort(), ["zcode", "zcode#a1"]);
  // everything besides signIns is carried through
  assert.equal(payload.providers.length, 2);
  assert.equal(payload.settings.language, "zh");

  // a codex account: its logins entry and the codex marker
  const codexRec = records.find((r) => r.providerId === "codex" && r.fullName === "a@example.com");
  const c = pick(records, [], [codexRec.id]);
  const p2 = fixturePayload();
  const c2 = trimSignIns(p2, c.identities);
  assert.deepEqual(c2, { logins: 1, plugins: 0, codex: true });
  assert.equal(p2.signIns.logins[0].user, "a@example.com");
  assert.equal(p2.signIns.codex, "codex|a@example.com|ws-1");

  // a retired built-in is refused, not silently dropped
  const kiroRec = records.find((r) => r.providerId === "kiro" && r.migratable === false);
  assert.throws(() => pick(records, [], [kiroRec.id]), /不能迁移/);

  // an unknown id is refused
  assert.throws(() => pick(records, [], ["acb_v1_nope"]), /未知的账号/);

  // picking nothing is refused
  assert.throws(() => pick(records, [], []), /至少选一个/);

  assert.equal(signInCount(fixturePayload()).total, 5);
}

async function testEnvelope() {
  const payload = fixturePayload();
  const sealed = await sealJSON(payload, PASS);
  const back = await openJSON(sealed, PASS);
  assert.deepEqual(back.signIns.logins.length, 2);

  const env = JSON.parse(sealed.toString("utf8"));
  assert.equal(env.format, "magpie-backup");
  assert.equal(env.kdf, "pbkdf2-sha256");
  assert.ok(env.iterations >= 100000);
  assert.equal(Buffer.from(env.salt, "base64").length, 16);
  assert.equal(Buffer.from(env.nonce, "base64").length, 12);

  await assert.rejects(() => openJSON(sealed, OTHER), /口令不对/);

  const tampered = JSON.parse(sealed.toString("utf8"));
  tampered.iterations = 100000;
  await assert.rejects(() => openJSON(Buffer.from(JSON.stringify(tampered)), PASS), /口令不对|损坏/);

  await assert.rejects(() => sealJSON(payload, "short"), /至少 8/);
}

async function testService(dir) {
  const port = 39897;
  const outDir = tmp("out");
  const runner = async ({ args, staged }) => {
    // what magpie backup writes: the fixture sealed with the passphrase the
    // CLI would have read from stdin, and no signIns without --sign-ins
    const file = args[args.length - 1];
    assert.equal(file, staged);
    const payload = fixturePayload();
    if (!args.includes("--sign-ins")) delete payload.signIns;
    fs.writeFileSync(staged, await sealJSON(payload, PASS), { mode: 0o600 });
    return { code: 0, stdout: "saved", stderr: "" };
  };
  await startService({ dir, options: { port, exportDir: outDir, cliRunner: runner } });

  // the page is served with a token only it gets, and that is what the API
  // asks for: another page on this computer has no way to guess it
  let page = await at(port, "/app.html", undefined, { Origin: "null" });
  assert.equal(page.status, 200);
  assert.equal(page.cors, "null", "the sandboxed page's origin isn't answered");
  const token = (page.text.match(/name="ab-token" content="([0-9a-f]{48})"/) || [])[1];
  assert.ok(token, "the page carries no token");
  assert.ok(!page.text.includes("__AB_TOKEN__"), "the token placeholder stayed in the page");

  let r = await at(port, "/api/accounts");
  assert.equal(r.status, 403, "the API answered without the token");

  r = await at(port, "/api/accounts", undefined, {}, token);
  assert.equal(r.status, 200);
  assert.ok(r.data.providers.length >= 4, "the catalog is short");
  assert.ok(!JSON.stringify(r.data).includes("a@example.com"), "the API leaked an email");

  r = await at(port, "/api/state", undefined, {}, token);
  assert.equal(r.status, 200);
  assert.equal(r.data.ok, true);

  // a foreign Host is refused
  r = await at(port, "/api/accounts", undefined, { Host: "evil.example" }, token);
  assert.equal(r.status, 403);

  // nothing picked
  r = await at(port, "/api/export", { passphrase: PASS, signIns: true, accountIds: [] }, {}, token);
  assert.equal(r.status, 400);

  // one plugin account only
  const rec = catalog(dir).find((x) => x.providerId === "zcode" && x.fullName === "z1@example.com");
  r = await at(port, "/api/export", {
    passphrase: PASS, keys: true, library: false, signIns: true,
    providerIds: ["zcode"], accountIds: [rec.id],
  }, {}, token);
  assert.equal(r.status, 200, r.text);
  assert.equal(r.data.signIns.plugins, 1, r.text);
  assert.equal(r.data.signIns.logins, 0, r.text);
  const file = path.join(outDir, path.basename(r.data.path));
  assert.ok(fs.existsSync(file), "no file was written");
  const opened = await openJSON(fs.readFileSync(file), PASS);
  assert.deepEqual(Object.keys(opened.signIns.plugins), ["zcode"]);
  assert.equal(opened.signIns.logins, undefined);
  assert.equal(opened.signIns.codex, undefined);

  // everything, no sign-ins
  r = await at(port, "/api/export", { passphrase: PASS, keys: true, library: true, signIns: false }, {}, token);
  assert.equal(r.status, 200, r.text);
  assert.equal(r.data.signIns.total, 0, r.text);
  const full = await openJSON(fs.readFileSync(path.join(outDir, path.basename(r.data.path))), PASS);
  assert.equal(full.signIns, undefined, "sign-ins were written without being asked for");
  assert.equal(full.providers.length, 2, "the rest of the backup went missing");

  // a wrong passphrase never leaves a file behind
  const before = fs.readdirSync(outDir).length;
  r = await at(port, "/api/export", { passphrase: "another-one-123", signIns: false }, {}, token);
  assert.equal(r.status, 400, r.text);
  assert.equal(fs.readdirSync(outDir).length, before, "a failed export wrote a file");

  stopService();
  console.log("  service: ok");
}

async function main() {
  const dir = await testCatalog();
  console.log("  catalog: ok");
  testPickAndTrim(dir);
  console.log("  pick/trim: ok");
  await testEnvelope();
  console.log("  envelope: ok");
  await testService(dir);
  const cli = findCLI({});
  console.log(`  magpie cli: ${cli.found ? cli.found.path : "not found here (fine for this test)"}`);
  console.log("all self-tests passed");
}

main().catch((e) => {
  stopService();
  console.error(e && e.stack ? e.stack : e);
  process.exitCode = 1;
});
