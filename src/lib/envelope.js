// The sealed envelope magpie's backups use: AES-256-GCM under
// PBKDF2-SHA256 (600,000 rounds), a fresh 16-byte salt and 12-byte nonce,
// and the envelope's own header as AEAD additional data, so the header
// cannot be weakened. See internal/backup in magpie core.
//
// A .magpie-backup this plugin writes is opened by magpie's own import
// (Settings → Sync & backup → Import) with nothing else installed.

import crypto from "node:crypto";
import { promisify } from "node:util";

const pbkdf2 = promisify(crypto.pbkdf2);

export const FORMAT = "magpie-backup";
export const KDF = "pbkdf2-sha256";
export const ITERATIONS = 600_000;
const VERSION = 1;
const SALT_LEN = 16;
const NONCE_LEN = 12;
const TAG_LEN = 16;
const MAX_PLAIN = 96 << 20; // a backup with the library can be large

function err(code, message) { const e = new Error(message); e.code = code; return e; }

function header(e) {
  const salt = Buffer.from(e.salt, "base64");
  return `${e.format}/${e.version}/${e.kdf}/${e.iterations}/${salt.toString("hex")}`;
}

async function aead(pass, e) {
  const salt = Buffer.from(e.salt, "base64");
  const key = await pbkdf2(pass, salt, e.iterations, 32, "sha256");
  return { key, aad: Buffer.from(header(e), "utf8") };
}

export async function sealJSON(payload, pass) {
  if (String(pass || "").length < 8) throw err("SHORT_PASSPHRASE", "口令至少 8 个字符");
  const plain = Buffer.from(JSON.stringify(payload), "utf8");
  if (plain.length > MAX_PLAIN) throw err("TOO_LARGE", "备份内容太大");
  const salt = crypto.randomBytes(SALT_LEN);
  const nonce = crypto.randomBytes(NONCE_LEN);
  const e = {
    format: FORMAT, version: VERSION, kdf: KDF, iterations: ITERATIONS,
    salt: salt.toString("base64"), nonce: nonce.toString("base64"), data: "",
  };
  const { key, aad } = await aead(pass, e);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
  e.data = ct.toString("base64");
  return Buffer.from(JSON.stringify(e, null, 2), "utf8");
}

export async function openJSON(input, pass) {
  const raw = Buffer.isBuffer(input) ? input : Buffer.from(input);
  const text = raw.toString("utf8").replace(/^\uFEFF/, "");
  if (!text.trim()) throw err("NOT_BACKUP", "不是一个 magpie 备份文件");
  let e;
  try { e = JSON.parse(text); }
  catch {
    if (/^\s*\{\s*"format"\s*:\s*"magpie-backup"/.test(text)) throw err("CORRUPT", "备份文件损坏或被截断");
    throw err("NOT_BACKUP", "不是一个 magpie 备份文件");
  }
  if (!e || e.format !== FORMAT) throw err("NOT_BACKUP", "不是一个 magpie 备份文件");
  if (e.version > VERSION || e.kdf !== KDF) throw err("NEWER_ENVELOPE", "这个备份由更新版本的 magpie 封出");
  const salt = Buffer.from(e.salt || "", "base64");
  const nonce = Buffer.from(e.nonce || "", "base64");
  const ct = Buffer.from(e.data || "", "base64");
  if (e.version !== VERSION || !(e.iterations >= 100000 && e.iterations <= 10000000) ||
      salt.length < SALT_LEN || nonce.length !== NONCE_LEN ||
      ct.length <= TAG_LEN || ct.length > MAX_PLAIN + 1024) {
    throw err("CORRUPT", "备份文件损坏或被截断");
  }
  const { key, aad } = await aead(pass, e);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(ct.subarray(ct.length - TAG_LEN));
  let plain;
  try { plain = Buffer.concat([decipher.update(ct.subarray(0, ct.length - TAG_LEN)), decipher.final()]); }
  catch { throw err("WRONG_PASSPHRASE", "口令不对，或文件被改过"); }
  try { return JSON.parse(plain.toString("utf8")); }
  catch { throw err("CORRUPT", "备份内容不是有效 JSON"); }
}
