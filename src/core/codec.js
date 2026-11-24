/**
 * TraceBurp v3.3 安全工程师全能编解码与哈希核心模块
 * 零外部依赖，兼容 Chrome / Edge / Firefox 与 Node.js 18+ 测试环境。
 * 支持：URL(含全编码)、Base64/Base64URL、Hex、Unicode、HTML实体/十进制、
 * JWT解析、JSON美化/压缩、QueryString↔JSON、字符串转义/反转义、
 * Gzip+Base64压缩/解压、时间戳互转、MD5/SHA-1/SHA-256/SHA-512/HMAC-SHA256、智能识别。
 */

import {
  base64ToBytes,
  bytesToBase64,
  decodeHexStr,
  decodeUnicodeStr,
  decodeUrlStr,
  encodeHexStr,
  encodeUnicodeStr,
  encodeUrlStr,
  tryParseJSON,
  tsToDateStr,
} from "./utils.js";

/* ============================ URL 编解码 ============================ */

export function urlEncode(s) {
  return encodeUrlStr(s);
}

export function urlEncodeAll(s) {
  const bytes = new TextEncoder().encode(String(s ?? ""));
  return [...bytes].map((b) => "%" + b.toString(16).toUpperCase().padStart(2, "0")).join("");
}

export function urlDecode(s) {
  return decodeUrlStr(s);
}

/* ============================ Base64 / Base64URL ============================ */

export function base64Encode(s) {
  return bytesToBase64(new TextEncoder().encode(String(s ?? "")));
}

export function base64Decode(s) {
  const clean = String(s ?? "").trim().replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (!clean) throw new Error("空输入");
  return new TextDecoder("utf-8", { fatal: false }).decode(base64ToBytes(clean));
}

export function base64UrlEncode(s) {
  return base64Encode(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlDecode(s) {
  return base64Decode(s);
}

/* ============================ Hex 编解码 ============================ */

export function hexEncode(s) {
  const bytes = new TextEncoder().encode(String(s ?? ""));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function hexEncodeSpaced(s) {
  return encodeHexStr(s);
}

export function hexDecode(s) {
  return decodeHexStr(s);
}

/* ============================ Unicode & 字符串转义 ============================ */

export function unicodeEncode(s) {
  return encodeUnicodeStr(s);
}

export function unicodeDecode(s) {
  return decodeUnicodeStr(s);
}

/** 字符串转义（如将双引号/换行转为 \" 与 \n，适合嵌套 JSON 构造） */
export function escapeStr(s) {
  return JSON.stringify(String(s ?? "")).slice(1, -1);
}

/** 字符串反转义（将 \"、\n、\t、\\ 等还原） */
export function unescapeStr(s) {
  const raw = String(s ?? "");
  try {
    return JSON.parse(`"${raw.replace(/(?<!\\)"/g, '\\"')}"`);
  } catch {
    return decodeUnicodeStr(raw);
  }
}

/* ============================ HTML 实体编解码 ============================ */

const HTML_ENC_MAP = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

const HTML_DEC_MAP = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: " ",
};

export function htmlEncode(s) {
  return String(s ?? "").replace(/[&<>"']/g, (ch) => HTML_ENC_MAP[ch]);
}

export function htmlEncodeDecimal(s) {
  return [...String(s ?? "")].map((ch) => `&#${ch.codePointAt(0)};`).join("");
}

export function htmlDecode(s) {
  return String(s ?? "").replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);/g, (full, body) => {
    if (body.startsWith("#x") || body.startsWith("#X")) {
      const cp = parseInt(body.slice(2), 16);
      return Number.isFinite(cp) ? String.fromCodePoint(cp) : full;
    }
    if (body.startsWith("#")) {
      const cp = parseInt(body.slice(1), 10);
      return Number.isFinite(cp) ? String.fromCodePoint(cp) : full;
    }
    return HTML_DEC_MAP[body.toLowerCase()] ?? full;
  });
}

/* ============================ JWT 解析 ============================ */

export function jwtDecode(s) {
  const raw = String(s ?? "").trim().replace(/^Bearer\s+/i, "");
  const parts = raw.split(".");
  if (parts.length < 2 || parts.length > 3) {
    throw new Error("不是合法的 JWT（需包含 Header.Payload.Signature）");
  }
  const header = JSON.parse(base64UrlDecode(parts[0]));
  const payload = JSON.parse(base64UrlDecode(parts[1]));
  const meta = {};
  if (typeof payload.iat === "number") meta.issuedAt = new Date(payload.iat * 1000).toISOString();
  if (typeof payload.nbf === "number") meta.notBefore = new Date(payload.nbf * 1000).toISOString();
  if (typeof payload.exp === "number") {
    meta.expiresAt = new Date(payload.exp * 1000).toISOString();
    meta.expired = Date.now() / 1000 > payload.exp;
  }
  return JSON.stringify(
    {
      header,
      payload,
      ...(Object.keys(meta).length ? { _time: meta } : {}),
      signature: parts[2] || "",
    },
    null,
    2
  );
}

/* ============================ JSON & QueryString 互转 ============================ */

export function jsonPretty(s) {
  const p = tryParseJSON(String(s ?? ""));
  if (p === null) throw new Error("不是合法 JSON");
  return JSON.stringify(p, null, 2);
}

export function jsonMinify(s) {
  const p = tryParseJSON(String(s ?? ""));
  if (p === null) throw new Error("不是合法 JSON");
  return JSON.stringify(p);
}

export function queryToJson(s) {
  let raw = String(s ?? "").trim();
  if (!raw) throw new Error("空输入");
  const qIdx = raw.indexOf("?");
  if (qIdx >= 0) raw = raw.slice(qIdx + 1);
  const hashIdx = raw.indexOf("#");
  if (hashIdx >= 0) raw = raw.slice(0, hashIdx);
  const params = new URLSearchParams(raw);
  const out = {};
  let count = 0;
  for (const [k, v] of params.entries()) {
    count++;
    if (k in out) {
      out[k] = Array.isArray(out[k]) ? [...out[k], v] : [out[k], v];
    } else {
      out[k] = v;
    }
  }
  if (!count) throw new Error("未解析到有效的 Query 参数");
  return JSON.stringify(out, null, 2);
}

export function jsonToQuery(s) {
  const obj = tryParseJSON(String(s ?? ""));
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    throw new Error("请输入合法的 JSON 对象（如 {\"a\":1,\"b\":\"test\"}）");
  }
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(obj)) {
    if (Array.isArray(v)) {
      for (const item of v) params.append(k, item == null ? "" : String(item));
    } else if (v && typeof v === "object") {
      params.append(k, JSON.stringify(v));
    } else {
      params.append(k, v == null ? "" : String(v));
    }
  }
  return params.toString();
}

/* ============================ Gzip + Base64 压缩/解压 ============================ */

async function streamTransform(bytes, StreamCtor, format = "gzip") {
  if (typeof StreamCtor !== "function") {
    throw new Error("当前运行环境不支持原生 Gzip 流");
  }
  const cs = new StreamCtor(format);
  const writer = cs.writable.getWriter();
  writer.write(bytes);
  writer.close();
  const ab = await new Response(cs.readable).arrayBuffer();
  return new Uint8Array(ab);
}

export async function gzipB64Encode(s) {
  const raw = new TextEncoder().encode(String(s ?? ""));
  if (typeof CompressionStream === "function") {
    const out = await streamTransform(raw, CompressionStream, "gzip");
    return bytesToBase64(out);
  }
  if (typeof process !== "undefined" && process.versions?.node) {
    const zlib = await import("node:zlib");
    return bytesToBase64(new Uint8Array(zlib.gzipSync(raw)));
  }
  throw new Error("当前环境不支持 Gzip 压缩");
}

export async function gzipB64Decode(s) {
  const clean = String(s ?? "").trim().replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (!clean) throw new Error("空输入");
  const bytes = base64ToBytes(clean);
  if (typeof DecompressionStream === "function") {
    const out = await streamTransform(bytes, DecompressionStream, "gzip");
    return new TextDecoder("utf-8", { fatal: false }).decode(out);
  }
  if (typeof process !== "undefined" && process.versions?.node) {
    const zlib = await import("node:zlib");
    return new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(zlib.gunzipSync(bytes)));
  }
  throw new Error("当前环境不支持 Gzip 解压");
}

/* ============================ 时间戳互转 ============================ */

export function timestampToDate(s) {
  return tsToDateStr(s);
}

export function dateToTimestamp(s) {
  const raw = String(s ?? "").trim();
  const d = !raw || raw.toLowerCase() === "now" ? new Date() : new Date(raw);
  if (Number.isNaN(d.getTime())) throw new Error("无法解析日期，可输入 YYYY-MM-DD HH:mm:ss 或留空获取当前时间");
  const ms = d.getTime();
  return `秒 (10位): ${Math.floor(ms / 1000)}\n毫秒 (13位): ${ms}\nISO: ${d.toISOString()}`;
}

/* ============================ 哈希（MD5 / SHA-1 / SHA-256 / SHA-512 / HMAC-SHA256） ============================ */

function rotl(x, c) {
  return (x << c) | (x >>> (32 - c));
}

const MD5_S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const MD5_K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0);

export function md5(str) {
  const bytes = new TextEncoder().encode(String(str ?? ""));
  const bitLen = bytes.length * 8;
  const padLen = ((56 - ((bytes.length + 1) % 64)) + 64) % 64;
  const totalLen = bytes.length + 1 + padLen + 8;
  const buf = new Uint8Array(totalLen);
  buf.set(bytes);
  buf[bytes.length] = 0x80;

  const dv = new DataView(buf.buffer);
  dv.setUint32(totalLen - 8, bitLen >>> 0, true);
  dv.setUint32(totalLen - 4, Math.floor(bitLen / 0x100000000) >>> 0, true);

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;

  for (let offset = 0; offset < totalLen; offset += 64) {
    const M = new Uint32Array(16);
    for (let j = 0; j < 16; j++) M[j] = dv.getUint32(offset + j * 4, true);

    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + MD5_K[i] + M[g]) >>> 0;
      A = D; D = C; C = B;
      B = (B + rotl(F, MD5_S[i])) >>> 0;
    }

    a0 = (a0 + A) >>> 0;
    b0 = (b0 + B) >>> 0;
    c0 = (c0 + C) >>> 0;
    d0 = (d0 + D) >>> 0;
  }

  const out = new Uint8Array(16);
  const outDv = new DataView(out.buffer);
  outDv.setUint32(0, a0, true);
  outDv.setUint32(4, b0, true);
  outDv.setUint32(8, c0, true);
  outDv.setUint32(12, d0, true);
  return [...out].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function getSubtle() {
  let subtle = globalThis.crypto?.subtle;
  if (!subtle && typeof process !== "undefined" && process.versions?.node) {
    const mod = await import("node:crypto");
    subtle = mod.webcrypto?.subtle;
  }
  if (!subtle) throw new Error("当前环境不支持 WebCrypto");
  return subtle;
}

async function webCryptoHash(alg, str) {
  const subtle = await getSubtle();
  const bytes = new TextEncoder().encode(String(str ?? ""));
  const digest = await subtle.digest(alg, bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function sha1(str) { return webCryptoHash("SHA-1", str); }
export function sha256(str) { return webCryptoHash("SHA-256", str); }
export function sha512(str) { return webCryptoHash("SHA-512", str); }

export async function hmacSha256(str, secret = "") {
  const keyStr = String(secret ?? "");
  if (!keyStr) throw new Error("请先在右侧输入框填写 HMAC Secret Key");
  const subtle = await getSubtle();
  const enc = new TextEncoder();
  const key = await subtle.importKey(
    "raw",
    enc.encode(keyStr),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await subtle.sign("HMAC", key, enc.encode(String(str ?? "")));
  const u8 = new Uint8Array(sig);
  const hex = [...u8].map((b) => b.toString(16).padStart(2, "0")).join("");
  const b64 = bytesToBase64(u8);
  return `Hex: ${hex}\nBase64: ${b64}`;
}

/* ============================ 智能自动识别 ============================ */

export function detectEncodings(input) {
  const s = String(input ?? "").trim();
  if (!s) return [];
  const hits = [];

  if (/^(?:Bearer\s+)?eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/i.test(s)) {
    hits.push({ op: "jwt_dec", label: "识别为 JWT · 一键解析" });
  }
  if (/^H4sI[A-Za-z0-9+/_-]+=*$/.test(s)) {
    hits.push({ op: "gzip_dec", label: "识别为 Gzip Base64 · 解压" });
  }
  if (/^\d{10}$/.test(s) || /^\d{13}$/.test(s)) {
    hits.push({ op: "ts_to_date", label: "识别为时间戳 · 转日期" });
  }
  if ((s.startsWith("{") && s.endsWith("}")) || (s.startsWith("[") && s.endsWith("]"))) {
    if (tryParseJSON(s) !== null) hits.push({ op: "json_pretty", label: "识别为 JSON · 格式化" });
  }
  if (/%[0-9a-fA-F]{2}/.test(s)) {
    hits.push({ op: "url_dec", label: "检测到 URL 编码 · 解码" });
  }
  if (/^[^=\s]+=[^&\s]*(&[^=\s]+=[^&\s]*)+$/.test(s)) {
    hits.push({ op: "qs_to_json", label: "识别为 Query 参数 · 转 JSON" });
  }
  if (/\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]+\}|\\x[0-9a-fA-F]{2}/.test(s)) {
    hits.push({ op: "uni_dec", label: "检测到 Unicode 转义 · 解码" });
  }
  if (/&(?:#x[0-9a-fA-F]+|#[0-9]+|amp|lt|gt|quot|apos|nbsp);/i.test(s)) {
    hits.push({ op: "html_dec", label: "检测到 HTML 实体 · 解码" });
  }
  if (!hits.some((h) => h.op === "jwt_dec" || h.op === "gzip_dec") && s.length >= 8 && !/^\d+$/.test(s) && /^[A-Za-z0-9+/_-]+=*$/.test(s)) {
    try {
      const dec = base64Decode(s);
      const printable = [...dec].filter((c) => c.charCodeAt(0) >= 32 || c === "\n" || c === "\r" || c === "\t").length;
      if (dec.length > 0 && printable / dec.length > 0.85) {
        hits.push({ op: "b64_dec", label: "疑似 Base64 · 解码" });
      }
    } catch {}
  }
  const hexClean = s.replace(/\s+/g, "").replace(/^0x/i, "");
  if (hexClean.length >= 6 && hexClean.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(hexClean) && !/^\d+$/.test(hexClean)) {
    try {
      const dec = hexDecode(hexClean);
      const printable = [...dec].filter((c) => c.charCodeAt(0) >= 32 || c === "\n" || c === "\r" || c === "\t").length;
      if (dec.length > 0 && printable / dec.length > 0.85) {
        hits.push({ op: "hex_dec", label: "疑似 Hex · 解码" });
      }
    } catch {}
  }

  return hits.slice(0, 3);
}

/* ============================ 统一调度表 ============================ */

export const CODEC_OPS = {
  url_dec: { label: "URL 解码", fn: urlDecode },
  url_enc: { label: "URL 编码", fn: urlEncode },
  url_enc_all: { label: "URL 全编码", fn: urlEncodeAll },
  b64_dec: { label: "Base64 / URL 解码", fn: base64Decode },
  b64_enc: { label: "Base64 编码", fn: base64Encode },
  b64url_enc: { label: "Base64URL 编码", fn: base64UrlEncode },
  hex_dec: { label: "Hex 解码", fn: hexDecode },
  hex_enc: { label: "Hex 编码", fn: hexEncode },
  uni_dec: { label: "Unicode 解码", fn: unicodeDecode },
  uni_enc: { label: "Unicode 编码", fn: unicodeEncode },
  str_unesc: { label: "反转义", fn: unescapeStr },
  str_esc: { label: "转义", fn: escapeStr },
  html_dec: { label: "HTML 解码", fn: htmlDecode },
  html_enc: { label: "HTML 编码", fn: htmlEncode },
  html_dec_enc: { label: "HTML 十进制", fn: htmlEncodeDecimal },
  jwt_dec: { label: "JWT 解析", fn: jwtDecode },
  json_pretty: { label: "JSON 格式化", fn: jsonPretty },
  json_min: { label: "JSON 压缩", fn: jsonMinify },
  qs_to_json: { label: "Query → JSON", fn: queryToJson },
  json_to_qs: { label: "JSON → Query", fn: jsonToQuery },
  gzip_dec: { label: "Gzip Base64 解压", fn: gzipB64Decode },
  gzip_enc: { label: "Gzip Base64 压缩", fn: gzipB64Encode },
  ts_to_date: { label: "时间戳 → 日期", fn: timestampToDate },
  date_to_ts: { label: "日期 → 时间戳", fn: dateToTimestamp },
  hash_md5: { label: "MD5", fn: md5 },
  hash_sha1: { label: "SHA-1", fn: sha1 },
  hash_sha256: { label: "SHA-256", fn: sha256 },
  hash_sha512: { label: "SHA-512", fn: sha512 },
  hmac_sha256: { label: "HMAC-SHA256", fn: (s, opts) => hmacSha256(s, opts?.secret) },
};

export async function runCodecOp(op, input, opts = {}) {
  const entry = CODEC_OPS[op];
  if (!entry) throw new Error(`未知编解码操作：${op}`);
  return await entry.fn(input, opts);
}
