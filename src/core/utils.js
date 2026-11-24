/**
 * TraceBurp 公共工具函数
 * 零依赖，同时兼容 Service Worker、Browser Panel 与 Node 测试环境。
 */

export const MAX_BODY_BYTES = 2 * 1024 * 1024; // 单条 body 最大 2MB
export const MAX_RECORDS_PER_TAB = 5000;

export function uid(prefix = "r") {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

export function byteLen(str) {
  if (!str) return 0;
  try {
    return new TextEncoder().encode(String(str)).length;
  } catch {
    return String(str).length;
  }
}

export function bytesToBase64(bytes) {
  let bin = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

export function base64ToBytes(b64) {
  if (!b64) return new Uint8Array(0);
  const clean = String(b64).replace(/\s+/g, "");
  const padded = clean.padEnd(Math.ceil(clean.length / 4) * 4, "=");
  const bin = atob(padded);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

export function textToBase64(str) {
  return bytesToBase64(new TextEncoder().encode(String(str ?? "")));
}

export function base64ToText(b64) {
  return new TextDecoder("utf-8", { fatal: false }).decode(base64ToBytes(b64));
}

/**
 * 截断大 Body：
 * - Base64 严格按 4 字节对齐截断，避免前端 atob() 抛 InvalidCharacterError
 * - 纯文本按 UTF-8 字节预算安全截断（避免拆裂 UTF-16 代理对）
 */
export function clipBody(text, isBase64, maxBytes = MAX_BODY_BYTES) {
  if (text == null) {
    return { text: null, b64: false, bytes: 0, truncated: false };
  }
  if (isBase64) {
    const raw = String(text);
    const approxBytes = Math.floor((raw.length * 3) / 4);
    const maxB64Len = Math.floor(maxBytes / 3) * 4; // 严格 4 的倍数
    if (raw.length > maxB64Len) {
      return {
        text: raw.slice(0, maxB64Len),
        b64: true,
        bytes: approxBytes,
        truncated: true,
      };
    }
    return { text: raw, b64: true, bytes: approxBytes, truncated: false };
  }

  const s = String(text);
  const totalBytes = byteLen(s);
  if (totalBytes <= maxBytes) {
    return { text: s, b64: false, bytes: totalBytes, truncated: false };
  }

  // 按字节编码后安全解码回合法 UTF-8 文本
  const encoded = new TextEncoder().encode(s).subarray(0, maxBytes);
  const clipped = new TextDecoder("utf-8", { fatal: false }).decode(encoded);
  return { text: clipped, b64: false, bytes: totalBytes, truncated: true };
}

export function headerObjToArr(obj) {
  if (!obj) return [];
  if (Array.isArray(obj)) {
    return obj
      .map((h) => (Array.isArray(h) ? { name: String(h[0]), value: String(h[1] ?? "") } : { name: String(h.name || ""), value: String(h.value ?? "") }))
      .filter((h) => h.name);
  }
  return Object.entries(obj).map(([name, value]) => ({ name, value: String(value ?? "") }));
}

export function parseHeaderText(text) {
  if (!text) return [];
  const lines = String(text).split(/\r?\n/);
  const out = [];
  for (const raw of lines) {
    const line = raw.trimEnd();
    if (!line || line.startsWith(" ") || line.startsWith("\t") || line.startsWith("#")) continue;
    if (/^HTTP\/\d/i.test(line)) continue;
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const name = line.slice(0, idx).trim();
    if (!name) continue;
    out.push({ name, value: line.slice(idx + 1).trim() });
  }
  return out;
}

export function headersToText(headers) {
  return (headers || []).map((h) => `${h.name}: ${h.value}`).join("\n");
}

export function findHeader(headers, name) {
  const target = name.toLowerCase();
  const hit = (headers || []).find((h) => String(h.name || "").toLowerCase() === target);
  return hit ? hit.value : "";
}

export function findAllHeaders(headers, name) {
  const target = name.toLowerCase();
  return (headers || [])
    .filter((h) => String(h.name || "").toLowerCase() === target)
    .map((h) => h.value);
}

export function looksBinary(mime, b64) {
  if (mime) {
    const m = mime.toLowerCase();
    if (/^(image|audio|video|font)\//.test(m)) return true;
    if (/octet-stream|protobuf|zip|gzip|pdf|wasm|msgpack|avro/.test(m)) return true;
  }
  if (!b64) return false;
  try {
    const head = String(b64).slice(0, 200);
    const bytes = base64ToBytes(head);
    let ctrl = 0;
    for (let i = 0; i < bytes.length; i++) {
      const c = bytes[i];
      if (c === 0) return true;
      if (c < 9 || (c > 13 && c < 32)) ctrl++;
    }
    return ctrl / Math.max(1, bytes.length) > 0.08;
  } catch {
    return false;
  }
}

export function fmtTime(ts) {
  if (!ts) return "";
  const d = new Date(ts);
  const p = (n, w = 2) => String(n).padStart(w, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

export function fmtSize(n) {
  if (n == null || n <= 0) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export function fmtDur(ms) {
  if (ms == null) return "";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

export function getHost(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

export function getPathAndQuery(url) {
  try {
    const u = new URL(url);
    return u.pathname + u.search;
  } catch {
    return String(url || "");
  }
}

/** 固定容量 LRU Cache，防止前端内存无限增长 */
export class LRUCache {
  constructor(limit = 60) {
    this.limit = limit;
    this.map = new Map();
  }
  get(key) {
    if (!this.map.has(key)) return undefined;
    const val = this.map.get(key);
    this.map.delete(key);
    this.map.set(key, val);
    return val;
  }
  set(key, val) {
    if (this.map.has(key)) this.map.delete(key);
    this.map.set(key, val);
    if (this.map.size > this.limit) {
      const oldest = this.map.keys().next().value;
      this.map.delete(oldest);
    }
  }
  delete(key) {
    this.map.delete(key);
  }
  clear() {
    this.map.clear();
  }
  has(key) {
    return this.map.has(key);
  }
}

/* ============================ 安全编解码工具 ============================ */

export function decodeBase64Str(s) {
  const clean = String(s).trim().replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (!clean) throw new Error("空输入");
  const bytes = base64ToBytes(clean);
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

export function encodeBase64Str(s) {
  return textToBase64(s);
}

export function decodeUrlStr(s) {
  const str = String(s);
  try {
    return decodeURIComponent(str.replace(/\+/g, " "));
  } catch {
    return decodeURIComponent(str);
  }
}

export function encodeUrlStr(s) {
  return encodeURIComponent(String(s));
}

export function decodeHexStr(s) {
  const clean = String(s).replace(/0x/gi, "").replace(/[^0-9a-fA-F]/g, "");
  if (!clean) throw new Error("无有效十六进制字符");
  if (clean.length % 2 !== 0) throw new Error("十六进制长度需为偶数");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

export function encodeHexStr(s) {
  const bytes = new TextEncoder().encode(String(s));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join(" ");
}

/** 正确处理反斜杠转义顺序，避免 \\n 被误解 */
export function decodeUnicodeStr(s) {
  return String(s).replace(
    /\\(\\|"|\/|n|r|t|u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2}))/g,
    (_, full, braceHex, uHex, xHex) => {
      if (braceHex) return String.fromCodePoint(parseInt(braceHex, 16));
      if (uHex) return String.fromCharCode(parseInt(uHex, 16));
      if (xHex) return String.fromCharCode(parseInt(xHex, 16));
      switch (full) {
        case "\\": return "\\";
        case '"': return '"';
        case "/": return "/";
        case "n": return "\n";
        case "r": return "\r";
        case "t": return "\t";
        default: return _;
      }
    }
  );
}

/** 支持代理对（emoji 等非 BMP 字符）的合法 Unicode 转义 */
export function encodeUnicodeStr(s) {
  const str = String(s);
  let out = "";
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code > 127) {
      out += "\\u" + code.toString(16).padStart(4, "0");
    } else {
      out += str[i];
    }
  }
  return out;
}

export function tsToDateStr(s) {
  const n = Number(String(s).trim());
  if (!Number.isFinite(n)) throw new Error("非有效数字时间戳");
  const ms = Math.abs(n) < 1e11 ? n * 1000 : n;
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) throw new Error("无法解析时间");
  return `${d.toLocaleString("zh-CN", { hour12: false })}\nUTC: ${d.toISOString()}`;
}

export function tryParseJSON(text) {
  if (!text || typeof text !== "string") return null;
  const t = text.trim();
  if (!t || (t[0] !== "{" && t[0] !== "[")) return null;
  try {
    return JSON.parse(t);
  } catch {
    return null;
  }
}
