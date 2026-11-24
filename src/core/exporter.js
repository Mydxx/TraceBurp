/**
 * TraceBurp 导出引擎
 * - 规范 HAR 1.2（完整映射 CDP timing，可选脱敏 Cookie/Authorization）
 * - Raw HTTP 报文（可直接粘贴进 Burp Repeater）
 * - 跨平台 cURL（Bash / PowerShell / Windows CMD，修复二进制注释续行与特殊字符转义）
 * - Python requests 脚本
 */

import { byteLen, findHeader } from "./utils.js";

const SENSITIVE_HEADER_RE = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-access-token|x-csrf-token)$/i;
const SKIP_CURL_HEADERS = /^(content-length|host|connection|accept-encoding|transfer-encoding)$/i;

export function redactHeaders(headers, redact = false) {
  const list = (headers || []).map((h) => ({ name: h.name, value: String(h.value ?? "") }));
  if (!redact) return list;
  return list.map((h) => (
    SENSITIVE_HEADER_RE.test(h.name)
      ? { name: h.name, value: "[REDACTED]" }
      : h
  ));
}

export function redactRecord(rec, redact = false) {
  if (!redact) return rec;
  return {
    ...rec,
    reqHeaders: redactHeaders(rec.reqHeaders, true),
    resHeaders: redactHeaders(rec.resHeaders, true),
  };
}

function isoDate(ts) {
  try {
    return new Date(ts || Date.now()).toISOString();
  } catch {
    return new Date().toISOString();
  }
}

function parseQueryString(url) {
  try {
    const u = new URL(url);
    return [...u.searchParams.entries()].map(([name, value]) => ({ name, value }));
  } catch {
    return [];
  }
}

function computeTimings(rec) {
  const t = rec.timing;
  const total = Math.max(0, Number(rec.duration) || 0);
  if (!t || typeof t !== "object") {
    return { blocked: -1, dns: -1, connect: -1, ssl: -1, send: 0, wait: total, receive: 0 };
  }
  const diff = (a, b) => (a >= 0 && b >= 0 && b >= a ? Math.round((b - a) * 100) / 100 : -1);
  const dns = diff(t.dnsStart, t.dnsEnd);
  const connect = diff(t.connectStart, t.connectEnd);
  const ssl = diff(t.sslStart, t.sslEnd);
  const send = Math.max(0, diff(t.sendStart, t.sendEnd));
  const wait = Math.max(0, diff(t.sendEnd, t.receiveHeadersEnd));
  const used = Math.max(0, dns) + Math.max(0, connect) + send + wait;
  const receive = Math.max(0, Math.round((total - used) * 100) / 100);
  return { blocked: -1, dns, connect, ssl, send, wait, receive };
}

export function toHAR(records, pageUrl = "", options = {}) {
  const redact = !!options.redact;
  const hasPage = !!pageUrl;
  return {
    log: {
      version: "1.2",
      creator: { name: "TraceBurp", version: "3.4.0" },
      pages: hasPage
        ? [{ startedDateTime: isoDate(records[0]?.ts), id: "page_1", title: pageUrl, pageTimings: {} }]
        : [],
      entries: records.map((r) => toHarEntry(redactRecord(r, redact), hasPage)),
    },
  };
}

function toHarEntry(rec, hasPage) {
  const reqSize = rec.reqBodyBytes || (rec.reqBody ? byteLen(rec.reqBody) : 0);
  const resSize = rec.resBodyBytes || rec.resSize || (rec.resBody ? byteLen(rec.resBody) : 0);
  const reqHeaders = (rec.reqHeaders || []).map((h) => ({ name: h.name, value: String(h.value ?? "") }));
  const resHeaders = (rec.resHeaders || []).map((h) => ({ name: h.name, value: String(h.value ?? "") }));

  const request = {
    method: rec.method || "GET",
    url: rec.url || "",
    httpVersion: rec.protocol || "HTTP/1.1",
    cookies: [],
    headers: reqHeaders,
    queryString: parseQueryString(rec.url || ""),
    ...(rec.reqBody
      ? {
          postData: {
            mimeType: findHeader(reqHeaders, "content-type") || "application/octet-stream",
            text: rec.reqBody,
            ...(rec.reqBodyB64 ? { encoding: "base64" } : {}),
          },
        }
      : {}),
    headersSize: -1,
    bodySize: reqSize,
  };

  const response = {
    status: rec.status || 0,
    statusText: rec.statusText || "",
    httpVersion: rec.protocol || "HTTP/1.1",
    cookies: [],
    headers: resHeaders,
    content: {
      size: resSize,
      mimeType: rec.mimeType || findHeader(resHeaders, "content-type") || "application/octet-stream",
      text: rec.resBody || "",
      ...(rec.resBodyB64 ? { encoding: "base64" } : {}),
    },
    redirectURL: findHeader(resHeaders, "location") || "",
    headersSize: -1,
    bodySize: resSize,
  };

  return {
    ...(hasPage ? { pageref: "page_1" } : {}),
    startedDateTime: isoDate(rec.ts),
    time: rec.duration || 0,
    request,
    response,
    cache: {},
    timings: computeTimings(rec),
    serverIPAddress: rec.remoteIP || "",
    connection: rec.remotePort ? String(rec.remotePort) : "",
    ...(rec.failed ? { _error: rec.failed } : {}),
  };
}

/** 导出 Raw HTTP 请求报文（可直接粘贴进 Burp Repeater） */
export function toRawHttp(rec, options = {}) {
  const r = redactRecord(rec, !!options.redact);
  let path = "/";
  let host = "";
  try {
    const u = new URL(r.url || "http://localhost/");
    path = (u.pathname || "/") + u.search;
    host = u.host;
  } catch {
    path = r.url || "/";
  }

  const lines = [`${(r.method || "GET").toUpperCase()} ${path} HTTP/1.1`];
  const hasHost = (r.reqHeaders || []).some((h) => h.name.toLowerCase() === "host");
  if (!hasHost && host) lines.push(`Host: ${host}`);

  for (const h of r.reqHeaders || []) {
    if (h.name.startsWith(":")) continue;
    lines.push(`${h.name}: ${h.value}`);
  }
  lines.push("");
  if (r.reqBody) {
    lines.push(r.reqBodyB64 ? `[Base64 Binary Body: ${r.reqBody.slice(0, 120)}...]` : r.reqBody);
  }
  return lines.join("\r\n");
}

function escapeSh(s) {
  return String(s).replace(/'/g, "'\\''");
}

function escapeCmd(s) {
  return String(s)
    .replace(/\r?\n/g, " ")
    .replace(/%/g, "%%")
    .replace(/"/g, '\\"');
}

function escapePs(s) {
  return String(s).replace(/'/g, "''");
}

/** Bash / macOS / Linux cURL */
export function toCurlBash(rec, options = {}) {
  const r = redactRecord(rec, !!options.redact);
  const lines = [`curl -X ${(r.method || "GET").toUpperCase()} '${escapeSh(r.url || "")}'`];
  for (const h of r.reqHeaders || []) {
    if (h.name.startsWith(":") || SKIP_CURL_HEADERS.test(h.name)) continue;
    lines.push(`  -H '${escapeSh(`${h.name}: ${h.value}`)}'`);
  }
  let suffixNote = "";
  if (r.reqBody) {
    if (r.reqBodyB64) {
      suffixNote = "\n# 注意：原始请求体为二进制（Base64），请导出 JSON 后使用 --data-binary @reqBody.bin";
    } else {
      lines.push(`  --data-raw '${escapeSh(r.reqBody)}'`);
    }
  }
  return lines.join(" \\\n") + suffixNote;
}

/** Windows CMD cURL */
export function toCurlCmd(rec, options = {}) {
  const r = redactRecord(rec, !!options.redact);
  const lines = [`curl -X ${(r.method || "GET").toUpperCase()} "${escapeCmd(r.url || "")}"`];
  for (const h of r.reqHeaders || []) {
    if (h.name.startsWith(":") || SKIP_CURL_HEADERS.test(h.name)) continue;
    lines.push(`  -H "${escapeCmd(`${h.name}: ${h.value}`)}"`);
  }
  let suffixNote = "";
  if (r.reqBody) {
    if (r.reqBodyB64) {
      suffixNote = '\nREM 注意：原始请求体为二进制，请导出 JSON 后使用 --data-binary "@reqBody.bin"';
    } else {
      lines.push(`  --data-raw "${escapeCmd(r.reqBody)}"`);
    }
  }
  return lines.join(" ^\n") + suffixNote;
}

/** PowerShell cURL (curl.exe) */
export function toCurlPowerShell(rec, options = {}) {
  const r = redactRecord(rec, !!options.redact);
  const lines = [`curl.exe -X ${(r.method || "GET").toUpperCase()} '${escapePs(r.url || "")}'`];
  for (const h of r.reqHeaders || []) {
    if (h.name.startsWith(":") || SKIP_CURL_HEADERS.test(h.name)) continue;
    lines.push(`  -H '${escapePs(`${h.name}: ${h.value}`)}'`);
  }
  let suffixNote = "";
  if (r.reqBody) {
    if (r.reqBodyB64) {
      suffixNote = "\n# 注意：原始请求体为二进制，请使用 --data-binary '@reqBody.bin'";
    } else {
      lines.push(`  --data-raw '${escapePs(r.reqBody)}'`);
    }
  }
  return lines.join(" `\n") + suffixNote;
}

/** Python requests 代码 */
export function toPython(rec, options = {}) {
  const r = redactRecord(rec, !!options.redact);
  const lines = ["import requests", ""];
  lines.push(`url = ${JSON.stringify(r.url || "")}`);
  lines.push("headers = {");
  for (const h of r.reqHeaders || []) {
    if (h.name.startsWith(":") || SKIP_CURL_HEADERS.test(h.name)) continue;
    lines.push(`    ${JSON.stringify(h.name)}: ${JSON.stringify(h.value)},`);
  }
  lines.push("}");
  if (r.reqBody) {
    if (r.reqBodyB64) {
      lines.push("import base64");
      lines.push(`data = base64.b64decode(${JSON.stringify(r.reqBody)})`);
    } else {
      lines.push(`data = ${JSON.stringify(r.reqBody)}.encode("utf-8")`);
    }
  } else {
    lines.push("data = None");
  }
  lines.push("");
  lines.push(`resp = requests.request(${JSON.stringify((r.method || "GET").toUpperCase())}, url, headers=headers, data=data, timeout=30)`);
  lines.push("print(resp.status_code, len(resp.content))");
  lines.push("print(resp.text[:2000])");
  return lines.join("\n");
}
