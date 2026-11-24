/**
 * TraceBurp 安全透视与参数解析器
 * - 自动提取 Query / Form / JSON 参数
 * - 自动识别并解码 JWT（Header / Payload / 过期状态）
 * - 自动审计 Set-Cookie 安全属性（HttpOnly / Secure / SameSite）
 * - 自动检测 CORS 与关键安全响应头
 */

import { decodeBase64Str, findHeader, findAllHeaders } from "./utils.js";

const JWT_RE = /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*(?![A-Za-z0-9_-])/g;

export function parseJWT(token) {
  try {
    const parts = String(token).split(".");
    if (parts.length !== 3) return null;
    const header = JSON.parse(decodeBase64Str(parts[0]));
    const payload = JSON.parse(decodeBase64Str(parts[1]));
    if (!header || typeof header !== "object" || !payload || typeof payload !== "object") return null;

    let status = "no-exp";
    let expText = "";
    if (typeof payload.exp === "number") {
      const expMs = payload.exp * 1000;
      const diffSec = Math.round((expMs - Date.now()) / 1000);
      status = diffSec > 0 ? "valid" : "expired";
      expText = new Date(expMs).toLocaleString("zh-CN", { hour12: false });
    }
    return {
      raw: token,
      alg: header.alg || "unknown",
      header,
      payload,
      status,
      expText,
    };
  } catch {
    return null;
  }
}

export function extractJWTs(rec) {
  const found = new Map();
  const scan = (source, text) => {
    if (!text || typeof text !== "string") return;
    const matches = text.match(JWT_RE);
    if (!matches) return;
    for (const m of matches) {
      if (found.has(m)) continue;
      const parsed = parseJWT(m);
      if (parsed) found.set(m, { ...parsed, source });
    }
  };

  for (const h of rec.reqHeaders || []) scan(`请求头 ${h.name}`, h.value);
  for (const h of rec.resHeaders || []) scan(`响应头 ${h.name}`, h.value);
  if (rec.reqBody && !rec.reqBodyB64) scan("请求体", rec.reqBody);
  if (rec.resBody && !rec.resBodyB64) scan("响应体", rec.resBody);

  return [...found.values()];
}

export function auditSetCookies(resHeaders) {
  const rawList = findAllHeaders(resHeaders, "set-cookie");
  const issues = [];
  for (const raw of rawList) {
    const parts = raw.split(";").map((s) => s.trim()).filter(Boolean);
    if (!parts.length) continue;
    const eq = parts[0].indexOf("=");
    const name = eq > 0 ? parts[0].slice(0, eq).trim() : parts[0];
    const flags = parts.slice(1).map((p) => p.toLowerCase());
    const hasHttpOnly = flags.includes("httponly");
    const hasSecure = flags.includes("secure");
    const sameSite = flags.find((f) => f.startsWith("samesite=")) || "";

    const missing = [];
    if (!hasHttpOnly) missing.push("HttpOnly");
    if (!hasSecure) missing.push("Secure");
    if (!sameSite) missing.push("SameSite");

    if (missing.length) {
      issues.push({
        name,
        missing,
        severity: missing.includes("HttpOnly") || missing.includes("Secure") ? "warn" : "info",
        detail: `Set-Cookie "${name}" 缺少 ${missing.join(" / ")}`,
      });
    }
  }
  return issues;
}

export function auditSecurityHeaders(rec) {
  const hints = [];
  const resHeaders = rec.resHeaders || [];

  // 1. CORS 检查
  const acao = findHeader(resHeaders, "access-control-allow-origin");
  const acac = findHeader(resHeaders, "access-control-allow-credentials");
  if (acao) {
    if (acao === "*" && acac.toLowerCase() === "true") {
      hints.push({
        kind: "cors",
        severity: "high",
        title: "危险 CORS 组合",
        detail: "ACAO 为 * 且 Allow-Credentials 为 true",
      });
    } else if (acao === "*") {
      hints.push({
        kind: "cors",
        severity: "info",
        title: "宽松 CORS",
        detail: "Access-Control-Allow-Origin: *",
      });
    } else if (acac.toLowerCase() === "true") {
      const reqOrigin = findHeader(rec.reqHeaders, "origin");
      if (reqOrigin && reqOrigin === acao) {
        hints.push({
          kind: "cors",
          severity: "warn",
          title: "Origin 反射 + 凭证允许",
          detail: `ACAO 反射了请求源 ${acao} 且允许携带 Credentials，建议确认服务端白名单校验`,
        });
      }
    }
  }

  // 2. Cookie 审计
  const cookieIssues = auditSetCookies(resHeaders);
  for (const ci of cookieIssues) {
    hints.push({
      kind: "cookie",
      severity: ci.severity,
      title: `Cookie 属性缺失`,
      detail: ci.detail,
    });
  }

  // 3. JWT 审计
  const jwts = extractJWTs(rec);
  for (const j of jwts) {
    if (j.alg.toLowerCase() === "none") {
      hints.push({
        kind: "jwt",
        severity: "high",
        title: "JWT alg=none",
        detail: `在 ${j.source} 中发现未签名算法 alg=none 的 JWT`,
      });
    } else {
      hints.push({
        kind: "jwt",
        severity: j.status === "expired" ? "warn" : "info",
        title: `检测到 JWT (${j.alg})`,
        detail: `${j.source}${j.expText ? ` · 过期时间 ${j.expText}` : ""}`,
        jwt: j,
      });
    }
  }

  // 4. Document 响应基础安全头检查
  if (rec.type === "Document" && rec.status >= 200 && rec.status < 300) {
    const missing = [];
    if (!findHeader(resHeaders, "content-security-policy")) missing.push("CSP");
    if (!findHeader(resHeaders, "x-frame-options") && !findHeader(resHeaders, "content-security-policy").includes("frame-ancestors")) {
      missing.push("X-Frame-Options");
    }
    if ((rec.url || "").startsWith("https://") && !findHeader(resHeaders, "strict-transport-security")) {
      missing.push("HSTS");
    }
    if (missing.length) {
      hints.push({
        kind: "header",
        severity: "info",
        title: "页面缺少常见防护头",
        detail: `未设置：${missing.join("、")}`,
      });
    }
  }

  return { hints, jwts, cookieIssues };
}

/** 提取请求中的 Query / Form / JSON 参数供结构化展示 */
export function extractParams(rec) {
  const query = [];
  try {
    const u = new URL(rec.url || "");
    for (const [k, v] of u.searchParams.entries()) {
      query.push({ name: k, value: v, source: "Query" });
    }
  } catch {}

  const bodyParams = [];
  if (rec.reqBody && !rec.reqBodyB64) {
    const ctype = findHeader(rec.reqHeaders, "content-type").toLowerCase();
    const raw = rec.reqBody.trim();
    if (ctype.includes("application/x-www-form-urlencoded")) {
      try {
        const sp = new URLSearchParams(raw);
        for (const [k, v] of sp.entries()) {
          bodyParams.push({ name: k, value: v, source: "Form" });
        }
      } catch {}
    } else if (ctype.includes("json") || raw.startsWith("{") || raw.startsWith("[")) {
      try {
        const parsed = JSON.parse(raw);
        flattenJsonParams(parsed, "", bodyParams, 0);
      } catch {}
    }
  }

  return { query, bodyParams };
}

function flattenJsonParams(val, prefix, out, depth) {
  if (out.length >= 200 || depth > 5) return;
  if (val === null || typeof val !== "object") {
    if (prefix) out.push({ name: prefix, value: String(val), source: "JSON" });
    return;
  }
  if (Array.isArray(val)) {
    val.slice(0, 30).forEach((item, idx) => {
      flattenJsonParams(item, prefix ? `${prefix}[${idx}]` : `[${idx}]`, out, depth + 1);
    });
    return;
  }
  for (const [k, v] of Object.entries(val)) {
    if (out.length >= 200) break;
    const key = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === "object") {
      flattenJsonParams(v, key, out, depth + 1);
    } else {
      out.push({ name: key, value: v === null ? "null" : String(v), source: "JSON" });
    }
  }
}
