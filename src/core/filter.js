/**
 * TraceBurp v3.4 极简过滤引擎
 * - hideStatic（默认开）：过滤图片/字体/CSS/音视频等静态资源
 * - methods（Set）：按 GET / POST / PUT / DELETE / PATCH 多选过滤
 * - hasBody：仅显示包含请求体（Request Body）的请求
 * - only2xx / onlyError：状态码筛选（同时开启时按并集匹配，不会误清空列表）
 * - sameHost：仅当前目标主域
 * - bodySearchIds：正文全文检索结果（不与普通 URL 关键词冲突）
 */

import { getHost } from "./utils.js";

const STATIC_TYPES = new Set(["Image", "Font", "Stylesheet", "Media"]);
const STATIC_EXT_RE = /\.(png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|css|map|mp4|mp3|wav|avif)(\?|$)/i;

export function parseFilterQuery(raw) {
  const tokens = String(raw || "").trim().split(/\s+/).filter(Boolean);
  const rules = [];
  for (const tok of tokens) {
    const neg = tok.startsWith("-") && tok.length > 1;
    const body = neg ? tok.slice(1) : tok;
    const colon = body.indexOf(":");
    if (colon > 0) {
      const key = body.slice(0, colon).toLowerCase();
      const val = body.slice(colon + 1).toLowerCase();
      if (["status", "method", "host", "type", "ext", "mime"].includes(key) && val) {
        rules.push({ neg, key, val });
        continue;
      }
    }
    rules.push({ neg, key: "any", val: body.toLowerCase() });
  }
  return rules;
}

export function matchesRecord(rec, opts) {
  const {
    hideStatic = false,
    onlyApi = false,
    methods = null,
    hasBody = false,
    only2xx = false,
    onlyError = false,
    sameHost = false,
    currentHost = "",
    hiddenHosts = null,
    focusHost = "",
    rules = [],
    bodySearchIds = null,
  } = opts;

  if (hideStatic) {
    const isJson = /json|graphql|xml/i.test(rec.mimeType || "");
    if (!isJson && (STATIC_TYPES.has(rec.type) || STATIC_EXT_RE.test(rec.url || ""))) {
      return false;
    }
  }

  if (onlyApi) {
    const isApi = ["XHR", "Fetch", "Replay", "WebSocket"].includes(rec.type) || /json|graphql|xml/i.test(rec.mimeType || "");
    if (!isApi) return false;
  }

  if (methods && methods.size > 0) {
    if (!methods.has((rec.method || "GET").toUpperCase())) return false;
  }

  if (hasBody) {
    const hasReqBody = !!rec.hasPostData || (rec.reqBodyBytes || 0) > 0;
    if (!hasReqBody) return false;
  }

  if (only2xx || onlyError) {
    const is2xx = !rec.failed && typeof rec.status === "number" && rec.status >= 200 && rec.status < 300;
    const isErr = !!rec.failed || (typeof rec.status === "number" && rec.status >= 400);
    const ok = (only2xx && is2xx) || (onlyError && isErr);
    if (!ok) return false;
  }

  const host = getHost(rec.url || "").toLowerCase();
  if (focusHost && host !== focusHost.toLowerCase()) return false;
  if (hiddenHosts && hiddenHosts.size && hiddenHosts.has(host)) return false;

  if (sameHost && currentHost) {
    const base = currentHost.toLowerCase();
    if (host !== base && !host.endsWith("." + base)) return false;
  }

  const isBodySearch = bodySearchIds instanceof Set;
  if (isBodySearch && !bodySearchIds.has(rec.id)) {
    return false;
  }

  if (rules.length) {
    const urlLower = (rec.url || "").toLowerCase();
    const methodLower = (rec.method || "").toLowerCase();
    const statusStr = rec.status != null ? String(rec.status) : "";
    const typeLower = (rec.type || "").toLowerCase();
    const mimeLower = (rec.mimeType || "").toLowerCase();

    for (const r of rules) {
      if (isBodySearch && r.key === "any" && !r.neg) continue;

      let hit = false;
      switch (r.key) {
        case "status":
          hit = r.val.endsWith("xx") ? statusStr.startsWith(r.val[0]) : statusStr === r.val;
          break;
        case "method":
          hit = methodLower === r.val;
          break;
        case "host":
          hit = host.includes(r.val);
          break;
        case "type":
          hit = typeLower.includes(r.val);
          break;
        case "mime":
          hit = mimeLower.includes(r.val);
          break;
        case "ext": {
          const cleanPath = urlLower.split("?")[0].split("#")[0];
          hit = cleanPath.endsWith("." + r.val);
          break;
        }
        default: {
          const hay = `${urlLower} ${methodLower} ${statusStr} ${typeLower} ${mimeLower}`;
          hit = hay.includes(r.val);
          break;
        }
      }
      if (r.neg ? hit : !hit) return false;
    }
  }

  return true;
}

export function filterRecords(records, opts) {
  const rules = typeof opts.query === "string" ? parseFilterQuery(opts.query) : (opts.rules || []);
  const compiled = { ...opts, rules };
  return records.filter((r) => matchesRecord(r, compiled));
}
