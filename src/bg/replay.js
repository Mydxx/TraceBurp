/**
 * TraceBurp v3.1 重放引擎
 * 修复：
 * - DNR 临时会话规则串行互斥锁，防止并发发包互相覆盖 Cookie/Origin
 * - 对含通配符(*, ^, |)或非 ASCII 字符的 URL 安全转义并自动编码，避免 DNR 规则报错降级
 * - 使用 headers.append() 保留同名多值 Header
 */

import { MAX_BODY_BYTES, base64ToBytes, bytesToBase64, headerObjToArr } from "../core/utils.js";

const FORBIDDEN_FETCH_HEADERS = new Set([
  "host", "connection", "content-length", "transfer-encoding",
  "upgrade", "keep-alive", "proxy-connection", "te", "trailer", "expect",
]);

const DNR_MANAGED_HEADERS = new Set(["cookie", "origin", "referer", "user-agent"]);
const AUTH_HEADER_RE = /^(authorization|proxy-authorization|cookie|x-api-key|x-auth-token|x-access-token|x-csrf-token|x-xsrf-token)$/i;

let nextDnrRuleId = 20000 + Math.floor(Math.random() * 50000);
let dnrLock = Promise.resolve();

function serializeDnr(task) {
  const run = dnrLock.then(task, task);
  dnrLock = run.then(() => {}, () => {});
  return run;
}

function normalizeSpecHeaders(headers, stripAuth = false) {
  return headerObjToArr(headers).filter((h) => {
    if (!h.name || h.name.startsWith(":")) return false;
    if (stripAuth && AUTH_HEADER_RE.test(h.name)) return false;
    return true;
  });
}

function buildDnrCondition(rawUrl) {
  let asciiUrl = String(rawUrl).split("#")[0];
  try {
    asciiUrl = new URL(asciiUrl).href.split("#")[0];
  } catch {}

  const resourceTypes = ["xmlhttprequest", "other", "main_frame", "sub_frame"];
  // 若 URL 含 urlFilter 特殊通配符（* / ^ / |），改用安全的正则精确匹配
  if (/[*^|]/.test(asciiUrl)) {
    const escaped = asciiUrl.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return { regexFilter: `^${escaped}$`, resourceTypes };
  }
  return { urlFilter: `|${asciiUrl}|`, resourceTypes };
}

async function withDnrHeaderOverrides(url, headers, stripAuth, fn) {
  const api = typeof browser !== "undefined" ? browser : chrome;
  const dnr = api?.declarativeNetRequest;
  if (!dnr?.updateSessionRules) return fn();

  const requestHeaders = [];
  if (stripAuth) {
    requestHeaders.push({ header: "cookie", operation: "remove" });
  } else {
    for (const h of headers) {
      const ln = h.name.toLowerCase();
      if (DNR_MANAGED_HEADERS.has(ln)) {
        requestHeaders.push({ header: h.name, operation: "set", value: String(h.value ?? "") });
      }
    }
  }

  if (!requestHeaders.length) return fn();

  // 串行化带 DNR 覆写的请求，彻底消除并发发包互相覆盖 Cookie/Origin 的竞态
  return serializeDnr(async () => {
    const ruleId = ++nextDnrRuleId;
    const condition = buildDnrCondition(url);
    try {
      await dnr.updateSessionRules({
        addRules: [{
          id: ruleId,
          priority: 100,
          action: { type: "modifyHeaders", requestHeaders },
          condition,
        }],
      });
    } catch (e) {
      console.warn("[TraceBurp] DNR 临时头覆写规则安装失败，降级普通 fetch", e);
      return fn();
    }

    try {
      return await fn();
    } finally {
      try {
        await dnr.updateSessionRules({ removeRuleIds: [ruleId] });
      } catch {}
    }
  });
}

async function replayInPage(tabId, spec) {
  const api = typeof browser !== "undefined" ? browser : chrome;
  const stripAuth = !!spec.stripAuth;
  const normHeaders = normalizeSpecHeaders(spec.headers, stripAuth);

  return withDnrHeaderOverrides(spec.url, normHeaders, stripAuth, async () => {
    const results = await api.scripting.executeScript({
      target: { tabId },
      world: "MAIN",
      func: (P) => {
        return (async () => {
          const t0 = Date.now();
          const ctrl = new AbortController();
          const timer = setTimeout(() => ctrl.abort(), P.timeoutMs);
          try {
            try {
              if (location.protocol === "https:" && new URL(P.url).protocol === "http:") {
                return {
                  ok: false,
                  error: "混合内容被阻止：HTTPS 页面无法直接请求 HTTP 地址，请切换到「后台通道」",
                  hint: "mixed-content",
                  duration: Date.now() - t0,
                };
              }
            } catch {}

            const hdrs = new Headers();
            for (const h of P.headers || []) {
              const ln = h.name.toLowerCase();
              if (["host", "content-length", "connection", "transfer-encoding", "cookie", "origin", "referer", "user-agent"].includes(ln)) continue;
              try { hdrs.append(h.name, h.value); } catch {}
            }

            let bodyInit = null;
            const m = (P.method || "GET").toUpperCase();
            if (P.body != null && m !== "GET" && m !== "HEAD") {
              if (P.bodyIsBase64) {
                const bin = atob(P.body);
                const u8 = new Uint8Array(bin.length);
                for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
                bodyInit = u8;
              } else {
                bodyInit = P.body;
              }
            }

            const res = await fetch(P.url, {
              method: m,
              headers: hdrs,
              body: bodyInit,
              credentials: P.stripAuth ? "omit" : "include",
              redirect: P.followRedirect ? "follow" : "manual",
              cache: "no-store",
              signal: ctrl.signal,
            });

            const ab = await res.arrayBuffer();
            const bytes = new Uint8Array(ab);
            const slice = bytes.length > P.limit ? bytes.subarray(0, P.limit) : bytes;
            let bin = "";
            const CH = 0x8000;
            for (let i = 0; i < slice.length; i += CH) {
              bin += String.fromCharCode.apply(null, slice.subarray(i, i + CH));
            }
            const headersArr = [];
            res.headers.forEach((v, k) => headersArr.push([k, v]));

            return {
              ok: true,
              status: res.status,
              statusText: res.statusText || "",
              headers: headersArr,
              body: btoa(bin),
              bodyB64: true,
              size: bytes.length,
              truncated: bytes.length > P.limit,
              url: res.url || P.url,
              redirected: res.redirected,
              duration: Date.now() - t0,
            };
          } catch (e) {
            if (e && e.name === "AbortError") {
              return { ok: false, error: `请求超时（${P.timeoutMs}ms）`, hint: "timeout", duration: Date.now() - t0 };
            }
            return {
              ok: false,
              error: "页面上下文请求失败（CORS/CSP 或网络问题），请切换到「后台通道」重试",
              hint: "cors",
              duration: Date.now() - t0,
            };
          } finally {
            clearTimeout(timer);
          }
        })();
      },
      args: [{
        method: spec.method || "GET",
        url: spec.url,
        headers: normHeaders,
        body: spec.body ?? null,
        bodyIsBase64: !!spec.bodyIsBase64,
        followRedirect: spec.followRedirect !== false,
        stripAuth,
        timeoutMs: Math.max(1000, spec.timeoutMs || 30000),
        limit: MAX_BODY_BYTES,
      }],
    });

    const val = results?.[0]?.result;
    if (!val) return { ok: false, error: "页面注入无返回（可能为受限页面或页面已导航）", hint: "page" };
    return val;
  });
}

async function replayInBackground(spec) {
  const stripAuth = !!spec.stripAuth;
  const normHeaders = normalizeSpecHeaders(spec.headers, stripAuth);

  return withDnrHeaderOverrides(spec.url, normHeaders, stripAuth, async () => {
    const t0 = Date.now();
    const ctrl = new AbortController();
    const timeoutMs = Math.max(1000, spec.timeoutMs || 30000);
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);

    try {
      const hdrs = new Headers();
      for (const h of normHeaders) {
        const ln = h.name.toLowerCase();
        if (FORBIDDEN_FETCH_HEADERS.has(ln) || DNR_MANAGED_HEADERS.has(ln)) continue;
        try { hdrs.append(h.name, h.value); } catch {}
      }

      let bodyInit = null;
      const m = (spec.method || "GET").toUpperCase();
      if (spec.body != null && m !== "GET" && m !== "HEAD") {
        bodyInit = spec.bodyIsBase64 ? base64ToBytes(spec.body) : spec.body;
      }

      const res = await fetch(spec.url, {
        method: m,
        headers: hdrs,
        body: bodyInit,
        credentials: stripAuth ? "omit" : "include",
        redirect: spec.followRedirect !== false ? "follow" : "manual",
        cache: "no-store",
        signal: ctrl.signal,
      });

      const ab = await res.arrayBuffer();
      const bytes = new Uint8Array(ab);
      const slice = bytes.length > MAX_BODY_BYTES ? bytes.subarray(0, MAX_BODY_BYTES) : bytes;
      const headersArr = [];
      res.headers.forEach((v, k) => headersArr.push([k, v]));

      return {
        ok: true,
        status: res.status,
        statusText: res.statusText || "",
        headers: headersArr,
        body: bytesToBase64(slice),
        bodyB64: true,
        size: bytes.length,
        truncated: bytes.length > MAX_BODY_BYTES,
        url: res.url || spec.url,
        redirected: res.redirected,
        duration: Date.now() - t0,
      };
    } catch (e) {
      if (e && e.name === "AbortError") {
        return { ok: false, error: `请求超时（${timeoutMs}ms）`, hint: "timeout", duration: Date.now() - t0 };
      }
      return {
        ok: false,
        error: "后台请求失败：请检查域名、端口、证书或网络连通性",
        hint: "network",
        duration: Date.now() - t0,
      };
    } finally {
      clearTimeout(timer);
    }
  });
}

export async function executeReplay(spec, ctx = {}) {
  if (!spec?.url) return { ok: false, error: "URL 不能为空", hint: "bad-url" };
  try {
    const u = new URL(spec.url);
    if (!/^https?:$/.test(u.protocol)) {
      return { ok: false, error: `仅支持 http / https 协议（当前为 ${u.protocol}）`, hint: "bad-url" };
    }
  } catch {
    return { ok: false, error: `URL 格式无效：${spec.url}`, hint: "bad-url" };
  }

  const mode = spec.mode || "background";
  if (mode === "background" || !ctx.tabId) {
    return replayInBackground(spec);
  }
  try {
    return await replayInPage(ctx.tabId, spec);
  } catch (e) {
    return { ok: false, error: `页面通道执行失败：${e?.message || e}`, hint: "page" };
  }
}
