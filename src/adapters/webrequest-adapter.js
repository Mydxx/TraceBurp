/**
 * TraceBurp Firefox 捕获适配器
 * 基于 Firefox webRequest + webRequest.filterResponseData（无需调试横幅）
 * 支持过滤非 HTTP 噪音、Auto-Mock 本地覆写与静默响应替换（Match & Replace）。
 */

import {
  MAX_BODY_BYTES,
  bytesToBase64,
  clipBody,
  findHeader,
  headerObjToArr,
  looksBinary,
  uid,
} from "../core/utils.js";
import { applyResponseReplacements, isHttpUrl, isTextualMime } from "../core/replace.js";

const STATIC_TYPES = new Set(["image", "font", "stylesheet", "media"]);

function mapResourceType(t) {
  const map = {
    xmlhttprequest: "XHR",
    fetch: "Fetch",
    main_frame: "Document",
    sub_frame: "Document",
    script: "Script",
    stylesheet: "Stylesheet",
    image: "Image",
    media: "Media",
    font: "Font",
    websocket: "WebSocket",
  };
  return map[t] || "Other";
}

function decodeRequestBody(reqBody) {
  if (!reqBody) return null;
  if (reqBody.formData) {
    const pairs = [];
    for (const [k, vals] of Object.entries(reqBody.formData)) {
      for (const v of vals) pairs.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
    }
    return clipBody(pairs.join("&"), false);
  }
  if (Array.isArray(reqBody.raw) && reqBody.raw.length) {
    const chunks = reqBody.raw.filter((x) => x.bytes).map((x) => new Uint8Array(x.bytes));
    const total = chunks.reduce((a, b) => a + b.length, 0);
    if (!total) return null;
    const merged = new Uint8Array(Math.min(total, MAX_BODY_BYTES));
    let offset = 0;
    for (const c of chunks) {
      const take = Math.min(c.length, merged.length - offset);
      if (take <= 0) break;
      merged.set(c.subarray(0, take), offset);
      offset += take;
    }
    const b64 = bytesToBase64(merged);
    if (looksBinary("", b64)) {
      return { text: b64, b64: true, bytes: total, truncated: total > MAX_BODY_BYTES };
    }
    const text = new TextDecoder("utf-8", { fatal: false }).decode(merged);
    return { text, b64: false, bytes: total, truncated: total > MAX_BODY_BYTES };
  }
  return null;
}

export function createWebRequestAdapter(hooks) {
  const api = typeof browser !== "undefined" ? browser : chrome;
  const attachedTabs = new Set();
  const pending = new Map(); // requestId -> rec
  const pausedItems = new Map(); // requestId -> { ...item, resolvePromise }

  async function attach(tabId) {
    attachedTabs.add(tabId);
  }

  async function detach(tabId) {
    attachedTabs.delete(tabId);
    await releaseAllPausedForTab(tabId, "detached");
    for (const [rid, rec] of [...pending]) {
      if (rec.tabId === tabId) pending.delete(rid);
    }
  }

  async function probeAttached(tabId) {
    return attachedTabs.has(tabId);
  }

  async function setIntercept(tabId, enabled) {
    if (!enabled) await releaseAllPausedForTab(tabId, "disabled");
  }

  async function releaseAllPausedForTab(tabId, reason) {
    for (const [rid, item] of [...pausedItems]) {
      if (item.tabId !== tabId) continue;
      clearTimeout(item._timer);
      pausedItems.delete(rid);
      item._resolve?.({});
      hooks.onPausedResolved(rid, reason, item);
    }
  }

  function listPaused(tabId) {
    return [...pausedItems.values()]
      .filter((x) => !tabId || x.tabId === tabId)
      .map(({ _timer, _resolve, ...rest }) => rest);
  }

  async function resolvePaused(requestId, action, payload = {}) {
    const item = pausedItems.get(requestId);
    if (!item) throw new Error("该拦截请求已失效或已超时");
    clearTimeout(item._timer);
    pausedItems.delete(requestId);

    try {
      if (action === "fail") {
        item._resolve({ cancel: true });
      } else if (action === "continue") {
        const res = {};
        if (payload.url && payload.url !== item.url) res.redirectUrl = payload.url;
        item._resolve(res);
      } else if (action === "fulfill") {
        const rec = pending.get(requestId);
        if (rec) rec._mockResponse = payload;
        item._resolve({});
      } else {
        item._resolve({});
      }
    } finally {
      hooks.onPausedResolved(requestId, action, item);
    }
    return { ok: true };
  }

  const filter = { urls: ["<all_urls>"] };

  if (api?.webRequest) {
    api.webRequest.onBeforeRequest.addListener(
      (details) => {
        if (details.tabId < 0 || !attachedTabs.has(details.tabId)) return;
        if (!hooks.isRecording(details.tabId)) return;
        if (!isHttpUrl(details.url)) return;

        const clippedReq = decodeRequestBody(details.requestBody);
        const rec = {
          id: uid("rec"),
          tabId: details.tabId,
          cdpId: details.requestId,
          sessionId: null,
          method: details.method || "GET",
          url: details.url || "",
          type: mapResourceType(details.type),
          ts: Math.round(details.timeStamp || Date.now()),
          _startTs: Date.now(),
          duration: null,
          state: "pending",
          reqHeaders: [],
          reqBodyBytes: clippedReq ? clippedReq.bytes : 0,
          hasPostData: !!clippedReq,
          status: null,
          statusText: "",
          resHeaders: [],
          mimeType: "",
          resSize: 0,
          resBodyBytes: 0,
          fromCache: false,
          fromServiceWorker: false,
          remoteIP: "",
          remotePort: 0,
          protocol: "",
          timing: null,
          initiator: details.originUrl ? { type: "origin", url: details.originUrl } : null,
          documentURL: details.documentUrl || "",
          redirectChain: [],
          failed: null,
          origin: "captured",
          replayed: false,
          intercepted: false,
          mocked: false,
          replaced: false,
        };
        pending.set(details.requestId, rec);

        const reqInfo = {
          url: details.url || "",
          method: details.method || "GET",
          resourceType: rec.type,
          isStatic: STATIC_TYPES.has(details.type),
          stage: "Request",
        };
        const replaceRules = hooks.matchReplaceRules?.(details.tabId, { ...reqInfo, stage: "Response" }) || [];
        if (replaceRules.length) rec._replaceRules = replaceRules;

        const initBodies = clippedReq
          ? {
              reqBody: clippedReq.text,
              reqBodyB64: clippedReq.b64,
              reqBodyBytes: clippedReq.bytes,
              reqBodyTruncated: clippedReq.truncated,
            }
          : null;
        hooks.onRecordNew(rec, initBodies);

        // Firefox 响应流捕获与静默替换（filterResponseData）
        if (typeof api.webRequest.filterResponseData === "function") {
          try {
            const stream = api.webRequest.filterResponseData(details.requestId);
            const chunks = [];
            let total = 0;

            stream.ondata = (ev) => {
              const u8 = new Uint8Array(ev.data);
              if (rec._mockResponse) return;
              if (total < MAX_BODY_BYTES) {
                const remain = MAX_BODY_BYTES - total;
                chunks.push(u8.length > remain ? u8.subarray(0, remain) : u8);
              }
              total += u8.length;
              // 有静默响应替换规则时仅缓存文本且小于 2MB 的响应，超限或二进制立即直通防截断
              if (!rec._replaceRules || rec._replaceBypassed) {
                stream.write(ev.data);
              } else if (!isTextualMime(rec.mimeType) || total > MAX_BODY_BYTES) {
                rec._replaceBypassed = true;
                for (const c of chunks) stream.write(c);
                if (total > MAX_BODY_BYTES) stream.write(ev.data);
              }
            };

            stream.onstop = () => {
              if (rec._mockResponse) {
                const mockBytes = new TextEncoder().encode(String(rec._mockResponse.body ?? ""));
                stream.write(mockBytes);
                stream.disconnect();
                rec.resBodyBytes = mockBytes.length;
                rec.resSize = mockBytes.length;
                hooks.onRecordUpdate(rec, {
                  resBody: String(rec._mockResponse.body ?? ""),
                  resBodyB64: false,
                  resBodyBytes: mockBytes.length,
                  resBodyTruncated: false,
                });
                return;
              }

              const merged = new Uint8Array(Math.min(total, MAX_BODY_BYTES));
              let pos = 0;
              for (const c of chunks) {
                merged.set(c, pos);
                pos += c.length;
              }
              const b64 = bytesToBase64(merged);
              const binary = looksBinary(rec.mimeType, b64);

              if (rec._replaceRules && !rec._replaceBypassed) {
                if (!binary) {
                  const origText = new TextDecoder("utf-8", { fatal: false }).decode(merged);
                  const applied = applyResponseReplacements(origText, rec._replaceRules, rec.status || 200);
                  const outBytes = new TextEncoder().encode(applied.body);
                  stream.write(outBytes);
                  stream.disconnect();
                  if (applied.changed) rec.replaced = true;
                  rec.resBodyBytes = outBytes.length;
                  rec.resSize = outBytes.length;
                  hooks.onRecordUpdate(rec, {
                    resBody: applied.body,
                    resBodyB64: false,
                    resBodyBytes: outBytes.length,
                    resBodyTruncated: false,
                  });
                  return;
                }
                stream.write(merged);
              }

              stream.disconnect();
              rec.resBodyBytes = total;
              rec.resSize = total;
              hooks.onRecordUpdate(rec, {
                resBody: binary ? b64 : new TextDecoder("utf-8", { fatal: false }).decode(merged),
                resBodyB64: binary,
                resBodyBytes: total,
                resBodyTruncated: total > MAX_BODY_BYTES,
              });
            };
          } catch {}
        }

        // 1) 静默本地 Mock 覆写
        const mockRule = hooks.matchMockRule?.(details.tabId, reqInfo);
        if (mockRule) {
          rec._mockResponse = { body: mockRule.body ?? "" };
          rec.mocked = true;
          hooks.onRecordUpdate(rec, null);
          return;
        }

        // 2) 断点拦截匹配（仅 Request 阶段）
        const match = hooks.matchInterceptRule(details.tabId, reqInfo);
        if (!match) return;

        rec.intercepted = true;
        hooks.onRecordUpdate(rec, null);

        const timeoutMs = Math.max(2000, Number(match.pauseTimeoutMs) || 60000);
        return new Promise((resolve) => {
          const item = {
            requestId: details.requestId,
            rawRequestId: details.requestId,
            sessionId: null,
            tabId: details.tabId,
            ts: Date.now(),
            deadline: Date.now() + timeoutMs,
            url: details.url || "",
            method: details.method || "GET",
            headers: [],
            postData: clippedReq && !clippedReq.b64 ? clippedReq.text : null,
            hasPostData: !!clippedReq,
            resourceType: rec.type,
            ruleId: match.id,
            _resolve: resolve,
          };
          pausedItems.set(details.requestId, item);
          hooks.onPausedNew(item);
          item._timer = setTimeout(() => {
            if (!pausedItems.has(details.requestId)) return;
            pausedItems.delete(details.requestId);
            resolve({});
            hooks.onPausedResolved(details.requestId, "timeout", item);
          }, timeoutMs);
        });
      },
      filter,
      ["blocking", "requestBody"]
    );

    api.webRequest.onSendHeaders.addListener(
      (details) => {
        const rec = pending.get(details.requestId);
        if (!rec) return;
        rec.reqHeaders = headerObjToArr(details.requestHeaders);
        hooks.onRecordUpdate(rec, null);
      },
      filter,
      ["requestHeaders"]
    );

    api.webRequest.onHeadersReceived.addListener(
      (details) => {
        const rec = pending.get(details.requestId);
        if (!rec) return;
        rec.status = details.statusCode ?? 0;
        rec.statusText = details.statusLine || "";
        rec.resHeaders = headerObjToArr(details.responseHeaders);
        rec.mimeType = findHeader(rec.resHeaders, "content-type") || "";
        rec.remoteIP = details.ip || "";
        rec.fromCache = !!details.fromCache;
        hooks.onRecordUpdate(rec, null);
      },
      filter,
      ["responseHeaders"]
    );

    api.webRequest.onCompleted.addListener((details) => {
      const rec = pending.get(details.requestId);
      if (!rec) return;
      pending.delete(details.requestId);
      rec.state = "done";
      rec.duration = Date.now() - rec._startTs;
      hooks.onRecordUpdate(rec, null);
    }, filter);

    api.webRequest.onErrorOccurred.addListener((details) => {
      const rec = pending.get(details.requestId);
      if (!rec) return;
      pending.delete(details.requestId);
      rec.state = "failed";
      rec.failed = details.error || "Network error";
      rec.duration = Date.now() - rec._startTs;
      hooks.onRecordUpdate(rec, { resBodyError: rec.failed });
    }, filter);
  }

  return {
    name: "webrequest",
    supportsRequestBodyEdit: false,
    attach,
    detach,
    probeAttached,
    setIntercept,
    listPaused,
    resolvePaused,
    releaseAllPausedForTab,
  };
}
