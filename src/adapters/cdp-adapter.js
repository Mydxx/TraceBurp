/**
 * TraceBurp Chromium 捕获适配器（Chrome / Edge / Brave）
 * 支持：
 * - CDP Network / Fetch / Target 自动附加（主目标 + 子目标完整 sessionId 隔离）
 * - 严格过滤非 http/https 噪音（如 chrome-extension://、data:、blob:）
 * - Auto-Mock 本地响应覆写（请求阶段命中即静默返回）
 * - Response Match & Replace（响应阶段静默替换指定字段/状态码，不弹窗不卡顿）
 * - 行内断点拦截（请求/响应两阶段挂起等待处理，超时自动放行）
 */

import {
  base64ToText,
  clipBody,
  findHeader,
  headerObjToArr,
  parseHeaderText,
  textToBase64,
  uid,
} from "../core/utils.js";
import {
  applyResponseReplacements,
  cleanHeadersForFulfill,
  isHttpUrl,
  isTextualMime,
} from "../core/replace.js";

const NETWORK_ENABLE_PARAMS = {
  maxTotalBufferSize: 100 * 1024 * 1024,
  maxResourceBufferSize: 25 * 1024 * 1024,
  maxPostDataSize: 5 * 1024 * 1024,
};

const AUTO_ATTACH_PARAMS = {
  autoAttach: true,
  waitForDebuggerOnStart: false,
  flatten: true,
};

const STATIC_RESOURCE_TYPES = new Set(["Image", "Font", "Stylesheet", "Media"]);

function cdpKey(sessionId, requestId) {
  return sessionId ? `${sessionId}|${requestId}` : String(requestId);
}

function send(tabId, method, params = {}, sessionId = null) {
  const target = sessionId ? { tabId, sessionId } : { tabId };
  return chrome.debugger.sendCommand(target, method, params);
}

function sanitizeInitiator(init) {
  if (!init) return null;
  return {
    type: init.type || "",
    url: init.url || "",
    lineNumber: init.lineNumber ?? null,
    columnNumber: init.columnNumber ?? null,
    stack: init.stack?.callFrames?.slice(0, 8).map((f) => ({
      functionName: f.functionName || "",
      url: f.url || "",
      lineNumber: f.lineNumber ?? null,
      columnNumber: f.columnNumber ?? null,
    })),
  };
}

export function createCdpAdapter(hooks) {
  const tabData = new Map();
  const pausedItems = new Map();

  function getTabData(tabId) {
    let d = tabData.get(tabId);
    if (!d) {
      d = { pending: new Map(), childSessions: new Set(), fetchEnabled: false };
      tabData.set(tabId, d);
    }
    return d;
  }

  async function probeAttached(tabId) {
    try {
      await send(tabId, "Browser.getVersion");
      return true;
    } catch {
      return false;
    }
  }

  function buildFetchPatterns(tabId) {
    if (typeof hooks.getFetchPatterns === "function") {
      return hooks.getFetchPatterns(tabId);
    }
    const patterns = [{ urlPattern: "*", requestStage: "Request" }];
    if (hooks.hasResponseInterceptRules?.() || hooks.hasActiveReplaceRules?.()) {
      patterns.push({ urlPattern: "*", requestStage: "Response" });
    }
    return patterns;
  }

  async function syncFetchDomain(tabId, shouldEnable, forceRefresh = false) {
    const d = getTabData(tabId);
    const patterns = shouldEnable ? buildFetchPatterns(tabId) : [];
    const effectiveEnable = shouldEnable && patterns.length > 0;
    if (!forceRefresh && d.fetchEnabled === effectiveEnable) return;
    d.fetchEnabled = effectiveEnable;
    const targets = [null, ...d.childSessions];

    if (effectiveEnable) {
      await Promise.all(
        targets.map((sid) =>
          send(tabId, "Fetch.enable", { patterns }, sid).catch(() => {})
        )
      );
    } else {
      await releaseAllPausedForTab(tabId, "disabled");
      await Promise.all(
        targets.map((sid) => send(tabId, "Fetch.disable", {}, sid).catch(() => {}))
      );
    }
  }

  async function attach(tabId, { hasOrphanSession = false, enableFetch = false } = {}) {
    try {
      await chrome.debugger.attach({ tabId }, "1.3");
    } catch (e) {
      const msg = String(e?.message || e);
      if (/chrome-extension:\/\/ URL of different extension/i.test(msg)) {
        throw new Error("该页面已被其他扩展接管，Chrome 禁止跨扩展附加");
      }
      if (/Another debugger is already attached/i.test(msg)) {
        if (hasOrphanSession) {
          try {
            await chrome.debugger.detach({ tabId }).catch(() => {});
            await chrome.debugger.attach({ tabId }, "1.3");
          } catch {
            throw new Error("该标签页已被 DevTools 或其他调试扩展占用，请先关闭后重试");
          }
        } else {
          throw new Error("该标签页已被 DevTools 或其他调试扩展占用，请先关闭后重试");
        }
      } else {
        throw new Error(`附加失败：${msg}`);
      }
    }

    const d = getTabData(tabId);
    d.pending.clear();
    d.childSessions.clear();
    d.fetchEnabled = false;

    await send(tabId, "Network.enable", NETWORK_ENABLE_PARAMS);
    try {
      await send(tabId, "Target.setAutoAttach", AUTO_ATTACH_PARAMS);
    } catch {}
    if (enableFetch) {
      await syncFetchDomain(tabId, true);
    }
  }

  async function detach(tabId) {
    await releaseAllPausedForTab(tabId, "detached");
    try {
      await chrome.debugger.detach({ tabId });
    } catch {}
    tabData.delete(tabId);
  }

  async function setIntercept(tabId, enabled, forceRefresh = false) {
    await syncFetchDomain(tabId, enabled, forceRefresh);
  }

  async function releaseAllPausedForTab(tabId, reason) {
    for (const [key, item] of [...pausedItems]) {
      if (item.tabId !== tabId) continue;
      clearTimeout(item._timer);
      pausedItems.delete(key);
      try {
        const cmd = item.stage === "Response" ? "Fetch.continueResponse" : "Fetch.continueRequest";
        await send(tabId, cmd, { requestId: item.rawRequestId }, item.sessionId);
      } catch {}
      hooks.onPausedResolved(key, reason, item);
    }
  }

  function listPaused(tabId) {
    return [...pausedItems.values()]
      .filter((x) => !tabId || x.tabId === tabId)
      .map(({ _timer, ...rest }) => rest);
  }

  async function resolvePaused(pausedKey, action, payload = {}) {
    const item = pausedItems.get(pausedKey);
    if (!item) throw new Error("该拦截请求已失效（可能已超时放行或页面已跳转）");

    clearTimeout(item._timer);
    pausedItems.delete(pausedKey);
    const { tabId, sessionId, rawRequestId } = item;

    try {
      if (action === "continue") {
        if (item.stage === "Response") {
          await send(tabId, "Fetch.continueResponse", { requestId: rawRequestId }, sessionId);
        } else {
          const params = { requestId: rawRequestId };
          if (payload.url) params.url = payload.url;
          if (payload.method) params.method = payload.method;
          if (Array.isArray(payload.headers) && payload.headers.length) {
            params.headers = payload.headers
              .filter((h) => h.name && !h.name.startsWith(":"))
              .map((h) => ({ name: h.name, value: String(h.value ?? "") }));
          }
          if (payload.postData !== undefined && payload.postData !== null) {
            params.postData = payload.postDataB64 ? payload.postData : textToBase64(payload.postData);
          }
          await send(tabId, "Fetch.continueRequest", params, sessionId);
        }
      } else if (action === "fulfill") {
        const params = {
          requestId: rawRequestId,
          responseCode: Number(payload.responseCode) || 200,
          responseHeaders: cleanHeadersForFulfill(payload.responseHeaders || []),
        };
        if (payload.responsePhrase) params.responsePhrase = payload.responsePhrase;
        if (payload.body != null) {
          params.body = payload.bodyB64 ? payload.body : textToBase64(payload.body);
        }
        await send(tabId, "Fetch.fulfillRequest", params, sessionId);
      } else if (action === "fail") {
        await send(tabId, "Fetch.failRequest", {
          requestId: rawRequestId,
          errorReason: payload.errorReason || "BlockedByClient",
        }, sessionId);
      } else {
        throw new Error(`未知拦截操作：${action}`);
      }
    } finally {
      hooks.onPausedResolved(pausedKey, action, item);
    }
    return { ok: true };
  }

  /* ==================== CDP 事件 ==================== */

  async function onRequestWillBeSent(tabId, sessionId, p) {
    if (!hooks.isRecording(tabId)) return;
    const r = p.request || {};
    // 过滤 chrome-extension://、data:、blob: 等非 HTTP/HTTPS 噪音
    if (!isHttpUrl(r.url)) return;

    const d = getTabData(tabId);
    const key = cdpKey(sessionId, p.requestId);

    let inheritedChain = [];
    const prev = d.pending.get(key);
    if (prev) {
      if (p.redirectResponse) {
        const hopHeaders = headerObjToArr(p.redirectResponse.headers);
        const hop = {
          url: prev.url,
          status: p.redirectResponse.status,
          location: findHeader(hopHeaders, "location") || r.url || "",
        };
        inheritedChain = [...(prev.redirectChain || []), hop];
        prev.redirectChain = inheritedChain;
        prev.status = p.redirectResponse.status;
        prev.statusText = p.redirectResponse.statusText || "";
        prev.resHeaders = hopHeaders;
        prev.mimeType = p.redirectResponse.mimeType || prev.mimeType;
        prev.state = "done";
        prev.duration = Date.now() - prev._startTs;
        hooks.onRecordUpdate(prev, null);
      }
      d.pending.delete(key);
    }

    const reqHeaders = headerObjToArr(r.headers);
    const clippedReq = r.postData != null ? clipBody(r.postData, false) : null;

    const rec = {
      id: uid("rec"),
      tabId,
      cdpId: p.requestId,
      sessionId: sessionId || null,
      method: r.method || "GET",
      url: r.url || "",
      type: p.type || "Other",
      ts: p.wallTime ? Math.round(p.wallTime * 1000) : Date.now(),
      _startTs: Date.now(),
      duration: null,
      state: "pending",
      reqHeaders,
      reqBodyBytes: clippedReq ? clippedReq.bytes : 0,
      hasPostData: !!r.hasPostData || !!clippedReq,
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
      initiator: sanitizeInitiator(p.initiator),
      documentURL: p.documentURL || "",
      redirectChain: inheritedChain,
      failed: null,
      origin: "captured",
      replayed: false,
      intercepted: false,
      mocked: false,
      replaced: false,
    };

    d.pending.set(key, rec);

    const initBodies = clippedReq
      ? {
          reqBody: clippedReq.text,
          reqBodyB64: clippedReq.b64,
          reqBodyBytes: clippedReq.bytes,
          reqBodyTruncated: clippedReq.truncated,
        }
      : null;

    hooks.onRecordNew(rec, initBodies);

    if (!r.postData && r.hasPostData) {
      try {
        const post = await send(tabId, "Network.getRequestPostData", { requestId: p.requestId }, sessionId);
        if (post?.postData != null) {
          const c = clipBody(post.postData, false);
          rec.reqBodyBytes = c.bytes;
          hooks.onRecordUpdate(rec, {
            reqBody: c.text,
            reqBodyB64: c.b64,
            reqBodyBytes: c.bytes,
            reqBodyTruncated: c.truncated,
          });
        }
      } catch {}
    }
  }

  function onRequestExtraInfo(tabId, sessionId, p) {
    const rec = tabData.get(tabId)?.pending.get(cdpKey(sessionId, p.requestId));
    if (!rec) return;
    const arr = p.headersText ? parseHeaderText(p.headersText) : headerObjToArr(p.headers);
    if (arr.length) rec.reqHeaders = arr;
  }

  function onResponseReceived(tabId, sessionId, p) {
    const rec = tabData.get(tabId)?.pending.get(cdpKey(sessionId, p.requestId));
    if (!rec) return;
    const r = p.response || {};
    rec.status = r.status ?? 0;
    rec.statusText = r.statusText || "";
    rec.mimeType = r.mimeType || findHeader(headerObjToArr(r.headers), "content-type") || "";
    if (!rec._hasRealResHeaders) rec.resHeaders = headerObjToArr(r.headers);
    rec.fromCache = !!(r.fromDiskCache || r.fromPrefetchCache);
    rec.fromServiceWorker = !!r.fromServiceWorker;
    rec.remoteIP = r.remoteIPAddress || "";
    rec.remotePort = r.remotePort || 0;
    rec.protocol = r.protocol || "";
    rec.timing = r.timing || null;
    hooks.onRecordUpdate(rec, null);
  }

  function onResponseExtraInfo(tabId, sessionId, p) {
    const rec = tabData.get(tabId)?.pending.get(cdpKey(sessionId, p.requestId));
    if (!rec) return;
    const arr = p.headersText ? parseHeaderText(p.headersText) : headerObjToArr(p.headers);
    if (arr.length) {
      rec.resHeaders = arr;
      rec._hasRealResHeaders = true;
    }
    if (p.statusCode) rec.status = p.statusCode;
  }

  async function onLoadingFinished(tabId, sessionId, p) {
    const d = tabData.get(tabId);
    if (!d) return;
    const key = cdpKey(sessionId, p.requestId);
    const rec = d.pending.get(key);
    if (!rec) return;
    d.pending.delete(key);

    rec.state = "done";
    rec.duration = Date.now() - rec._startTs;
    rec.resSize = p.encodedDataLength || rec.resSize || 0;

    let resBodyPatch = null;
    try {
      const rb = await send(tabId, "Network.getResponseBody", { requestId: p.requestId }, sessionId);
      const clipped = clipBody(rb.body, !!rb.base64Encoded);
      rec.resBodyBytes = clipped.bytes;
      if (!rec.resSize && clipped.bytes) rec.resSize = clipped.bytes;
      resBodyPatch = {
        resBody: clipped.text,
        resBodyB64: clipped.b64,
        resBodyBytes: clipped.bytes,
        resBodyTruncated: clipped.truncated,
      };
    } catch (e) {
      resBodyPatch = { resBodyError: String(e?.message || e) };
    }

    delete rec._hasRealResHeaders;
    hooks.onRecordUpdate(rec, resBodyPatch);
  }

  function onLoadingFailed(tabId, sessionId, p) {
    const d = tabData.get(tabId);
    if (!d) return;
    const key = cdpKey(sessionId, p.requestId);
    const rec = d.pending.get(key);
    if (!rec) return;
    d.pending.delete(key);

    rec.state = "failed";
    rec.failed = p.errorText || p.blockedReason || "Request failed";
    rec.duration = Date.now() - rec._startTs;
    delete rec._hasRealResHeaders;
    hooks.onRecordUpdate(rec, { resBodyError: rec.failed });
  }

  async function onRequestPaused(tabId, sessionId, p) {
    const pausedKey = cdpKey(sessionId, p.requestId);
    const isResponseStage = p.responseStatusCode != null || Array.isArray(p.responseHeaders);
    try {
      const req = p.request || {};
      if (!isHttpUrl(req.url)) {
        await send(tabId, isResponseStage ? "Fetch.continueResponse" : "Fetch.continueRequest", { requestId: p.requestId }, sessionId);
        return;
      }

      const reqInfo = {
        url: req.url || "",
        method: req.method || "GET",
        resourceType: p.resourceType || "Other",
        isStatic: STATIC_RESOURCE_TYPES.has(p.resourceType),
        stage: isResponseStage ? "Response" : "Request",
      };

      // ===== 响应阶段 =====
      if (isResponseStage) {
        // 1) 优先执行静默响应替换规则（Match & Replace，跳过二进制响应防止误伤）
        const replaceRules = hooks.matchReplaceRules?.(tabId, reqInfo) || [];
        const resMime = findHeader(p.responseHeaders || [], "content-type");
        if (replaceRules.length && isTextualMime(resMime)) {
          let bodyText = "";
          let gotBody = false;
          try {
            const rb = await send(tabId, "Fetch.getResponseBody", { requestId: p.requestId }, sessionId);
            bodyText = rb?.base64Encoded ? base64ToText(rb.body || "") : String(rb?.body ?? "");
            gotBody = true;
          } catch {}

          const applied = applyResponseReplacements(
            gotBody ? bodyText : "",
            replaceRules,
            p.responseStatusCode || 200
          );

          if (applied.changed) {
            await send(tabId, "Fetch.fulfillRequest", {
              requestId: p.requestId,
              responseCode: applied.status,
              responseHeaders: cleanHeadersForFulfill(p.responseHeaders),
              body: textToBase64(applied.body),
            }, sessionId);

            if (p.networkId) {
              const rec = tabData.get(tabId)?.pending.get(cdpKey(sessionId, p.networkId));
              if (rec) {
                rec.replaced = true;
                hooks.onRecordUpdate(rec, null);
              }
            }
            return;
          }
        }

        // 2) 检查手动响应阶段断点规则
        const resRule = hooks.matchInterceptRule(tabId, reqInfo);
        if (!resRule) {
          await send(tabId, "Fetch.continueResponse", { requestId: p.requestId }, sessionId);
          return;
        }
        let resBody = "";
        let resBodyB64 = false;
        try {
          const rb = await send(tabId, "Fetch.getResponseBody", { requestId: p.requestId }, sessionId);
          resBody = rb?.body ?? "";
          resBodyB64 = !!rb?.base64Encoded;
        } catch {}

        const timeoutMs = Math.max(2000, Number(resRule.pauseTimeoutMs) || 60000);
        const item = {
          requestId: pausedKey,
          rawRequestId: p.requestId,
          sessionId: sessionId || null,
          tabId,
          stage: "Response",
          ts: Date.now(),
          deadline: Date.now() + timeoutMs,
          url: req.url || "",
          method: req.method || "GET",
          responseCode: p.responseStatusCode || 200,
          responseStatusText: p.responseStatusText || "",
          responseHeaders: (p.responseHeaders || []).map((h) => ({ name: h.name, value: String(h.value ?? "") })),
          responseBody: resBody,
          responseBodyB64: resBodyB64,
          resourceType: p.resourceType || "Other",
          ruleId: resRule.id,
        };
        pausedItems.set(pausedKey, item);
        hooks.onPausedNew(item);
        item._timer = setTimeout(() => {
          if (!pausedItems.has(pausedKey)) return;
          pausedItems.delete(pausedKey);
          send(tabId, "Fetch.continueResponse", { requestId: p.requestId }, sessionId).catch(() => {});
          hooks.onPausedResolved(pausedKey, "timeout", item);
        }, timeoutMs);
        return;
      }

      // ===== 请求阶段：1) 优先检查 Auto-Mock（静默响应覆写） =====
      const mockRule = hooks.matchMockRule?.(tabId, reqInfo);
      if (mockRule) {
        const bodyStr = String(mockRule.body ?? "");
        const resHeaders = [
          { name: "Content-Type", value: mockRule.contentType || "application/json; charset=utf-8" },
          { name: "X-TraceBurp-Mock", value: "true" },
          { name: "Access-Control-Allow-Origin", value: "*" },
        ];
        await send(tabId, "Fetch.fulfillRequest", {
          requestId: p.requestId,
          responseCode: Number(mockRule.status) || 200,
          responseHeaders: resHeaders,
          body: textToBase64(bodyStr),
        }, sessionId);

        if (p.networkId) {
          const rec = tabData.get(tabId)?.pending.get(cdpKey(sessionId, p.networkId));
          if (rec) {
            rec.mocked = true;
            hooks.onRecordUpdate(rec, null);
          }
        }
        return;
      }

      // 2) 检查断点拦截规则
      const match = hooks.matchInterceptRule(tabId, reqInfo);
      if (!match) {
        await send(tabId, "Fetch.continueRequest", { requestId: p.requestId }, sessionId);
        return;
      }

      const timeoutMs = Math.max(2000, Number(match.pauseTimeoutMs) || 60000);
      const item = {
        requestId: pausedKey,
        rawRequestId: p.requestId,
        sessionId: sessionId || null,
        tabId,
        stage: "Request",
        ts: Date.now(),
        deadline: Date.now() + timeoutMs,
        url: req.url || "",
        method: req.method || "GET",
        headers: headerObjToArr(req.headers),
        postData: req.postData ?? null,
        hasPostData: !!req.hasPostData,
        resourceType: p.resourceType || "Other",
        ruleId: match.id,
      };

      pausedItems.set(pausedKey, item);

      if (p.networkId) {
        const rec = tabData.get(tabId)?.pending.get(cdpKey(sessionId, p.networkId));
        if (rec) {
          rec.intercepted = true;
          hooks.onRecordUpdate(rec, null);
        }
      }

      hooks.onPausedNew(item);

      item._timer = setTimeout(() => {
        if (!pausedItems.has(pausedKey)) return;
        pausedItems.delete(pausedKey);
        send(tabId, "Fetch.continueRequest", { requestId: p.requestId }, sessionId).catch(() => {});
        hooks.onPausedResolved(pausedKey, "timeout", item);
      }, timeoutMs);
    } catch {
      try {
        await send(tabId, isResponseStage ? "Fetch.continueResponse" : "Fetch.continueRequest", { requestId: p.requestId }, sessionId);
      } catch {}
    }
  }

  function onTargetAttached(tabId, p) {
    const sid = p?.sessionId;
    if (!sid) return;
    const d = getTabData(tabId);
    d.childSessions.add(sid);
    send(tabId, "Network.enable", NETWORK_ENABLE_PARAMS, sid).catch(() => {});
    send(tabId, "Target.setAutoAttach", AUTO_ATTACH_PARAMS, sid).catch(() => {});
    if (d.fetchEnabled) {
      send(tabId, "Fetch.enable", { patterns: buildFetchPatterns(tabId) }, sid).catch(() => {});
    }
  }

  function onTargetDetached(tabId, p) {
    const sid = p?.sessionId;
    if (!sid) return;
    const d = tabData.get(tabId);
    if (!d) return;
    d.childSessions.delete(sid);
    const prefix = sid + "|";
    for (const k of [...d.pending.keys()]) {
      if (k.startsWith(prefix)) d.pending.delete(k);
    }
  }

  chrome.debugger.onEvent.addListener(async (source, method, params) => {
    const tabId = source.tabId;
    if (tabId == null) return;
    await hooks.waitReady();
    const sid = source.sessionId || null;

    switch (method) {
      case "Network.requestWillBeSent":
        onRequestWillBeSent(tabId, sid, params).catch(() => {});
        break;
      case "Network.requestWillBeSentExtraInfo":
        onRequestExtraInfo(tabId, sid, params);
        break;
      case "Network.responseReceived":
        onResponseReceived(tabId, sid, params);
        break;
      case "Network.responseReceivedExtraInfo":
        onResponseExtraInfo(tabId, sid, params);
        break;
      case "Network.loadingFinished":
        onLoadingFinished(tabId, sid, params).catch(() => {});
        break;
      case "Network.loadingFailed":
        onLoadingFailed(tabId, sid, params);
        break;
      case "Fetch.requestPaused":
        onRequestPaused(tabId, sid, params).catch(() => {});
        break;
      case "Target.attachedToTarget":
        onTargetAttached(tabId, params);
        break;
      case "Target.detachedFromTarget":
        onTargetDetached(tabId, params);
        break;
      default:
        break;
    }
  });

  chrome.debugger.onDetach.addListener((source, reason) => {
    const tabId = source.tabId;
    if (tabId == null) return;
    for (const [k, item] of [...pausedItems]) {
      if (item.tabId === tabId) {
        clearTimeout(item._timer);
        pausedItems.delete(k);
        hooks.onPausedResolved(k, "detached", item);
      }
    }
    tabData.delete(tabId);
    hooks.onExternalDetach(tabId, reason);
  });

  return {
    name: "cdp",
    supportsRequestBodyEdit: true,
    attach,
    detach,
    probeAttached,
    setIntercept,
    listPaused,
    resolvePaused,
    releaseAllPausedForTab,
  };
}
