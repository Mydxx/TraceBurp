/**
 * TraceBurp v3.2 后台控制面
 * - 点击扩展图标直接打开/聚焦全屏工作台（保留侧边栏手动打开兼容）
 * - 断点规则（请求前 / 响应后）+ 行内一键打断点
 * - 本地 Mock（请求阶段静默返回）
 * - 响应替换（Response Match & Replace：响应阶段静默替换指定文本/正则/状态码）
 * - 身份预设（Auth Profiles）持久化，支持一键切换身份对比发包
 */

import {
  batchWrite,
  clearTab,
  countTab,
  deleteRecord,
  exportTab,
  getRecord,
  listRecords,
  pruneDeadTabs,
  pruneTab,
  searchTabBodies,
} from "../core/db.js";
import {
  redactRecord,
  toCurlBash,
  toCurlCmd,
  toCurlPowerShell,
  toHAR,
  toPython,
  toRawHttp,
} from "../core/exporter.js";
import { MAX_RECORDS_PER_TAB, byteLen, uid } from "../core/utils.js";
import { buildFetchPatterns } from "../core/replace.js";
import { createCdpAdapter } from "../adapters/cdp-adapter.js";
import { createWebRequestAdapter } from "../adapters/webrequest-adapter.js";
import { executeReplay } from "./replay.js";

const api = typeof browser !== "undefined" ? browser : chrome;
const RULES_KEY = "traceburp_rules_v2";
const MOCKS_KEY = "traceburp_mocks_v2";
const REPLACES_KEY = "traceburp_replaces_v2";
const PROFILES_KEY = "traceburp_auth_profiles_v2";
const SESSION_PREFIX = "tb_sess_";

if (typeof chrome !== "undefined" && chrome.sidePanel?.setPanelBehavior) {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false }).catch(() => {});
}

async function openOrFocusWorkbench(targetTabId = null) {
  const base = api.runtime.getURL("panel/panel.html");
  const allTabs = await api.tabs.query({});
  const existing = allTabs.find((x) => (x.url || "").startsWith(base));
  if (existing) {
    await api.tabs.update(existing.id, { active: true });
    await api.windows.update(existing.windowId, { focused: true }).catch(() => {});
    if (targetTabId) broadcast({ type: "panel:focusTab", tabId: targetTabId });
    return existing.id;
  }
  const url = base + (targetTabId ? `?tabId=${targetTabId}` : "");
  const created = await api.tabs.create({ url });
  return created.id;
}

if (api.action?.onClicked) {
  api.action.onClicked.addListener(async (tab) => {
    const validTarget = tab?.id && /^https?:/i.test(tab.url || "") ? tab.id : null;
    await openOrFocusWorkbench(validTarget);
  });
}

/* ============================ 运行态 ============================ */

const sessions = new Map();
let globalRules = [];
let globalMocks = [];
let globalReplaces = [];
let authProfiles = [];
const ports = new Set();

const writeBuffer = [];
let writeTimer = null;
let flushing = false;
const tabWriteCounts = new Map();
let keepAliveTimer = null;

function broadcast(msg) {
  for (const p of [...ports]) {
    try { p.postMessage(msg); } catch { ports.delete(p); }
  }
  try {
    const res = api.runtime.sendMessage(msg);
    if (res && typeof res.catch === "function") res.catch(() => {});
  } catch {}
}

api.runtime.onConnect.addListener((port) => {
  if (port.name !== "traceburp-panel") return;
  ports.add(port);
  port.onDisconnect.addListener(() => ports.delete(port));
});

/* ============================ 批量写库 ============================ */

function scheduleFlush() {
  if (writeTimer) return;
  writeTimer = setTimeout(flushWrites, 120);
}

async function flushWrites() {
  writeTimer = null;
  if (flushing || !writeBuffer.length) return;
  flushing = true;
  try {
    while (writeBuffer.length) {
      const batch = writeBuffer.splice(0, 50);
      await batchWrite(batch);
    }
  } catch (e) {
    console.error("[TraceBurp] 批量写库失败", e);
  } finally {
    flushing = false;
    if (writeBuffer.length) scheduleFlush();
  }
}

function enqueueWrite(rec, bodies, replaceBody = false) {
  writeBuffer.push({ rec, bodies, replaceBody });
  if (writeBuffer.length >= 40) {
    if (writeTimer) { clearTimeout(writeTimer); writeTimer = null; }
    flushWrites();
  } else {
    scheduleFlush();
  }

  if (rec?.tabId && rec.state === "done") {
    const n = (tabWriteCounts.get(rec.tabId) || 0) + 1;
    if (n >= 400) {
      tabWriteCounts.set(rec.tabId, 0);
      pruneTab(rec.tabId, MAX_RECORDS_PER_TAB).catch(() => {});
    } else {
      tabWriteCounts.set(rec.tabId, n);
    }
  }
}

function listView(rec) {
  return {
    id: rec.id,
    tabId: rec.tabId,
    method: rec.method,
    url: rec.url,
    status: rec.status,
    statusText: rec.statusText,
    type: rec.type,
    mimeType: rec.mimeType,
    ts: rec.ts,
    duration: rec.duration,
    resSize: rec.resSize || 0,
    reqBodyBytes: rec.reqBodyBytes || 0,
    resBodyBytes: rec.resBodyBytes || 0,
    hasPostData: !!rec.hasPostData,
    state: rec.state,
    failed: rec.failed,
    fromCache: !!rec.fromCache,
    fromServiceWorker: !!rec.fromServiceWorker,
    replayed: !!rec.replayed,
    origin: rec.origin || "captured",
    intercepted: !!rec.intercepted,
    mocked: !!rec.mocked,
    replaced: !!rec.replaced,
    hasAuth: (rec.reqHeaders || []).some((h) => /^(authorization|cookie|x-api-key|x-auth-token)$/i.test(h.name)),
  };
}

function syncKeepAlive() {
  const active = [...sessions.values()].some((s) => s.attached);
  if (active && !keepAliveTimer) {
    keepAliveTimer = setInterval(() => {
      try { api.runtime.getPlatformInfo?.(() => {}); } catch {}
      if (![...sessions.values()].some((s) => s.attached)) {
        clearInterval(keepAliveTimer);
        keepAliveTimer = null;
      }
    }, 20000);
  } else if (!active && keepAliveTimer) {
    clearInterval(keepAliveTimer);
    keepAliveTimer = null;
  }
}

/* ============================ 持久化 ============================ */

async function loadPersistedConfig() {
  try {
    const got = await api.storage.local.get([RULES_KEY, MOCKS_KEY, REPLACES_KEY, PROFILES_KEY]);
    globalRules = Array.isArray(got?.[RULES_KEY]) ? got[RULES_KEY] : [];
    globalMocks = Array.isArray(got?.[MOCKS_KEY]) ? got[MOCKS_KEY] : [];
    globalReplaces = Array.isArray(got?.[REPLACES_KEY]) ? got[REPLACES_KEY] : [];
    authProfiles = Array.isArray(got?.[PROFILES_KEY]) ? got[PROFILES_KEY] : [];
  } catch {
    globalRules = [];
    globalMocks = [];
    globalReplaces = [];
    authProfiles = [];
  }
}

async function saveRules(rules) {
  globalRules = Array.isArray(rules) ? rules : [];
  try { await api.storage.local.set({ [RULES_KEY]: globalRules }); } catch {}
}

async function saveMocks(mocks) {
  globalMocks = Array.isArray(mocks) ? mocks : [];
  try { await api.storage.local.set({ [MOCKS_KEY]: globalMocks }); } catch {}
}

async function saveReplaces(replaces) {
  globalReplaces = Array.isArray(replaces) ? replaces : [];
  try { await api.storage.local.set({ [REPLACES_KEY]: globalReplaces }); } catch {}
}

async function saveProfiles(profiles) {
  authProfiles = Array.isArray(profiles) ? profiles : [];
  try { await api.storage.local.set({ [PROFILES_KEY]: authProfiles }); } catch {}
}

function hasActiveMocks() {
  return globalMocks.some((m) => m.enabled && m.url);
}

function hasActiveReplaces() {
  return globalReplaces.some((r) => r.enabled && r.url && (r.find || r.status));
}

function hasActiveAutoRules() {
  return hasActiveMocks() || hasActiveReplaces();
}

async function syncFetchForAllAttached(forceRefresh = false) {
  const autoOn = hasActiveAutoRules();
  for (const [tabId, s] of sessions.entries()) {
    if (!s.attached) continue;
    await adapter.setIntercept(tabId, s.interceptEnabled || autoOn, forceRefresh).catch(() => {});
  }
}

function broadcastConfig() {
  broadcast({
    type: "config:updated",
    rules: globalRules,
    mocks: globalMocks,
    replaces: globalReplaces,
    authProfiles,
  });
}

function sessionKey(tabId) {
  return SESSION_PREFIX + tabId;
}

async function persistSession(tabId) {
  const storage = api.storage.session || api.storage.local;
  const s = sessions.get(tabId);
  try {
    if (!s || !s.attached) {
      await storage.remove(sessionKey(tabId));
      return;
    }
    await storage.set({
      [sessionKey(tabId)]: {
        attached: true,
        recording: s.recording,
        interceptEnabled: s.interceptEnabled,
        tabUrl: s.tabUrl,
        tabTitle: s.tabTitle,
      },
    });
  } catch {}
}

async function hasOrphanSession(tabId) {
  const storage = api.storage.session || api.storage.local;
  try {
    const k = sessionKey(tabId);
    const got = await storage.get(k);
    return !!got?.[k]?.attached;
  } catch {
    return false;
  }
}

function matchUrlAndMethod(rule, req) {
  if (!rule.enabled || !rule.url) return false;
  if (rule.ignoreStatic !== false && req.isStatic) return false;
  if (rule.method && rule.method !== "ANY" && rule.method.toUpperCase() !== (req.method || "GET").toUpperCase()) return false;
  if (rule.url === "*") return true;
  if (rule.isRegex) {
    try { return new RegExp(rule.url).test(req.url); } catch { return false; }
  }
  return req.url.includes(rule.url);
}

function matchPattern(rule, req) {
  if (req.stage && (rule.stage || "Request") !== req.stage) return false;
  return matchUrlAndMethod(rule, req);
}

/* ============================ 适配器与启动屏障 ============================ */

let readyResolve;
const readyPromise = new Promise((r) => { readyResolve = r; });

const adapterHooks = {
  waitReady: () => readyPromise,
  isRecording: (tabId) => {
    const s = sessions.get(tabId);
    return !!(s && s.attached && s.recording);
  },
  isInterceptEnabled: (tabId) => !!sessions.get(tabId)?.interceptEnabled || hasActiveAutoRules(),
  hasResponseInterceptRules: () => globalRules.some((r) => r.enabled && r.url && r.stage === "Response"),
  hasActiveReplaceRules: () => hasActiveReplaces(),
  getFetchPatterns: (tabId) => buildFetchPatterns({
    interceptEnabled: !!sessions.get(tabId)?.interceptEnabled,
    rules: globalRules,
    mocks: globalMocks,
    replaces: globalReplaces,
  }),
  matchMockRule: (_tabId, req) => globalMocks.find((m) => matchPattern(m, req)) || null,
  matchReplaceRules: (_tabId, req) => globalReplaces.filter((r) => (r.find || r.status) && matchUrlAndMethod(r, req)),
  matchInterceptRule: (tabId, req) => {
    const s = sessions.get(tabId);
    if (!s || !s.interceptEnabled) return null;
    return globalRules.find((r) => matchPattern(r, req)) || null;
  },
  onRecordNew: (rec, bodies) => {
    enqueueWrite(rec, bodies, false);
    broadcast({ type: "record:new", record: listView(rec) });
  },
  onRecordUpdate: (rec, bodies) => {
    enqueueWrite(rec, bodies, false);
    broadcast({ type: "record:update", record: listView(rec) });
  },
  onPausedNew: (item) => {
    const { _timer, _resolve, ...safe } = item;
    broadcast({ type: "paused:new", item: safe });
    broadcast({ type: "state:changed", state: sessionState(item.tabId) });
  },
  onPausedResolved: (requestId, reason, item) => {
    broadcast({ type: "paused:resolved", requestId, reason, tabId: item?.tabId });
    if (item?.tabId) broadcast({ type: "state:changed", state: sessionState(item.tabId) });
  },
  onExternalDetach: async (tabId, reason) => {
    const s = sessions.get(tabId);
    if (s) {
      s.attached = false;
      s.interceptEnabled = false;
    }
    await persistSession(tabId);
    syncKeepAlive();
    broadcast({ type: "state:changed", state: sessionState(tabId), reason });
  },
};

const adapter = typeof chrome !== "undefined" && chrome.debugger
  ? createCdpAdapter(adapterHooks)
  : createWebRequestAdapter(adapterHooks);

(async function boot() {
  try {
    await loadPersistedConfig();
    const storage = api.storage.session || api.storage.local;
    const all = await storage.get(null);
    for (const [k, v] of Object.entries(all || {})) {
      if (!k.startsWith(SESSION_PREFIX) || !v?.attached) continue;
      const tabId = Number(k.slice(SESSION_PREFIX.length));
      if (!Number.isFinite(tabId)) continue;
      const alive = await adapter.probeAttached(tabId);
      if (!alive) {
        await storage.remove(k).catch(() => {});
        continue;
      }
      const restored = {
        attached: true,
        recording: v.recording !== false,
        interceptEnabled: !!v.interceptEnabled,
        tabUrl: v.tabUrl || "",
        tabTitle: v.tabTitle || "",
      };
      sessions.set(tabId, restored);
      await adapter.setIntercept(tabId, restored.interceptEnabled || hasActiveAutoRules(), true).catch(() => {});
    }
    syncKeepAlive();
    api.tabs.query({}).then((tabs) => {
      const aliveIds = tabs.map((t) => t.id).filter((id) => typeof id === "number");
      return pruneDeadTabs(aliveIds);
    }).catch(() => {});
  } catch (e) {
    console.warn("[TraceBurp] 启动恢复异常", e);
  } finally {
    readyResolve();
  }
})();

/* ============================ 会话控制 ============================ */

function sessionState(tabId) {
  const s = sessions.get(tabId);
  return {
    tabId,
    adapter: adapter.name,
    attached: !!s?.attached,
    recording: s ? !!s.recording : true,
    interceptEnabled: !!s?.interceptEnabled,
    tabUrl: s?.tabUrl || "",
    tabTitle: s?.tabTitle || "",
    rules: globalRules,
    mocks: globalMocks,
    replaces: globalReplaces,
    authProfiles,
    pausedCount: adapter.listPaused(tabId).length,
  };
}

async function attachTab(tabId) {
  if (!tabId) throw new Error("请选择要抓包的网页标签页");
  const tab = await api.tabs.get(tabId).catch(() => null);
  if (!tab) throw new Error("目标标签页不存在");
  if (/^(chrome|edge|about|chrome-extension|moz-extension|devtools):/i.test(tab.url || "")) {
    throw new Error("浏览器内部页面不支持抓包，请切换到普通 http/https 网页");
  }

  let s = sessions.get(tabId);
  if (!s) {
    s = { attached: false, recording: true, interceptEnabled: false, tabUrl: "", tabTitle: "" };
    sessions.set(tabId, s);
  }

  if (s.attached) {
    s.tabUrl = tab.url || "";
    s.tabTitle = tab.title || "";
    return sessionState(tabId);
  }

  const orphan = await hasOrphanSession(tabId);
  await adapter.attach(tabId, { hasOrphanSession: orphan, enableFetch: hasActiveAutoRules() });

  s.attached = true;
  s.tabUrl = tab.url || "";
  s.tabTitle = tab.title || "";
  syncKeepAlive();
  await persistSession(tabId);

  const st = sessionState(tabId);
  broadcast({ type: "state:changed", state: st });
  return st;
}

async function detachTab(tabId) {
  await adapter.detach(tabId);
  const s = sessions.get(tabId);
  if (s) {
    s.attached = false;
    s.interceptEnabled = false;
  }
  await persistSession(tabId);
  syncKeepAlive();

  const st = sessionState(tabId);
  broadcast({ type: "state:changed", state: st });
  return st;
}

async function doReplay(spec) {
  const tabId = spec.tabId;
  const result = await executeReplay(spec, { tabId });

  const sess = sessions.get(tabId);
  const alreadyCapturedByPage = (spec.mode || "page") === "page" && sess?.attached && sess?.recording;

  if (result && result.ok !== false && !alreadyCapturedByPage) {
    const rec = {
      id: uid("rp"),
      tabId: tabId || 0,
      cdpId: "",
      sessionId: null,
      method: (spec.method || "GET").toUpperCase(),
      url: result.url || spec.url,
      type: "Replay",
      ts: Date.now(),
      duration: result.duration || 0,
      state: "done",
      reqHeaders: (spec.headers || []).map((h) => ({ name: h.name, value: String(h.value ?? "") })),
      reqBodyBytes: spec.body ? (spec.bodyIsBase64 ? Math.floor((spec.body.length * 3) / 4) : byteLen(spec.body)) : 0,
      hasPostData: !!spec.body,
      status: result.status ?? 0,
      statusText: result.statusText || "",
      resHeaders: (result.headers || []).map(([name, value]) => ({ name, value })),
      mimeType: (result.headers || []).find(([k]) => String(k).toLowerCase() === "content-type")?.[1] || "",
      resSize: result.size || 0,
      resBodyBytes: result.size || 0,
      fromCache: false,
      fromServiceWorker: false,
      remoteIP: "",
      remotePort: 0,
      protocol: "",
      timing: null,
      initiator: { type: "replay", url: "" },
      redirectChain: [],
      failed: null,
      origin: "replay",
      replayed: true,
      replayMode: spec.mode || "page",
      replayOf: spec.sourceRecordId || null,
    };

    enqueueWrite(rec, {
      reqBody: spec.body ?? null,
      reqBodyB64: !!spec.bodyIsBase64,
      reqBodyBytes: rec.reqBodyBytes,
      resBody: result.body || null,
      resBodyB64: true,
      resBodyBytes: rec.resBodyBytes,
      resBodyTruncated: !!result.truncated,
    }, true);
    broadcast({ type: "record:new", record: listView(rec) });
  }

  return result;
}

/* ============================ 标签页实时同步 ============================ */

async function getInspectableTabs() {
  const tabs = await api.tabs.query({});
  return tabs
    .filter((t) => /^https?:/i.test(t.url || ""))
    .map((t) => ({
      id: t.id,
      title: t.title || t.url,
      url: t.url || "",
      active: !!t.active,
      attached: !!sessions.get(t.id)?.attached,
    }));
}

let tabTimer = null;
function scheduleTabsBroadcast() {
  if (tabTimer) return;
  tabTimer = setTimeout(async () => {
    tabTimer = null;
    try { broadcast({ type: "tabs:updated", tabs: await getInspectableTabs() }); } catch {}
  }, 220);
}

api.tabs.onCreated.addListener(scheduleTabsBroadcast);
api.tabs.onActivated.addListener(scheduleTabsBroadcast);
api.tabs.onUpdated.addListener((tabId, info, tab) => {
  const s = sessions.get(tabId);
  if (s && (info.url || info.title || info.status === "complete")) {
    s.tabUrl = tab?.url || s.tabUrl;
    s.tabTitle = tab?.title || s.tabTitle;
    broadcast({ type: "state:changed", state: sessionState(tabId) });
  }
  if (info.url || info.title || info.status === "complete") scheduleTabsBroadcast();
});
api.tabs.onRemoved.addListener(async (tabId) => {
  if (sessions.has(tabId)) {
    await adapter.releaseAllPausedForTab(tabId, "tab-closed");
    sessions.delete(tabId);
    await persistSession(tabId);
    syncKeepAlive();
  }
  scheduleTabsBroadcast();
});

/* ============================ 消息路由 ============================ */

async function handleMessage(msg) {
  await readyPromise;
  const t = msg?.type;

  switch (t) {
    case "getState":
      return { ok: true, state: sessionState(msg.tabId) };

    case "attach":
      return { ok: true, state: await attachTab(msg.tabId) };

    case "detach":
      return { ok: true, state: await detachTab(msg.tabId) };

    case "setRecording": {
      const s = sessions.get(msg.tabId);
      if (s) { s.recording = !!msg.recording; await persistSession(msg.tabId); }
      const st = sessionState(msg.tabId);
      broadcast({ type: "state:changed", state: st });
      return { ok: true, state: st };
    }

    case "saveRules": {
      await saveRules(msg.rules || []);
      await syncFetchForAllAttached(true);
      broadcastConfig();
      return { ok: true, rules: globalRules };
    }

    case "togglePinBreakpoint": {
      const { tabId, method = "ANY", urlPattern } = msg;
      if (!urlPattern) throw new Error("缺少路径条件");
      const existsIdx = globalRules.findIndex((r) => r.url === urlPattern && (r.method || "ANY") === method);
      let pinned = false;
      if (existsIdx >= 0) {
        globalRules.splice(existsIdx, 1);
      } else {
        globalRules.unshift({
          id: uid("pin"),
          enabled: true,
          stage: "Request",
          method,
          isRegex: false,
          url: urlPattern,
          ignoreStatic: true,
          pauseTimeoutMs: 60000,
        });
        pinned = true;
      }
      await saveRules(globalRules);
      const s = sessions.get(tabId);
      if (pinned && s?.attached && !s.interceptEnabled) {
        s.interceptEnabled = true;
        await adapter.setIntercept(tabId, true, true);
        await persistSession(tabId);
      }
      broadcastConfig();
      if (tabId) broadcast({ type: "state:changed", state: sessionState(tabId) });
      return { ok: true, pinned, rules: globalRules };
    }

    case "saveMocks": {
      await saveMocks(msg.mocks || []);
      await syncFetchForAllAttached(true);
      broadcastConfig();
      return { ok: true, mocks: globalMocks };
    }

    case "saveReplaces": {
      await saveReplaces(msg.replaces || []);
      await syncFetchForAllAttached(true);
      broadcastConfig();
      return { ok: true, replaces: globalReplaces };
    }

    case "addReplaceRule": {
      const rule = {
        id: uid("rep"),
        enabled: true,
        method: msg.rule?.method || "ANY",
        url: String(msg.rule?.url || "*").trim() || "*",
        find: String(msg.rule?.find ?? ""),
        replace: String(msg.rule?.replace ?? ""),
        isRegex: !!msg.rule?.isRegex,
        status: msg.rule?.status ? Number(msg.rule.status) : "",
        ignoreStatic: true,
      };
      if (!rule.find && !rule.status) throw new Error("请填写要查找替换的内容或目标状态码");
      globalReplaces.unshift(rule);
      await saveReplaces(globalReplaces);
      await syncFetchForAllAttached(true);
      broadcastConfig();
      return { ok: true, rule, replaces: globalReplaces };
    }

    case "saveAuthProfiles": {
      await saveProfiles(msg.authProfiles || []);
      broadcastConfig();
      return { ok: true, authProfiles };
    }

    case "setIntercept": {
      const s = sessions.get(msg.tabId);
      if (!s || !s.attached) throw new Error("请先开始抓包后再开启拦截");
      s.interceptEnabled = !!msg.enabled;
      await adapter.setIntercept(msg.tabId, s.interceptEnabled || hasActiveAutoRules(), true);
      await persistSession(msg.tabId);
      const st = sessionState(msg.tabId);
      broadcast({ type: "state:changed", state: st });
      return { ok: true, state: st };
    }

    case "listRecords": {
      await flushWrites();
      const rows = await listRecords(msg.tabId, msg.offset || 0, msg.limit || 300);
      const total = await countTab(msg.tabId);
      return { ok: true, rows: rows.map(listView), total };
    }

    case "getRecord":
      await flushWrites();
      return { ok: true, record: await getRecord(msg.id) };

    case "searchBodies":
      await flushWrites();
      return { ok: true, ids: await searchTabBodies(msg.tabId, msg.query || "", 500) };

    case "deleteRecord":
      await deleteRecord(msg.id);
      return { ok: true };

    case "clearRecords": {
      await flushWrites();
      const removed = await clearTab(msg.tabId);
      broadcast({ type: "records:cleared", tabId: msg.tabId });
      return { ok: true, removed };
    }

    case "paused:list":
      return { ok: true, items: adapter.listPaused(msg.tabId) };

    case "paused:resolve":
      return adapter.resolvePaused(msg.requestId, msg.action, msg.payload || {});

    case "replay":
      return { ok: true, result: await doReplay(msg.spec || {}) };

    case "export": {
      await flushWrites();
      const records = await exportTab(msg.tabId, msg.max || 10000, msg.ids || null);
      const opts = { redact: !!msg.redact };
      if (msg.format === "har") return { ok: true, data: JSON.stringify(toHAR(records, msg.pageUrl || "", opts), null, 2), ext: "har" };
      if (msg.format === "curl") return { ok: true, data: records.map((r) => toCurlBash(r, opts)).join("\n\n"), ext: "sh" };
      if (msg.format === "python") return { ok: true, data: records.map((r) => toPython(r, opts)).join("\n\n"), ext: "py" };
      return { ok: true, data: JSON.stringify(opts.redact ? records.map((r) => redactRecord(r, true)) : records, null, 2), ext: "json" };
    }

    case "exportOne": {
      await flushWrites();
      const rec = await getRecord(msg.id);
      if (!rec) throw new Error("记录不存在");
      const opts = { redact: !!msg.redact };
      if (msg.format === "raw") return { ok: true, data: toRawHttp(rec, opts), ext: "txt" };
      if (msg.format === "curl-bash") return { ok: true, data: toCurlBash(rec, opts), ext: "sh" };
      if (msg.format === "curl-cmd") return { ok: true, data: toCurlCmd(rec, opts), ext: "bat" };
      if (msg.format === "curl-ps") return { ok: true, data: toCurlPowerShell(rec, opts), ext: "ps1" };
      if (msg.format === "python") return { ok: true, data: toPython(rec, opts), ext: "py" };
      return { ok: true, data: JSON.stringify(redactRecord(rec, opts.redact), null, 2), ext: "json" };
    }

    case "getTabList":
      return { ok: true, tabs: await getInspectableTabs() };

    case "openFullWindow": {
      const id = await openOrFocusWorkbench(msg.tabId || null);
      return { ok: true, tabId: id };
    }

    default:
      throw new Error(`未知消息类型：${t}`);
  }
}

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  handleMessage(msg, sender)
    .then((r) => sendResponse(r))
    .catch((e) => sendResponse({ ok: false, error: String(e?.message || e) }));
  return true;
});
