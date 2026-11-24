/**
 * TraceBurp v3.0 极简高效版主控制器
 *
 * 核心交互原则：
 * 1. 左侧过滤标签一眼明白：去静态 / GET / POST / PUT / DELETE / PATCH / 4xx-5xx / 仅本域
 * 2. 右侧报文详情默认上下分屏：右上 Raw Request + 右下 Raw Response，一眼看全
 * 3. 重放器像极简顺手版 Burp Repeater：点任意报文直接带入完整 Raw 报文，改完直接 Ctrl+Enter 发送看 Raw 响应或 Diff
 */

import {
  LRUCache,
  base64ToBytes,
  byteLen,
  findHeader,
  fmtDur,
  fmtTime,
  getHost,
  getPathAndQuery,
  headersToText,
  looksBinary,
  parseHeaderText,
  tryParseJSON,
  uid,
} from "../core/utils.js";
import { CODEC_OPS, detectEncodings, runCodecOp } from "../core/codec.js";
import { auditSecurityHeaders } from "../core/analyzer.js";
import { filterRecords, matchesRecord, parseFilterQuery } from "../core/filter.js";
import { toCurlBash, toPython } from "../core/exporter.js";
import { diffText } from "../core/diff.js";

const api = typeof browser !== "undefined" ? browser : chrome;
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

const ROW_H = 48;
const PAGE_SIZE = 300;
const OVERSCAN = 10;

/* ============================ 状态 ============================ */

let currentTabId = null;
let currentTabUrl = "";
let attached = false;
let recording = true;
let interceptEnabled = false;
let dbTotal = 0;

let allRows = [];
let viewRows = [];
let selectedId = null;
let currentRecord = null;
const recordCache = new LRUCache(60);

let loadingMore = false;
let hasMore = true;

const filterState = {
  query: "",
  hideStatic: true,
  methods: new Set(), // GET / POST / PUT / DELETE / PATCH
  hasBody: false,
  only2xx: false,
  onlyError: false,
  sameHost: false,
  bodySearchIds: null,
  focusHost: "",
  hiddenHosts: new Set(),
};

let rules = [];
let mocks = [];
let replaces = [];
let authProfiles = [];
let pausedItems = [];
let pausedTarget = null;

let reqPretty = false;
let resMode = "raw"; // raw | pretty | hex

// 极简 Raw 重放器标签页：{ id, title, sourceRecordId, origStatus, origResRaw, rawText, baseline, lastCommitted, undoStack, mode, response, responseTag, resView, history, activeHistIdx }
const repeaterTabs = [];
let activeRepeaterId = null;

/* ============================ 工具 ============================ */

function send(msg) {
  return api.runtime.sendMessage(msg).then((r) => {
    if (!r) throw new Error("后台无响应");
    if (r.ok === false) throw new Error(r.error || "操作失败");
    return r;
  });
}

function toast(msg, kind = "") {
  const el = document.createElement("div");
  el.className = "toast " + kind;
  el.textContent = msg;
  $("#toastWrap").appendChild(el);
  setTimeout(() => {
    el.style.transition = "opacity 0.2s";
    el.style.opacity = "0";
    setTimeout(() => el.remove(), 220);
  }, 2000);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(String(text ?? ""));
    toast("已复制", "ok");
  } catch (e) {
    toast("复制失败：" + e.message, "err");
  }
}

function methodCls(m) {
  const map = { GET: "m-get", POST: "m-post", PUT: "m-put", DELETE: "m-delete", PATCH: "m-patch" };
  return map[(m || "").toUpperCase()] || "m-other";
}

function statusCls(r) {
  if (r.failed) return "s-fail";
  if (r.state === "pending" && r.status == null) return "s-pend";
  const s = r.status;
  if (s >= 200 && s < 300) return "s-2";
  if (s >= 300 && s < 400) return "s-3";
  if (s >= 400 && s < 500) return "s-4";
  if (s >= 500) return "s-5";
  return "s-pend";
}

function isPinnedPath(method, path) {
  return rules.some((r) => r.enabled && r.url === path && (r.method === "ANY" || r.method === method));
}

function decodeBody(rec, which) {
  const isReq = which === "req";
  const body = isReq ? rec.reqBody : rec.resBody;
  const isB64 = isReq ? rec.reqBodyB64 : rec.resBodyB64;
  const mime = isReq ? findHeader(rec.reqHeaders, "content-type") : rec.mimeType;
  if (body == null) return { text: "", binary: false, bytes: new Uint8Array(0) };
  if (!isB64) {
    const text = String(body);
    return { text, binary: false, bytes: new TextEncoder().encode(text) };
  }
  const bytes = base64ToBytes(body);
  if (looksBinary(mime, body)) return { text: "", binary: true, bytes };
  return { text: new TextDecoder("utf-8", { fatal: false }).decode(bytes), binary: false, bytes };
}

function hexDump(bytes, maxLen = 4096) {
  const n = Math.min(bytes.length, maxLen);
  const lines = [];
  for (let i = 0; i < n; i += 16) {
    const s = bytes.subarray(i, Math.min(i + 16, n));
    const hx = [...s].map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const asc = [...s].map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${i.toString(16).padStart(8, "0")}  ${hx.padEnd(47)}  ${asc}`);
  }
  if (bytes.length > n) lines.push(`… 已显示 ${n} / ${bytes.length} 字节`);
  return lines.join("\n");
}

/** 组装标准可读的 Raw HTTP 请求报文（保留完整 URL 方便直接改包重放） */
function formatRawRequest(rec, { prettyJson = false, fullUrl = false } = {}) {
  let path = "/";
  let host = "";
  try {
    const u = new URL(rec.url || "http://localhost/");
    path = fullUrl ? u.toString() : ((u.pathname || "/") + u.search);
    host = u.host;
  } catch {
    path = rec.url || "/";
  }

  const lines = [`${(rec.method || "GET").toUpperCase()} ${path} HTTP/1.1`];
  const hasHost = (rec.reqHeaders || []).some((h) => h.name.toLowerCase() === "host");
  if (!fullUrl && !hasHost && host) lines.push(`Host: ${host}`);
  for (const h of rec.reqHeaders || []) {
    if (!h.name || h.name.startsWith(":")) continue;
    if (fullUrl && /^(host|content-length|connection|accept-encoding|transfer-encoding)$/i.test(h.name)) continue;
    lines.push(`${h.name}: ${h.value}`);
  }

  const d = decodeBody(rec, "req");
  if (d.binary) {
    lines.push("", `[二进制请求体 ${d.bytes.length} bytes]`);
  } else if (d.text) {
    let bodyOut = d.text;
    if (prettyJson) {
      const p = tryParseJSON(d.text);
      if (p !== null) bodyOut = JSON.stringify(p, null, 2);
    }
    lines.push("", bodyOut);
  }
  return lines.join("\n");
}

/** 组装标准可读的 Raw HTTP 响应报文 */
function formatRawResponse(rec, { prettyJson = false, hex = false } = {}) {
  if (rec.failed) return `请求失败：${rec.failed}`;
  const proto = (rec.protocol || "HTTP/1.1").toUpperCase().startsWith("HTTP") ? rec.protocol.toUpperCase() : "HTTP/1.1";
  const lines = [`${proto} ${rec.status ?? "-"} ${rec.statusText || ""}`.trim()];
  for (const h of rec.resHeaders || []) {
    if (!h.name || h.name.startsWith(":")) continue;
    lines.push(`${h.name}: ${h.value}`);
  }
  if (rec.resBodyError) {
    lines.push("", `（无法读取响应体：${rec.resBodyError}）`);
    return lines.join("\n");
  }
  const d = decodeBody(rec, "res");
  if (hex || d.binary) {
    if (d.bytes.length) lines.push("", hexDump(d.bytes));
  } else if (d.text) {
    let bodyOut = d.text;
    if (prettyJson) {
      const p = tryParseJSON(d.text);
      if (p !== null) bodyOut = JSON.stringify(p, null, 2);
    }
    lines.push("", bodyOut);
  }
  return lines.join("\n");
}

/** 从用户在重放器里直接修改的 Raw HTTP 报文解析出 method / url / headers / body */
function parseRawRequestText(rawText, fallbackUrl = "") {
  const normalized = String(rawText || "").replace(/\r\n/g, "\n").replace(/^\n+/, "");
  const sep = normalized.indexOf("\n\n");
  const headStr = sep >= 0 ? normalized.slice(0, sep) : normalized;
  const body = sep >= 0 ? normalized.slice(sep + 2) : "";
  const lines = headStr.split("\n").map((l) => l.trimEnd()).filter(Boolean);

  let method = "GET";
  let target = "";
  let hdrLines = lines;

  const first = (lines[0] || "").trim();
  const m = first.match(/^([A-Z]+)\s+(\S+)(?:\s+HTTP\/[\d.]+)?$/i);
  if (m) {
    method = m[1].toUpperCase();
    target = m[2];
    hdrLines = lines.slice(1);
  }

  const headers = parseHeaderText(hdrLines.join("\n"));

  // 如果首行是相对路径（如 /api/v1/user?x=2），自动结合 Host 头或原 URL 拼出完整 URL
  let url = target;
  if (!/^https?:\/\//i.test(url)) {
    const hostHdr = findHeader(headers, "host");
    let proto = "https:";
    let origin = "";
    try {
      const fb = new URL(fallbackUrl);
      proto = fb.protocol;
      origin = fb.origin;
    } catch {}
    if (hostHdr) {
      url = `${proto}//${hostHdr}${target.startsWith("/") ? target : "/" + target}`;
    } else if (origin) {
      url = `${origin}${target.startsWith("/") ? target : "/" + target}`;
    } else {
      url = fallbackUrl;
    }
  }

  return { method, url, headers, body };
}

/* ============================ 标签页同步 ============================ */

function renderTabPicker(tabs, preferId = null) {
  const sel = $("#tabSelect");
  const keep = preferId ?? currentTabId;
  sel.textContent = "";
  for (const t of tabs) {
    const opt = document.createElement("option");
    opt.value = String(t.id);
    opt.textContent = `${t.attached ? "● " : ""}${(t.title || t.url || "").slice(0, 44)}`;
    opt.title = t.url;
    sel.appendChild(opt);
  }
  if (!tabs.length) {
    const opt = document.createElement("option");
    opt.value = "";
    opt.textContent = "请打开普通网页";
    sel.appendChild(opt);
    return null;
  }
  const pick = keep && tabs.some((t) => t.id === keep)
    ? keep
    : (tabs.find((t) => t.active)?.id || tabs.find((t) => t.attached)?.id || tabs[0].id);
  sel.value = String(pick);
  return pick;
}

async function loadTabList(preferId = null) {
  const { tabs } = await send({ type: "getTabList" });
  const picked = renderTabPicker(tabs, preferId);
  if (picked !== currentTabId) await switchTab(picked);
}

async function switchTab(tabId) {
  currentTabId = tabId ? Number(tabId) : null;
  selectedId = null;
  currentRecord = null;
  recordCache.clear();
  allRows = [];
  viewRows = [];
  dbTotal = 0;
  hasMore = true;
  filterState.bodySearchIds = null;

  showInspectEmpty();
  renderList(true);

  if (!currentTabId) {
    applyState({ attached: false, recording: true, interceptEnabled: false });
    return;
  }
  const { state } = await send({ type: "getState", tabId: currentTabId });
  applyState(state);
  await reloadRecords();
  await refreshPaused();
}

function applyState(state) {
  if (!state) return;
  attached = !!state.attached;
  recording = state.recording !== false;
  interceptEnabled = !!state.interceptEnabled;
  currentTabUrl = state.tabUrl || $("#tabSelect").selectedOptions[0]?.title || "";
  if (Array.isArray(state.rules)) rules = state.rules;
  if (Array.isArray(state.mocks)) mocks = state.mocks;
  if (Array.isArray(state.replaces)) replaces = state.replaces;
  if (Array.isArray(state.authProfiles)) authProfiles = state.authProfiles;

  $("#btnCapture").className = "capture-btn " + (attached ? "on" : "off");
  $("#captureLabel").textContent = attached ? "抓包中" : "开始抓包";

  const rp = $("#btnRecordPause");
  rp.classList.toggle("hidden", !attached);
  rp.textContent = recording ? "暂停记录" : "恢复记录";
  rp.classList.toggle("active", !recording);

  $("#btnInterceptToggle").classList.toggle("active", interceptEnabled);
  updateConfigBadges();
}

function updateConfigBadges() {
  const repN = replaces.filter((r) => r.enabled && r.url && (r.find || r.status)).length;
  const n =
    rules.filter((r) => r.enabled && r.url).length +
    repN +
    mocks.filter((m) => m.enabled && m.url).length;
  const b = $("#configCount");
  b.textContent = String(n);
  b.classList.toggle("hidden", n === 0);
  $("#btnRulesDrawer").classList.toggle("has-replace", repN > 0);
}

/* ============================ 实时流量列表 ============================ */

async function reloadRecords() {
  if (!currentTabId) return;
  const { rows, total } = await send({ type: "listRecords", tabId: currentTabId, offset: 0, limit: PAGE_SIZE });
  allRows = rows;
  dbTotal = total;
  hasMore = rows.length >= PAGE_SIZE;
  applyFilter(true);
}

async function loadMore() {
  if (loadingMore || !hasMore || !currentTabId) return;
  loadingMore = true;
  try {
    const { rows, total } = await send({ type: "listRecords", tabId: currentTabId, offset: allRows.length, limit: PAGE_SIZE });
    dbTotal = total;
    if (!rows.length) hasMore = false;
    else {
      const seen = new Set(allRows.map((r) => r.id));
      for (const r of rows) if (!seen.has(r.id)) allRows.push(r);
      hasMore = rows.length >= PAGE_SIZE;
      applyFilter(false);
    }
  } finally {
    loadingMore = false;
  }
}

function buildFilterOpts() {
  return {
    query: filterState.query,
    rules: parseFilterQuery(filterState.query),
    hideStatic: filterState.hideStatic,
    methods: filterState.methods,
    hasBody: filterState.hasBody,
    only2xx: filterState.only2xx,
    onlyError: filterState.onlyError,
    sameHost: filterState.sameHost,
    currentHost: getHost(currentTabUrl),
    hiddenHosts: filterState.hiddenHosts,
    focusHost: filterState.focusHost,
    bodySearchIds: filterState.bodySearchIds,
  };
}

function updateResetFilterBtn() {
  const dirty = !!filterState.query || !filterState.hideStatic || filterState.methods.size > 0 ||
    filterState.hasBody || filterState.only2xx || filterState.onlyError || filterState.sameHost || !!filterState.focusHost ||
    filterState.hiddenHosts.size > 0 || filterState.bodySearchIds !== null;
  $("#btnResetFilters").classList.toggle("hidden", !dirty);
}

function applyFilter(resetScroll = true) {
  viewRows = filterRecords(allRows, buildFilterOpts());
  const shown = viewRows.length;
  const total = Math.max(dbTotal, allRows.length);
  $("#counter").textContent = shown === total ? `${total} 条` : `${shown} / ${total} 条`;
  updateResetFilterBtn();
  renderList(resetScroll);
}

const viewport = $("#listViewport");
const phantom = $("#listPhantom");
const rowsEl = $("#listRows");
let rafPending = false;
function scheduleRender() {
  if (rafPending) return;
  rafPending = true;
  requestAnimationFrame(() => { rafPending = false; renderList(false); });
}

function renderList(resetScroll = false) {
  if (resetScroll) viewport.scrollTop = 0;
  const total = viewRows.length;
  phantom.style.height = total * ROW_H + 12 + "px";
  const maxScroll = Math.max(0, total * ROW_H - viewport.clientHeight);
  if (viewport.scrollTop > maxScroll) viewport.scrollTop = maxScroll;

  const scrollTop = viewport.scrollTop;
  const h = viewport.clientHeight || 480;
  const start = Math.max(0, Math.floor(scrollTop / ROW_H) - OVERSCAN);
  const end = Math.min(total, Math.ceil((scrollTop + h) / ROW_H) + OVERSCAN);

  rowsEl.style.transform = `translateY(${start * ROW_H}px)`;
  rowsEl.textContent = "";
  const frag = document.createDocumentFragment();
  for (let i = start; i < end; i++) frag.appendChild(buildCard(viewRows[i]));
  rowsEl.appendChild(frag);
  $("#streamEmpty").classList.toggle("hidden", total > 0);
}

function buildCard(r) {
  const card = document.createElement("div");
  card.className = "req-card";
  card.dataset.id = r.id;
  if (r.id === selectedId) card.classList.add("selected");
  if (r.replaced) card.classList.add("is-replaced");
  else if (r.mocked) card.classList.add("is-mock");
  else if (r.origin === "replay") card.classList.add("is-replay");
  else if (r.intercepted) card.classList.add("is-intercepted");

  const cleanPath = getPathAndQuery(r.url || "");
  const pathOnly = cleanPath.split("?")[0];
  const host = getHost(r.url || "");

  const top = document.createElement("div");
  top.className = "rc-top";
  const m = document.createElement("span");
  m.className = `m-tag ${methodCls(r.method)}`;
  m.textContent = r.method || "GET";
  const p = document.createElement("span");
  p.className = "rc-path";
  p.textContent = cleanPath;
  p.title = r.url || "";
  top.append(m, p);

  const bot = document.createElement("div");
  bot.className = "rc-bot";
  const st = document.createElement("span");
  st.className = `st-tag ${statusCls(r)}`;
  st.textContent = r.failed ? "ERR" : (r.status != null ? String(r.status) : "···");
  const h = document.createElement("span");
  h.className = "rc-host";
  h.textContent = host;
  h.title = host;
  const meta = document.createElement("span");
  meta.className = "rc-meta";
  meta.textContent = fmtDur(r.duration) || "";
  meta.title = fmtTime(r.ts) || "";
  bot.append(st, h);
  if (meta.textContent) bot.appendChild(meta);

  if (r.replaced) {
    const t = document.createElement("span"); t.className = "micro-tag rep"; t.textContent = "已替换"; bot.appendChild(t);
  } else if (r.mocked) {
    const t = document.createElement("span"); t.className = "micro-tag mock"; t.textContent = "Mock"; bot.appendChild(t);
  } else if (r.origin === "replay") {
    const t = document.createElement("span"); t.className = "micro-tag rp"; t.textContent = "重放"; bot.appendChild(t);
  }

  const acts = document.createElement("div");
  acts.className = "rc-hover-acts";
  const pinBtn = document.createElement("button");
  const pinned = isPinnedPath(r.method || "GET", pathOnly);
  pinBtn.className = "rc-act" + (pinned ? " pinned" : "");
  pinBtn.textContent = pinned ? "📌 已断点" : "📌";
  pinBtn.title = "一键断点";
  pinBtn.addEventListener("click", (e) => { e.stopPropagation(); togglePin(r.method || "GET", pathOnly); });

  const rpBtn = document.createElement("button");
  rpBtn.className = "rc-act";
  rpBtn.textContent = "⚡ 重放";
  rpBtn.addEventListener("click", async (e) => {
    e.stopPropagation();
    await selectRecord(r.id);
    if (currentRecord) openInRepeater(currentRecord);
  });

  acts.append(pinBtn, rpBtn);
  card.append(top, bot, acts);
  return card;
}

const incoming = [];
let incomingRaf = false;
function queueIncoming(msg) {
  incoming.push(msg);
  if (incomingRaf) return;
  incomingRaf = true;
  requestAnimationFrame(() => {
    incomingRaf = false;
    const batch = incoming.splice(0, incoming.length);
    let addedShown = 0, needFullFilter = false, needRender = false, refreshSel = false;
    const fOpts = buildFilterOpts();
    for (const m of batch) {
      if (m.type === "record:new") {
        if (m.record.tabId !== currentTabId) continue;
        allRows.unshift(m.record);
        if (allRows.length > 5000) allRows.length = 5000;
        dbTotal++;
        if (matchesRecord(m.record, fOpts)) {
          viewRows.unshift(m.record);
          addedShown++;
        }
        needRender = true;
      } else if (m.type === "record:update") {
        if (m.record.tabId !== currentTabId) continue;
        const idx = allRows.findIndex((x) => x.id === m.record.id);
        if (idx >= 0) allRows[idx] = m.record;
        else { allRows.unshift(m.record); dbTotal++; }
        recordCache.delete(m.record.id);
        needFullFilter = true;
        if (selectedId === m.record.id) refreshSel = true;
      }
    }
    if (needFullFilter || needRender) {
      const keep = viewport.scrollTop > 0;
      const prev = viewport.scrollTop;
      if (needFullFilter) {
        applyFilter(false);
      } else {
        const shown = viewRows.length;
        const total = Math.max(dbTotal, allRows.length);
        $("#counter").textContent = shown === total ? `${total} 条` : `${shown} / ${total} 条`;
        renderList(false);
      }
      if (keep && addedShown > 0) { viewport.scrollTop = prev + addedShown * ROW_H; scheduleRender(); }
    }
    if (refreshSel && selectedId) refreshSelectedDetail(selectedId);
  });
}

/* ============================ 右侧：上下 Raw 报文详情 ============================ */

function showInspectEmpty() {
  $("#inspectEmpty").classList.remove("hidden");
  $("#inspectSplit").classList.add("hidden");
  $("#dHeroSummary").classList.add("hidden");
  $("#dSecPill").classList.add("hidden");
  $("#secDrawer").classList.add("hidden");
  $("#btnToReplay").disabled = true;
  $("#btnQuickReplace").disabled = true;
  $("#btnQuickMock").disabled = true;
  $("#btnDeleteOne").disabled = true;
  $("#btnCopyMenu").disabled = true;
}

async function selectRecord(id, ensureVisible = false) {
  selectedId = id;
  scheduleRender();
  switchWorkMode("inspect");

  if (ensureVisible) {
    const idx = viewRows.findIndex((r) => r.id === id);
    if (idx >= 0) {
      const top = idx * ROW_H, bot = top + ROW_H;
      if (top < viewport.scrollTop) viewport.scrollTop = top;
      else if (bot > viewport.scrollTop + viewport.clientHeight) viewport.scrollTop = bot - viewport.clientHeight;
    }
  }

  let rec = recordCache.get(id);
  if (!rec) {
    try {
      const { record } = await send({ type: "getRecord", id });
      if (selectedId !== id) return;
      rec = record;
      if (rec) recordCache.set(id, rec);
    } catch (e) {
      toast("读取失败：" + e.message, "err");
      return;
    }
  }
  if (!rec || selectedId !== id) return;
  currentRecord = rec;
  reqPretty = false;
  resMode = "raw";
  resShowFull = false;
  renderInspect(rec);
}

async function refreshSelectedDetail(id) {
  try {
    const { record } = await send({ type: "getRecord", id });
    if (!record || selectedId !== id) return;
    recordCache.set(id, record);
    currentRecord = record;
    renderInspect(record);
  } catch {}
}

function renderInspect(rec) {
  $("#inspectEmpty").classList.add("hidden");
  $("#inspectSplit").classList.remove("hidden");
  $("#btnToReplay").disabled = false;
  $("#btnQuickReplace").disabled = false;
  $("#btnQuickMock").disabled = false;
  $("#btnDeleteOne").disabled = false;
  $("#btnCopyMenu").disabled = false;

  const summary = $("#dHeroSummary");
  summary.textContent = `${rec.method || "GET"} ${rec.url || ""}`;
  summary.title = "点击复制 URL";
  summary.classList.remove("hidden");

  // 安全线索（折叠收起，有发现才显示小徽章，不挡 Raw 报文）
  const audit = auditSecurityHeaders(rec);
  const pill = $("#dSecPill");
  $("#secDrawer").classList.add("hidden");
  if (audit.hints.length) {
    pill.textContent = `${audit.hints.length} 条安全提示`;
    pill.className = "sec-pill" + (audit.hints.some((h) => h.severity === "high") ? " high" : "");
    pill.classList.remove("hidden");

    const hb = $("#secHintsBox");
    hb.textContent = "";
    for (const h of audit.hints) {
      const d = document.createElement("div");
      d.className = `hint-item ${h.severity}`;
      d.innerHTML = `<b></b><span></span>`;
      d.querySelector("b").textContent = h.title;
      d.querySelector("span").textContent = h.detail;
      hb.appendChild(d);
    }
    const jb = $("#jwtBox");
    jb.textContent = "";
    if (audit.jwts.length) {
      jb.classList.remove("hidden");
      for (const j of audit.jwts) {
        const hd = document.createElement("div");
        hd.className = "jwt-card-hd";
        hd.textContent = `JWT · ${j.source} · alg=${j.alg}`;
        const pre = document.createElement("pre");
        pre.textContent = JSON.stringify({ header: j.header, payload: j.payload }, null, 2);
        jb.append(hd, pre);
      }
    } else jb.classList.add("hidden");
  } else {
    pill.classList.add("hidden");
  }

  renderReqRaw(rec);
  renderResRaw(rec);
}

const BIG_RAW_LIMIT = 250 * 1024;
let resShowFull = false;
let resMatchEls = [];
let resMatchIdx = -1;

/** 轻度着色渲染 Raw HTTP（首行与 Header 名着色，复制时仍为 100% 原始纯文本） */
function renderTintedRaw(box, text, searchKw = "") {
  box.textContent = "";
  const frag = document.createDocumentFragment();
  const sep = text.indexOf("\n\n");
  const headStr = sep >= 0 ? text.slice(0, sep) : text;
  const bodyStr = sep >= 0 ? text.slice(sep) : "";

  const headLines = headStr.split("\n");
  headLines.forEach((line, idx) => {
    if (idx === 0) {
      const s = document.createElement("span");
      s.className = "raw-line-req";
      s.textContent = line;
      frag.appendChild(s);
    } else {
      const colon = line.indexOf(":");
      if (colon > 0) {
        const k = document.createElement("span");
        k.className = "raw-hdr-k";
        k.textContent = line.slice(0, colon + 1);
        frag.appendChild(k);
        frag.appendChild(document.createTextNode(line.slice(colon + 1)));
      } else {
        frag.appendChild(document.createTextNode(line));
      }
    }
    if (idx < headLines.length - 1) frag.appendChild(document.createTextNode("\n"));
  });

  if (!searchKw) {
    if (bodyStr) frag.appendChild(document.createTextNode(bodyStr));
    box.appendChild(frag);
    return [];
  }

  // 带上限（300 处）的安全高亮，防止大文本卡顿
  const hits = [];
  const lower = bodyStr.toLowerCase();
  const q = searchKw.toLowerCase();
  let pos = 0;
  const MAX_HITS = 300;
  while (pos < bodyStr.length && hits.length < MAX_HITS) {
    const hit = lower.indexOf(q, pos);
    if (hit < 0) break;
    if (hit > pos) frag.appendChild(document.createTextNode(bodyStr.slice(pos, hit)));
    const sp = document.createElement("span");
    sp.className = "raw-hit";
    sp.textContent = bodyStr.slice(hit, hit + searchKw.length);
    frag.appendChild(sp);
    hits.push(sp);
    pos = hit + searchKw.length;
  }
  if (pos < bodyStr.length) frag.appendChild(document.createTextNode(bodyStr.slice(pos)));
  box.appendChild(frag);
  return hits;
}

function jumpResMatch(delta) {
  if (!resMatchEls.length) return;
  if (resMatchIdx >= 0 && resMatchEls[resMatchIdx]) resMatchEls[resMatchIdx].classList.remove("raw-hit-active");
  resMatchIdx = (resMatchIdx + delta + resMatchEls.length) % resMatchEls.length;
  const el = resMatchEls[resMatchIdx];
  el.classList.add("raw-hit-active");
  el.scrollIntoView({ block: "center" });
  $("#resSearchCount").textContent = `${resMatchIdx + 1}/${resMatchEls.length}`;
}

function renderReqRaw(rec) {
  $("#reqBarMeta").textContent = rec.remoteIP ? rec.remoteIP : "";
  $("#btnReqPretty").textContent = reqPretty ? "原始 Raw" : "美化 JSON";
  renderTintedRaw($("#reqRawBox"), formatRawRequest(rec, { prettyJson: reqPretty }));
}

function renderResRaw(rec) {
  const st = $("#resStatusTag");
  st.textContent = rec.failed ? "ERR" : `${rec.status ?? "-"} ${rec.statusText || ""}`.trim();
  st.className = `st-tag ${statusCls(rec)}`;
  $("#resReplacedTag").classList.toggle("hidden", !rec.replaced);
  $("#resBarMeta").textContent = [rec.duration != null ? `${Math.round(rec.duration)} ms` : "", (rec.mimeType || "").split(";")[0]].filter(Boolean).join(" · ");

  const box = $("#resRawBox");
  const imgWrap = $("#resImgWrap");
  const bigNotice = $("#resBigNotice");
  const mime = (rec.mimeType || "").toLowerCase();

  if (mime.startsWith("image/") && rec.resBodyB64 && resMode !== "hex") {
    box.classList.add("hidden");
    bigNotice.classList.add("hidden");
    imgWrap.classList.remove("hidden");
    $("#resImg").src = `data:${mime.split(";")[0]};base64,${rec.resBody}`;
    return;
  }

  imgWrap.classList.add("hidden");
  box.classList.remove("hidden");
  $("#btnResPretty").textContent = resMode === "pretty" ? "原始 Raw" : "美化 JSON";
  $("#btnResHex").textContent = resMode === "hex" ? "原始 Raw" : "Hex";

  let text = formatRawResponse(rec, { prettyJson: resMode === "pretty", hex: resMode === "hex" });
  if (!resShowFull && text.length > BIG_RAW_LIMIT) {
    $("#resBigText").textContent = `响应体较大（${Math.round(text.length / 1024)} KB），已先展示前 250 KB 防止卡顿`;
    bigNotice.classList.remove("hidden");
    text = text.slice(0, BIG_RAW_LIMIT) + "\n\n…（已截断预览，点击上方「显示完整内容」展开）";
  } else {
    bigNotice.classList.add("hidden");
  }

  const kw = $("#resSearchInp").value.trim();
  resMatchEls = renderTintedRaw(box, text, kw);
  resMatchIdx = -1;
  const nav = $("#resSearchNav");
  if (kw) {
    nav.classList.remove("hidden");
    $("#resSearchCount").textContent = resMatchEls.length ? `1/${resMatchEls.length}` : "0/0";
    if (resMatchEls.length) jumpResMatch(1);
  } else {
    nav.classList.add("hidden");
  }
}

/* ============================ 极简 Burp 式重放器 ============================ */

function switchWorkMode(mode) {
  $$("#workModeSwitch .seg-item").forEach((b) => b.classList.toggle("active", b.dataset.work === mode));
  $("#paneInspect").classList.toggle("active", mode === "inspect");
  $("#paneReplay").classList.toggle("active", mode === "replay");
  $("#paneCodec").classList.toggle("active", mode === "codec");
  $("#inspectActions").classList.toggle("hidden", mode !== "inspect");
  hideSelFloat();
}

function openInRepeater(rec = null) {
  if (rec) {
    const exist = repeaterTabs.find((t) => t.sourceRecordId === rec.id);
    if (exist) {
      activeRepeaterId = exist.id;
      renderRepeaterTabs();
      renderActiveRepeater();
      switchWorkMode("replay");
      return;
    }
  }

  const rawText = rec
    ? formatRawRequest(rec, { fullUrl: true })
    : "GET https://example.com/api HTTP/1.1\nAccept: application/json\n\n";

  const title = rec
    ? `${(rec.method || "GET").toUpperCase()} ${getPathAndQuery(rec.url || "").split("?")[0].slice(0, 20)}`
    : `新建 #${repeaterTabs.length + 1}`;

  const tab = {
    id: uid("rpt"),
    title,
    sourceRecordId: rec?.id || null,
    fallbackUrl: rec?.url || "",
    origStatus: rec?.status ?? null,
    origResRaw: rec ? formatRawResponse(rec, { prettyJson: true }) : "",
    origReqBodyB64: rec?.reqBodyB64 ? rec.reqBody : null,
    origReqBinPlaceholder: rec?.reqBodyB64 ? `[二进制请求体 ${decodeBody(rec, "req").bytes.length} bytes]` : null,
    rawText,
    baseline: rawText,
    lastCommitted: rawText,
    undoStack: [],
    mode: "background",
    response: null,
    responseTag: "",
    resView: "raw", // raw | pretty | diff
    history: [],
    activeHistIdx: -1,
  };

  repeaterTabs.push(tab);
  activeRepeaterId = tab.id;
  renderRepeaterTabs();
  renderActiveRepeater();
  switchWorkMode("replay");
}

function activeRepeater() {
  return repeaterTabs.find((t) => t.id === activeRepeaterId) || null;
}

function renderRepeaterTabs() {
  const wrap = $("#repeaterTabs");
  wrap.textContent = "";
  const badge = $("#replayBadge");
  badge.textContent = String(repeaterTabs.length);
  badge.classList.toggle("hidden", repeaterTabs.length === 0);

  for (const tab of repeaterTabs) {
    const el = document.createElement("div");
    el.className = "rp-tab" + (tab.id === activeRepeaterId ? " active" : "");
    const n = document.createElement("span");
    n.className = "rp-tab-name";
    n.textContent = tab.title;
    n.title = "双击重命名页签";
    n.addEventListener("dblclick", (e) => {
      e.stopPropagation();
      const next = prompt("重命名重放页签", tab.title);
      if (next && next.trim()) { tab.title = next.trim(); renderRepeaterTabs(); }
    });
    const x = document.createElement("button");
    x.className = "rp-tab-x";
    x.textContent = "×";
    x.addEventListener("click", (e) => {
      e.stopPropagation();
      const idx = repeaterTabs.findIndex((t) => t.id === tab.id);
      if (idx >= 0) repeaterTabs.splice(idx, 1);
      if (activeRepeaterId === tab.id) activeRepeaterId = repeaterTabs[Math.max(0, idx - 1)]?.id || null;
      renderRepeaterTabs();
      renderActiveRepeater();
    });
    el.addEventListener("click", () => {
      activeRepeaterId = tab.id;
      renderRepeaterTabs();
      renderActiveRepeater();
    });
    el.append(n, x);
    wrap.appendChild(el);
  }
}

let undoTimer = null;
function scheduleUndo(tab) {
  clearTimeout(undoTimer);
  undoTimer = setTimeout(() => {
    if (tab.rawText !== tab.lastCommitted) {
      tab.undoStack.push(tab.lastCommitted);
      if (tab.undoStack.length > 40) tab.undoStack.shift();
      tab.lastCommitted = tab.rawText;
    }
  }, 400);
}

function renderActiveRepeater() {
  const tab = activeRepeater();
  $("#replayEmpty").classList.toggle("hidden", !!tab);
  $("#replayBody").classList.toggle("hidden", !tab);
  if (!tab) return;

  $("#rpRaw").value = tab.rawText;
  $("#rpMode").value = tab.mode;
  renderRepeaterHistory(tab);
  renderRepeaterResponse(tab);
}

function renderRepeaterHistory(tab) {
  const pills = $("#rpHistoryPills");
  pills.textContent = "";
  tab.history.forEach((h, idx) => {
    const b = document.createElement("button");
    b.className = "hist-pill" + (idx === tab.activeHistIdx ? " active" : "");
    const st = h.response?.ok === false ? "ERR" : (h.response?.status ?? "-");
    b.textContent = `#${idx + 1} ${st}`;
    b.title = `点击还原第 ${idx + 1} 次发送的请求与响应`;
    b.addEventListener("click", () => {
      tab.activeHistIdx = idx;
      tab.rawText = h.rawText;
      tab.lastCommitted = h.rawText;
      tab.response = h.response;
      tab.responseTag = h.tag;
      renderActiveRepeater();
    });
    pills.appendChild(b);
  });
}

function formatReplayResponseRaw(r, prettyJson = false) {
  if (r.ok === false) return r.error || "请求失败";
  const lines = [`HTTP/1.1 ${r.status ?? "-"} ${r.statusText || ""}`.trim()];
  for (const [k, v] of r.headers || []) lines.push(`${k}: ${v}`);
  const bytes = r.body ? base64ToBytes(r.body) : new Uint8Array(0);
  const ctype = (r.headers || []).find(([k]) => String(k).toLowerCase() === "content-type")?.[1] || "";
  if (looksBinary(ctype, r.body)) {
    if (bytes.length) lines.push("", hexDump(bytes));
  } else {
    let text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    if (prettyJson) {
      const p = tryParseJSON(text);
      if (p !== null) text = JSON.stringify(p, null, 2);
    }
    if (text) lines.push("", text);
  }
  return lines.join("\n");
}

function renderRepeaterResponse(tab) {
  const r = tab.response;
  const empty = $("#rpResEmpty");
  const pre = $("#rpResRaw");
  const diffBox = $("#rpResDiff");
  const st = $("#rpResStatus");
  const tag = $("#rpResTag");
  const delta = $("#rpResDelta");

  if (!r) {
    empty.classList.remove("hidden");
    pre.classList.add("hidden");
    diffBox.classList.add("hidden");
    st.textContent = "";
    tag.classList.add("hidden");
    delta.textContent = "";
    return;
  }

  empty.classList.add("hidden");
  tag.textContent = tab.responseTag || "";
  tag.classList.toggle("hidden", !tab.responseTag);

  if (r.ok === false) {
    st.textContent = "ERR";
    st.className = "st-tag s-fail";
    delta.textContent = "";
  } else {
    st.textContent = `${r.status} ${r.statusText || ""}`.trim();
    st.className = `st-tag ${statusCls({ status: r.status })}`;
    const bits = [];
    if (tab.origStatus != null && tab.origStatus !== r.status) bits.push(`${tab.origStatus} → ${r.status}`);
    if (r.duration != null) bits.push(`${Math.round(r.duration)} ms`);
    delta.textContent = bits.join(" · ");
  }

  $$("#rpResSwitch .seg-item").forEach((b) => b.classList.toggle("active", b.dataset.rpres === tab.resView));

  if (tab.resView === "diff") {
    pre.classList.add("hidden");
    diffBox.classList.remove("hidden");
    diffBox.textContent = "";
    const curRaw = formatReplayResponseRaw(r, true);
    const df = diffText(tab.origResRaw || "", curRaw);
    if (df.identical) {
      diffBox.innerHTML = `<div class="diff-line diff-same">与原始抓包响应完全一致</div>`;
    } else {
      const frag = document.createDocumentFragment();
      for (const l of df.lines) {
        const div = document.createElement("div");
        div.className = `diff-line diff-${l.type}`;
        div.textContent = (l.type === "add" ? "+ " : l.type === "del" ? "- " : "  ") + l.text;
        frag.appendChild(div);
      }
      diffBox.appendChild(frag);
    }
  } else {
    diffBox.classList.add("hidden");
    pre.classList.remove("hidden");
    pre.textContent = formatReplayResponseRaw(r, tab.resView === "pretty");
  }
}

async function sendRepeater({ stripAuth = false, profile = null } = {}) {
  const tab = activeRepeater();
  if (!tab) return;

  const parsed = parseRawRequestText(tab.rawText, tab.fallbackUrl);
  if (!parsed.url) return toast("请在首行提供有效 URL", "warn");

  let headers = parsed.headers;
  if (profile) {
    const extra = parseHeaderText(profile.headersText || "");
    const names = new Set(extra.map((h) => h.name.toLowerCase()));
    headers = headers.filter((h) => !names.has(h.name.toLowerCase()));
    headers.push(...extra);
  }

  const btn = $("#btnRpSend");
  btn.disabled = true;
  btn.textContent = "发送中…";
  try {
    const useBody = !["GET", "HEAD"].includes(parsed.method);
    const { result } = await send({
      type: "replay",
      spec: {
        tabId: currentTabId,
        mode: stripAuth || profile ? "background" : tab.mode,
        method: parsed.method,
        url: parsed.url,
        headers,
        body: useBody
          ? (tab.origReqBodyB64 && parsed.body.trim() === tab.origReqBinPlaceholder ? tab.origReqBodyB64 : (parsed.body || null))
          : null,
        bodyIsBase64: !!(useBody && tab.origReqBodyB64 && parsed.body.trim() === tab.origReqBinPlaceholder),
        followRedirect: true,
        stripAuth,
        sourceRecordId: tab.sourceRecordId,
      },
    });
    tab.response = result;
    tab.responseTag = stripAuth ? "去鉴权" : profile ? profile.name : "";
    tab.history.push({ rawText: tab.rawText, tag: tab.responseTag, response: result });
    if (tab.history.length > 15) tab.history.shift();
    tab.activeHistIdx = tab.history.length - 1;
    renderRepeaterHistory(tab);
    renderRepeaterResponse(tab);
    toast(result.ok === false ? "发送失败" : `响应 ${result.status}`, result.ok === false ? "err" : "ok");
  } catch (e) {
    toast(e.message, "err");
  } finally {
    btn.disabled = false;
    btn.textContent = "发送";
  }
}

/* ============================ 断点规则 / Mock / 身份预设 ============================ */

async function togglePin(method, pathOnly) {
  try {
    const { pinned, rules: nextRules } = await send({
      type: "togglePinBreakpoint",
      tabId: currentTabId,
      method,
      urlPattern: pathOnly,
    });
    rules = nextRules;
    updateConfigBadges();
    scheduleRender();
    toast(pinned ? `已为 ${pathOnly} 挂上断点` : `已取消 ${pathOnly} 断点`, "ok");
  } catch (e) {
    toast(e.message, "err");
  }
}

let cfgDraft = { rules: [], replaces: [], mocks: [], profiles: [] };
function openConfigModal(initialTab = "rules", prefillMock = null) {
  cfgDraft = {
    rules: structuredClone(rules),
    replaces: structuredClone(replaces),
    mocks: structuredClone(mocks),
    profiles: structuredClone(authProfiles),
  };
  if (prefillMock) cfgDraft.mocks.unshift(prefillMock);
  renderConfigModal();
  $$("#configTabs .seg-item").forEach((b) => b.classList.toggle("active", b.dataset.cfg === initialTab));
  $$(".cfg-pane[data-cfgpane]").forEach((p) => p.classList.toggle("active", p.dataset.cfgpane === initialTab));
  $("#configModal").classList.remove("hidden");
}

function renderConfigModal() {
  const rl = $("#rulesList");
  rl.textContent = "";
  cfgDraft.rules.forEach((r, idx) => {
    const c = document.createElement("div");
    c.className = "cfg-card";
    c.innerHTML = `<div class="cfg-row">
      <input type="checkbox" ${r.enabled ? "checked" : ""}>
      <select class="select-xs stage-sel">
        <option value="Request" ${(r.stage || "Request") === "Request" ? "selected" : ""}>请求前</option>
        <option value="Response" ${r.stage === "Response" ? "selected" : ""}>响应后</option>
      </select>
      <select class="select-xs mono method-sel">${["ANY", "GET", "POST", "PUT", "PATCH", "DELETE"].map((m) => `<option ${r.method === m ? "selected" : ""}>${m}</option>`).join("")}</select>
      <input class="input-sm grow mono" type="text" placeholder="URL 包含或正则">
      <button class="text-btn">删除</button>
    </div>`;
    const cb = c.querySelector('input[type="checkbox"]');
    const st = c.querySelector(".stage-sel");
    const ms = c.querySelector(".method-sel");
    const inp = c.querySelector('input[type="text"]');
    const del = c.querySelector("button");
    inp.value = r.url || "";
    cb.addEventListener("change", () => { r.enabled = cb.checked; });
    st.addEventListener("change", () => { r.stage = st.value; });
    ms.addEventListener("change", () => { r.method = ms.value; });
    inp.addEventListener("input", () => { r.url = inp.value; });
    del.addEventListener("click", () => { cfgDraft.rules.splice(idx, 1); renderConfigModal(); });
    rl.appendChild(c);
  });

  const rpl = $("#replacesList");
  rpl.textContent = "";
  cfgDraft.replaces.forEach((rp, idx) => {
    const c = document.createElement("div");
    c.className = "cfg-card";
    c.innerHTML = `<div class="cfg-row">
      <input type="checkbox" class="rp-en" ${rp.enabled ? "checked" : ""}>
      <select class="select-xs mono rp-method">${["ANY", "GET", "POST", "PUT", "PATCH", "DELETE"].map((m) => `<option ${rp.method === m ? "selected" : ""}>${m}</option>`).join("")}</select>
      <input class="input-sm grow mono rp-url" type="text" placeholder="匹配路径（* 匹配全部）">
      <label class="menu-check" style="padding:0 4px"><input type="checkbox" class="rp-re" ${rp.isRegex ? "checked" : ""}><span>正则</span></label>
      <input class="input-sm mono rp-st" type="number" style="width:74px" placeholder="状态码" value="${rp.status || ""}">
      <button class="text-btn rp-del">删除</button>
    </div>
    <div class="cfg-row">
      <input class="input-sm grow mono rp-find" type="text" placeholder="查找内容，如 &quot;isLogin&quot;:false">
      <span class="io-meta">→</span>
      <input class="input-sm grow mono rp-rep" type="text" placeholder="替换为，如 &quot;isLogin&quot;:true">
    </div>`;
    const en = c.querySelector(".rp-en");
    const ms = c.querySelector(".rp-method");
    const uInp = c.querySelector(".rp-url");
    const reCb = c.querySelector(".rp-re");
    const stInp = c.querySelector(".rp-st");
    const fInp = c.querySelector(".rp-find");
    const rInp = c.querySelector(".rp-rep");
    const del = c.querySelector(".rp-del");
    uInp.value = rp.url || "";
    fInp.value = rp.find || "";
    rInp.value = rp.replace || "";
    en.addEventListener("change", () => { rp.enabled = en.checked; });
    ms.addEventListener("change", () => { rp.method = ms.value; });
    uInp.addEventListener("input", () => { rp.url = uInp.value; });
    reCb.addEventListener("change", () => { rp.isRegex = reCb.checked; });
    stInp.addEventListener("input", () => { rp.status = stInp.value ? Number(stInp.value) : ""; });
    fInp.addEventListener("input", () => { rp.find = fInp.value; });
    rInp.addEventListener("input", () => { rp.replace = rInp.value; });
    del.addEventListener("click", () => { cfgDraft.replaces.splice(idx, 1); renderConfigModal(); });
    rpl.appendChild(c);
  });

  const ml = $("#mocksList");
  ml.textContent = "";
  cfgDraft.mocks.forEach((m, idx) => {
    const c = document.createElement("div");
    c.className = "cfg-card";
    c.innerHTML = `<div class="cfg-row">
      <input type="checkbox" ${m.enabled ? "checked" : ""}>
      <select class="select-xs mono">${["ANY", "GET", "POST", "PUT", "DELETE"].map((x) => `<option ${m.method === x ? "selected" : ""}>${x}</option>`).join("")}</select>
      <input class="input-sm grow mono" type="text" placeholder="匹配路径">
      <input class="input-sm mono" type="number" style="width:74px" value="${m.status || 200}">
      <button class="text-btn">删除</button>
    </div>
    <textarea class="ta mono" rows="4" spellcheck="false"></textarea>`;
    const cb = c.querySelector('input[type="checkbox"]');
    const sel = c.querySelector("select");
    const uInp = c.querySelector('input[type="text"]');
    const sInp = c.querySelector('input[type="number"]');
    const ta = c.querySelector("textarea");
    const del = c.querySelector("button");
    uInp.value = m.url || "";
    ta.value = m.body || "";
    cb.addEventListener("change", () => { m.enabled = cb.checked; });
    sel.addEventListener("change", () => { m.method = sel.value; });
    uInp.addEventListener("input", () => { m.url = uInp.value; });
    sInp.addEventListener("input", () => { m.status = Number(sInp.value) || 200; });
    ta.addEventListener("input", () => { m.body = ta.value; });
    del.addEventListener("click", () => { cfgDraft.mocks.splice(idx, 1); renderConfigModal(); });
    ml.appendChild(c);
  });

  const pl = $("#profilesList");
  pl.textContent = "";
  cfgDraft.profiles.forEach((p, idx) => {
    const c = document.createElement("div");
    c.className = "cfg-card";
    c.innerHTML = `<div class="cfg-row">
      <input class="input-sm grow" type="text" placeholder="身份名称，如：账号 B">
      <button class="text-btn">删除</button>
    </div>
    <textarea class="ta mono" rows="3" spellcheck="false" placeholder="每行一个头，如：\nCookie: sid=userB\nAuthorization: Bearer ..."></textarea>`;
    const inp = c.querySelector("input");
    const ta = c.querySelector("textarea");
    const del = c.querySelector("button");
    inp.value = p.name || "";
    ta.value = p.headersText || "";
    inp.addEventListener("input", () => { p.name = inp.value; });
    ta.addEventListener("input", () => { p.headersText = ta.value; });
    del.addEventListener("click", () => { cfgDraft.profiles.splice(idx, 1); renderConfigModal(); });
    pl.appendChild(c);
  });
}

/* ============================ 挂起拦截队列 ============================ */

async function refreshPaused() {
  if (!currentTabId) return;
  try {
    const { items } = await send({ type: "paused:list", tabId: currentTabId });
    pausedItems = items || [];
    renderPaused();
  } catch {}
}

function renderPaused() {
  const dock = $("#pauseDock");
  const list = $("#pausedList");
  $("#pausedCount").textContent = String(pausedItems.length);
  dock.classList.toggle("hidden", pausedItems.length === 0);
  $("#footHint").classList.toggle("hidden", pausedItems.length > 0);
  list.textContent = "";
  const now = Date.now();
  for (const item of pausedItems) {
    const row = document.createElement("div");
    row.className = "pause-item";
    if (item.stage === "Response") {
      const stg = document.createElement("span");
      stg.className = "stage-tag";
      stg.textContent = `响应 ${item.responseCode || ""}`;
      row.appendChild(stg);
    }
    const m = document.createElement("span");
    m.className = `m-tag ${methodCls(item.method)}`;
    m.textContent = item.method;
    const u = document.createElement("span");
    u.className = "pause-url";
    u.textContent = getPathAndQuery(item.url);
    u.title = item.url;
    const ttl = document.createElement("span");
    ttl.className = "pause-ttl";
    ttl.textContent = `${Math.max(0, Math.ceil(((item.deadline || now) - now) / 1000))}s`;
    const b1 = document.createElement("button"); b1.className = "btn btn-primary btn-xs"; b1.textContent = "处理";
    b1.addEventListener("click", () => openPauseModal(item));
    const b2 = document.createElement("button"); b2.className = "btn btn-soft btn-xs"; b2.textContent = "放行";
    b2.addEventListener("click", () => resolvePaused(item.requestId, "continue", {}));
    const b3 = document.createElement("button"); b3.className = "btn btn-danger btn-xs"; b3.textContent = "阻断";
    b3.addEventListener("click", () => resolvePaused(item.requestId, "fail", { errorReason: "BlockedByClient" }));
    row.append(m, u, ttl, b1, b2, b3);
    list.appendChild(row);
  }
}

function openPauseModal(item) {
  pausedTarget = item;
  const isRes = item.stage === "Response";
  $("#pauseModalTitle").textContent = isRes ? "断点改包 · 响应阶段（实时修改返回包）" : "断点改包 · 请求阶段";
  $("#pmReqSection").classList.toggle("hidden", isRes);
  $("#pmResStageNote").classList.toggle("hidden", !isRes);
  $("#pmResFold").open = isRes;
  $("#pmResSummary").textContent = isRes ? "服务器响应内容" : "直接返回自定义响应（不发往服务器）";
  $("#btnPmFulfill").classList.toggle("hidden", isRes);
  $("#btnPmSend").textContent = isRes ? "修改响应后放行" : "修改后放行";

  if (isRes) {
    $("#pmResCode").value = String(item.responseCode || 200);
    $("#pmResType").value = findHeader(item.responseHeaders, "content-type") || "application/json; charset=utf-8";
    $("#pmResHeaders").value = headersToText(item.responseHeaders);
    let bodyText = item.responseBody || "";
    if (item.responseBodyB64 && bodyText) {
      try { bodyText = new TextDecoder("utf-8", { fatal: false }).decode(base64ToBytes(bodyText)); } catch {}
    }
    const p = tryParseJSON(bodyText);
    $("#pmResBody").value = p !== null ? JSON.stringify(p, null, 2) : bodyText;
  } else {
    $("#pmMethod").value = item.method || "GET";
    $("#pmUrl").value = item.url || "";
    $("#pmHeaders").value = headersToText(item.headers);
    $("#pmBody").value = item.postData || "";
    $("#pmResCode").value = "200";
    $("#pmResType").value = "application/json; charset=utf-8";
    $("#pmResHeaders").value = "";
    $("#pmResBody").value = "";
  }
  updatePauseCountdown();
  $("#pauseModal").classList.remove("hidden");
}

function updatePauseCountdown() {
  if (!pausedTarget) return;
  const sec = Math.max(0, Math.ceil(((pausedTarget.deadline || Date.now()) - Date.now()) / 1000));
  $("#pauseCountdown").textContent = `${sec}s 后自动放行`;
}

async function resolvePaused(requestId, action, payload) {
  try {
    await send({ type: "paused:resolve", requestId, action, payload });
    pausedItems = pausedItems.filter((x) => x.requestId !== requestId);
    renderPaused();
    if (pausedTarget?.requestId === requestId) {
      pausedTarget = null;
      $("#pauseModal").classList.add("hidden");
    }
  } catch (e) {
    toast(e.message, "err");
  }
}

/* ============================ 右键菜单 & 微解码 ============================ */

const ctxMenu = $("#contextMenu");
function showCtx(x, y, items) {
  ctxMenu.textContent = "";
  for (const it of items) {
    if (it === "sep") { const s = document.createElement("div"); s.className = "menu-sep"; ctxMenu.appendChild(s); continue; }
    const el = document.createElement("div");
    el.className = "menu-item";
    el.textContent = it.label;
    el.addEventListener("click", () => { ctxMenu.classList.add("hidden"); it.action(); });
    ctxMenu.appendChild(el);
  }
  ctxMenu.classList.remove("hidden");
  const r = ctxMenu.getBoundingClientRect();
  ctxMenu.style.left = `${Math.min(x, window.innerWidth - r.width - 8)}px`;
  ctxMenu.style.top = `${Math.min(y, window.innerHeight - r.height - 8)}px`;
}

/* ============================ 编解码器、划词浮条与快速响应替换 ============================ */

let lastCodecOp = "";
let selFloatText = "";

function hideSelFloat() {
  const bar = $("#selFloatBar");
  if (bar) bar.classList.add("hidden");
  selFloatText = "";
}

function updateCodecMetaAndDetect() {
  const val = $("#codecInput").value;
  $("#codecInMeta").textContent = `${val.length} 字符 · ${byteLen(val)} B`;
  const sug = $("#codecSuggest");
  sug.textContent = "";
  const hints = detectEncodings(val);
  for (const h of hints) {
    const b = document.createElement("button");
    b.className = "codec-sug-pill";
    b.textContent = h.label;
    b.addEventListener("click", () => executeCodec(h.op));
    sug.appendChild(b);
  }
}

async function executeCodec(op) {
  const input = $("#codecInput").value;
  if (!input && op !== "date_to_ts") {
    $("#codecOutput").value = "";
    $("#codecOpLabel").textContent = "";
    return;
  }
  lastCodecOp = op;
  $$("#codecOpsBar .codec-btn").forEach((b) => b.classList.toggle("active", b.dataset.op === op));
  const label = CODEC_OPS[op]?.label || op;
  $("#codecOpLabel").textContent = label;
  try {
    const out = await runCodecOp(op, input, { secret: $("#codecHmacKey")?.value || "" });
    $("#codecOutput").value = out;
  } catch (e) {
    $("#codecOutput").value = `错误：${e.message}`;
  }
}

function openInCodec(src = "") {
  hideSelFloat();
  switchWorkMode("codec");
  if (src) {
    $("#codecInput").value = src;
    $("#codecOutput").value = "";
    $("#codecOpLabel").textContent = "";
    $$("#codecOpsBar .codec-btn").forEach((b) => b.classList.remove("active"));
    updateCodecMetaAndDetect();
    const hints = detectEncodings(src);
    if (hints.length) executeCodec(hints[0].op);
  } else {
    updateCodecMetaAndDetect();
  }
  $("#codecInput").focus();
}

function openQuickReplace(findText = "") {
  hideSelFloat();
  const defaultPath = currentRecord ? getPathAndQuery(currentRecord.url || "").split("?")[0] : "*";
  $("#qrUrl").value = defaultPath || "*";
  $("#qrFind").value = findText || "";
  $("#qrReplace").value = "";
  $("#qrRegex").checked = false;
  $("#qrStatus").value = "";
  $("#quickReplaceModal").classList.remove("hidden");
  setTimeout(() => {
    if (findText) $("#qrReplace").focus();
    else $("#qrFind").focus();
  }, 20);
}

async function submitQuickReplace() {
  const url = $("#qrUrl").value.trim() || "*";
  const find = $("#qrFind").value;
  const replace = $("#qrReplace").value;
  const isRegex = $("#qrRegex").checked;
  const statusRaw = $("#qrStatus").value.trim();
  const status = statusRaw ? Number(statusRaw) : "";
  if (!find && !status) return toast("请填写查找内容或目标状态码", "warn");
  try {
    const { replaces: nextReplaces } = await send({
      type: "addReplaceRule",
      rule: { method: "ANY", url, find, replace, isRegex, status },
    });
    replaces = nextReplaces;
    updateConfigBadges();
    $("#quickReplaceModal").classList.add("hidden");
    toast(`已启用响应替换（${url}），刷新或重发即生效`, "ok");
  } catch (e) {
    toast(e.message, "err");
  }
}

function renderHostTags() {
  const wrap = $("#hostTags");
  wrap.textContent = "";
  if (filterState.focusHost) {
    const t = document.createElement("span");
    t.className = "host-tag";
    t.innerHTML = `仅 ${filterState.focusHost} <button>×</button>`;
    t.querySelector("button").addEventListener("click", () => { filterState.focusHost = ""; renderHostTags(); applyFilter(); });
    wrap.appendChild(t);
  }
  for (const h of filterState.hiddenHosts) {
    const t = document.createElement("span");
    t.className = "host-tag";
    t.innerHTML = `-${h} <button>×</button>`;
    t.querySelector("button").addEventListener("click", () => { filterState.hiddenHosts.delete(h); renderHostTags(); applyFilter(); });
    wrap.appendChild(t);
  }
}

/* ============================ 事件绑定 ============================ */

function bindEvents() {
  document.documentElement.dataset.theme = localStorage.getItem("tb_theme_v3") || "light";
  $("#btnTheme").addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = next;
    localStorage.setItem("tb_theme_v3", next);
  });

  $("#tabSelect").addEventListener("change", (e) => switchTab(e.target.value));
  $("#btnCapture").addEventListener("click", async () => {
    if (!currentTabId) return toast("请先选择普通网页标签页", "warn");
    try {
      const { state } = await send({ type: attached ? "detach" : "attach", tabId: currentTabId });
      applyState(state);
      toast(state.attached ? "已开始抓包" : "已停止抓包", "ok");
    } catch (e) { toast(e.message, "err"); }
  });
  $("#btnRecordPause").addEventListener("click", async () => {
    if (!currentTabId) return;
    const { state } = await send({ type: "setRecording", tabId: currentTabId, recording: !recording });
    applyState(state);
  });
  $("#btnInterceptToggle").addEventListener("click", async () => {
    if (!currentTabId || !attached) return toast("请先开始抓包", "warn");
    try {
      const { state } = await send({ type: "setIntercept", tabId: currentTabId, enabled: !interceptEnabled });
      applyState(state);
    } catch (e) { toast(e.message, "err"); }
  });
  $("#btnRulesDrawer").addEventListener("click", () => openConfigModal("rules"));

  // 搜索与直观过滤芯片
  const inp = $("#filterInput");
  function syncBodySearchBtn() {
    $("#btnBodySearch").classList.toggle("active", filterState.bodySearchIds !== null);
  }
  async function runBodySearch() {
    if (!currentTabId || !inp.value.trim()) return toast("请先输入关键字", "warn");
    const { ids } = await send({ type: "searchBodies", tabId: currentTabId, query: inp.value.trim() });
    filterState.bodySearchIds = new Set(ids);
    syncBodySearchBtn();
    applyFilter();
    toast(`正文命中 ${ids.length} 条`, "ok");
  }
  inp.addEventListener("input", () => {
    filterState.query = inp.value;
    $("#btnClearSearch").classList.toggle("hidden", !inp.value);
    if (filterState.bodySearchIds !== null) {
      filterState.bodySearchIds = null;
      syncBodySearchBtn();
    }
    applyFilter();
  });
  inp.addEventListener("keydown", (e) => { if (e.key === "Enter" && inp.value.trim()) runBodySearch(); });
  $("#btnBodySearch").addEventListener("click", runBodySearch);
  $("#btnClearSearch").addEventListener("click", () => {
    inp.value = ""; filterState.query = ""; filterState.bodySearchIds = null;
    syncBodySearchBtn();
    $("#btnClearSearch").classList.add("hidden");
    syncBodySearchBtn();
    applyFilter();
  });

  // HTTP 方法多选芯片（GET / POST / PUT / DELETE / PATCH）
  $$(".chip-m[data-method]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const m = btn.dataset.method;
      if (filterState.methods.has(m)) filterState.methods.delete(m);
      else filterState.methods.add(m);
      btn.classList.toggle("active", filterState.methods.has(m));
      applyFilter();
    });
  });

  const bindChip = (id, key) => {
    $(id).addEventListener("click", () => {
      filterState[key] = !filterState[key];
      $(id).classList.toggle("active", filterState[key]);
      applyFilter();
    });
  };
  bindChip("#chipHideStatic", "hideStatic");
  bindChip("#chipHasBody", "hasBody");
  bindChip("#chip2xx", "only2xx");
  bindChip("#chipErr", "onlyError");
  bindChip("#chipSameHost", "sameHost");

  $("#btnClear").addEventListener("click", async () => {
    if (!currentTabId) return;
    await send({ type: "clearRecords", tabId: currentTabId });
    allRows = []; viewRows = []; dbTotal = 0; recordCache.clear();
    selectedId = null; currentRecord = null;
    showInspectEmpty();
    applyFilter(true);
    toast("已清空", "ok");
  });

  // 列表滚动、点击、右键
  viewport.addEventListener("scroll", () => {
    scheduleRender();
    if (viewport.scrollTop + viewport.clientHeight >= viewport.scrollHeight - 320) loadMore();
  });
  rowsEl.addEventListener("click", (e) => {
    const c = e.target.closest(".req-card");
    if (c) selectRecord(c.dataset.id);
  });
  rowsEl.addEventListener("contextmenu", (e) => {
    const c = e.target.closest(".req-card");
    if (!c) return;
    e.preventDefault();
    const r = allRows.find((x) => x.id === c.dataset.id);
    if (!r) return;
    const host = getHost(r.url || "");
    const pathOnly = getPathAndQuery(r.url || "").split("?")[0];
    showCtx(e.clientX, e.clientY, [
      { label: "⚡ 发送到重放器", action: async () => { await selectRecord(r.id); if (currentRecord) openInRepeater(currentRecord); } },
      { label: "📌 切换断点", action: () => togglePin(r.method || "GET", pathOnly) },
      "sep",
      { label: "复制 Raw HTTP", action: async () => copyText((await send({ type: "exportOne", id: r.id, format: "raw" })).data) },
      { label: "复制 cURL (Bash)", action: async () => copyText((await send({ type: "exportOne", id: r.id, format: "curl-bash" })).data) },
      { label: "删除此条记录", action: () => deleteOneRecord(r.id) },
      ...(host ? [
        "sep",
        { label: `仅看域名：${host}`, action: () => { filterState.focusHost = host; renderHostTags(); applyFilter(); } },
        { label: `隐藏域名：${host}`, action: () => { filterState.hiddenHosts.add(host); renderHostTags(); applyFilter(); } },
      ] : []),
    ]);
  });

  async function applyRepeaterInPlace(op) {
    const ta = $("#rpRaw");
    const tab = activeRepeater();
    if (!ta || !tab) return;
    const start = ta.selectionStart;
    const end = ta.selectionEnd;
    if (start == null || end == null || end <= start) return;
    const slice = ta.value.slice(start, end);
    try {
      const converted = await runCodecOp(op, slice);
      tab.undoStack.push(tab.rawText);
      const next = ta.value.slice(0, start) + converted + ta.value.slice(end);
      ta.value = next;
      tab.rawText = next;
      tab.lastCommitted = next;
      ta.focus();
      ta.setSelectionRange(start, start + converted.length);
      hideSelFloat();
      toast(`已原位执行 ${CODEC_OPS[op]?.label || op}`, "ok");
    } catch (e) {
      toast(e.message, "err");
    }
  }

  $("#panelWork").addEventListener("contextmenu", (e) => {
    const inRp = e.target.id === "rpRaw";
    const sel = inRp
      ? $("#rpRaw").value.slice($("#rpRaw").selectionStart, $("#rpRaw").selectionEnd).trim()
      : (window.getSelection()?.toString().trim() || "");
    if (!sel) return;
    e.preventDefault();
    const inRes = !!e.target.closest("#resRawBox");
    const items = [];
    if (inRes && currentRecord) {
      items.push({ label: "⚡ 固定替换此响应内容", action: () => openQuickReplace(sel) });
    }
    if (inRp) {
      items.push(
        { label: "原位 URL 编码", action: () => applyRepeaterInPlace("url_enc") },
        { label: "原位 URL 解码", action: () => applyRepeaterInPlace("url_dec") },
        { label: "原位 Base64 编码", action: () => applyRepeaterInPlace("b64_enc") },
        { label: "原位 Base64 解码", action: () => applyRepeaterInPlace("b64_dec") },
        "sep"
      );
    }
    items.push(
      { label: "🔐 发送到编解码器", action: () => openInCodec(sel) },
      { label: "复制选中文本", action: () => copyText(sel) }
    );
    showCtx(e.clientX, e.clientY, items);
  });

  // 划词快捷浮条：报文区支持「固定替换 / 编解码」，重放器支持「原位编解码」，滚动自动收起
  for (const boxId of ["#reqRawBox", "#resRawBox", "#rpRaw"]) {
    $(boxId).addEventListener("scroll", hideSelFloat, { passive: true });
    $(boxId).addEventListener("mouseup", (e) => {
      setTimeout(() => {
        const isRp = boxId === "#rpRaw";
        let text = "";
        let anchor = { left: e.clientX, top: e.clientY };
        if (isRp) {
          const ta = $("#rpRaw");
          text = ta.value.slice(ta.selectionStart, ta.selectionEnd).trim();
        } else {
          const s = window.getSelection();
          text = s ? s.toString().trim() : "";
          if (s && s.rangeCount) anchor = s.getRangeAt(0).getBoundingClientRect();
        }
        if (!text || text.length < 2 || text.length > 2000) {
          hideSelFloat();
          return;
        }
        const bar = $("#selFloatBar");
        selFloatText = text;
        const isRes = boxId === "#resRawBox" && !!currentRecord;
        $("#btnSelReplace").classList.toggle("hidden", !isRes);
        $$("#selFloatBar [data-rpinplace]").forEach((b) => b.classList.toggle("hidden", !isRp));
        bar.classList.remove("hidden");
        const bw = bar.offsetWidth || 200;
        const left = Math.max(8, Math.min(window.innerWidth - bw - 8, anchor.left));
        const top = Math.max(8, anchor.top - 38);
        bar.style.left = `${left}px`;
        bar.style.top = `${top}px`;
      }, 10);
    });
  }
  $$("#selFloatBar [data-rpinplace]").forEach((b) => {
    b.addEventListener("click", () => applyRepeaterInPlace(b.dataset.rpinplace));
  });
  $("#btnSelReplace").addEventListener("click", () => openQuickReplace(selFloatText));
  $("#btnSelCodec").addEventListener("click", () => openInCodec(selFloatText));
  $("#btnQuickReplace").addEventListener("click", () => openQuickReplace(""));
  $("#btnQrAllUrl").addEventListener("click", () => { $("#qrUrl").value = "*"; });
  $("#btnQrSave").addEventListener("click", submitQuickReplace);
  $("#qrReplace").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); submitQuickReplace(); } });

  // 编解码器事件
  $("#codecInput").addEventListener("input", updateCodecMetaAndDetect);
  $("#codecOpsBar").addEventListener("click", (e) => {
    const b = e.target.closest(".codec-btn[data-op]");
    if (b) executeCodec(b.dataset.op);
  });
  $("#btnCodecChain").addEventListener("click", () => {
    const out = $("#codecOutput").value;
    if (!out) return toast("当前没有可继续处理的结果", "warn");
    $("#codecInput").value = out;
    $("#codecOutput").value = "";
    $("#codecOpLabel").textContent = "";
    $$("#codecOpsBar .codec-btn").forEach((b) => b.classList.remove("active"));
    updateCodecMetaAndDetect();
    toast("已将结果送回输入框，可继续下一层编解码", "ok");
  });
  $("#btnCodecSwap").addEventListener("click", () => {
    const a = $("#codecInput").value;
    const b = $("#codecOutput").value;
    $("#codecInput").value = b;
    $("#codecOutput").value = a;
    updateCodecMetaAndDetect();
  });
  $("#btnCodecClear").addEventListener("click", () => {
    $("#codecInput").value = "";
    $("#codecOutput").value = "";
    $("#codecOpLabel").textContent = "";
    $$("#codecOpsBar .codec-btn").forEach((b) => b.classList.remove("active"));
    updateCodecMetaAndDetect();
  });
  $("#btnCodecCopy").addEventListener("click", () => copyText($("#codecOutput").value));

  // 右侧模式切换：点击「重放器」自动带入当前选中报文
  $("#workModeSwitch").addEventListener("click", (e) => {
    const b = e.target.closest(".seg-item");
    if (!b) return;
    if (b.dataset.work === "replay" && currentRecord) {
      openInRepeater(currentRecord);
      return;
    }
    switchWorkMode(b.dataset.work);
  });

  // 报文详情动作
  $("#dHeroSummary").addEventListener("click", () => currentRecord?.url && copyText(currentRecord.url));
  $("#dSecPill").addEventListener("click", () => $("#secDrawer").classList.toggle("hidden"));
  $("#btnToReplay").addEventListener("click", () => currentRecord && openInRepeater(currentRecord));
  $("#btnQuickMock").addEventListener("click", () => {
    if (!currentRecord) return;
    const d = decodeBody(currentRecord, "res");
    const bodyText = d.binary ? "" : (tryParseJSON(d.text) ? JSON.stringify(tryParseJSON(d.text), null, 2) : d.text);
    openConfigModal("mocks", {
      id: uid("mock"),
      enabled: true,
      method: currentRecord.method || "ANY",
      isRegex: false,
      url: getPathAndQuery(currentRecord.url || "").split("?")[0],
      status: currentRecord.status || 200,
      contentType: currentRecord.mimeType || "application/json; charset=utf-8",
      body: bodyText || '{"code": 0}',
    });
  });

  $("#btnReqPretty").addEventListener("click", () => { reqPretty = !reqPretty; if (currentRecord) renderReqRaw(currentRecord); });
  $("#btnCopyReqRaw").addEventListener("click", () => copyText($("#reqRawBox").textContent));
  $("#btnResPretty").addEventListener("click", () => { resMode = resMode === "pretty" ? "raw" : "pretty"; if (currentRecord) renderResRaw(currentRecord); });
  $("#btnResHex").addEventListener("click", () => { resMode = resMode === "hex" ? "raw" : "hex"; if (currentRecord) renderResRaw(currentRecord); });
  $("#btnCopyResRaw").addEventListener("click", () => copyText($("#resRawBox").textContent));
  let resSearchTimer = null;
  $("#resSearchInp").addEventListener("input", () => {
    clearTimeout(resSearchTimer);
    resSearchTimer = setTimeout(() => currentRecord && renderResRaw(currentRecord), 150);
  });
  $("#resSearchInp").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); jumpResMatch(e.shiftKey ? -1 : 1); }
  });
  $("#btnResPrev").addEventListener("click", () => jumpResMatch(-1));
  $("#btnResNext").addEventListener("click", () => jumpResMatch(1));
  $("#btnResShowFull").addEventListener("click", () => { resShowFull = true; if (currentRecord) renderResRaw(currentRecord); });

  async function deleteOneRecord(id) {
    try {
      await send({ type: "deleteRecord", id });
      allRows = allRows.filter((r) => r.id !== id);
      dbTotal = Math.max(0, dbTotal - 1);
      recordCache.delete(id);
      if (selectedId === id) { selectedId = null; currentRecord = null; showInspectEmpty(); }
      applyFilter(false);
      toast("已删除", "ok");
    } catch (e) { toast(e.message, "err"); }
  }
  $("#btnDeleteOne").addEventListener("click", () => currentRecord && deleteOneRecord(currentRecord.id));

  $("#btnResetFilters").addEventListener("click", () => {
    inp.value = "";
    filterState.query = "";
    filterState.hideStatic = true;
    filterState.methods.clear();
    filterState.hasBody = false;
    filterState.only2xx = false;
    filterState.onlyError = false;
    filterState.sameHost = false;
    filterState.focusHost = "";
    filterState.hiddenHosts.clear();
    filterState.bodySearchIds = null;
    $("#btnClearSearch").classList.add("hidden");
    $("#chipHideStatic").classList.add("active");
    $("#chipHasBody").classList.remove("active");
    $("#chip2xx").classList.remove("active");
    $("#chipErr").classList.remove("active");
    $("#chipSameHost").classList.remove("active");
    $$(".chip-m[data-method]").forEach((b) => b.classList.remove("active"));
    renderHostTags();
    applyFilter(true);
  });

  $("#btnRpLayout").addEventListener("click", () => {
    $(".rp-split").classList.toggle("vertical");
  });

  // 下拉菜单
  const toggleMenu = (btnId, menuId) => {
    $(btnId).addEventListener("click", (e) => {
      e.stopPropagation();
      for (const id of ["exportMenu", "copyMenu", "authSwapMenu", "rpCopyMenu"]) if (id !== menuId) $("#" + id).classList.add("hidden");
      if (menuId === "authSwapMenu") buildAuthSwapMenu();
      $("#" + menuId).classList.toggle("hidden");
    });
  };
  toggleMenu("#btnExport", "exportMenu");
  toggleMenu("#btnCopyMenu", "copyMenu");
  toggleMenu("#btnAuthSwap", "authSwapMenu");
  toggleMenu("#btnRpCopyMenu", "rpCopyMenu");

  $("#rpCopyMenu").addEventListener("click", (e) => {
    const it = e.target.closest("[data-rpcopy]");
    const tab = activeRepeater();
    if (!it || !tab) return;
    $("#rpCopyMenu").classList.add("hidden");
    const p = parseRawRequestText(tab.rawText, tab.fallbackUrl);
    const recLike = { method: p.method, url: p.url, reqHeaders: p.headers, reqBody: p.body || null, reqBodyB64: false };
    const out = it.dataset.rpcopy === "python" ? toPython(recLike) : toCurlBash(recLike);
    copyText(out);
  });

  function buildAuthSwapMenu() {
    const menu = $("#authSwapMenu");
    menu.textContent = "";
    if (!authProfiles.length) {
      const it = document.createElement("div");
      it.className = "menu-item";
      it.textContent = "+ 添加测试身份预设…";
      it.addEventListener("click", () => { menu.classList.add("hidden"); openConfigModal("profiles"); });
      menu.appendChild(it);
      return;
    }
    for (const p of authProfiles) {
      const it = document.createElement("div");
      it.className = "menu-item";
      it.textContent = `用「${p.name}」重发`;
      it.addEventListener("click", () => { menu.classList.add("hidden"); sendRepeater({ profile: p }); });
      menu.appendChild(it);
    }
    const sep = document.createElement("div"); sep.className = "menu-sep";
    const mgr = document.createElement("div"); mgr.className = "menu-item"; mgr.textContent = "管理身份预设…";
    mgr.addEventListener("click", () => { menu.classList.add("hidden"); openConfigModal("profiles"); });
    menu.append(sep, mgr);
  }

  $("#exportMenu").addEventListener("click", async (e) => {
    const it = e.target.closest("[data-export]");
    if (!it) return;
    $("#exportMenu").classList.add("hidden");
    if (!currentTabId || !viewRows.length) return toast("无记录可导出", "warn");
    const ids = viewRows.map((r) => r.id).reverse();
    const { data, ext } = await send({ type: "export", tabId: currentTabId, format: it.dataset.export, ids, redact: $("#chkExportRedact").checked, pageUrl: currentTabUrl });
    const url = URL.createObjectURL(new Blob([data], { type: "text/plain;charset=utf-8" }));
    const a = document.createElement("a"); a.href = url; a.download = `traceburp-${new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19)}.${ext}`; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 3000);
    toast(`已导出 ${ids.length} 条`, "ok");
  });

  $("#copyMenu").addEventListener("click", async (e) => {
    const it = e.target.closest("[data-copy]");
    if (!it || !currentRecord) return;
    $("#copyMenu").classList.add("hidden");
    const { data } = await send({ type: "exportOne", id: currentRecord.id, format: it.dataset.copy, redact: $("#chkExportRedact").checked });
    copyText(data);
  });

  document.addEventListener("click", (e) => {
    for (const id of ["exportMenu", "copyMenu", "authSwapMenu", "rpCopyMenu", "contextMenu"]) {
      const m = $("#" + id);
      if (!m.contains(e.target)) m.classList.add("hidden");
    }
    const sf = $("#selFloatBar");
    if (sf && !sf.contains(e.target) && !e.target.closest("#reqRawBox, #resRawBox, #rpRaw")) {
      hideSelFloat();
    }
  });

  // 极简重放器事件
  $("#btnNewRp").addEventListener("click", () => openInRepeater(null));
  $("#btnRpSend").addEventListener("click", () => sendRepeater());
  $("#btnRpNoAuth").addEventListener("click", () => sendRepeater({ stripAuth: true }));
  $("#rpMode").addEventListener("change", () => { const t = activeRepeater(); if (t) t.mode = $("#rpMode").value; });
  $("#rpRaw").addEventListener("input", () => {
    const t = activeRepeater();
    if (!t) return;
    t.rawText = $("#rpRaw").value;
    scheduleUndo(t);
  });
  $("#btnRpPretty").addEventListener("click", () => {
    const t = activeRepeater();
    if (!t) return;
    const norm = t.rawText.replace(/\r\n/g, "\n");
    const sep = norm.indexOf("\n\n");
    if (sep < 0) return toast("当前请求没有 Body", "warn");
    const head = norm.slice(0, sep);
    const body = norm.slice(sep + 2);
    const p = tryParseJSON(body);
    if (p === null) return toast("请求体不是合法 JSON", "warn");
    t.rawText = `${head}\n\n${JSON.stringify(p, null, 2)}`;
    $("#rpRaw").value = t.rawText;
    scheduleUndo(t);
    toast("已美化 JSON", "ok");
  });
  $("#btnRpUndo").addEventListener("click", () => {
    const t = activeRepeater();
    if (!t || !t.undoStack.length) return toast("没有可撤销的修改", "warn");
    t.rawText = t.undoStack.pop();
    t.lastCommitted = t.rawText;
    $("#rpRaw").value = t.rawText;
  });
  $("#btnRpReset").addEventListener("click", () => {
    const t = activeRepeater();
    if (!t) return;
    t.undoStack.push(t.lastCommitted);
    t.rawText = t.baseline;
    t.lastCommitted = t.baseline;
    $("#rpRaw").value = t.rawText;
    toast("已重置", "ok");
  });
  $("#rpResSwitch").addEventListener("click", (e) => {
    const b = e.target.closest(".seg-item");
    const t = activeRepeater();
    if (!b || !t) return;
    t.resView = b.dataset.rpres;
    renderRepeaterResponse(t);
  });

  // 配置弹窗
  $("#configTabs").addEventListener("click", (e) => {
    const b = e.target.closest(".seg-item");
    if (!b) return;
    $$("#configTabs .seg-item").forEach((x) => x.classList.toggle("active", x === b));
    $$(".cfg-pane[data-cfgpane]").forEach((p) => p.classList.toggle("active", p.dataset.cfgpane === b.dataset.cfg));
  });
  $("#btnAddRule").addEventListener("click", () => {
    cfgDraft.rules.push({ id: uid("rule"), enabled: true, stage: "Request", method: "ANY", isRegex: false, url: "", ignoreStatic: true, pauseTimeoutMs: 60000 });
    renderConfigModal();
  });
  $("#btnAddReplace").addEventListener("click", () => {
    cfgDraft.replaces.push({ id: uid("rep"), enabled: true, method: "ANY", url: "*", find: "", replace: "", isRegex: false, status: "", ignoreStatic: true });
    renderConfigModal();
  });
  $("#btnAddMock").addEventListener("click", () => {
    cfgDraft.mocks.push({ id: uid("mock"), enabled: true, method: "ANY", isRegex: false, url: "", status: 200, contentType: "application/json; charset=utf-8", body: '{"code":0}' });
    renderConfigModal();
  });
  $("#btnAddProfile").addEventListener("click", () => {
    cfgDraft.profiles.push({ id: uid("prof"), name: `账号 ${cfgDraft.profiles.length + 1}`, headersText: "Cookie: sid=\nAuthorization: Bearer " });
    renderConfigModal();
  });
  $("#btnSaveConfig").addEventListener("click", async () => {
    const cleanRules = cfgDraft.rules.filter((r) => r.url?.trim());
    const cleanReplaces = cfgDraft.replaces.filter((r) => r.url?.trim() && (r.find || r.status));
    const cleanMocks = cfgDraft.mocks.filter((m) => m.url?.trim());
    const cleanProfiles = cfgDraft.profiles.filter((p) => p.name?.trim());
    await send({ type: "saveRules", rules: cleanRules });
    await send({ type: "saveReplaces", replaces: cleanReplaces });
    await send({ type: "saveMocks", mocks: cleanMocks });
    await send({ type: "saveAuthProfiles", authProfiles: cleanProfiles });
    rules = cleanRules; replaces = cleanReplaces; mocks = cleanMocks; authProfiles = cleanProfiles;
    updateConfigBadges();
    scheduleRender();
    $("#configModal").classList.add("hidden");
    toast("配置已保存并立即生效", "ok");
  });

  // 断点改包弹窗
  $("#btnPassAll").addEventListener("click", async () => { for (const it of [...pausedItems]) await resolvePaused(it.requestId, "continue", {}); });
  $("#btnPmRaw").addEventListener("click", () => pausedTarget && resolvePaused(pausedTarget.requestId, "continue", {}));
  function buildFulfill() {
    const body = $("#pmResBody").value;
    const hdrs = parseHeaderText($("#pmResHeaders").value);
    return {
      responseCode: Number($("#pmResCode").value) || 200,
      responseHeaders: hdrs.length ? hdrs.filter((h) => !/^content-length$/i.test(h.name)) : [{ name: "Content-Type", value: $("#pmResType").value.trim() || "application/json; charset=utf-8" }],
      body,
      bodyB64: false,
    };
  }
  $("#btnPmSend").addEventListener("click", () => {
    if (!pausedTarget) return;
    if (pausedTarget.stage === "Response") return resolvePaused(pausedTarget.requestId, "fulfill", buildFulfill());
    resolvePaused(pausedTarget.requestId, "continue", {
      url: $("#pmUrl").value.trim(),
      method: $("#pmMethod").value,
      headers: parseHeaderText($("#pmHeaders").value),
      postData: $("#pmBody").value,
      postDataB64: false,
    });
  });
  $("#btnPmFulfill").addEventListener("click", () => pausedTarget && resolvePaused(pausedTarget.requestId, "fulfill", buildFulfill()));
  $("#btnPmFail").addEventListener("click", () => pausedTarget && resolvePaused(pausedTarget.requestId, "fail", { errorReason: "BlockedByClient" }));

  $$("[data-close]").forEach((b) => b.addEventListener("click", () => {
    $("#" + b.dataset.close).classList.add("hidden");
    if (b.dataset.close === "pauseModal") pausedTarget = null;
  }));
  for (const id of ["configModal", "pauseModal", "quickReplaceModal"]) {
    $("#" + id).addEventListener("click", (e) => {
      if (e.target.id === id) { $("#" + id).classList.add("hidden"); if (id === "pauseModal") pausedTarget = null; }
    });
  }

  // 全局快捷键
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      for (const id of ["configModal", "pauseModal", "quickReplaceModal", "contextMenu"]) $("#" + id).classList.add("hidden");
      hideSelFloat();
      pausedTarget = null;
      return;
    }
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter" && $("#paneReplay").classList.contains("active")) {
      e.preventDefault();
      sendRepeater();
      return;
    }
    if (e.target.matches("input, textarea, select")) return;
    if (e.key === "/") { e.preventDefault(); $("#filterInput").focus(); return; }
    if (e.key.toLowerCase() === "r" && currentRecord) { e.preventDefault(); openInRepeater(currentRecord); return; }
    const idx = viewRows.findIndex((r) => r.id === selectedId);
    if (e.key === "ArrowDown" && idx < viewRows.length - 1) { e.preventDefault(); selectRecord(viewRows[idx + 1].id, true); }
    else if (e.key === "ArrowUp" && idx > 0) { e.preventDefault(); selectRecord(viewRows[idx - 1].id, true); }
  });

  // 左右分割条拖拽
  let dragX = false;
  $("#splitter").addEventListener("mousedown", (e) => { dragX = true; e.preventDefault(); });
  // 右侧上下分割条拖拽（Request / Response）
  let dragY = false;
  $("#inspectHSplit").addEventListener("mousedown", (e) => { dragY = true; e.preventDefault(); });

  window.addEventListener("mousemove", (e) => {
    if (dragX) {
      const rect = $("#stage").getBoundingClientRect();
      $("#panelFeed").style.width = `${Math.max(300, Math.min(rect.width - 420, e.clientX - rect.left))}px`;
      scheduleRender();
    } else if (dragY) {
      const rect = $("#inspectSplit").getBoundingClientRect();
      const topH = Math.max(120, Math.min(rect.height - 140, e.clientY - rect.top));
      $("#reqPane").style.flex = `0 0 ${topH}px`;
    }
  });
  window.addEventListener("mouseup", () => { dragX = false; dragY = false; });
}

/* ============================ Port 连接与启动 ============================ */

function connectPort() {
  const port = api.runtime.connect({ name: "traceburp-panel" });
  port.onMessage.addListener((msg) => {
    if (!msg?.type) return;
    switch (msg.type) {
      case "record:new":
      case "record:update":
        queueIncoming(msg);
        break;
      case "records:cleared":
        if (msg.tabId === currentTabId) {
          allRows = []; viewRows = []; dbTotal = 0; recordCache.clear();
          selectedId = null; currentRecord = null;
          showInspectEmpty();
          applyFilter(true);
        }
        break;
      case "paused:new":
        if (msg.item.tabId === currentTabId) {
          if (!pausedItems.some((x) => x.requestId === msg.item.requestId)) pausedItems.push(msg.item);
          renderPaused();
        }
        break;
      case "paused:resolved":
        pausedItems = pausedItems.filter((x) => x.requestId !== msg.requestId);
        renderPaused();
        if (pausedTarget?.requestId === msg.requestId) {
          pausedTarget = null;
          $("#pauseModal").classList.add("hidden");
          if (msg.reason === "timeout") toast("挂起请求已超时自动放行", "warn");
        }
        break;
      case "state:changed":
        if (msg.state?.tabId === currentTabId) applyState(msg.state);
        break;
      case "config:updated":
        if (Array.isArray(msg.rules)) rules = msg.rules;
        if (Array.isArray(msg.mocks)) mocks = msg.mocks;
        if (Array.isArray(msg.replaces)) replaces = msg.replaces;
        if (Array.isArray(msg.authProfiles)) authProfiles = msg.authProfiles;
        updateConfigBadges();
        scheduleRender();
        break;
      case "tabs:updated":
        renderTabPicker(msg.tabs || []);
        break;
      case "panel:focusTab":
        if (msg.tabId && msg.tabId !== currentTabId) loadTabList(msg.tabId);
        break;
      default:
        break;
    }
  });
  port.onDisconnect.addListener(() => setTimeout(connectPort, 1000));
}

(async function init() {
  bindEvents();
  connectPort();
  const params = new URLSearchParams(location.search);
  await loadTabList(Number(params.get("tabId")) || null);
  setInterval(() => {
    if (pausedItems.length) {
      renderPaused();
      if (pausedTarget) updatePauseCountdown();
    }
  }, 1000);
})();
