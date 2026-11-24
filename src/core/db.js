/**
 * TraceBurp IndexedDB 存储层
 *
 * 设计红线：
 * 1. records 仅存轻量元数据，严禁写入 reqBody / resBody
 * 2. bodies 按 id 单独存储，支持增量局部合并（避免空对象覆盖已有 reqBody）
 * 3. batchWrite 在单个 readwrite 事务内批量落库，极大提升并发吞吐
 * 4. listRecords 使用 cursor.advance(offset) 跳页，exportTab 分批读取避免万级并发事务
 */

import { base64ToText, looksBinary } from "./utils.js";

const DB_NAME = "traceburp-db";
const DB_VERSION = 1;
const STORE_REC = "records";
const STORE_BODY = "bodies";
const STORE_SET = "settings";

let _db = null;
let _opening = null;

export function openDB() {
  if (_db) return Promise.resolve(_db);
  if (_opening) return _opening;

  _opening = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_REC)) {
        const os = db.createObjectStore(STORE_REC, { keyPath: "id" });
        os.createIndex("tabId", "tabId", { unique: false });
        os.createIndex("tab_ts", ["tabId", "ts"], { unique: false });
      }
      if (!db.objectStoreNames.contains(STORE_BODY)) {
        db.createObjectStore(STORE_BODY, { keyPath: "id" });
      }
      if (!db.objectStoreNames.contains(STORE_SET)) {
        db.createObjectStore(STORE_SET, { keyPath: "k" });
      }
    };
    req.onsuccess = () => {
      _db = req.result;
      _db.onclose = () => {
        _db = null;
        _opening = null;
      };
      resolve(_db);
    };
    req.onerror = () => {
      _opening = null;
      reject(req.error);
    };
  });

  return _opening;
}

/** 剥离所有内部字段和大体积 body，确保 records 表始终轻量 */
export function stripRecordMeta(rec) {
  const {
    _startTs,
    _bodyDirty,
    _metaDirty,
    reqBody,
    resBody,
    ...meta
  } = rec;
  return meta;
}

/**
 * 单事务批量写入元数据与（可选）body 片段。
 * bodies 为 null/undefined 或空对象时跳过，绝不覆盖已有 body。
 */
export async function batchWrite(jobs) {
  if (!jobs || !jobs.length) return;

  // 先在内存中按 record id 合并同批次的多次更新，彻底消除同事务并发 get(id) 覆盖 reqBody 的竞态
  const merged = new Map();
  for (const job of jobs) {
    const id = job.rec?.id || job.id;
    if (!id) continue;
    let entry = merged.get(id);
    if (!entry) {
      entry = { id, rec: null, bodies: null, replaceBody: false };
      merged.set(id, entry);
    }
    if (job.rec) entry.rec = job.rec;
    if (job.bodies && Object.keys(job.bodies).length > 0) {
      if (job.replaceBody) {
        entry.bodies = { ...job.bodies };
        entry.replaceBody = true;
      } else {
        entry.bodies = { ...(entry.bodies || {}), ...job.bodies };
      }
    }
  }

  const list = [...merged.values()];
  if (!list.length) return;

  const db = await openDB();
  const hasBodies = list.some((e) => e.bodies && Object.keys(e.bodies).length > 0);
  const stores = hasBodies ? [STORE_REC, STORE_BODY] : [STORE_REC];

  return new Promise((resolve, reject) => {
    const t = db.transaction(stores, "readwrite");
    const recStore = t.objectStore(STORE_REC);
    const bodyStore = hasBodies ? t.objectStore(STORE_BODY) : null;

    for (const entry of list) {
      if (entry.rec) {
        recStore.put(stripRecordMeta(entry.rec));
      }
      if (bodyStore && entry.bodies) {
        if (entry.replaceBody) {
          bodyStore.put({ id: entry.id, ...entry.bodies });
        } else {
          const getReq = bodyStore.get(entry.id);
          getReq.onsuccess = () => {
            const prev = getReq.result || { id: entry.id };
            bodyStore.put({ ...prev, ...entry.bodies, id: entry.id });
          };
        }
      }
    }

    t.oncomplete = () => resolve();
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error || new Error("IndexedDB transaction aborted"));
  });
}

export async function getRecord(id) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction([STORE_REC, STORE_BODY], "readonly");
    const metaReq = t.objectStore(STORE_REC).get(id);
    const bodyReq = t.objectStore(STORE_BODY).get(id);
    t.oncomplete = () => {
      const meta = metaReq.result || null;
      if (!meta) return resolve(null);
      const body = bodyReq.result || {};
      resolve({
        ...meta,
        reqBody: body.reqBody ?? null,
        reqBodyB64: body.reqBodyB64 ?? false,
        reqBodyBytes: body.reqBodyBytes ?? meta.reqBodyBytes ?? 0,
        reqBodyTruncated: body.reqBodyTruncated ?? false,
        reqBodyError: body.reqBodyError ?? null,
        resBody: body.resBody ?? null,
        resBodyB64: body.resBodyB64 ?? false,
        resBodyBytes: body.resBodyBytes ?? meta.resBodyBytes ?? 0,
        resBodyTruncated: body.resBodyTruncated ?? false,
        resBodyError: body.resBodyError ?? null,
      });
    };
    t.onerror = () => reject(t.error);
  });
}

/** 分页读取某 tab 的轻量元数据（新→旧），使用 advance(offset) 跳过 */
export async function listRecords(tabId, offset = 0, limit = 300) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction([STORE_REC], "readonly");
    const idx = t.objectStore(STORE_REC).index("tab_ts");
    const range = IDBKeyRange.bound([tabId, 0], [tabId, Number.MAX_SAFE_INTEGER]);
    const out = [];
    let advanced = offset === 0;
    const req = idx.openCursor(range, "prev");
    req.onsuccess = () => {
      const cur = req.result;
      if (!cur) return resolve(out);
      if (!advanced) {
        advanced = true;
        cur.advance(offset);
        return;
      }
      out.push(cur.value);
      if (out.length >= limit) return resolve(out);
      cur.continue();
    };
    req.onerror = () => reject(req.error);
  });
}

export async function countTab(tabId) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction([STORE_REC], "readonly");
    const idx = t.objectStore(STORE_REC).index("tab_ts");
    const range = IDBKeyRange.bound([tabId, 0], [tabId, Number.MAX_SAFE_INTEGER]);
    const r = idx.count(range);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

export async function deleteRecord(id) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction([STORE_REC, STORE_BODY], "readwrite");
    t.objectStore(STORE_REC).delete(id);
    t.objectStore(STORE_BODY).delete(id);
    t.oncomplete = () => resolve();
    t.onerror = () => reject(t.error);
  });
}

export async function clearTab(tabId) {
  const db = await openDB();
  const ids = await getTabIds(db, tabId);
  if (!ids.length) return 0;
  await deleteByIds(db, ids);
  return ids.length;
}

export async function pruneTab(tabId, keep = 5000) {
  const db = await openDB();
  const overflow = await new Promise((resolve, reject) => {
    const t = db.transaction([STORE_REC], "readonly");
    const idx = t.objectStore(STORE_REC).index("tab_ts");
    const range = IDBKeyRange.bound([tabId, 0], [tabId, Number.MAX_SAFE_INTEGER]);
    const out = [];
    let seen = 0;
    const r = idx.openKeyCursor(range, "prev");
    r.onsuccess = () => {
      const cur = r.result;
      if (!cur) return resolve(out);
      seen++;
      if (seen > keep) out.push(cur.primaryKey);
      cur.continue();
    };
    r.onerror = () => reject(r.error);
  });
  if (!overflow.length) return 0;
  await deleteByIds(db, overflow);
  return overflow.length;
}

/** 清理已经关闭且不再存在的旧 tab 历史，防止磁盘无限膨胀 */
export async function pruneDeadTabs(aliveTabIds) {
  const db = await openDB();
  const aliveSet = new Set(aliveTabIds);
  const deadTabIds = new Set();

  await new Promise((resolve, reject) => {
    const t = db.transaction([STORE_REC], "readonly");
    const idx = t.objectStore(STORE_REC).index("tabId");
    const r = idx.openKeyCursor(null, "nextunique");
    r.onsuccess = () => {
      const cur = r.result;
      if (!cur) return resolve();
      const tid = cur.key;
      if (typeof tid === "number" && tid > 0 && !aliveSet.has(tid)) {
        deadTabIds.add(tid);
      }
      cur.continue();
    };
    r.onerror = () => reject(r.error);
  });

  let totalRemoved = 0;
  for (const tid of deadTabIds) {
    totalRemoved += await clearTab(tid);
  }
  return totalRemoved;
}

/**
 * 分批读取完整记录（用于导出或全文搜索）。
 * 每次最多在单个 readonly 事务内读取 200 条 body，避免万级并发事务崩溃。
 */
export async function getRecordsWithBodies(ids) {
  if (!ids || !ids.length) return [];
  const db = await openDB();
  const out = [];
  const BATCH = 200;

  for (let i = 0; i < ids.length; i += BATCH) {
    const slice = ids.slice(i, i + BATCH);
    const chunk = await new Promise((resolve, reject) => {
      const t = db.transaction([STORE_REC, STORE_BODY], "readonly");
      const recStore = t.objectStore(STORE_REC);
      const bodyStore = t.objectStore(STORE_BODY);
      const pairs = slice.map((id) => ({
        metaReq: recStore.get(id),
        bodyReq: bodyStore.get(id),
      }));
      t.oncomplete = () => {
        const res = [];
        for (const { metaReq, bodyReq } of pairs) {
          const meta = metaReq.result;
          if (!meta) continue;
          const body = bodyReq.result || {};
          res.push({
            ...meta,
            reqBody: body.reqBody ?? null,
            reqBodyB64: body.reqBodyB64 ?? false,
            reqBodyBytes: body.reqBodyBytes ?? meta.reqBodyBytes ?? 0,
            reqBodyTruncated: body.reqBodyTruncated ?? false,
            resBody: body.resBody ?? null,
            resBodyB64: body.resBodyB64 ?? false,
            resBodyBytes: body.resBodyBytes ?? meta.resBodyBytes ?? 0,
            resBodyTruncated: body.resBodyTruncated ?? false,
            resBodyError: body.resBodyError ?? null,
          });
        }
        resolve(res);
      };
      t.onerror = () => reject(t.error);
    });
    out.push(...chunk);
  }
  return out;
}

export async function exportTab(tabId, max = 10000, specificIds = null) {
  if (Array.isArray(specificIds) && specificIds.length) {
    return getRecordsWithBodies(specificIds.slice(0, max));
  }
  const db = await openDB();
  const ids = await new Promise((resolve, reject) => {
    const t = db.transaction([STORE_REC], "readonly");
    const idx = t.objectStore(STORE_REC).index("tab_ts");
    const range = IDBKeyRange.bound([tabId, 0], [tabId, Number.MAX_SAFE_INTEGER]);
    const out = [];
    const r = idx.openKeyCursor(range, "next");
    r.onsuccess = () => {
      const cur = r.result;
      if (!cur || out.length >= max) return resolve(out);
      out.push(cur.primaryKey);
      cur.continue();
    };
    r.onerror = () => reject(r.error);
  });
  return getRecordsWithBodies(ids);
}

/** 在指定 tab 的全部历史中执行 Header / Body 关键字搜索，返回匹配的 record id 列表 */
export async function searchTabBodies(tabId, query, limit = 500) {
  const q = String(query || "").trim().toLowerCase();
  if (!q) return [];
  const db = await openDB();
  const metas = await listRecords(tabId, 0, MAX_SEARCH_SCAN);
  const matched = [];
  const BATCH = 150;

  for (let i = 0; i < metas.length && matched.length < limit; i += BATCH) {
    const slice = metas.slice(i, i + BATCH);
    const ids = slice.map((m) => m.id);
    const fulls = await getRecordsWithBodies(ids);
    for (const r of fulls) {
      if (matched.length >= limit) break;
      const hitHeader =
        (r.reqHeaders || []).some((h) => `${h.name}: ${h.value}`.toLowerCase().includes(q)) ||
        (r.resHeaders || []).some((h) => `${h.name}: ${h.value}`.toLowerCase().includes(q));
      if (hitHeader) {
        matched.push(r.id);
        continue;
      }
      if (r.reqBody) {
        const reqTxt = r.reqBodyB64
          ? (!looksBinary("", r.reqBody) ? base64ToText(r.reqBody) : "")
          : r.reqBody;
        if (reqTxt && reqTxt.toLowerCase().includes(q)) {
          matched.push(r.id);
          continue;
        }
      }
      if (r.resBody) {
        const resTxt = r.resBodyB64
          ? (!looksBinary(r.mimeType, r.resBody) ? base64ToText(r.resBody) : "")
          : r.resBody;
        if (resTxt && resTxt.toLowerCase().includes(q)) {
          matched.push(r.id);
        }
      }
    }
  }
  return matched;
}

const MAX_SEARCH_SCAN = 2000;

export async function getSetting(k, fallback = null) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction([STORE_SET], "readonly");
    const r = t.objectStore(STORE_SET).get(k);
    r.onsuccess = () => resolve(r.result ? r.result.v : fallback);
    r.onerror = () => reject(r.error);
  });
}

export async function setSetting(k, v) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction([STORE_SET], "readwrite");
    t.objectStore(STORE_SET).put({ k, v });
    t.oncomplete = () => resolve();
    t.onerror = () => reject(t.error);
  });
}

function getTabIds(db, tabId) {
  return new Promise((resolve, reject) => {
    const t = db.transaction([STORE_REC], "readonly");
    const idx = t.objectStore(STORE_REC).index("tabId");
    const out = [];
    const r = idx.openKeyCursor(IDBKeyRange.only(tabId));
    r.onsuccess = () => {
      const cur = r.result;
      if (!cur) return resolve(out);
      out.push(cur.primaryKey);
      cur.continue();
    };
    r.onerror = () => reject(r.error);
  });
}

function deleteByIds(db, ids) {
  return new Promise((resolve, reject) => {
    const t = db.transaction([STORE_REC, STORE_BODY], "readwrite");
    const recStore = t.objectStore(STORE_REC);
    const bodyStore = t.objectStore(STORE_BODY);
    for (const id of ids) {
      recStore.delete(id);
      bodyStore.delete(id);
    }
    t.oncomplete = () => resolve();
    t.onerror = () => reject(t.error);
  });
}
