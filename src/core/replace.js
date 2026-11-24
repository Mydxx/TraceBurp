/**
 * TraceBurp v3.3 静默响应替换引擎、精确 Fetch 模式构造与二进制安全过滤
 */

export function isHttpUrl(url) {
  return typeof url === "string" && /^https?:\/\//i.test(url);
}

const BINARY_MIME_RE = /^(image|audio|video|font)\//i;
const BINARY_APP_RE = /application\/(octet-stream|pdf|zip|gzip|x-gzip|x-tar|wasm|protobuf|msgpack|vnd\.ms-|vnd\.openxmlformats)/i;

/**
 * 判断 Content-Type 是否适合执行文本响应替换（跳过图片、音视频、字体、压缩包等二进制）
 */
export function isTextualMime(mime) {
  if (!mime) return true;
  const m = String(mime).split(";")[0].trim().toLowerCase();
  if (!m) return true;
  if (BINARY_MIME_RE.test(m)) return false;
  if (BINARY_APP_RE.test(m)) return false;
  return true;
}

/**
 * 构造精确的 CDP Fetch.enable patterns：
 * - 非正则具体路径使用 `*<url>*`，让无关静态资源与接口在浏览器内核层零开销直通
 * - 仅当存在 `*` 或正则规则时才回退到全量 `*`
 * - 无该阶段活跃规则时不注册该阶段，避免多余的跨进程往返
 */
export function buildFetchPatterns({
  interceptEnabled = false,
  rules = [],
  mocks = [],
  replaces = [],
} = {}) {
  const patterns = [];

  const addStage = (stage, activeList) => {
    if (!activeList.length) return;
    if (activeList.some((r) => r.url === "*" || r.isRegex)) {
      patterns.push({ urlPattern: "*", requestStage: stage });
      return;
    }
    const seen = new Set();
    for (const r of activeList) {
      const raw = String(r.url || "").trim();
      if (!raw) continue;
      const pat = raw.includes("*") ? raw : `*${raw}*`;
      if (seen.has(pat)) continue;
      seen.add(pat);
      patterns.push({ urlPattern: pat, requestStage: stage });
    }
  };

  const reqRules = [
    ...(interceptEnabled ? rules.filter((r) => r.enabled && r.url && (r.stage || "Request") === "Request") : []),
    ...mocks.filter((m) => m.enabled && m.url),
  ];
  const resRules = [
    ...(interceptEnabled ? rules.filter((r) => r.enabled && r.url && r.stage === "Response") : []),
    ...replaces.filter((r) => r.enabled && r.url && (r.find || r.status)),
  ];

  addStage("Request", reqRules);
  addStage("Response", resRules);
  return patterns;
}

/**
 * 对响应体和状态码按顺序执行匹配的替换规则
 */
export function applyResponseReplacements(bodyText, rules, originalStatus = 200) {
  let body = String(bodyText ?? "");
  let status = Number(originalStatus) || 200;
  let changed = false;
  let hitCount = 0;
  const matchedRuleIds = [];

  for (const rule of rules || []) {
    if (!rule || !rule.enabled) continue;
    let ruleHit = false;

    const find = rule.find ?? "";
    const replace = String(rule.replace ?? "");

    if (find) {
      if (rule.isRegex) {
        try {
          const re = new RegExp(find, "g");
          const next = body.replace(re, replace);
          if (next !== body) {
            body = next;
            ruleHit = true;
          }
        } catch {}
      } else if (body.includes(find)) {
        body = body.split(find).join(replace);
        ruleHit = true;
      }
    }

    const overrideStatus = Number(rule.status);
    if (Number.isFinite(overrideStatus) && overrideStatus >= 100 && overrideStatus <= 599 && overrideStatus !== status) {
      status = overrideStatus;
      ruleHit = true;
    }

    if (ruleHit) {
      changed = true;
      hitCount++;
      if (rule.id) matchedRuleIds.push(rule.id);
    }
  }

  return { body, status, changed, hitCount, matchedRuleIds };
}

/**
 * 清理已被 CDP 解压或长度变化的响应头，防止 ERR_CONTENT_DECODING_FAILED 或截断
 */
export function cleanHeadersForFulfill(headers) {
  return (headers || [])
    .filter((h) => h && h.name && !/^(content-length|content-encoding|transfer-encoding)$/i.test(h.name))
    .map((h) => ({ name: h.name, value: String(h.value ?? "") }));
}
