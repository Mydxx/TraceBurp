import test from "node:test";
import assert from "node:assert/strict";

import {
  LRUCache,
  base64ToBytes,
  clipBody,
  decodeUnicodeStr,
  encodeUnicodeStr,
  textToBase64,
} from "../src/core/utils.js";
import { stripRecordMeta } from "../src/core/db.js";
import { auditSecurityHeaders, extractParams, parseJWT } from "../src/core/analyzer.js";
import { filterRecords } from "../src/core/filter.js";
import { diffText } from "../src/core/diff.js";
import {
  toCurlBash,
  toCurlCmd,
  toCurlPowerShell,
  toHAR,
  toPython,
  toRawHttp,
} from "../src/core/exporter.js";

test("clipBody 对齐截断 Base64，确保可安全 atob 解码", () => {
  const big = "A".repeat(1024 * 60);
  const b64 = textToBase64(big);
  const clipped = clipBody(b64, true, 1000);
  assert.equal(clipped.truncated, true);
  assert.equal(clipped.text.length % 4, 0);
  assert.ok(base64ToBytes(clipped.text).length > 0);
});

test("stripRecordMeta 彻底剥离 reqBody / resBody 与内部字段", () => {
  const meta = stripRecordMeta({
    id: "r1",
    url: "https://example.com/api",
    reqBody: "secret-req",
    resBody: "huge-res",
    _startTs: 123,
  });
  assert.equal("reqBody" in meta, false);
  assert.equal("resBody" in meta, false);
  assert.equal("_startTs" in meta, false);
  assert.equal(meta.id, "r1");
});

test("decodeUnicodeStr 与 encodeUnicodeStr 正确处理反斜杠与 Emoji 代理对", () => {
  assert.equal(decodeUnicodeStr("\\\\n"), "\\n");
  assert.equal(decodeUnicodeStr("\\u4e2d\\u6587\\n"), "中文\n");
  assert.equal(decodeUnicodeStr(encodeUnicodeStr("Hi😀")), "Hi😀");
});

test("LRUCache 超过上限自动淘汰最旧项", () => {
  const lru = new LRUCache(2);
  lru.set("a", 1);
  lru.set("b", 2);
  lru.get("a");
  lru.set("c", 3);
  assert.equal(lru.has("b"), false);
  assert.equal(lru.has("a"), true);
  assert.equal(lru.has("c"), true);
});

test("JWT 解析、Cookie 审计与参数提取", () => {
  const h = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const p = Buffer.from(JSON.stringify({ sub: "u_1001", role: "admin", exp: 4102444800 })).toString("base64url");
  const jwt = `${h}.${p}.sig123`;

  const parsed = parseJWT(jwt);
  assert.equal(parsed.alg, "HS256");
  assert.equal(parsed.payload.role, "admin");
  assert.equal(parsed.status, "valid");

  const rec = {
    url: "https://api.example.com/v1/user?id=42&debug=1",
    type: "XHR",
    status: 200,
    reqHeaders: [
      { name: "Authorization", value: `Bearer ${jwt}` },
      { name: "Content-Type", value: "application/json" },
      { name: "Origin", value: "https://evil.test" },
    ],
    reqBody: JSON.stringify({ user: { name: "alice" }, active: true }),
    reqBodyB64: false,
    resHeaders: [
      { name: "Set-Cookie", value: "sid=abc123; Path=/" },
      { name: "Access-Control-Allow-Origin", value: "https://evil.test" },
      { name: "Access-Control-Allow-Credentials", value: "true" },
    ],
  };

  const audit = auditSecurityHeaders(rec);
  assert.equal(audit.jwts.length, 1);
  assert.equal(audit.cookieIssues.length, 1);
  assert.ok(audit.hints.some((x) => x.kind === "cors"));

  const params = extractParams(rec);
  assert.equal(params.query.length, 2);
  assert.ok(params.bodyParams.some((x) => x.name === "user.name" && x.value === "alice"));
});

test("filterRecords 支持芯片、语法与排除规则", () => {
  const rows = [
    { id: "1", url: "https://api.app.com/v1/login", method: "POST", status: 403, type: "Fetch", mimeType: "application/json", reqBodyBytes: 24 },
    { id: "2", url: "https://cdn.app.com/logo.png", method: "GET", status: 200, type: "Image", mimeType: "image/png", resSize: 4096 },
    { id: "3", url: "https://analytics.google.com/collect", method: "POST", status: 200, type: "XHR", mimeType: "text/plain", reqBodyBytes: 10 },
  ];

  assert.deepEqual(filterRecords(rows, { hideStatic: true, methods: new Set(["POST"]), query: "-host:google" }).map((r) => r.id), ["1"]);
  assert.deepEqual(filterRecords(rows, { query: "status:4xx method:POST" }).map((r) => r.id), ["1"]);
});

test("diffText 准确识别增删行", () => {
  const d = diffText('{"ok":true,\n"role":"guest"}', '{"ok":true,\n"role":"admin"}');
  assert.equal(d.identical, false);
  assert.equal(d.added, 1);
  assert.equal(d.removed, 1);
});

test("exporter 规范导出 HAR / Raw HTTP / cURL（含脱敏与二进制安全换行）", () => {
  const rec = {
    id: "r1",
    method: "POST",
    url: "https://api.example.com/v1/pay?a=1&b=2",
    status: 200,
    statusText: "OK",
    ts: 1700000000000,
    duration: 120,
    reqHeaders: [
      { name: "Authorization", value: "Bearer secret_token" },
      { name: "Cookie", value: "sid=xyz" },
      { name: "Content-Type", value: "application/json" },
    ],
    reqBody: '{"amount":100}',
    reqBodyB64: false,
    resHeaders: [{ name: "Content-Type", value: "application/json" }],
    resBody: '{"ok":true}',
    resBodyB64: false,
    timing: { dnsStart: 0, dnsEnd: 10, connectStart: 10, connectEnd: 30, sendStart: 30, sendEnd: 35, receiveHeadersEnd: 100 },
  };

  const har = toHAR([rec], "", { redact: true });
  assert.equal(har.log.pages.length, 0);
  assert.equal("pageref" in har.log.entries[0], false);
  assert.equal(har.log.entries[0].request.headers[0].value, "[REDACTED]");
  assert.equal(har.log.entries[0].timings.dns, 10);

  const raw = toRawHttp(rec, { redact: true });
  assert.ok(raw.startsWith("POST /v1/pay?a=1&b=2 HTTP/1.1\r\n"));
  assert.ok(raw.includes("Authorization: [REDACTED]"));

  const binRec = { ...rec, reqBody: "AAAA", reqBodyB64: true };
  assert.equal(toCurlBash(binRec).includes("\\\n#"), false);
  assert.equal(toCurlCmd(binRec).includes("^\nREM"), false);
  assert.ok(toCurlPowerShell(rec).includes("curl.exe"));
  assert.ok(toPython(rec).includes("import requests"));
});

import {
  base64Decode,
  base64Encode,
  base64UrlEncode,
  detectEncodings,
  hexDecode,
  hexEncode,
  htmlDecode,
  htmlEncode,
  htmlEncodeDecimal,
  jsonMinify,
  jsonPretty,
  jwtDecode,
  md5,
  sha1,
  sha256,
  unicodeDecode,
  unicodeEncode,
  urlDecode,
  urlEncode,
  urlEncodeAll,
} from "../src/core/codec.js";
import {
  applyResponseReplacements,
  cleanHeadersForFulfill,
  isHttpUrl,
} from "../src/core/replace.js";

test("codec 编解码、哈希与智能识别全覆盖", async () => {
  assert.equal(urlDecode(urlEncode("a=1&b=中文")), "a=1&b=中文");
  assert.equal(urlEncodeAll("AB"), "%41%42");
  assert.equal(base64Decode(base64Encode("TraceBurp 安全")), "TraceBurp 安全");
  assert.equal(base64Decode(base64UrlEncode("foo+bar/baz=")), "foo+bar/baz=");
  assert.equal(hexDecode(hexEncode("admin:123")), "admin:123");
  assert.equal(unicodeDecode(unicodeEncode("测试Hi")), "测试Hi");
  assert.equal(htmlDecode(htmlEncode(`<script>"a"&'b'</script>`)), `<script>"a"&'b'</script>`);
  assert.equal(htmlDecode(htmlEncodeDecimal("AB")), "AB");
  assert.equal(jsonMinify(jsonPretty('{"a":1,"b":[2,3]}')), '{"a":1,"b":[2,3]}');

  // RFC 1321 标准向量校验 MD5 / SHA-1 / SHA-256
  assert.equal(md5("hello"), "5d41402abc4b2a76b9719d911017c592");
  assert.equal(md5(""), "d41d8cd98f00b204e9800998ecf8427e");
  assert.equal(await sha1("hello"), "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
  assert.equal(await sha256("hello"), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");

  const h = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const p = Buffer.from(JSON.stringify({ uid: 7, role: "admin", exp: 4102444800 })).toString("base64url");
  const jwt = `${h}.${p}.sig`;
  const jwtOut = JSON.parse(jwtDecode(`Bearer ${jwt}`));
  assert.equal(jwtOut.payload.role, "admin");
  assert.equal(jwtOut._time.expired, false);

  assert.ok(detectEncodings(jwt).some((x) => x.op === "jwt_dec"));
  assert.ok(detectEncodings("%E4%B8%AD%E6%96%87").some((x) => x.op === "url_dec"));
  assert.ok(detectEncodings("1700000000").some((x) => x.op === "ts_to_date"));
});

test("replace 静默响应替换引擎与 HTTP 噪音过滤", () => {
  assert.equal(isHttpUrl("https://mon.zijieapi.com/api"), true);
  assert.equal(isHttpUrl("http://127.0.0.1:8080/test"), true);
  assert.equal(isHttpUrl("chrome-extension://gppongmhjkpfnbhagpmjfkannfbllamg/js/dom.js"), false);
  assert.equal(isHttpUrl("data:image/png;base64,AAA"), false);
  assert.equal(isHttpUrl("blob:https://example.com/123"), false);

  const rules = [
    { id: "r1", enabled: true, find: '"isLogin":false', replace: '"isLogin":true', isRegex: false, status: 200 },
    { id: "r2", enabled: true, find: '"role":"\\w+"', replace: '"role":"admin"', isRegex: true, status: "" },
    { id: "r3", enabled: false, find: "admin", replace: "guest", isRegex: false, status: 500 },
  ];
  const res = applyResponseReplacements('{"code":401,"isLogin":false,"role":"guest"}', rules, 401);
  assert.equal(res.changed, true);
  assert.equal(res.status, 200);
  assert.equal(res.hitCount, 2);
  assert.equal(res.body, '{"code":401,"isLogin":true,"role":"admin"}');

  const cleaned = cleanHeadersForFulfill([
    { name: "Content-Type", value: "application/json" },
    { name: "Content-Length", value: "42" },
    { name: "Content-Encoding", value: "gzip" },
    { name: "Transfer-Encoding", value: "chunked" },
  ]);
  assert.deepEqual(cleaned, [{ name: "Content-Type", value: "application/json" }]);
});

import {
  escapeStr,
  gzipB64Decode,
  gzipB64Encode,
  hmacSha256,
  jsonToQuery,
  queryToJson,
  sha512,
  unescapeStr,
} from "../src/core/codec.js";
import { buildFetchPatterns, isTextualMime } from "../src/core/replace.js";

test("v3.3 搜正文不与普通 URL 关键词冲突，且仍兼容结构化语法", () => {
  const rows = [
    { id: "a", url: "https://api.app.com/v1/profile", method: "POST", status: 200, type: "Fetch", mimeType: "application/json" },
    { id: "b", url: "https://api.app.com/v1/other", method: "GET", status: 403, type: "Fetch", mimeType: "application/json" },
  ];
  // 关键字 "secret_admin" 仅出现在 id="a" 的正文里，URL 中不含该词
  const out = filterRecords(rows, { query: "secret_admin", bodySearchIds: new Set(["a"]) });
  assert.deepEqual(out.map((r) => r.id), ["a"]);
  // 正文检索同时叠加 method:POST 仍生效
  const out2 = filterRecords(rows, { query: "secret_admin method:GET", bodySearchIds: new Set(["a"]) });
  assert.deepEqual(out2.map((r) => r.id), []);
});

test("v3.3 精确 Fetch 模式构造与二进制 MIME 防误伤", () => {
  assert.equal(isTextualMime("application/json; charset=utf-8"), true);
  assert.equal(isTextualMime("text/html"), true);
  assert.equal(isTextualMime("image/png"), false);
  assert.equal(isTextualMime("application/octet-stream"), false);
  assert.equal(isTextualMime("font/woff2"), false);

  // 仅启用单接口响应替换时，只注册该接口 Response 阶段，不拦截 Request 阶段也不全量拦截 *
  const pats = buildFetchPatterns({
    interceptEnabled: false,
    rules: [],
    mocks: [],
    replaces: [{ enabled: true, url: "/api/auth/status", find: "false", replace: "true" }],
  });
  assert.deepEqual(pats, [{ urlPattern: "*/api/auth/status*", requestStage: "Response" }]);
});

test("v3.3 编解码进阶能力（SHA-512 / HMAC-SHA256 / Gzip / Query↔JSON / 转义）", async () => {
  assert.equal((await sha512("hello")).length, 128);
  const hmac = await hmacSha256("payload", "my-secret");
  assert.ok(hmac.includes("Hex: ") && hmac.includes("Base64: "));

  const gz = await gzipB64Encode("TraceBurp Gzip 测试 123");
  assert.ok(gz.startsWith("H4sI"));
  assert.equal(await gzipB64Decode(gz), "TraceBurp Gzip 测试 123");
  assert.ok(detectEncodings(gz).some((x) => x.op === "gzip_dec"));

  const j = JSON.parse(queryToJson("https://a.com/x?foo=1&bar=%E4%B8%AD%E6%96%87"));
  assert.deepEqual(j, { foo: "1", bar: "中文" });
  assert.equal(jsonToQuery('{"a":1,"b":"ok"}'), "a=1&b=ok");
  assert.equal(unescapeStr(escapeStr('{"k":"v"}\nline2')), '{"k":"v"}\nline2');
});

test("v3.4 有Body / 2xx 过滤芯片（含 2xx+4xx/5xx 并集）与 alg=none 无签名 JWT 检出", () => {
  const rows = [
    { id: "1", url: "https://api.app.com/a", method: "POST", status: 200, type: "Fetch", hasPostData: true, reqBodyBytes: 18 },
    { id: "2", url: "https://api.app.com/b", method: "GET", status: 204, type: "Fetch", hasPostData: false, reqBodyBytes: 0 },
    { id: "3", url: "https://api.app.com/c", method: "POST", status: 403, type: "Fetch", hasPostData: true, reqBodyBytes: 12 },
    { id: "4", url: "https://api.app.com/d", method: "GET", status: 302, type: "Document", hasPostData: false, reqBodyBytes: 0 },
  ];
  assert.deepEqual(filterRecords(rows, { hasBody: true }).map((r) => r.id), ["1", "3"]);
  assert.deepEqual(filterRecords(rows, { only2xx: true }).map((r) => r.id), ["1", "2"]);
  assert.deepEqual(filterRecords(rows, { only2xx: true, onlyError: true }).map((r) => r.id), ["1", "2", "3"]);
  assert.deepEqual(filterRecords(rows, { hasBody: true, only2xx: true }).map((r) => r.id), ["1"]);

  // alg=none 无签名 JWT（末尾以点号结尾）必须被检出为 high 风险
  const h = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  const p = Buffer.from(JSON.stringify({ sub: "1", role: "admin" })).toString("base64url");
  const unsignedJwt = `${h}.${p}.`;
  const audit = auditSecurityHeaders({
    url: "https://api.app.com/a",
    reqHeaders: [{ name: "Authorization", value: `Bearer ${unsignedJwt}` }],
    resHeaders: [],
  });
  assert.equal(audit.jwts.length, 1);
  assert.ok(audit.hints.some((x) => x.severity === "high" && x.title.includes("alg=none")));
});
