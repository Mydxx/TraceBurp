# TraceBurp v3.4.0

面向安全工程师的轻量级**免代理、免装证书**浏览器抓包、静默响应替换、全能编解码与修改重放工作台（MV3 跨端支持 **Chrome / Edge / Firefox**）。

## 核心功能

- **一键直达全屏工作台**：点击扩展图标直接打开或聚焦全屏工作台（复用已有工作台不重载、不丢草稿），同时兼容侧边栏打开。
- **干净直观的实时流量流**：
  - 自动过滤 `chrome-extension://`、`data:`、`blob:` 等非 HTTP 噪音，突出展示完整域名。
  - 直观过滤芯片：`去静态`（默认开启）、`GET` / `POST` / `PUT` / `DELETE` / `PATCH`、`有Body`、`2xx`、`4xx/5xx`、`仅本域`，支持 `status:` / `method:` / `host:` / `-host:` 语法及**正文全文检索（搜正文）**。
- **默认 Raw 上下分屏视图**：右上展示完整 Raw 请求，右下展示完整 Raw 响应（轻度着色、支持 JSON 美化 / Hex / 响应内搜索跳转 / 250KB 大响应防卡顿保护 / JWT 与安全头提示）。
- **静默响应替换（Match & Replace）与本地 Mock**：
  - 划选响应区任意文本一键「⚡ 固定替换」，支持字符串/正则替换及状态码覆写，命中接口静默生效（列表绿色标记「已替换」），自动跳过二进制响应。
  - 支持「请求前 / 响应后」两阶段断点拦截与「本地 Mock」静默返回。
- **极简 Burp 式 Raw 重放器**：
  - 选中任意请求按 `R` 或点 `⚡ 重放` 自动带入完整 Raw HTTP 报文，支持多标签草稿、撤销/重置、**去鉴权重发**、**身份预设切换**、**历史回溯**、**JSON Diff 对比**与**原位编解码**。
- **安全工程师全能编解码器**：
  - 内置 URL（含全编码）、Base64 / Base64URL、Hex、Unicode、字符串转义/反转义、HTML 实体/十进制、JWT 解析、JSON 美化/压缩、Query ↔ JSON、Gzip Base64 压缩/解压、时间戳互转、MD5 / SHA-1 / SHA-256 / SHA-512 / HMAC-SHA256，支持**智能识别**与**继续套娃**链式解码。
- **零外部运行时依赖**：基于 IndexedDB（元数据与 Body 分离）与虚拟滚动，支持单条复制 Raw HTTP / cURL / Python 及批量脱敏导出 HAR 1.2。

## 构建与安装

需要 Node.js 18+：

```bash
npm run build   # 生成 dist/chromium 与 dist/firefox
npm test        # 运行核心单元测试（14 项）
```

- **Chrome / Edge**：打开 `chrome://extensions/`（或 `edge://extensions/`）→ 开启「开发者模式」→「加载已解压的扩展程序」→ 选择 `dist/chromium` 目录。
- **Firefox**：打开 `about:debugging#/runtime/this-firefox` →「临时载入附加组件」→ 选择 `dist/firefox/manifest.json`。
