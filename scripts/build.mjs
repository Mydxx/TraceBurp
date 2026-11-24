/**
 * TraceBurp 跨浏览器零依赖构建脚本
 * 输出：
 *   dist/chromium  -> Chrome / Edge / Brave 可直接加载的已解压扩展目录
 *   dist/firefox   -> Firefox 可直接加载的已解压扩展目录
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcDir = path.join(root, "src");
const distDir = path.join(root, "dist");

function copyDir(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, entry.name);
    const d = path.join(dest, entry.name);
    if (entry.isDirectory()) copyDir(s, d);
    else fs.copyFileSync(s, d);
  }
}

function buildTarget(name, manifestFile) {
  const out = path.join(distDir, name);
  fs.rmSync(out, { recursive: true, force: true });
  copyDir(srcDir, out);

  const manifestSrc = path.join(root, "manifests", manifestFile);
  const manifestJson = JSON.parse(fs.readFileSync(manifestSrc, "utf8"));
  fs.writeFileSync(path.join(out, "manifest.json"), JSON.stringify(manifestJson, null, 2) + "\n", "utf8");
  console.log(`[TraceBurp] Built dist/${name} (manifest_version=${manifestJson.manifest_version}, v${manifestJson.version})`);
}

fs.mkdirSync(distDir, { recursive: true });
buildTarget("chromium", "chromium.json");
buildTarget("firefox", "firefox.json");
