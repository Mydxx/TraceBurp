/**
 * TraceBurp 轻量级行级 Diff 算法（用于重放响应快速对比）
 * 对超大文本自动截断行数保护，避免主线程卡顿。
 */

const MAX_DIFF_LINES = 600;

export function diffText(oldStr, newStr) {
  const aAll = String(oldStr ?? "").split(/\r?\n/);
  const bAll = String(newStr ?? "").split(/\r?\n/);
  const truncated = aAll.length > MAX_DIFF_LINES || bAll.length > MAX_DIFF_LINES;
  const a = aAll.slice(0, MAX_DIFF_LINES);
  const b = bAll.slice(0, MAX_DIFF_LINES);

  const n = a.length;
  const m = b.length;

  // 跳过共同前缀与后缀，大幅加速常见小改动对比
  let prefix = 0;
  while (prefix < n && prefix < m && a[prefix] === b[prefix]) prefix++;

  let suffix = 0;
  while (
    suffix < n - prefix &&
    suffix < m - prefix &&
    a[n - 1 - suffix] === b[m - 1 - suffix]
  ) {
    suffix++;
  }

  const midA = a.slice(prefix, n - suffix);
  const midB = b.slice(prefix, m - suffix);
  const na = midA.length;
  const nb = midB.length;

  const lines = [];
  for (let i = 0; i < prefix; i++) lines.push({ type: "same", text: a[i] });

  if (na === 0 && nb === 0) {
    // 无差异
  } else if (na * nb > 120000) {
    // 极大差异降级为块级展示，保证瞬间返回
    for (const line of midA) lines.push({ type: "del", text: line });
    for (const line of midB) lines.push({ type: "add", text: line });
  } else {
    const dp = Array.from({ length: na + 1 }, () => new Uint16Array(nb + 1));
    for (let i = na - 1; i >= 0; i--) {
      for (let j = nb - 1; j >= 0; j--) {
        if (midA[i] === midB[j]) dp[i][j] = dp[i + 1][j + 1] + 1;
        else dp[i][j] = dp[i + 1][j] >= dp[i][j + 1] ? dp[i + 1][j] : dp[i][j + 1];
      }
    }
    let i = 0;
    let j = 0;
    while (i < na && j < nb) {
      if (midA[i] === midB[j]) {
        lines.push({ type: "same", text: midA[i] });
        i++;
        j++;
      } else if (dp[i + 1][j] >= dp[i][j + 1]) {
        lines.push({ type: "del", text: midA[i] });
        i++;
      } else {
        lines.push({ type: "add", text: midB[j] });
        j++;
      }
    }
    while (i < na) lines.push({ type: "del", text: midA[i++] });
    while (j < nb) lines.push({ type: "add", text: midB[j++] });
  }

  for (let i = n - suffix; i < n; i++) lines.push({ type: "same", text: a[i] });

  let added = 0;
  let removed = 0;
  for (const l of lines) {
    if (l.type === "add") added++;
    else if (l.type === "del") removed++;
  }

  return { lines, added, removed, identical: added === 0 && removed === 0 && !truncated, truncated };
}
