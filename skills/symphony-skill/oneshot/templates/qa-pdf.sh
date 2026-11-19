#!/usr/bin/env bash
# qa-pdf.sh — Render .oneshot/vault/qa-report.md → .oneshot/vault/artifacts/qa-report.pdf
#
# Uses Playwright (already installed for the QA spec) to render markdown
# → HTML → PDF. No pandoc, no wkhtmltopdf, no LaTeX dependency.
#
# Refuses to render unless the QA test results JSON exists — prevents
# generating an "approved" PDF without actually running the spec.
set -euo pipefail

# Resolve vault to absolute path. Prefer ONESHOT_ROOT (set by lane prompt
# preamble), fall back to .oneshot/.project_root, then to relative path.
if [ -n "${ONESHOT_ROOT:-}" ]; then
  ROOT="$ONESHOT_ROOT"
elif [ -f "$(pwd)/.oneshot/.project_root" ]; then
  ROOT="$(cat "$(pwd)/.oneshot/.project_root")"
else
  ROOT="$(pwd)"
fi

VAULT="${VAULT:-$ROOT/.oneshot/vault}"
MD="${VAULT}/qa-report.md"
PDF="${VAULT}/artifacts/qa-report.pdf"
PDF_HASH="${PDF}.sha256"
RESULTS_DIR="${VAULT}/artifacts/test-results"

if [ ! -f "$ROOT/package.json" ]; then
  echo "error: $ROOT/package.json missing — qa-pdf.sh requires a Node project (uses Playwright + marked)" >&2
  exit 1
fi

if [ ! -s "$MD" ]; then
  echo "error: $MD missing or empty — write the QA report markdown first" >&2
  exit 1
fi

# Refuse to render without test evidence (prevents a 'rubber-stamp' PDF)
if [ ! -d "$RESULTS_DIR" ] || [ -z "$(ls -A "$RESULTS_DIR" 2>/dev/null)" ]; then
  echo "error: $RESULTS_DIR is empty — Playwright spec must run before PDF render" >&2
  echo "       expected at least one of: results.json, *.xml, trace.zip" >&2
  exit 1
fi

# Verdict line is mandatory
if ! grep -qE '^Verdict: (APPROVED FOR DELIVERY|BLOCKED — see Findings)' "$MD"; then
  echo "error: $MD missing required 'Verdict:' line" >&2
  echo "       last line should be 'Verdict: APPROVED FOR DELIVERY' or 'Verdict: BLOCKED — see Findings'" >&2
  exit 1
fi

mkdir -p "$(dirname "$PDF")"

# Tiny Node renderer using Playwright + marked.
# Inlined to keep the skill self-contained — no extra files.
TMP_RENDERER="$(mktemp -t qa-pdf.XXXXXX.mjs)"
trap 'rm -f "$TMP_RENDERER"' EXIT

cat > "$TMP_RENDERER" <<'NODE'
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { chromium } from '@playwright/test';
import { marked } from 'marked';

const [, , mdPath, pdfPath] = process.argv;
if (!mdPath || !pdfPath) {
  console.error('usage: node qa-pdf.mjs <input.md> <output.pdf>');
  process.exit(2);
}

const mdAbs = resolve(mdPath);
const pdfAbs = resolve(pdfPath);
const mdDir = dirname(mdAbs);
const md = readFileSync(mdAbs, 'utf8');

// Resolve <img src="artifacts/screenshots/foo.png"> relative to md file
marked.use({
  renderer: {
    image(href, title, text) {
      let resolved = href;
      try {
        const candidate = resolve(mdDir, href);
        if (existsSync(candidate)) {
          resolved = pathToFileURL(candidate).href;
        }
      } catch {
        // leave as-is
      }
      const t = title ? ` title="${title}"` : '';
      return `<img src="${resolved}" alt="${text}"${t} />`;
    },
  },
});

const bodyHtml = marked.parse(md);
const generatedAt = new Date().toISOString();

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>QA Report</title>
<style>
  @page { size: A4; margin: 18mm; }
  body { font: 11pt/1.5 -apple-system, Segoe UI, Helvetica, Arial, sans-serif; color: #111; }
  h1 { font-size: 22pt; margin: 0 0 8pt; border-bottom: 2pt solid #333; padding-bottom: 4pt; }
  h2 { font-size: 15pt; margin: 18pt 0 6pt; color: #1d4ed8; }
  h3 { font-size: 12pt; margin: 12pt 0 4pt; }
  table { border-collapse: collapse; width: 100%; margin: 6pt 0; }
  th, td { border: 0.5pt solid #999; padding: 4pt 6pt; vertical-align: top; }
  th { background: #f3f4f6; text-align: left; }
  code, pre { font-family: ui-monospace, SF Mono, Menlo, monospace; }
  pre { background: #f7f7f7; padding: 8pt; overflow: hidden; }
  img { max-width: 100%; height: auto; border: 0.5pt solid #ddd; margin: 4pt 0; }
  .meta { color: #555; font-size: 9pt; margin-top: 24pt; border-top: 0.5pt solid #ccc; padding-top: 4pt; }
</style>
</head>
<body>
${bodyHtml}
<div class="meta">Rendered ${generatedAt} by Symphony OneShot qa-pdf.sh — Playwright/Chromium PDF.</div>
</body>
</html>`;

const browser = await chromium.launch();
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.setContent(html, { waitUntil: 'networkidle' });
  await page.pdf({
    path: pdfAbs,
    format: 'A4',
    printBackground: true,
    margin: { top: '18mm', right: '18mm', bottom: '18mm', left: '18mm' },
    displayHeaderFooter: true,
    headerTemplate: '<div></div>',
    footerTemplate:
      '<div style="font-size:8pt;color:#888;width:100%;text-align:center;">' +
      '<span class="pageNumber"></span> / <span class="totalPages"></span>' +
      '</div>',
  });
} finally {
  await browser.close();
}

console.log(`wrote ${pdfAbs}`);
NODE

# Make sure marked is installed (cheap if already present)
if ! node -e "import('marked')" 2>/dev/null; then
  echo "info: installing 'marked' (one-time)" >&2
  npm i -D marked >/dev/null 2>&1 || npm i marked >/dev/null 2>&1 || {
    echo "error: failed to install 'marked' — run \`npm i -D marked\` manually" >&2
    exit 1
  }
fi

cd "$ROOT" && node "$TMP_RENDERER" "$MD" "$PDF"

# Verify and emit hash to a separate file (Deliver gate reads from here, NOT from verification.md)
test -s "$PDF" || { echo "error: PDF not produced" >&2; exit 1; }
HASH="$(shasum -a 256 "$PDF" | awk '{print $1}')"
SIZE="$(wc -c < "$PDF" | tr -d ' ')"

# Refuse to "approve" trivially small PDFs (likely empty/error pages)
if [ "$SIZE" -lt 4096 ]; then
  echo "error: PDF too small (${SIZE} bytes) — likely render failure" >&2
  rm -f "$PDF"
  exit 1
fi

# Single-source-of-truth hash file. Deliver gate verifies this matches re-shasum'd PDF.
printf '%s  %s\n' "$HASH" "$(basename "$PDF")" > "$PDF_HASH"
echo "ok: $PDF  size=${SIZE}  sha256=${HASH}  hash-file=${PDF_HASH}"
