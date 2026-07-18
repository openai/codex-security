import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { brotliDecompressSync, gunzipSync } from "node:zlib";

const args = process.argv.slice(2);
if (args[0] === "--") args.shift();
const [archive] = args;
if (archive === undefined || args.length !== 1) {
  throw new Error("Usage: node scripts/check-package.mjs <npm-tarball>");
}

const archiveBytes = gunzipSync(readFileSync(archive));
const tarOptions = { maxBuffer: archiveBytes.byteLength + 1024 };
function tar(args, encoding = "buffer") {
  const result = spawnSync("tar", ["--ignore-zeros", ...args], {
    ...tarOptions,
    encoding,
  });
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0 || result.stderr.length !== 0) {
    const stderr = result.stderr.toString().trim();
    throw new Error(
      `npm tarball contains an invalid tar entry${stderr === "" ? "." : `: ${stderr}`}`,
    );
  }
  return result.stdout;
}

const entries = tar(["-tzf", archive], "utf8").split(/\r?\n/u).filter(Boolean);
const files = new Set(entries);
if (files.size !== entries.length) {
  throw new Error("npm tarball contains duplicate paths.");
}
const required = [
  "package/package.json",
  "package/README.md",
  "package/LICENSE",
  "package/dist/index.js",
  "package/dist/index.d.ts",
  "package/dist/cli.js",
  "package/_bundled_plugin/.codex-plugin/plugin.json",
];

for (const file of required) {
  if (!files.has(file)) throw new Error(`npm tarball is missing ${file}.`);
}

const pluginFiles = new Set([
  ".app.json",
  ".codex-plugin/plugin.json",
  ".mcp.json",
  "assets/logo.png",
  "examples/completed-scan/coverage.json",
  "examples/completed-scan/findings.json",
  "examples/completed-scan/scan-manifest.json",
  "mcp/mcp-app.html.br",
  "mcp/server.mjs",
  "mcp/server.mjs.br.part-000",
  "mcp/server.mjs.br.part-001",
  "preflight/capability-profiles.toml",
  "references/config-preflight.md",
  "references/final-report.md",
  "references/finding-detail-fields.md",
  "references/sarif-adapter.md",
  "references/scan-artifacts.md",
  "references/scan-contract.md",
  "references/security-guidance.md",
  "references/shared-hard-rules.md",
  "references/static-finding-assessment.md",
  "schemas/coverage.schema.json",
  "schemas/findings.schema.json",
  "schemas/scan-manifest.schema.json",
  "scripts/config_preflight.py",
  "scripts/deep_scan_config.py",
  "scripts/deep_scan_workbench.py",
  "scripts/filesystem_identity.py",
  "scripts/finalize_scan_contract.py",
  "scripts/finding_preview.py",
  "scripts/generate_rank_input.py",
  "scripts/rank_preview.py",
  "scripts/report_projection.py",
  "scripts/resolve_security_md.py",
  "scripts/snapshot_sqlite.py",
  "scripts/validate_report_format.py",
  "scripts/validate_scan_contract.py",
  "scripts/validate_tracking_source.py",
  "scripts/windows_scan_local_files.py",
  "scripts/workbench/__init__.py",
  "scripts/workbench/handoff.py",
  "scripts/workbench_cli.py",
  "scripts/workbench_constants.py",
  "scripts/workbench_db.py",
  "scripts/workbench_progress.py",
  "scripts/workbench_remediation.py",
  "scripts/workbench_scan_history.py",
  "scripts/workbench_scan_start.py",
  "scripts/workbench_schema.py",
  "scripts/workbench_source_excerpt.py",
  "scripts/workbench_target.py",
  "scripts/workbench_target_state.py",
  "scripts/workbench_validation.py",
  "skills/attack-path-analysis/SKILL.md",
  "skills/attack-path-analysis/agents/openai.yaml",
  "skills/attack-path-analysis/references/attack-path-facts.md",
  "skills/attack-path-analysis/references/severity-policy.md",
  "skills/deep-security-scan/SKILL.md",
  "skills/deep-security-scan/agents/openai.yaml",
  "skills/finding-discovery/SKILL.md",
  "skills/finding-discovery/agents/openai.yaml",
  "skills/fix-finding/SKILL.md",
  "skills/fix-finding/agents/openai.yaml",
  "skills/propose-security-hardening/SKILL.md",
  "skills/propose-security-hardening/agents/openai.yaml",
  "skills/propose-security-hardening/references/proposal-format.md",
  "skills/security-diff-scan/SKILL.md",
  "skills/security-diff-scan/agents/openai.yaml",
  "skills/security-scan/SKILL.md",
  "skills/security-scan/agents/openai.yaml",
  "skills/security-scan/references/repo-wide-artifacts-and-ledger.md",
  "skills/security-scan/references/repo-wide-high-impact-families.md",
  "skills/security-scan/references/repo-wide-instance-expansion.md",
  "skills/security-scan/references/repo-wide-validation-closure.md",
  "skills/security-scan/references/repository-wide-scan.md",
  "skills/security-scan/references/scan-artifacts-and-ledger.md",
  "skills/threat-model/SKILL.md",
  "skills/threat-model/agents/openai.yaml",
  "skills/threat-model/references/threat-model-guidance.md",
  "skills/track-findings/SKILL.md",
  "skills/track-findings/agents/openai.yaml",
  "skills/track-findings/references/github-security-advisories.md",
  "skills/track-findings/references/jira.md",
  "skills/triage-finding/SKILL.md",
  "skills/triage-finding/agents/openai.yaml",
  "skills/triage-finding/references/github-rest-intake.md",
  "skills/triage-finding/references/ticket-intake.md",
  "skills/triage-finding/references/triage-result-contract.md",
  "skills/validation/SKILL.md",
  "skills/validation/agents/openai.yaml",
  "skills/validation/references/validation-guidance.md",
  "skills/vulnerability-writeup/SKILL.md",
  "skills/vulnerability-writeup/agents/openai.yaml",
  "skills/vulnerability-writeup/references/report-format.md",
]);
const pluginEntries = new Set();
const pluginDirectories = new Set(["package/_bundled_plugin"]);
for (const file of pluginFiles) {
  const archivePath = `package/_bundled_plugin/${file}`;
  pluginEntries.add(archivePath);
  if (!files.has(archivePath)) {
    throw new Error(`npm tarball is missing ${archivePath}.`);
  }
  const parts = file.split("/");
  for (let index = 1; index < parts.length; index++) {
    pluginDirectories.add(
      `package/_bundled_plugin/${parts.slice(0, index).join("/")}`,
    );
  }
}

const allowedRoot = new Set([
  "package/package.json",
  "package/README.md",
  "package/LICENSE",
]);
const distFiles = new Set(
  [
    "api",
    "auth",
    "cli",
    "config",
    "contract",
    "errors",
    "index",
    "models",
    "result",
    "runtime",
    "targets",
    "version",
  ].flatMap((module) =>
    ["js", "js.map", "d.ts", "d.ts.map"].map(
      (extension) => `package/dist/${module}.${extension}`,
    ),
  ),
);
for (const file of distFiles) {
  if (!files.has(file)) throw new Error(`npm tarball is missing ${file}.`);
}
const unsafePath = /(?:^|\/)\.{1,2}(?:\/|$)/u;
for (const file of files) {
  const normalized = file.endsWith("/") ? file.slice(0, -1) : file;
  const allowed = file.endsWith("/")
    ? normalized === "package" ||
      normalized === "package/dist" ||
      pluginDirectories.has(normalized)
    : allowedRoot.has(normalized) ||
      distFiles.has(normalized) ||
      pluginEntries.has(normalized);
  if (!allowed || unsafePath.test(file) || file.includes("\\")) {
    throw new Error(`npm tarball contains an unexpected file: ${file}.`);
  }
}

const listing = tar(["-tvzf", archive], "utf8");
if (/^[^d-]/mu.test(listing)) {
  throw new Error(
    "npm tarball contains a non-regular entry (symbolic or hard link, device, or pipe).",
  );
}

const internalMarker =
  /(?:internal\.api\.openai\.org|gateway\.[a-z0-9.-]*internal|\.openai\.org|openai\.firewall\.socket\.dev|socket-firewall-registry|openai\.(?:enterprise\.)?slack\.com|(?:app\.notion\.com\/p|notion\.so)\/openai|github\.com[:/]openai\/openai(?:\.git)?(?:[/?#@%\s()<>]|$)|LicenseRef-Proprietary|\/Users\/|\/home\/dev-user|(?:^|[\0\s"'`(</])go\/[a-z0-9_-]+)/iu;
const obsoletePythonMarker =
  /(?:sdk\/python|openai_codex_security|pip install(?: --pre)? openai-codex-security|python-(?:ci|release))/iu;

const payloads = [archiveBytes.toString("utf8")];
const compressedFiles = [...files].filter((file) => /\.br$/iu.test(file));
const compressedParts = new Map();
for (const file of files) {
  const match = /^(.*\.br)\.part-([0-9]+)$/iu.exec(file);
  if (match === null) continue;
  const [, name, part] = match;
  const parts = compressedParts.get(name) ?? [];
  parts.push({ file, part: Number(part) });
  compressedParts.set(name, parts);
}

function brotliPayload(bytes, file) {
  const result = brotliDecompressSync(bytes, { info: true });
  if (result.engine.bytesWritten !== bytes.length) {
    throw new Error(`npm tarball contains trailing Brotli data: ${file}.`);
  }
  return result.buffer.toString("utf8");
}

for (const file of compressedFiles) {
  payloads.push(brotliPayload(tar(["-xOf", archive, file]), file));
}
for (const parts of compressedParts.values()) {
  parts.sort((left, right) => left.part - right.part);
  const bytes = Buffer.concat(
    parts.map(({ file }) => tar(["-xOf", archive, file])),
  );
  payloads.push(brotliPayload(bytes, parts[0].file));
}

for (const contents of payloads) {
  if (internalMarker.test(contents)) {
    throw new Error("npm tarball contains an internal reference.");
  }
  if (obsoletePythonMarker.test(contents)) {
    throw new Error("npm tarball contains an obsolete Python SDK reference.");
  }
}

console.log(`Validated ${archive}: ${files.size} entries.`);
