#!/usr/bin/env node
/**
 * One-time mechanical pass that rebrands the vendored Codex Security plugin for
 * Claude Code. Run against `plugin/` after re-copying from upstream; the
 * orchestration-heavy files (the three top-level scan skills and the config
 * preflight) still need hand edits afterwards, because their setup and
 * completion sections describe a Codex-only MCP app surface that has no
 * mechanical translation.
 *
 * Deliberately NOT rewritten:
 *   - `documentType: "codex-security.*"` and `fingerprints.algorithm`
 *     ("codex-security/v1"). Those are schema `const` values that form the
 *     on-disk scan contract; keeping them means results stay interchangeable
 *     with upstream and the 500 KB of Python validators keep working untouched.
 *   - `CODEX_SECURITY_STATE_DIR` / `CODEX_HOME` inside Python. Those are the
 *     env names the workbench reads, and the CLI sets them explicitly.
 *
 * Usage: node tools/port-plugin.mjs [--check]
 */
import { readFile, readdir, writeFile } from "node:fs/promises";
import { extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const PLUGIN_ROOT = fileURLToPath(new URL("../plugin/", import.meta.url));
const CHECK_ONLY = process.argv.includes("--check");

const SKILL_NAMES = [
  "attack-path-analysis",
  "deep-security-scan",
  "define-security-policy",
  "finding-discovery",
  "fix-finding",
  "propose-security-hardening",
  "security-diff-scan",
  "security-scan",
  "threat-model",
  "track-findings",
  "triage-finding",
  "validation",
  "vulnerability-writeup",
];

const MARKDOWN_RULES = [
  // Skill invocation syntax: Codex used `$plugin:skill` and bare `$skill`.
  [/\$codex-security:/g, "claude-security:"],
  ...SKILL_NAMES.map((name) => [
    new RegExp(`\\$${name}\\b`, "g"),
    `claude-security:${name}`,
  ]),
  // Runtime environment handed to the scan session.
  [/\bCODEX_SECURITY_/g, "CLAUDE_SECURITY_"],
  // Product and host naming.
  [/\bCodex Security\b/g, "Claude Security"],
  [/\bCodex CLI\b/g, "Claude Code"],
  [/\bCodex desktop app\b/g, "Claude Code"],
  [/\bCodex thread\b/g, "Claude Code session"],
  [/\bCodex goal\b/g, "scan goal"],
  [/\bcodex exec\b/g, "claude --print"],
  [/\bCodex home\b/g, "Claude Code home"],
  [/\bCodex config\b/g, "Claude Code config"],
  [/\bthe Codex Security plugin server\b/g, "the claude-security CLI"],
  [/\bCodex loads\b/g, "Claude Code loads"],
  [/\bCodex should\b/g, "the scan should"],
  [/\bCodex rejects\b/g, "Claude Code rejects"],
  [/\bCodex workers\b/g, "Claude Code workers"],
  [/\bcodex-security-plugin\b/g, "claude-security-plugin"],
];

const PYTHON_RULES = [
  [/\bCodex Security\b/g, "Claude Security"],
  [/"\.codex-plugin"/g, '".claude-plugin"'],
  [/PRODUCER_NAME = "codex-security-plugin"/g, 'PRODUCER_NAME = "claude-security-plugin"'],
  [/"name": "Codex Security",/g, '"name": "Claude Security",'],
];

async function* walk(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) yield* walk(path);
    else if (entry.isFile()) yield path;
  }
}

const changed = [];
for await (const path of walk(PLUGIN_ROOT)) {
  const extension = extname(path);
  const rules =
    extension === ".md" || extension === ".toml"
      ? MARKDOWN_RULES
      : extension === ".py"
        ? PYTHON_RULES
        : null;
  if (rules === null) continue;
  const original = await readFile(path, "utf8");
  let updated = original;
  for (const [pattern, replacement] of rules) updated = updated.replace(pattern, replacement);
  if (updated === original) continue;
  changed.push(relative(PLUGIN_ROOT, path));
  if (!CHECK_ONLY) await writeFile(path, updated);
}

process.stdout.write(
  `${CHECK_ONLY ? "Would rewrite" : "Rewrote"} ${changed.length} file(s):\n` +
    changed.map((path) => `  ${path}\n`).join(""),
);
