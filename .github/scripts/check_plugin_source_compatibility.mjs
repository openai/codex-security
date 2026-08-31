#!/usr/bin/env node
// Check that tracked plugin source stays portable across repository imports.

import { spawnSync } from "node:child_process";
import { lstatSync, readFileSync } from "node:fs";
import { basename, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const MAX_SOURCE_FILE_BYTES = 150_000;
const MAX_DEPENDENCY_LOCK_BYTES = 2_000_000;
const DEPENDENCY_LOCK_NAMES = new Set([
  "Cargo.lock",
  "package-lock.json",
  "pnpm-lock.yaml",
  "requirements.txt",
  "uv.lock",
  "yarn.lock",
]);
const LIST_ITEM = /^\s*(?:[-*+]|\d+[.)])\s+/u;
const HTML_BLOCK = /^\s*<\/?[A-Za-z][^>]*>\s*$/u;
const NATURAL_LINE_ENDINGS = new Set("\\.?!:;。！？：；)]}'\"`>");
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function trackedFiles(pluginRoot) {
  const result = spawnSync(
    "git",
    ["-C", pluginRoot, "ls-files", "-z", "--", "."],
    {
      maxBuffer: Infinity,
    },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(result.stderr.toString().trim() || "git ls-files failed");
  }
  return utf8.decode(result.stdout).split("\0").filter(Boolean);
}

function isMarkdownStructure(line) {
  const stripped = line.trim();
  return (
    !stripped ||
    ["#", ">", "|", "<!--", "::", "```", "~~~"].some((prefix) =>
      stripped.startsWith(prefix),
    ) ||
    ["---", "***", "___"].includes(stripped) ||
    HTML_BLOCK.test(stripped) ||
    line.startsWith("    ") ||
    line.startsWith("\t")
  );
}

function lineEndsNaturally(line) {
  const stripped = line.trimEnd();
  return (
    line.endsWith("  ") ||
    NATURAL_LINE_ENDINGS.has(stripped.at(-1)) ||
    /https?:\/\/\S+$/u.test(stripped)
  );
}

function hardWrappedLines(content) {
  const lines = content.split(
    /\r\n|[\n\r\v\f\u001c-\u001e\u0085\u2028\u2029]/u,
  );
  const offenders = [];
  let inFence = false;
  let inFrontmatter = content.startsWith("---\n");
  for (let index = 0; index < lines.length - 1; index++) {
    const line = lines[index];
    const stripped = line.trim();
    if (stripped.startsWith("```") || stripped.startsWith("~~~")) {
      inFence = !inFence;
      continue;
    }
    if (index > 0 && inFrontmatter && stripped === "---") {
      inFrontmatter = false;
      continue;
    }
    if (inFence || inFrontmatter) continue;
    const followingLine = lines[index + 1];
    if (isMarkdownStructure(line) || isMarkdownStructure(followingLine))
      continue;
    if (LIST_ITEM.test(followingLine) || lineEndsNaturally(line)) continue;
    if (!/[A-Za-z0-9`]$/u.test(stripped)) continue;
    if (!/^[A-Za-z0-9`(]/u.test(followingLine.trim())) continue;
    offenders.push(index + 1);
  }
  return offenders;
}

function sourceCompatibilityErrors(pluginRoot) {
  const errors = [];
  for (const relativePath of trackedFiles(pluginRoot)) {
    const path = join(pluginRoot, relativePath);
    const stat = lstatSync(path);
    if (!stat.isFile()) continue;
    const maximum = DEPENDENCY_LOCK_NAMES.has(basename(relativePath))
      ? MAX_DEPENDENCY_LOCK_BYTES
      : MAX_SOURCE_FILE_BYTES;
    // Git emits forward slashes even on Windows.
    if (stat.size > maximum) {
      errors.push(
        `${relativePath}: file is ${stat.size} bytes; maximum is ${maximum} bytes`,
      );
    }
    if (extname(relativePath).toLowerCase() !== ".md") continue;
    const content = utf8.decode(readFileSync(path)).replace(/\r\n?/gu, "\n");
    for (const lineNumber of hardWrappedLines(content)) {
      errors.push(
        `${relativePath}:${lineNumber}: prose is hard-wrapped mid-sentence; use a natural Markdown line`,
      );
    }
  }
  return errors.sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
}

function main() {
  let values;
  try {
    ({ values } = parseArgs({
      options: {
        "plugin-root": {
          type: "string",
          default: fileURLToPath(
            new URL("../../plugins/codex-security", import.meta.url),
          ),
        },
        help: { type: "boolean", short: "h" },
      },
    }));
  } catch (error) {
    console.error(error.message);
    return 2;
  }
  if (values.help) {
    console.log(
      "Check tracked plugin source for deterministic import compatibility.\n",
    );
    console.log(
      "Usage: node check_plugin_source_compatibility.mjs [--plugin-root PATH]",
    );
    console.log(
      "\n--plugin-root PATH  plugin source root (default: plugins/codex-security in this repository)",
    );
    return 0;
  }
  try {
    const errors = sourceCompatibilityErrors(resolve(values["plugin-root"]));
    if (errors.length) {
      console.error(errors.join("\n"));
      return 1;
    }
  } catch (error) {
    console.error(`source compatibility check failed: ${error.message}`);
    return 2;
  }
  console.log("Plugin source compatibility checks passed.");
  return 0;
}

process.exitCode = main();
