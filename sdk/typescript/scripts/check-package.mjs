import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { brotliDecompressSync, gunzipSync } from "node:zlib";
import { assertExpectedGitHead } from "./package-provenance.mjs";
import { packageSmokeTimeouts } from "./package-smoke-timeouts.mjs";
import { regularTarListingLines } from "./package-tar-listing.mjs";

const PACKAGE_SMOKE_PROCESS_TIMEOUT_MS =
  packageSmokeTimeouts().processTimeoutMs;

const args = process.argv.slice(2);
if (args[0] === "--") args.shift();
const [
  archive,
  contractPath = new URL(
    "../../../plugins/codex-security/plugin-files.json",
    import.meta.url,
  ),
] = args;
if (archive === undefined || args.length > 2) {
  throw new Error(
    "Usage: node scripts/check-package.mjs <npm-tarball> [plugin-contract]",
  );
}

const MAX_EXPANDED_ASSET_BYTES = 32 * 1024 * 1024;
const archiveBytes = gunzipSync(readFileSync(archive), {
  maxOutputLength: MAX_EXPANDED_ASSET_BYTES,
});
const PUBLIC_LOGO_SHA256 =
  "9b9c2b09b2fa064611fb62307d321d5c2ea70cf0789f7ce34cdb0fc0d9190b3a";
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

let offset = 0;
const archiveFiles = new Map();
for (; offset + 512 <= archiveBytes.byteLength; ) {
  const header = archiveBytes.subarray(offset, offset + 512);
  if (header.every((byte) => byte === 0)) {
    offset += 512;
    continue;
  }
  const name = header.subarray(0, 100).toString("utf8").split("\0", 1)[0];
  const prefix = header.subarray(345, 500).toString("utf8").split("\0", 1)[0];
  const path = prefix === "" ? name : `${prefix}/${name}`;
  const sizeField = header
    .subarray(124, 136)
    .toString("ascii")
    .split("\0", 1)[0]
    .trim();
  if (!/^[0-7]*$/u.test(sizeField)) {
    throw new Error("npm tarball contains an invalid tar entry.");
  }
  if (path.endsWith("/") && header[156] !== 0x35) {
    throw new Error("npm tarball contains an invalid tar entry.");
  }
  const size = Number.parseInt(sizeField || "0", 8);
  const contentsStart = offset + 512;
  const nextOffset = contentsStart + Math.ceil(size / 512) * 512;
  if (nextOffset > archiveBytes.byteLength) {
    throw new Error("npm tarball contains an invalid tar entry.");
  }
  if (header[156] === 0 || header[156] === 0x30) {
    archiveFiles.set(
      path,
      archiveBytes.subarray(contentsStart, contentsStart + size),
    );
  }
  offset = nextOffset;
}
if (archiveBytes.subarray(offset).some((byte) => byte !== 0)) {
  throw new Error("npm tarball contains trailing tar data.");
}

function archiveFile(path) {
  const contents = archiveFiles.get(path);
  if (contents === undefined) {
    throw new Error("npm tarball contains an invalid tar entry: " + path + ".");
  }
  return contents;
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
  "package/bin/codex-security.mjs",
  "package/dist/index.js",
  "package/dist/index.d.ts",
  "package/dist/cli.js",
  "package/_bundled_plugin/.codex-plugin/plugin.json",
];

for (const file of required) {
  if (!files.has(file)) throw new Error(`npm tarball is missing ${file}.`);
}

const contract = JSON.parse(readFileSync(contractPath, "utf8"));
const { externalOwnedExact, shippedExact } = contract;
if (
  !Array.isArray(externalOwnedExact) ||
  !externalOwnedExact.every((path) => typeof path === "string") ||
  !Array.isArray(shippedExact) ||
  !shippedExact.every((path) => typeof path === "string")
) {
  throw new Error("Plugin projection contract contains invalid paths.");
}
const publicManifest = ".codex-plugin/plugin.json";
if (!externalOwnedExact.includes(publicManifest)) {
  throw new Error(
    "Plugin projection contract must declare the public manifest as externally owned.",
  );
}
const pluginPaths = [
  publicManifest,
  ...shippedExact.filter((path) => !path.startsWith("sdk/")),
];
const pluginFiles = new Set(pluginPaths);
if (pluginFiles.size !== pluginPaths.length) {
  throw new Error("Plugin projection contract contains duplicate paths.");
}

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
  "package/bin/codex-security.mjs",
]);
const distFiles = new Set(
  [
    "api",
    "auth",
    "bulk-scan-discovery",
    "cli",
    "classify-severity",
    "classify-scan-severity",
    "severity-store",
    "cloud-publish",
    "codex-prompt",
    "component-plan",
    "component-scan",
    "config",
    "contract",
    "cost",
    "cost-model",
    "custom-validation",
    "custom-validation-prompt",
    "custom-publish",
    "deep-progress",
    "errors",
    "finding-catalogue",
    "github",
    "index",
    "knowledge-base",
    "linear",
    "models",
    "multiscan",
    "mock-scan",
    "patch-tui",
    "publication",
    "publication-events",
    "publication-store",
    "publish",
    "result",
    "runtime",
    "scan-activity",
    "scan-comparison",
    "scan-dashboard",
    "scan-history-renderer",
    "scan-logs",
    "scan-sessions",
    "server/index",
    "server/api",
    "deduplication/codex-review",
    "deduplication/checkpointed-review",
    "deduplication/deduplication",
    "finding-retrieval",
    "finding-workflow",
    "findings-client",
    "finding-dedupe-groups",
    "deduplication/deduplication-prompts",
    "deduplication/deduplication-reviewer",
    "deduplication/scan",
    "saved-scan",
    "server/embeddings",
    "server/dashboard",
    "server/dashboard-types",
    "server/errors",
    "server/findings-service",
    "server/routes",
    "server/server",
    "server/serve",
    "server/sqlite-store",
    "server/storage",
    "server/validation",
    "targets",
    "thread-source",
    "trusted-executable",
    "version",
    "windows-path",
    "worker-progress",
  ].flatMap((module) =>
    ["js", "js.map", "d.ts", "d.ts.map"].map(
      (extension) => `package/dist/${module}.${extension}`,
    ),
  ),
);
const dashboardFiles = new Set([
  "package/dist/server/dashboard/index.html",
  "package/dist/server/dashboard/app.js",
  "package/dist/server/dashboard/app.css",
  "package/dist/server/dashboard/THIRD_PARTY_NOTICES.txt",
]);
for (const file of dashboardFiles) {
  if (!files.has(file)) throw new Error(`npm tarball is missing ${file}.`);
}
for (const file of distFiles) {
  if (!files.has(file)) throw new Error(`npm tarball is missing ${file}.`);
}
const unsafePath = /(?:^|\/)\.{1,2}(?:\/|$)/u;
for (const file of files) {
  const normalized = file.endsWith("/") ? file.slice(0, -1) : file;
  const allowed = file.endsWith("/")
    ? normalized === "package" ||
      normalized === "package/bin" ||
      normalized === "package/dist" ||
      normalized === "package/dist/server" ||
      normalized === "package/dist/server/dashboard" ||
      normalized === "package/dist/deduplication" ||
      pluginDirectories.has(normalized)
    : allowedRoot.has(normalized) ||
      distFiles.has(normalized) ||
      dashboardFiles.has(normalized) ||
      pluginEntries.has(normalized);
  if (!allowed || unsafePath.test(file) || file.includes("\\")) {
    throw new Error(`npm tarball contains an unexpected file: ${file}.`);
  }
}

const listing = tar(["-tvzf", archive], "utf8");
const listingLines = regularTarListingLines(listing);
if (
  listingLines.length !== entries.length ||
  listingLines.some(
    (line, index) => line.startsWith("d") !== entries[index].endsWith("/"),
  )
) {
  throw new Error("npm tarball contains an invalid tar entry.");
}
for (const [path, name] of [
  ["package/bin/codex-security.mjs", "CLI"],
  ["package/_bundled_plugin/scripts/launch_codex_security_mcp", "MCP"],
]) {
  const permissions =
    listingLines[entries.indexOf(path)]?.split(/\s/u, 1)[0] ?? "";
  if ([3, 6, 9].some((index) => permissions[index] !== "x")) {
    throw new Error(`npm package ${name} launcher is not executable.`);
  }
}
const packageJson = JSON.parse(
  archiveFile("package/package.json").toString("utf8"),
);
if (
  packageJson.name !== "@openai/codex-security" ||
  packageJson.license !== "Apache-2.0"
) {
  throw new Error("npm package does not contain the expected public metadata.");
}
assertExpectedGitHead(
  packageJson,
  process.env.CODEX_SECURITY_EXPECTED_GIT_HEAD,
);

const internalMarker =
  /(?:internal\.api\.openai\.org|gateway\.[a-z0-9.-]*internal|\.openai\.org|openai\.firewall\.socket\.dev|socket\x2dfirewall\x2dregistry|openai\.(?:enterprise\.)?slack\.com|app\.slack\.com\/client|(?:app\.notion\.com\/p|notion\.so)\/openai|linear\.app\/openai|(?:github\.com[:/]|api\.github\.com\/repos\/|raw\.githubusercontent\.com\/)openai\/openai(?:\.git)?(?:[^a-z0-9_-]|$)|LicenseRef\x2dProprietary|\/Users\/|\/home\/dev-user|flow\.apps\.openai\.org|(?:^|[^a-z0-9_-])go\/[a-z0-9_-]+)/iu;

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
  const result = brotliDecompressSync(bytes, {
    info: true,
    maxOutputLength: MAX_EXPANDED_ASSET_BYTES,
  });
  if (result.engine.bytesWritten !== bytes.length) {
    throw new Error(`npm tarball contains trailing Brotli data: ${file}.`);
  }
  return result.buffer;
}

for (const file of compressedFiles) {
  payloads.push(brotliPayload(archiveFile(file), file).toString("utf8"));
}
for (const parts of compressedParts.values()) {
  parts.sort((left, right) => left.part - right.part);
  const bytes = Buffer.concat(parts.map(({ file }) => archiveFile(file)));
  payloads.push(brotliPayload(bytes, parts[0].file).toString("utf8"));
}
for (const file of files) {
  if (/\.png$/iu.test(file)) {
    const digest = createHash("sha256").update(archiveFile(file)).digest("hex");
    if (digest !== PUBLIC_LOGO_SHA256) {
      throw new Error(`npm tarball contains an unexpected PNG asset: ${file}.`);
    }
  }
}

for (const contents of payloads) {
  if (internalMarker.test(contents)) {
    throw new Error("npm tarball contains an internal reference.");
  }
}

if (args.length === 1) {
  const smoke = spawnSync(
    process.execPath,
    [fileURLToPath(new URL("./smoke-package.mjs", import.meta.url)), archive],
    {
      stdio: "inherit",
      timeout: PACKAGE_SMOKE_PROCESS_TIMEOUT_MS,
      killSignal: "SIGKILL",
      windowsHide: true,
    },
  );
  if (smoke.error?.code === "ETIMEDOUT") {
    throw new Error(
      `Installed npm package smoke timed out after ${PACKAGE_SMOKE_PROCESS_TIMEOUT_MS} ms.`,
      { cause: smoke.error },
    );
  }
  if (smoke.error !== undefined) throw smoke.error;
  if (smoke.status !== 0) {
    throw new Error(
      `Installed npm package smoke exited with status ${smoke.status ?? smoke.signal ?? "unknown"}.`,
    );
  }
}

console.log(`Validated ${archive}: ${files.size} entries.`);
