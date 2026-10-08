import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import {
  assertPublicPackageContents,
  MAX_EXPANDED_ASSET_BYTES,
} from "./package-public-content.mjs";
import { assertExpectedGitHead } from "./package-provenance.mjs";
import { packageSmokeTimeouts } from "./package-smoke-timeouts.mjs";
import { regularTarListingLines } from "./package-tar-listing.mjs";
import { pluginContractFiles } from "./plugin-contract.mjs";

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
const archiveMetadata = [];
for (; offset + 512 <= archiveBytes.byteLength;) {
  const header = archiveBytes.subarray(offset, offset + 512);
  if (header.every((byte) => byte === 0)) {
    archiveMetadata.push(header);
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
    archiveMetadata.push(
      header,
      archiveBytes.subarray(contentsStart + size, nextOffset),
    );
  } else {
    archiveMetadata.push(archiveBytes.subarray(offset, nextOffset));
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
  "package/docs/cli.md",
  "package/docs/findings-service.md",
  "package/docs/dedupe-records.md",
  "package/LICENSE",
  "package/bin/codex-security.mjs",
  "package/dist/index.js",
  "package/dist/index.d.ts",
  "package/dist/cli.js",
  "package/schemas/project-config.schema.json",
  "package/_bundled_plugin/.codex-plugin/plugin.json",
];

for (const file of required) {
  if (!files.has(file)) throw new Error(`npm tarball is missing ${file}.`);
}

const contract = JSON.parse(readFileSync(contractPath, "utf8"));
const pluginPaths = pluginContractFiles(contract);
if (new Set(pluginPaths).size !== pluginPaths.length) {
  throw new Error("Plugin projection contract contains duplicate paths.");
}

const allowedFiles = new Set([
  ...required,
  ...pluginPaths.map((file) => `package/_bundled_plugin/${file}`),
  "package/dist/server/dashboard/index.html",
  "package/dist/server/dashboard/app.js",
  "package/dist/server/dashboard/app.css",
  "package/dist/server/dashboard/THIRD_PARTY_NOTICES.txt",
  ...[
    "api",
    "artifact-export",
    "auth",
    "bulk-scan-discovery",
    "cli",
    "cli-help",
    "cli-scan-logs-json",
    "cli-signals",
    "classify-severity",
    "classify-scan-severity",
    "severity-store",
    "cloud-publish",
    "codex-prompt",
    "codex-sdk-environment",
    "component-plan",
    "component-scan",
    "config",
    "config-path",
    "contract",
    "cost",
    "cost-model",
    "custom-validation",
    "custom-validation-prompt",
    "custom-publish",
    "deep-progress",
    "deep-config",
    "deep-scan-defaults",
    "project-config",
    "project-config-schema",
    "prompt-files",
    "provider-profile",
    "scan-modes",
    "scan-settings",
    "errors",
    "feedback",
    "finding-catalogue",
    "findings-import",
    "github",
    "index",
    "import-scan",
    "knowledge-base",
    "linear",
    "models",
    "multiscan",
    "mock-scan",
    "owner-evidence",
    "patch-tui",
    "publication",
    "publication-events",
    "publication-store",
    "publish",
    "result",
    "record",
    "request-metadata",
    "runtime",
    "scan-activity",
    "scan-comparison",
    "scan-dashboard",
    "scan-history-renderer",
    "scan-logs",
    "security-policy",
    "security-policy-cli",
    "suggest-owners",
    "scan-sessions",
    "server/index",
    "server/api",
    "deduplication/codex-review",
    "deduplication/checkpointed-review",
    "deduplication/refusal",
    "deduplication/retry",
    "deduplication/deduplication",
    "finding-retrieval",
    "finding-workflow",
    "findings-client",
    "finding-dedupe-groups",
    "deduplication/deduplication-prompts",
    "deduplication/deduplication-reviewer",
    "deduplication/diagnostics",
    "deduplication/scan",
    "deduplication/local",
    "deduplication/finding-schema",
    "deduplication/records",
    "deduplication/records-protocol",
    "deduplication/review",
    "saved-scan",
    "saved-scan-bootstrap",
    "server/embeddings",
    "server/dashboard",
    "server/dashboard-types",
    "server/errors",
    "server/routes",
    "server/server",
    "server/serve",
    "server/sqlite-store",
    "server/storage",
    "server/validation",
    "targets",
    "thread-source",
    "trusted-executable",
    "value",
    "version",
    "windows-path",
    "worker-progress",
  ].flatMap((module) =>
    ["js", "js.map", "d.ts", "d.ts.map"].map(
      (extension) => `package/dist/${module}.${extension}`,
    ),
  ),
]);
for (const file of [...allowedFiles]) {
  if (!files.has(file)) throw new Error(`npm tarball is missing ${file}.`);
  const parts = file.split("/");
  for (let index = 1; index < parts.length; index++) {
    allowedFiles.add(`${parts.slice(0, index).join("/")}/`);
  }
}
const unsafePath = /(?:^|\/)\.{1,2}(?:\/|$)/u;
for (const file of files) {
  if (!allowedFiles.has(file) || unsafePath.test(file) || file.includes("\\")) {
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

for (const file of files) {
  if (/\.png$/iu.test(file)) {
    const digest = createHash("sha256").update(archiveFile(file)).digest("hex");
    if (digest !== PUBLIC_LOGO_SHA256) {
      throw new Error(`npm tarball contains an unexpected PNG asset: ${file}.`);
    }
  }
}

assertPublicPackageContents(archiveFiles, Buffer.concat(archiveMetadata));

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
