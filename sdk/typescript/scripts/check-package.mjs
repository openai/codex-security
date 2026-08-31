import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import { packageDistFiles } from "./package-dist-files.mjs";
import { assertNoInternalReferences } from "./package-internal-references.mjs";
import { assertExpectedGitHead } from "./package-provenance.mjs";
import { packageSmokeTimeouts } from "./package-smoke-timeouts.mjs";
import { plainTarEntries } from "./package-tar-entries.mjs";
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

const archivePath = resolve(archive);
const MAX_EXPANDED_ASSET_BYTES = 32 * 1024 * 1024;
const compressedArchive = readFileSync(archivePath);
const archiveBytes = gunzipSync(compressedArchive, {
  maxOutputLength: MAX_EXPANDED_ASSET_BYTES,
});
const rawEntries = plainTarEntries(archiveBytes);
const PUBLIC_LOGO_SHA256 =
  "9b9c2b09b2fa064611fb62307d321d5c2ea70cf0789f7ce34cdb0fc0d9190b3a";
const processEnvironment = { ...process.env };
delete processEnvironment.TAR_OPTIONS;
const tarOptions = {
  env: { ...processEnvironment, LC_ALL: "C" },
  input: compressedArchive,
  maxBuffer: archiveBytes.byteLength + 1024,
};
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

function invalidTarEntry() {
  throw new Error("npm tarball contains an invalid tar entry.");
}

const entries = tar(["-tzf", "-"], "utf8").split(/\r?\n/u).filter(Boolean);
const files = new Set(entries);
if (files.size !== entries.length) {
  throw new Error("npm tarball contains duplicate paths.");
}
if (
  rawEntries.length !== entries.length ||
  rawEntries.some(({ path }, index) => path !== entries[index])
) {
  invalidTarEntry();
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
for (const file of pluginFiles) {
  const pluginArchivePath = `package/_bundled_plugin/${file}`;
  pluginEntries.add(pluginArchivePath);
  if (!files.has(pluginArchivePath)) {
    throw new Error(`npm tarball is missing ${pluginArchivePath}.`);
  }
}

const allowedRoot = new Set([
  "package/package.json",
  "package/README.md",
  "package/LICENSE",
  "package/bin/codex-security.mjs",
]);
const distFiles = new Set(packageDistFiles);
for (const file of distFiles) {
  if (!files.has(file)) throw new Error(`npm tarball is missing ${file}.`);
}
const unsafePath = /(?:^|\/)\.{1,2}(?:\/|$)/u;
for (const file of files) {
  const allowed =
    allowedRoot.has(file) || distFiles.has(file) || pluginEntries.has(file);
  if (!allowed || unsafePath.test(file) || file.includes("\\")) {
    throw new Error(`npm tarball contains an unexpected file: ${file}.`);
  }
}

const listing = tar(["-tvzf", "-"], "utf8");
const listingLines = regularTarListingLines(listing);
if (
  listingLines.length !== entries.length ||
  listingLines.some((line) => !line.startsWith("-"))
) {
  invalidTarEntry();
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

function extractedArchiveFiles() {
  const rawSizes = new Map();
  const expectedPaths = new Map();
  for (const { path, size } of rawEntries) {
    if (expectedPaths.get(path) === "directory") invalidTarEntry();
    rawSizes.set(path, size);
    expectedPaths.set(path, "file");
    const parts = path.split("/");
    for (let index = 1; index < parts.length; index++) {
      const directory = parts.slice(0, index).join("/");
      if (rawSizes.has(directory)) invalidTarEntry();
      expectedPaths.set(directory, "directory");
    }
  }

  const extractionRoot = mkdtempSync(
    join(tmpdir(), "codex-security-package-check-"),
  );
  try {
    chmodSync(extractionRoot, 0o700);
    tar([
      "--keep-old-files",
      "--no-same-owner",
      "--no-same-permissions",
      "--no-acls",
      "--no-xattrs",
      "-xzf",
      "-",
      "-C",
      extractionRoot,
    ]);

    const archiveFiles = new Map();
    let expandedBytes = 0;
    function visit(directory, relative = "") {
      for (const name of readdirSync(directory)) {
        const path = relative === "" ? name : `${relative}/${name}`;
        const expectedType = expectedPaths.get(path);
        if (expectedType === undefined) invalidTarEntry();
        const extractedPath = join(extractionRoot, path);
        const stats = lstatSync(extractedPath);
        expectedPaths.delete(path);

        if (expectedType === "directory") {
          if (!stats.isDirectory()) invalidTarEntry();
          visit(extractedPath, path);
          continue;
        }

        if (
          !stats.isFile() ||
          stats.nlink !== 1 ||
          stats.size !== rawSizes.get(path) ||
          stats.size > MAX_EXPANDED_ASSET_BYTES ||
          expandedBytes > MAX_EXPANDED_ASSET_BYTES - stats.size
        ) {
          invalidTarEntry();
        }
        expandedBytes += stats.size;
        archiveFiles.set(path, readFileSync(extractedPath));
      }
    }
    visit(extractionRoot);

    if (expectedPaths.size !== 0 || archiveFiles.size !== rawEntries.length) {
      invalidTarEntry();
    }
    return archiveFiles;
  } finally {
    rmSync(extractionRoot, { force: true, recursive: true });
  }
}

const archiveFiles = extractedArchiveFiles();
function archiveFile(path) {
  const contents = archiveFiles.get(path);
  if (contents === undefined) invalidTarEntry();
  return contents;
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

assertNoInternalReferences(archiveFiles, MAX_EXPANDED_ASSET_BYTES);

if (args.length === 1) {
  const smoke = spawnSync(
    process.execPath,
    [
      fileURLToPath(new URL("./smoke-package.mjs", import.meta.url)),
      archivePath,
    ],
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
