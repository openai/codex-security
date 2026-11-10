import { spawnSync } from "node:child_process";
import {
  chmodSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import { packageDistFiles } from "./package-dist-files.mjs";
import {
  assertPublicPackageContents,
  assertPublicText,
  MAX_EXPANDED_ASSET_BYTES,
} from "./package-public-content.mjs";
import { assertExpectedGitHead } from "./package-provenance.mjs";
import { packageSmokeTimeouts } from "./package-smoke-timeouts.mjs";
import { readTarArchive } from "./package-tar-entries.mjs";
import {
  assertTarListingSizes,
  regularTarListingLines,
} from "./package-tar-listing.mjs";
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

const archivePath = resolve(archive);
const compressedArchive = readFileSync(archivePath);
const archiveBytes = gunzipSync(compressedArchive, {
  maxOutputLength: MAX_EXPANDED_ASSET_BYTES,
});
const storedArchive = readTarArchive(archiveBytes);
const rawEntries = storedArchive.entries;
validatePackagePaths(rawEntries.map(({ path }) => path));
assertPublicPackageContents(
  storedArchive.files,
  Buffer.concat(storedArchive.metadata),
);
const processEnvironment = { ...process.env };
delete processEnvironment.TAR_OPTIONS;
const characterLocale =
  processEnvironment.LC_ALL || processEnvironment.LC_CTYPE;
delete processEnvironment.LC_ALL;
const tarOptions = {
  env: {
    ...processEnvironment,
    LC_CTYPE: characterLocale,
    LC_MESSAGES: "C",
    LC_NUMERIC: "C",
  },
  input: compressedArchive,
  maxBuffer: archiveBytes.byteLength + 1024,
};
function tar(args, encoding = "buffer") {
  const result = spawnSync("tar", ["--ignore-zeros", ...args], {
    ...tarOptions,
    encoding,
  });
  const stderr = result.stderr?.toString().trim() ?? "";
  if (
    result.status !== 0 &&
    stderr.startsWith("tar: unrecognized option: ignore-zeros\nBusyBox ")
  ) {
    // BusyBox can exit before Node finishes writing a larger archive to stdin.
    throw new Error(
      `Package validation requires tar with --ignore-zeros. On Alpine Linux, install GNU tar with 'apk add tar'.\n${stderr}`,
      { cause: result.error },
    );
  }
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0 || result.stderr.length !== 0) {
    throw new Error(
      `npm tarball contains an invalid tar entry${stderr === "" ? "." : `: ${stderr}`}`,
    );
  }
  return result.stdout;
}

function invalidTarEntry() {
  throw new Error("npm tarball contains an invalid tar entry.");
}

function validatePackagePaths(entries) {
  const files = new Set(entries);
  if (files.size !== entries.length)
    throw new Error("npm tarball contains duplicate paths.");
  const required = [
    "package/package.json",
    "package/README.md",
    "package/docs/cli.md",
    "package/docs/findings-service.md",
    "package/docs/dedupe-records.md",
    "package/docs/classify-severity-records.md",
    "package/docs/hosted-scans.md",
    "package/docs/validate-records.md",
    "package/docs/hosted-remediation.md",
    "package/docs/telemetry.md",
    "package/schemas/hosted-scan-v2.fixture.json",
    "package/LICENSE",
    "package/bin/codex-security.mjs",
    "package/dist/index.js",
    "package/dist/index.d.ts",
    "package/dist/cli.js",
    "package/schemas/project-config.schema.json",
    "package/schemas/external-findings.schema.json",
    "package/_bundled_plugin/.codex-plugin/plugin.json",
  ];

  const allowedFiles = new Set();
  function requireFile(path) {
    if (!files.has(path)) throw new Error(`npm tarball is missing ${path}.`);
    allowedFiles.add(path);
  }
  for (const path of required) requireFile(path);

  const contract = JSON.parse(readFileSync(contractPath, "utf8"));
  const pluginPaths = pluginContractFiles(contract);

  for (const path of pluginPaths)
    requireFile(`package/_bundled_plugin/${path}`);
  for (const path of packageDistFiles) requireFile(path);
  for (const file of [...allowedFiles]) {
    const parts = file.split("/");
    for (let index = 1; index < parts.length; index++) {
      allowedFiles.add(`${parts.slice(0, index).join("/")}/`);
    }
  }
  const unsafePath = /(?:^|\/)\.{1,2}(?:\/|$)/u;
  for (const file of files) {
    if (
      !allowedFiles.has(file) ||
      unsafePath.test(file) ||
      file.includes("\\")
    ) {
      const displayPath = file.replace(
        /[\u0000-\u001f\u007f-\u009f]/gu,
        (character) =>
          `\\x${character.charCodeAt(0).toString(16).padStart(2, "0")}`,
      );
      throw new Error(
        `npm tarball contains an unexpected file: ${displayPath}.`,
      );
    }
  }
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

const listing = tar(["--numeric-owner", "-tvzf", "-"], "utf8");
const listingLines = regularTarListingLines(listing);
if (
  listingLines.length !== entries.length ||
  listingLines.some(
    (line, index) => line.startsWith("d") !== entries[index].endsWith("/"),
  )
) {
  invalidTarEntry();
}
const listingSizes = assertTarListingSizes(
  listingLines,
  MAX_EXPANDED_ASSET_BYTES,
);
if (rawEntries.some(({ size }, index) => size !== listingSizes[index]))
  invalidTarEntry();
const posixMcpLauncher =
  "package/_bundled_plugin/scripts/launch_codex_security_mcp";
for (const [path, name] of [
  ["package/bin/codex-security.mjs", "CLI"],
  [posixMcpLauncher, "MCP"],
]) {
  const permissions =
    listingLines[entries.indexOf(path)]?.split(/\s/u, 1)[0] ?? "";
  if ([3, 6, 9].some((index) => permissions[index] !== "x")) {
    throw new Error(`npm package ${name} launcher is not executable.`);
  }
}
if (
  [storedArchive.files, storedArchive.npmFiles].some((files) =>
    files.get(posixMcpLauncher)?.includes("\r\n"),
  )
) {
  throw new Error("npm package POSIX MCP launcher contains CRLF line endings.");
}

function privateExtractionDirectories(directory) {
  chmodSync(directory, 0o700);
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      privateExtractionDirectories(join(directory, entry.name));
    }
  }
}

function extractedArchiveFiles() {
  const expectedSizes = new Map(
    entries.map((path, index) => [path, listingSizes[index]]),
  );
  for (const path of entries) {
    const parts = path.split("/");
    for (let depth = 1; depth < parts.length; depth++) {
      const parent = parts.slice(0, depth).join("/");
      if (expectedSizes.has(parent)) invalidTarEntry();
      expectedSizes.set(parent + "/", 0);
    }
  }

  const extractionRoot = mkdtempSync(
    join(tmpdir(), "codex-security-package-check-"),
  );
  try {
    chmodSync(extractionRoot, 0o700);
    const fileList = join(extractionRoot, "members.list");
    const fileNames = entries.filter((path) => !path.endsWith("/"));
    writeFileSync(fileList, [...fileNames, ""].join("\0"));
    try {
      tar([
        "-m",
        "--keep-old-files",
        "--no-same-owner",
        "--no-same-permissions",
        "--no-acls",
        "--no-xattrs",
        "-xzf",
        "-",
        "-C",
        extractionRoot,
        "--null",
        "-T",
        fileList,
      ]);
    } finally {
      privateExtractionDirectories(extractionRoot);
    }
    rmSync(fileList);

    const archiveFiles = new Map();
    function visit(directory, relative = "") {
      for (const name of readdirSync(directory)) {
        const path = relative === "" ? name : `${relative}/${name}`;
        const extractedPath = join(extractionRoot, path);
        const stats = lstatSync(extractedPath);
        if (expectedSizes.delete(path + "/")) {
          if (!stats.isDirectory()) invalidTarEntry();
          visit(extractedPath, path);
          continue;
        }
        if (
          !stats.isFile() ||
          stats.nlink !== 1 ||
          stats.size !== expectedSizes.get(path)
        ) {
          invalidTarEntry();
        }
        expectedSizes.delete(path);
        chmodSync(extractedPath, 0o600);
        const contents = readFileSync(extractedPath);
        if (!storedArchive.files.get(path)?.equals(contents)) invalidTarEntry();
        archiveFiles.set(path, contents);
      }
    }
    visit(extractionRoot);

    if (expectedSizes.size !== 0) invalidTarEntry();
    return archiveFiles;
  } finally {
    rmSync(extractionRoot, { force: true, recursive: true });
  }
}

const archiveFiles = extractedArchiveFiles();
const npmManifest = storedArchive.npmFiles.get("package/package.json");
if (npmManifest === undefined) invalidTarEntry();
const packageJson = JSON.parse(npmManifest.toString("utf8"));
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

assertPublicPackageContents(archiveFiles);
// Keep the separate UTF-8 decoding of headers and padding alongside the raw metadata scan.
assertPublicText(
  storedArchive.metadata.map((part) => part.toString("utf8")).join(""),
);
for (const path of archiveFiles.keys()) {
  if (
    /\.(?:png|br(?:\.part-[0-9]+)?)$/iu.test(path) &&
    !storedArchive.npmFiles.has(path)
  )
    invalidTarEntry();
}
assertPublicPackageContents(storedArchive.npmFiles);

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
