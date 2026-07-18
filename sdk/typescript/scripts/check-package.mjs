import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { brotliDecompressSync, gunzipSync } from "node:zlib";

const args = process.argv.slice(2);
if (args[0] === "--") args.shift();
const [archive] = args;
if (archive === undefined || args.length !== 1) {
  throw new Error("Usage: node scripts/check-package.mjs <npm-tarball>");
}

const entries = execFileSync("tar", ["-tzf", archive], {
  encoding: "utf8",
}).split(/\r?\n/u);
const files = new Set(entries.filter(Boolean));
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

const allowed =
  /^package(?:\/(?:package\.json|README\.md|LICENSE|dist(?:\/.*)?|_bundled_plugin(?:\/.*)?))?\/?$/u;
const forbiddenPath =
  /(?:^|\/)(?:\.internal|buildkite|mcp-app|private_release|evals|tests?)(?:\/|$)/u;
for (const file of files) {
  if (!allowed.test(file) || forbiddenPath.test(file)) {
    throw new Error(`npm tarball contains an unexpected file: ${file}.`);
  }
}

const internalMarker =
  /(?:internal\.api\.openai\.org|gateway\.[a-z0-9.-]*internal|\.openai\.org|openai\.firewall\.socket\.dev|socket-firewall-registry|openai\.(?:enterprise\.)?slack\.com|(?:app\.notion\.com\/p|notion\.so)\/openai|github\.com\/openai\/openai|LicenseRef-Proprietary|\/Users\/|\/home\/dev-user|(?:^|[\s"'(<])go\/[a-z0-9_-]+)/iu;
const obsoletePythonMarker =
  /(?:sdk\/python|openai_codex_security|pip install(?: --pre)? openai-codex-security|python-(?:ci|release))/iu;

const payloads = [gunzipSync(readFileSync(archive)).toString("utf8")];
const compressedFiles = [...files].filter((file) => file.endsWith(".br"));
const compressedParts = new Map();
for (const file of files) {
  const match = /^(.*\.br)\.part-([0-9]+)$/u.exec(file);
  if (match === null) continue;
  const [, name, part] = match;
  const parts = compressedParts.get(name) ?? [];
  parts.push({ file, part: Number(part) });
  compressedParts.set(name, parts);
}

for (const file of compressedFiles) {
  payloads.push(
    brotliDecompressSync(execFileSync("tar", ["-xOf", archive, file])).toString(
      "utf8",
    ),
  );
}
for (const parts of compressedParts.values()) {
  parts.sort((left, right) => left.part - right.part);
  const bytes = Buffer.concat(
    parts.map(({ file }) => execFileSync("tar", ["-xOf", archive, file])),
  );
  payloads.push(brotliDecompressSync(bytes).toString("utf8"));
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
