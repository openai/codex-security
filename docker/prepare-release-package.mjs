// Prepare an npm ci consumer that reads the scanner from the verified archive.
// Keep every dependency and integrity from the release runtime lock.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { copyFileSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const [archive, runtimeLock, directory] = process.argv.slice(2);
const lock = JSON.parse(readFileSync(runtimeLock, "utf8"));
const scanner = lock.packages["node_modules/@openai/codex-security"];
const integrity =
  "sha512-" +
  createHash("sha512").update(readFileSync(archive)).digest("base64");
assert.equal(
  scanner.integrity,
  integrity,
  "Scanner archive differs from the release runtime lock",
);

const localArchive = join(directory, "scanner.tgz");
if (resolve(archive) !== resolve(localArchive))
  copyFileSync(archive, localArchive);
scanner.resolved = "file:scanner.tgz";
writeFileSync(
  join(directory, "package.json"),
  JSON.stringify(lock.packages[""]),
);
writeFileSync(join(directory, "package-lock.json"), JSON.stringify(lock));
