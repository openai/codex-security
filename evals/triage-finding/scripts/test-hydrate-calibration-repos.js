#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const evalDir = path.join(__dirname, "..");
const scriptPath = path.join(evalDir, "scripts", "hydrate-calibration-repos.js");

function runHydrator(args) {
  return childProcess.execFileSync(process.execPath, [scriptPath, ...args], {
    cwd: evalDir,
    encoding: "utf8",
  });
}

const allOutput = runHydrator(["--dry-run"]);
assert.match(allOutput, /would hydrate 16 calibration variants/);
assert.match(allOutput, /oss-mantisbt-ghsa-73vx-49mv-v8w5\/vulnerable/);
assert.match(allOutput, /https:\/\/github\.com\/mantisbt\/mantisbt/);
assert.match(allOutput, /80990f43153167c73f11eb4b2bc7108d0c3d6b46/);

const filteredOutput = runHydrator(["--dry-run", "--case", "oss-mantisbt-ghsa-73vx-49mv-v8w5", "--variant", "fixed"]);
assert.match(filteredOutput, /would hydrate 1 calibration variant/);
assert.match(filteredOutput, /oss-mantisbt-ghsa-73vx-49mv-v8w5\/fixed/);
assert.doesNotMatch(filteredOutput, /oss-mantisbt-ghsa-73vx-49mv-v8w5\/vulnerable/);

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "calibration-checkouts-"));
function git(directory, ...args) {
  return childProcess.execFileSync("git", args, { cwd: directory, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}
function repository(name) {
  const directory = path.join(temporary, name);
  fs.mkdirSync(directory);
  git(directory, "init", "-b", "main");
  fs.writeFileSync(path.join(directory, "fixture.txt"), name);
  git(directory, "add", "fixture.txt");
  git(directory, "-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid", "-c", "commit.gpgsign=false", "commit", "-m", "Fixture");
  return directory;
}
try {
  const source = repository("source");
  const parent = repository("parent");
  git(parent, "remote", "add", "origin", "https://example.invalid/original.git");
  const originalHead = git(parent, "rev-parse", "HEAD");
  const originalOrigin = git(parent, "remote", "get-url", "origin");
  const expectedHead = git(source, "rev-parse", "HEAD");
  const dataset = path.join(temporary, "dataset.json");
  fs.writeFileSync(dataset, JSON.stringify({ cases: [{ case_id: "case", repo: { url: source }, variants: [{ variant_id: "variant", checkout_ref: expectedHead }] }] }));
  const repoRoot = path.join(parent, "checkouts");
  const target = path.join(repoRoot, "case", "variant");
  fs.mkdirSync(path.join(target, ".git"), { recursive: true });
  const rejected = childProcess.spawnSync(process.execPath, [scriptPath, "--dataset", dataset, "--repo-root", repoRoot], { encoding: "utf8" });
  assert.equal(git(parent, "remote", "get-url", "origin"), originalOrigin);
  assert.equal(git(parent, "rev-parse", "HEAD"), originalHead);
  assert.equal(git(parent, "symbolic-ref", "--short", "HEAD"), "main");
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /non-empty non-git directory/);

  fs.rmdirSync(path.join(target, ".git"));
  assert.match(runHydrator(["--dataset", dataset, "--repo-root", repoRoot]), /hydrated: case\/variant/);
  assert.equal(git(target, "rev-parse", "HEAD"), expectedHead);
  assert.equal(git(parent, "remote", "get-url", "origin"), originalOrigin);
  assert.equal(git(parent, "rev-parse", "HEAD"), originalHead);
  assert.match(runHydrator(["--dataset", dataset, "--repo-root", repoRoot]), /already current/);

  const alias = path.join(temporary, " checkout alias ");
  fs.symlinkSync(repoRoot, alias, process.platform === "win32" ? "junction" : "dir");
  assert.match(runHydrator(["--dataset", dataset, "--repo-root", alias]), /already current/);
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}

console.log("calibration hydration tests passed");
