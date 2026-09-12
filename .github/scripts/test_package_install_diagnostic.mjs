import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { installPair, projectPhases } from "./diagnose_package_install.mjs";
import { packageSmokeTimeouts } from "../../sdk/typescript/scripts/package-smoke-timeouts.mjs";

test("retains phase timing without publishing npm URL, argv or configuration data", () => {
  const events = projectPhases(
    [
      "3 timing idealTree:init Completed in 12ms",
      "4 silly fetch manifest private-package@https://token@example.invalid/archive",
      "5 http fetch GET 200 https://token@example.invalid/archive 37ms (cache miss)",
      "6 verbose argv --registry=https://token@example.invalid",
      "7 timing reifyNode:node_modules/private-package Completed in 8ms",
      "8 timing reify:unpack Completed in 20ms",
    ].join("\n"),
  );
  assert.deepEqual(events, [
    { phase: "idealTree:init", completedMs: 12 },
    { phase: "fetch-manifest" },
    { phase: "http-fetch", method: "GET", status: 200, durationMs: 37 },
    { phase: "reify:unpack", completedMs: 20 },
  ]);
});

test("both child installs start from copied cache state and retain failures and logs after consumer cleanup", async () => {
  const directory = await mkdtemp(join(tmpdir(), "package diagnostic % "));
  try {
    const cache = join(directory, "restored-cache");
    await mkdir(cache);
    await writeFile(join(cache, "state"), "original");
    const archives = [];
    for (const label of ["baseline", "candidate"]) {
      const path = join(directory, `${label}.tgz`);
      await writeFile(path, label);
      archives.push({
        label,
        path,
        sha256: createHash("sha256").update(label).digest("hex"),
      });
    }
    const npmCli = join(directory, "npm-cli.cjs");
    await writeFile(
      npmCli,
      `
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const args = process.argv.slice(2);
assert.deepEqual(args.slice(0, 7), ['install', '--prefer-offline', '--include=optional', '--ignore-scripts', '--package-lock=false', '--no-audit', '--no-fund']);
assert.deepEqual(args.slice(8), ['typescript@7.0.2', '@types/node@26.4.1']);
assert.equal(fs.readFileSync(path.join(process.env.npm_config_cache, 'state'), 'utf8'), 'original');
assert.equal(process.env.DIAGNOSTIC_TEST_INHERITED, 'preserved');
assert.equal(process.env.npm_config_timing, 'true');
assert.equal(process.env.npm_config_loglevel, 'http');
fs.writeFileSync(path.join(process.env.npm_config_cache, 'state'), 'changed');
fs.writeFileSync(path.join(process.env.npm_config_logs_dir, 'fixture-debug-0.log'), '0 timing idealTree:init Completed in 9ms\\n1 verbose argv synthetic-secret\\n');
console.log('synthetic-private-output');
process.exit(path.basename(args[7]) === 'baseline.tgz' ? 7 : 0);
`,
    );
    const root = join(directory, "diagnostic");
    const comparison = await installPair({
      archives,
      cache,
      root,
      npmCli,
      npmVersion: "fixture",
      environment: { ...process.env, DIAGNOSTIC_TEST_INHERITED: "preserved" },
    });
    assert.equal(comparison.timeoutMs, packageSmokeTimeouts().commandTimeoutMs);
    assert.deepEqual(
      comparison.results.map((row) => row.exitCode),
      [7, 0],
    );
    assert.equal(await readFile(join(cache, "state"), "utf8"), "original");
    for (const { label } of archives) {
      await assert.rejects(
        readFile(join(root, label, "consumer", "package.json")),
        { code: "ENOENT" },
      );
      assert.match(
        await readFile(join(root, label, "logs", "process.log"), "utf8"),
        /synthetic-private-output/,
      );
      assert.deepEqual(
        comparison.results.find((row) => row.label === label).events,
        [{ phase: "idealTree:init", completedMs: 9 }],
      );
    }
    const published = await readFile(
      join(root, "evidence", "comparison.json"),
      "utf8",
    );
    assert.doesNotMatch(
      published,
      /synthetic-private-output|synthetic-secret|DIAGNOSTIC_TEST_INHERITED/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a timed-out child retains its last phase and does not prevent the second arm", async () => {
  const directory = await mkdtemp(join(tmpdir(), "package timeout % "));
  try {
    const cache = join(directory, "cache");
    await mkdir(cache);
    const archives = [];
    for (const label of ["baseline", "candidate"]) {
      const path = join(directory, `${label}.tgz`);
      await writeFile(path, label);
      archives.push({
        label,
        path,
        sha256: createHash("sha256").update(label).digest("hex"),
      });
    }
    const npmCli = join(directory, "npm-cli.cjs");
    await writeFile(
      npmCli,
      `
const fs = require('node:fs');
const path = require('node:path');
fs.writeFileSync(path.join(process.env.npm_config_logs_dir, 'fixture-debug-0.log'), '0 timing idealTree:init Completed in 2ms\\n');
if (path.basename(process.argv[9]) === 'baseline.tgz') setInterval(() => {}, 1000);
`,
    );
    const comparison = await installPair({
      archives,
      cache,
      root: join(directory, "diagnostic"),
      npmCli,
      npmVersion: "fixture",
      timeoutMs: 2000,
    });
    assert.equal(comparison.results[0].errorCode, "ETIMEDOUT");
    assert.equal(comparison.results[0].exitCode, null);
    assert.deepEqual(comparison.results[0].events, [
      { phase: "idealTree:init", completedMs: 2 },
    ]);
    assert.equal(comparison.results[1].exitCode, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("rejects a different archive before either install starts", async () => {
  const directory = await mkdtemp(join(tmpdir(), "package digest % "));
  try {
    const path = join(directory, "archive.tgz");
    await writeFile(path, "different archive");
    const root = join(directory, "diagnostic");
    await assert.rejects(
      installPair({
        archives: [{ label: "baseline", path, sha256: "0".repeat(64) }],
        root,
      }),
      /Unexpected baseline archive digest/,
    );
    await assert.rejects(readFile(join(root, "evidence", "comparison.json")), {
      code: "ENOENT",
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
