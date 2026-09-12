import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, openSync } from "node:fs";
import { cp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { packageSmokeTimeouts } from "../../sdk/typescript/scripts/package-smoke-timeouts.mjs";

// Publish phase measurements without copying npm's URLs, configuration or argv.
const phases = new Set([
  "npm",
  "npm:load",
  "command:install",
  "idealTree",
  "idealTree:init",
  "idealTree:inflate",
  "idealTree:userRequests",
  "idealTree:buildDeps",
  "idealTree:fixDepFlags",
  "reify",
  "reify:loadTrees",
  "reify:diffTrees",
  "reify:retireShallow",
  "reify:createSparse",
  "reify:loadBundles",
  "reify:unpack",
  "reify:unretire",
  "reify:build",
  "reify:trash",
  "reify:save",
  "build",
  "build:deps",
  "build:queue",
  "build:link",
  "build:run:preinstall",
  "build:run:install",
  "build:run:postinstall",
]);

export function projectPhases(log) {
  const events = [];
  for (const line of log.split(/\r?\n/)) {
    const timing = line.match(
      /^(?:\d+|npm) timing (\S+) Completed in (\d+)ms$/,
    );
    if (timing && phases.has(timing[1])) {
      events.push({ phase: timing[1], completedMs: Number(timing[2]) });
    } else if (/^(?:\d+|npm) silly fetch manifest /.test(line)) {
      events.push({ phase: "fetch-manifest" });
    } else {
      const fetch = line.match(
        /^(?:\d+|npm) http fetch (GET|POST) (\d+) .* (\d+)ms(?: |$)/,
      );
      if (fetch)
        events.push({
          phase: "http-fetch",
          method: fetch[1],
          status: Number(fetch[2]),
          durationMs: Number(fetch[3]),
        });
    }
  }
  return events;
}

export async function installPair({
  archives,
  cache,
  root,
  npmCli,
  npmVersion,
  environment = process.env,
  timeoutMs = packageSmokeTimeouts().commandTimeoutMs,
}) {
  for (const archive of archives) {
    const digest = createHash("sha256")
      .update(await readFile(archive.path))
      .digest("hex");
    assert.equal(
      digest,
      archive.sha256,
      `Unexpected ${archive.label} archive digest.`,
    );
  }
  await mkdir(root);
  const evidence = join(root, "evidence");
  await mkdir(evidence);
  const prepared = [];
  // Complete both copies before either npm install can warm its cache.
  for (const archive of archives) {
    const arm = join(root, archive.label);
    const consumer = join(arm, "consumer");
    const logs = join(arm, "logs");
    const cacheCopy = join(arm, "cache");
    await mkdir(consumer, { recursive: true });
    await mkdir(logs);
    await cp(cache, cacheCopy, { recursive: true });
    await writeFile(
      join(consumer, "package.json"),
      JSON.stringify({
        name: "codex-security-package-smoke",
        private: true,
        type: "module",
      }) + "\n",
    );
    prepared.push({ archive, consumer, logs, cacheCopy });
  }
  const comparison = {
    node: process.version,
    npm: npmVersion,
    platform: process.platform,
    arch: process.arch,
    timeoutMs,
    results: [],
  };
  for (const { archive, consumer, logs, cacheCopy } of prepared) {
    const args = [
      npmCli,
      "install",
      "--prefer-offline",
      "--include=optional",
      "--ignore-scripts",
      "--package-lock=false",
      "--no-audit",
      "--no-fund",
      resolve(archive.path),
      "typescript@7.0.2",
      "@types/node@26.4.1",
    ];
    const outputPath = join(logs, "process.log");
    const fd = openSync(outputPath, "w");
    const started = performance.now();
    let result;
    try {
      result = spawnSync(process.execPath, args, {
        cwd: consumer,
        env: {
          ...environment,
          npm_config_cache: cacheCopy,
          npm_config_logs_dir: logs,
          npm_config_timing: "true",
          npm_config_loglevel: "http",
        },
        stdio: ["ignore", fd, fd],
        timeout: timeoutMs,
        killSignal: "SIGKILL",
        windowsHide: true,
      });
    } finally {
      closeSync(fd);
    }
    const durationMs = Math.round(performance.now() - started);
    const logFiles = (await readdir(logs))
      .filter((name) => /-debug-\d+\.log$/.test(name))
      .sort();
    const inputs = logFiles.length ? logFiles : ["process.log"];
    const events = [];
    for (const name of inputs)
      events.push(...projectPhases(await readFile(join(logs, name), "utf8")));
    const row = {
      label: archive.label,
      archiveSha256: archive.sha256,
      exitCode: result.status,
      signal: result.signal,
      errorCode: result.error?.code ?? null,
      durationMs,
      phaseEvidenceAvailable: events.length > 0,
      events,
    };
    comparison.results.push(row);
    await writeFile(
      join(evidence, "comparison.json"),
      JSON.stringify(comparison, null, 2) + "\n",
    );
    const { events: measuredPhases, ...summary } = row;
    console.log(
      JSON.stringify({ ...summary, phaseEvents: measuredPhases.length }),
    );
  }
  // Both measurements survive cleanup failure; npm logs remain outside consumers.
  for (const { consumer } of prepared) {
    await rm(consumer, {
      recursive: true,
      force: true,
      maxRetries: 10,
      retryDelay: 100,
    });
  }
  return comparison;
}

async function main() {
  const npmCli =
    process.platform === "win32"
      ? join(
          dirname(process.execPath),
          "node_modules",
          "npm",
          "bin",
          "npm-cli.js",
        )
      : resolve(
          dirname(process.execPath),
          "../lib/node_modules/npm/bin/npm-cli.js",
        );
  const npmVersion = JSON.parse(
    await readFile(resolve(dirname(npmCli), "../package.json"), "utf8"),
  ).version;
  const cacheResult = spawnSync(
    process.execPath,
    [npmCli, "config", "get", "cache"],
    { encoding: "utf8" },
  );
  assert.equal(
    cacheResult.status,
    0,
    "Could not locate the restored npm cache.",
  );
  assert.ok(
    process.env.RUNNER_TEMP,
    "RUNNER_TEMP must identify the diagnostic runner's temporary directory.",
  );
  const comparison = await installPair({
    archives: [
      {
        label: "baseline",
        path: resolve("dist/package-baseline/openai-codex-security-0.1.27.tgz"),
        sha256:
          "b8a66d239bd4193734be7f3abedb1d180f94c4448caabe4b2c4641795a00eb3a",
      },
      {
        label: "candidate",
        path: resolve(
          "dist/package-candidate/openai-codex-security-0.1.27.tgz",
        ),
        sha256:
          "0938546920234729740f897bfe9fe89b219ee675546cadc7012881a350446be2",
      },
    ],
    cache: cacheResult.stdout.trim(),
    root: join(process.env.RUNNER_TEMP, "package-install-diagnostic"),
    npmCli,
    npmVersion,
  });
  if (
    comparison.results.some(
      (result) => result.exitCode !== 0 || result.errorCode !== null,
    )
  )
    process.exitCode = 1;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  await main();
}
