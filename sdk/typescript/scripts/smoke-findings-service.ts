import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import type { Finding, FindingsDocument } from "../src/models.js";
import type { FindingsPage } from "../src/server/storage.js";

const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));
const container = "findings-ci";
const compose = ["compose", "-p", container, "-f", "compose.findings.yaml"];
const base = "http://127.0.0.1:3000";
const document: FindingsDocument = JSON.parse(
  await readFile(
    new URL(
      "../_bundled_plugin/examples/completed-scan/findings.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const example = document.findings[0];
assert.ok(example);
const findings: Finding[] = [
  example,
  {
    ...example,
    findingId: "csf_ffffffffffffffffffffffff",
    occurrenceId: "occ_ffffffffffffffffffffffff",
    fingerprints: {
      ...example.fingerprints,
      primary: `codex-security/v1:sha256:${"f".repeat(64)}`,
    },
    title: "Synthetic second finding",
  },
];
const ids = findings.map((finding) => finding.findingId);

function docker(args: string[], { check = true } = {}): string {
  const result = spawnSync("docker", args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  });
  if (result.stdout) process.stdout.write(result.stdout);
  if (check) {
    if (result.error) throw result.error;
    assert.equal(result.status, 0, `docker ${args.join(" ")} failed`);
  }
  return result.stdout?.trim() ?? "";
}

async function startService(): Promise<void> {
  docker([
    ...compose,
    "run",
    "--detach",
    "--service-ports",
    "--name",
    container,
    "--env",
    "OPENAI_API_KEY=synthetic-container-key",
    "--volume",
    `${join(repositoryRoot, "docker/fixtures/mock-embeddings.mjs")}:/test/mock-embeddings.mjs:ro`,
    "--volume",
    `${fileURLToPath(new URL("fixtures/findings-service-sqlite.ts", import.meta.url))}:/test/findings-service-sqlite.ts:ro`,
    "findings",
    "--import",
    "/test/mock-embeddings.mjs",
    "dist/server/index.js",
  ]);
  for (let attempt = 0; ; attempt++) {
    try {
      const response = await fetch(`${base}/v1/findings`, {
        signal: AbortSignal.timeout(1000),
      });
      assert.equal(response.status, 200);
      await response.arrayBuffer();
      return;
    } catch (error) {
      if (attempt === 100) throw error;
      await setTimeout(100);
    }
  }
}

async function checkInsertions(): Promise<void> {
  const response = await fetch(`${base}/v1/bulk/findings`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ findings }),
  });
  assert.equal(response.status, 201);
  assert.deepEqual(await response.json(), ids);
}

async function checkPages(): Promise<void> {
  for (let offset = 0; offset <= findings.length; offset++) {
    const path = `/v1/findings?limit=1&offset=${offset}`;
    const response = await fetch(`${base}${path}`);
    assert.equal(response.status, 200, path);
    const expected: FindingsPage = {
      findings: findings.slice(offset, offset + 1),
      limit: 1,
      offset,
      total: findings.length,
      nextOffset: offset + 1 < findings.length ? offset + 1 : null,
    };
    const actual: unknown = await response.json();
    assert.deepEqual(actual, expected, path);
  }
}

function checkStorage(): void {
  docker([
    "exec",
    container,
    "node",
    "--experimental-strip-types",
    "/test/findings-service-sqlite.ts",
    JSON.stringify(ids),
  ]);
}

function stopService(): void {
  docker(["stop", "--timeout", "10", container]);
  assert.equal(
    docker(["inspect", "--format", "{{.State.ExitCode}}", container]),
    "0",
    "The service must exit cleanly on SIGTERM",
  );
}

let passed = false;
try {
  docker([...compose, "build"]);
  await startService();
  await checkInsertions();
  await checkPages();
  checkStorage();
  stopService();
  docker(["rm", container]);
  await startService();
  checkStorage();
  await checkPages();
  await checkInsertions();
  stopService();
  passed = true;
  console.log("Findings service Docker smoke test passed.");
} finally {
  if (!passed) docker(["logs", container], { check: false });
  docker(["rm", "--force", container], { check: false });
  docker([...compose, "down", "--volumes"], { check: passed });
}
