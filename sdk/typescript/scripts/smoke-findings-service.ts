import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, cp, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import type { Finding, FindingsDocument, ScanManifest } from "../src/models.js";
import type { DeduplicateScanResult } from "../src/deduplication/scan.js";
import type { FindingsPage } from "../src/server/storage.js";
import type { FindingDedupeGroup } from "../src/finding-dedupe-groups.js";
import type { DashboardSnapshot } from "../src/server/dashboard-types.js";

const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));
const container = "findings-ci";
const compose = ["compose", "-p", container, "-f", "compose.findings.yaml"];
const localRoot = await mkdtemp(join(tmpdir(), "findings-host-publish-"));
let base: string;
const document: FindingsDocument = JSON.parse(
  await readFile(
    new URL(
      "../../../plugins/codex-security/examples/completed-scan/findings.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const manifest: ScanManifest = JSON.parse(
  await readFile(
    new URL(
      "../../../plugins/codex-security/examples/completed-scan/scan-manifest.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const repositoryId = manifest.scan.target.targetId;
const example = document.findings[0];
assert.ok(example);
const findings: Finding[] = [
  {
    ...example,
    extensions: { ...example.extensions, smokeGroup: "duplicate" },
  },
  ...[1, 2, 3].map(
    (index): Finding => ({
      ...example,
      findingId: `csf_${"f".repeat(23)}${index}`,
      occurrenceId: `occ_${"f".repeat(23)}${index}`,
      fingerprints: {
        ...example.fingerprints,
        primary: `codex-security/v1:sha256:${"f".repeat(63)}${index}`,
      },
      title: `Synthetic finding ${index}`,
      extensions: {
        ...example.extensions,
        smokeGroup: index < 3 ? "duplicate" : "distinct",
      },
    }),
  ),
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
    "--publish",
    "127.0.0.1::3000",
    "--name",
    container,
    "--env",
    "OPENAI_API_KEY=synthetic-container-key",
    "--volume",
    `${join(repositoryRoot, "docker/fixtures/mock-embeddings.mjs")}:/test/mock-embeddings.mjs:ro`,
    "--volume",
    `${join(repositoryRoot, "docker/fixtures/mock-reviews.mjs")}:/test/mock-reviews.mjs:ro`,
    "--volume",
    `${fileURLToPath(new URL("fixtures/findings-service-sqlite.ts", import.meta.url))}:/test/findings-service-sqlite.ts:ro`,
    "findings",
    "--import",
    "/test/mock-embeddings.mjs",
    "dist/server/index.js",
  ]);
  base = `http://${docker(["port", container, "3000/tcp"])}`;
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

async function checkHostPublication(): Promise<void> {
  const installed = join(localRoot, "package");
  docker([
    "cp",
    `${container}:/usr/local/lib/node_modules/@openai/codex-security`,
    installed,
  ]);
  const scanDir = join(localRoot, "completed-scan");
  await cp(
    join(installed, "_bundled_plugin/examples/completed-scan"),
    scanDir,
    { recursive: true },
  );
  if (process.platform !== "win32") await chmod(scanDir, 0o700);
  const result = spawnSync(
    process.execPath,
    [
      join(installed, "bin/codex-security.mjs"),
      "publish",
      "scan",
      "--scan-dir",
      scanDir,
      "--to",
      "custom",
      "--findings-url",
      base,
      "--json",
    ],
    {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "inherit"],
      env: { ...process.env, CODEX_SECURITY_NO_UPDATE_NOTICE: "1" },
    },
  );
  if (result.error) throw result.error;
  assert.equal(
    result.status,
    0,
    "The installed CLI must publish from the host to Docker",
  );
  assert.deepEqual(JSON.parse(result.stdout), {
    scanId: manifest.scan.id,
    repositoryId,
    findingIds: [ids[0]],
    findingCount: 1,
  });
  const response = await fetch(
    `${base}/v1/finding/${ids[0]}/potential-duplicates?repositoryId=${repositoryId}`,
  );
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    finding: example,
    potentialDuplicates: [],
  });
}

async function checkDashboard(): Promise<void> {
  for (const [path, type] of [
    ["/dashboard", "text/html"],
    ["/dashboard/app.js", "text/javascript"],
    ["/dashboard/app.css", "text/css"],
  ]) {
    const response = await fetch(`${base}${path}`);
    assert.equal(response.status, 200);
    assert.ok(response.headers.get("content-type")?.startsWith(type!));
    assert.ok((await response.text()).length > 0);
  }
  const response = await fetch(`${base}/v1/dashboard?view=findings`);
  assert.equal(response.status, 200);
  const snapshot = (await response.json()) as DashboardSnapshot;
  assert.equal(snapshot.total, findings.length);
  assert.equal(snapshot.overview.findings, findings.length);
  assert.equal(snapshot.items.length, findings.length);
}

async function checkInsertions(): Promise<void> {
  for (const [repository, batch] of [
    [repositoryId, findings.slice(0, 3)],
    ["synthetic-other", findings.slice(3)],
  ] as const) {
    const response = await fetch(`${base}/v1/bulk/findings`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repositoryId: repository, findings: batch }),
    });
    assert.equal(response.status, 201);
    assert.deepEqual(
      await response.json(),
      batch.map((finding) => finding.findingId),
    );
  }
}

async function checkCandidates(): Promise<void> {
  for (const [index, finding] of findings.entries()) {
    for (const allRepositories of [false, true]) {
      const repository = index < 3 ? repositoryId : "synthetic-other";
      const response = await fetch(
        `${base}/v1/finding/${finding.findingId}/potential-duplicates?${allRepositories ? "allRepositories=true" : `repositoryId=${encodeURIComponent(repository)}`}`,
      );
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), {
        finding,
        potentialDuplicates: (allRepositories
          ? findings
          : index < 3
            ? findings.slice(0, 3)
            : findings.slice(3)
        ).filter((candidate) => candidate.findingId !== finding.findingId),
      });
    }
  }
}

function checkCliDeduplication(): void {
  docker([
    "exec",
    container,
    "node",
    "--experimental-strip-types",
    "/test/findings-service-sqlite.ts",
    JSON.stringify(ids),
    "--prepare-scan",
  ]);
  for (const allRepositories of [false, true]) {
    const command = [
      "exec",
      container,
      "node",
      "--import",
      "/test/mock-reviews.mjs",
      "dist/cli.js",
      "dedupe",
      "--scan",
      manifest.scan.id,
      "--workflow-id",
      allRepositories ? "smoke-all" : "smoke-repository",
      "--findings-url",
      "http://127.0.0.1:3000",
      "--json",
      ...(allRepositories ? ["--all-repositories"] : []),
    ];
    const actual: unknown = JSON.parse(docker(command));
    const expected: DeduplicateScanResult = {
      scanId: manifest.scan.id,
      uniqueFindingIds: [ids[0]!],
      duplicateGroups: [ids.slice(0, 3)],
      deduplicationStatus: "completed",
    };
    assert.deepEqual(actual, expected);
    const calls = docker([
      "exec",
      container,
      "cat",
      "/state/review-calls.jsonl",
    ]);
    assert.deepEqual(JSON.parse(docker(command)), expected);
    assert.equal(
      docker(["exec", container, "cat", "/state/review-calls.jsonl"]),
      calls,
    );
  }
  findings[0] = example!;
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

function checkStorage(expectGroups = false): void {
  docker([
    "exec",
    container,
    "node",
    "--experimental-strip-types",
    "/test/findings-service-sqlite.ts",
    JSON.stringify(ids),
    ...(expectGroups ? ["--expect-groups"] : []),
  ]);
}

async function checkStoredGroups(): Promise<FindingDedupeGroup[]> {
  let stored: FindingDedupeGroup[] = [];
  for (const [index, id] of ids.entries()) {
    const response = await fetch(`${base}/v1/finding/${id}/dedupe-groups`);
    assert.equal(response.status, 200);
    const groups = (await response.json()) as FindingDedupeGroup[];
    if (index === 0) {
      assert.equal(groups.length, 1, "Repeated dedupe must reuse the group");
      assert.deepEqual(groups[0]!.findingIds, ids.slice(0, 3).sort());
      stored = groups;
    } else {
      assert.deepEqual(groups, index < 3 ? stored : []);
    }
  }
  return stored;
}

function checkReviews(): void {
  const calls = docker(["exec", container, "cat", "/state/review-calls.jsonl"])
    .split("\n")
    .map(
      (line) =>
        JSON.parse(line) as {
          stage: string;
          findingIds: string[];
        },
    );
  for (const stage of ["screen", "pair"]) {
    assert.ok(
      calls.some((call) => call.stage === stage),
      `${stage} review must run through Codex`,
    );
  }
  for (const count of [3, 4])
    assert.ok(
      calls.some(
        (call) => call.stage === "screen" && call.findingIds.length === count,
      ),
    );
  assert.ok(
    calls.every(
      (call) =>
        call.stage === "screen" ||
        (call.stage === "pair" && call.findingIds.length === 2),
    ),
  );
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
  await checkHostPublication();
  await checkInsertions();
  await checkDashboard();
  await checkCandidates();
  await checkPages();
  checkStorage();
  checkCliDeduplication();
  checkStorage(true);
  const storedGroups = await checkStoredGroups();
  checkReviews();
  stopService();
  docker(["rm", container]);
  await startService();
  checkStorage(true);
  assert.deepEqual(await checkStoredGroups(), storedGroups);
  await checkPages();
  await checkCandidates();
  stopService();
  passed = true;
  console.log("Findings service Docker smoke test passed.");
} finally {
  if (!passed) docker(["logs", container], { check: false });
  docker(["rm", "--force", container], { check: false });
  docker([...compose, "down", "--volumes"], { check: passed });
  await rm(localRoot, { recursive: true, force: true });
}
