import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
const container = `findings-ci-${process.pid}`;
const image = process.argv[2] ?? "codex-security:local";
const compose = ["compose", "-p", container, "-f", "compose.findings.yaml"];
const runnerRoot = await mkdtemp(join(tmpdir(), "codex-security-runner-"));
const runnerCompose = [
  "compose",
  "-p",
  `${container}-runner`,
  "-f",
  "compose.runner.yaml",
  "-f",
  join(runnerRoot, "network.json"),
];
const runner = [...runnerCompose, "run", "--rm", "-T"];
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

function docker(args: string[], { check = true, status = 0 } = {}): string {
  const result = spawnSync("docker", args, {
    cwd: repositoryRoot,
    env: {
      ...process.env,
      CODEX_SECURITY_FINDINGS_IMAGE: image,
      CODEX_SECURITY_IMAGE: image,
      CODEX_SECURITY_USER: `${process.getuid!()}:${process.getgid!()}`,
      CODEX_SECURITY_RESULTS: join(runnerRoot, "results"),
      CODEX_SECURITY_STATE: join(runnerRoot, "state"),
      CODEX_SECURITY_SECCOMP: join(
        repositoryRoot,
        "docker/codex-security-seccomp.json",
      ),
      OPENAI_API_KEY: "synthetic-container-key",
      CODEX_API_KEY: "",
      GH_TOKEN: "",
      GITHUB_TOKEN: "",
    },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  });
  if (result.stdout) process.stdout.write(result.stdout);
  if (check) {
    if (result.error) throw result.error;
    assert.equal(
      result.status,
      status,
      `docker ${args.join(" ")} returned an unexpected exit code`,
    );
  }
  return result.stdout?.trim() ?? "";
}

async function startService(): Promise<void> {
  docker([
    ...compose,
    "run",
    "--detach",
    "--use-aliases",
    "--publish",
    "127.0.0.1::3000",
    "--name",
    container,
    "--env",
    "OPENAI_API_KEY=synthetic-container-key",
    "--env",
    "NODE_OPTIONS=--import=/test/mock-embeddings.mjs",
    "--volume",
    `${join(repositoryRoot, "docker/fixtures/mock-embeddings.mjs")}:/test/mock-embeddings.mjs:ro`,
    "--volume",
    `${fileURLToPath(new URL("fixtures/findings-service-sqlite.ts", import.meta.url))}:/test/findings-service-sqlite.ts:ro`,
    "findings",
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

async function checkCliDeduplication(): Promise<void> {
  for (const allRepositories of [false, true]) {
    const command = [
      ...runner,
      "--env",
      "NODE_OPTIONS=--import=/test/mock-reviews.mjs",
      "--volume",
      `${join(repositoryRoot, "docker/fixtures/mock-reviews.mjs")}:/test/mock-reviews.mjs:ro`,
      "codex-security",
      "dedupe",
      "--scan",
      manifest.scan.id,
      "--workflow-id",
      allRepositories ? "smoke-all" : "smoke-repository",
      "--findings-url",
      "http://findings:3000",
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
    const callsPath = join(
      runnerRoot,
      "results/.codex-security-state/review-calls.jsonl",
    );
    const calls = await readFile(callsPath, "utf8");
    assert.deepEqual(JSON.parse(docker(command)), expected);
    assert.equal(await readFile(callsPath, "utf8"), calls);
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

function checkWorkflowStorage(): void {
  docker([
    ...runner,
    "--entrypoint",
    "node",
    "--volume",
    `${fileURLToPath(new URL("fixtures/prepare-runner-scan.ts", import.meta.url))}:/test/prepare-runner-scan.ts:ro`,
    "codex-security",
    "--experimental-strip-types",
    "/test/prepare-runner-scan.ts",
    "--check-workflows",
    JSON.stringify(ids),
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

async function checkReviews(): Promise<void> {
  const calls = (
    await readFile(
      join(runnerRoot, "results/.codex-security-state/review-calls.jsonl"),
      "utf8",
    )
  )
    .trim()
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
  for (const directory of ["results", "state"])
    await mkdir(join(runnerRoot, directory), { mode: 0o700 });
  await writeFile(
    join(runnerRoot, "network.json"),
    JSON.stringify({
      networks: { default: { external: true, name: `${container}_default` } },
    }),
  );
  if (!process.argv[2])
    docker(["build", "--target", "scanner", "--tag", image, "."]);
  await startService();
  docker([...runnerCompose, "config", "--quiet"]);
  docker([
    ...runnerCompose,
    "-f",
    "compose.apparmor.yaml",
    "config",
    "--quiet",
  ]);
  docker([...runner, "codex-security", "dedupe", "--help"]);
  docker([
    ...runner,
    "--entrypoint",
    "node",
    "--volume",
    `${fileURLToPath(new URL("fixtures/prepare-runner-scan.ts", import.meta.url))}:/test/prepare-runner-scan.ts:ro`,
    "codex-security",
    "--experimental-strip-types",
    "/test/prepare-runner-scan.ts",
  ]);
  assert.equal(
    docker(
      [
        ...runner,
        "codex-security",
        "dedupe",
        "--scan",
        "missing-scan",
        "--findings-url",
        "http://findings:3000",
        "--json",
      ],
      { status: 2 },
    ),
    "",
  );
  await checkInsertions();
  await checkDashboard();
  await checkCandidates();
  await checkPages();
  checkStorage();
  await checkCliDeduplication();
  checkStorage(true);
  checkWorkflowStorage();
  const storedGroups = await checkStoredGroups();
  await checkReviews();
  stopService();
  docker(["rm", container]);
  await startService();
  checkStorage(true);
  assert.deepEqual(await checkStoredGroups(), storedGroups);
  await checkDashboard();
  await checkPages();
  await checkCandidates();
  await checkCliDeduplication();
  checkWorkflowStorage();
  await checkReviews();
  stopService();
  assert.equal(
    await readFile(join(runnerRoot, "state/runner-marker"), "utf8"),
    "synthetic runner state\n",
  );
  passed = true;
  console.log(
    "Findings service and separate scanner runner Docker smoke test passed.",
  );
} finally {
  if (!passed) docker(["logs", container], { check: false });
  docker(["rm", "--force", container], { check: false });
  docker([...compose, "down", "--volumes"], { check: passed });
  await rm(runnerRoot, { recursive: true, force: true });
}
