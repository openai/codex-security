import assert from "node:assert/strict";
import { execFile as nodeExecFile } from "node:child_process";
import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { after, test } from "node:test";
import { promisify } from "node:util";
import { importSource } from "./import-module.ts";
import { draftApi, draftFixture } from "./scan-draft-recovery-fixture.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const execFile = promisify(nodeExecFile);
const { aggregateDiscoveryCoverage } = await importSource(
  path.join(import.meta.dirname, "../src/deep-scan/artifact-validation.ts"),
);
const { createDeepScanArtifacts } = await importSource(
  path.join(import.meta.dirname, "../src/deep-scan/artifacts.ts"),
);
const root = await temporaryDirectory("reviewed-files-", true);
after(() => rm(root, { recursive: true, force: true }));

async function fixture(
  name: string,
  layout: "standard" | "worker" | "diff" = "standard",
) {
  const scanDir = path.join(root, name, "scan");
  const repoRoot = path.join(root, name, "repo");
  await mkdir(scanDir, { recursive: true });
  await mkdir(path.join(repoRoot, "src"), { recursive: true });
  for (const file of ["a.ts", "b.ts", "résumé.ts"])
    await writeFile(
      path.join(repoRoot, "src", file),
      "export const value = 1;\n",
    );
  const fixture = draftFixture(scanDir, layout);
  fixture.context.repoRoot = repoRoot;
  fixture.context.pluginRoot = path.resolve(import.meta.dirname, "../..");
  return { ...fixture, repoRoot };
}

test("normalizes and preserves file claims across parent and worker checkpoints", async () => {
  for (const layout of ["standard", "worker"] as const) {
    const f = await fixture(`checkpoints-${layout}`, layout);
    await f.write(
      f.draft({ reviewedFiles: ["src/résumé.ts", "./src/a.ts", "src/a.ts"] }),
    );
    await f.write(f.draft({ reviewedFiles: ["src/b.ts"] }));
    const result = await f.write(f.draft({}, true));
    assert.deepEqual(result.coverage.reviewedFiles, [
      "src/a.ts",
      "src/b.ts",
      "src/résumé.ts",
    ]);
    const saved = JSON.parse(
      await readFile(
        path.join(
          f.root,
          layout === "worker" ? "result.json" : "coverage.json",
        ),
        "utf8",
      ),
    );
    assert.deepEqual(
      (layout === "worker" ? saved.coverage : saved).reviewedFiles,
      result.coverage.reviewedFiles,
    );
    const final = await f.write(f.draft({ reviewedFiles: [] }, true));
    assert.deepEqual(
      final.coverage.reviewedFiles,
      result.coverage.reviewedFiles,
    );
  }
});

test("omitted accounting remains unknown and explicit empty remains empty", async () => {
  const unknown = await fixture("unknown");
  assert.equal(
    Object.hasOwn(
      (await unknown.write(unknown.draft({}, true))).coverage,
      "reviewedFiles",
    ),
    false,
  );
  const empty = await fixture("empty");
  assert.deepEqual(
    (await empty.write(empty.draft({ reviewedFiles: [] }, true))).coverage
      .reviewedFiles,
    [],
  );
});

test("rejects malformed paths and non-inventory claims before saving checkpoints", async () => {
  const f = await fixture("invalid");
  for (const value of [
    null,
    "src/a.ts",
    [42],
    ["../a.ts"],
    ["/src/a.ts"],
    ["C:\\src\\a.ts"],
    ["src/../a.ts"],
    ["src"],
    ["src/missing.ts"],
  ]) {
    await assert.rejects(f.write(f.draft({ reviewedFiles: value })));
  }
  assert.equal((await readdir(f.root)).includes("checkpoints"), false);
});

test("checks authoritative parent scope and coordinator-bound worker scope", async () => {
  const parent = await fixture("parent-scope");
  parent.context.targetContract = {
    ...parent.context.targetContract,
    scope: {
      requiredIncludePaths: ["src"],
      requiredExcludePaths: ["src/b.ts"],
    },
  };
  await assert.rejects(
    parent.write(parent.draft({ reviewedFiles: ["src/b.ts"] })),
    /requested scope/,
  );
  await parent.write(parent.draft({ reviewedFiles: ["src/a.ts"] }));
  const worker = await fixture("worker-scope", "worker");
  delete worker.context.targetContract;
  worker.context.includePaths = ["src/a.ts"];
  await assert.rejects(
    worker.write(worker.draft({ reviewedFiles: ["src/b.ts"] })),
    /requested scope/,
  );
  await worker.write(worker.draft({ reviewedFiles: ["src/a.ts"] }));
});

test("diff accounting accepts deleted base files and rejects unchanged files", async () => {
  const f = await fixture("diff", "diff");
  const git = async (...args: string[]) =>
    (await execFile("git", args, { cwd: f.repoRoot })).stdout.trim();
  await git("init", "-q");
  await git("add", ".");
  await git(
    "-c",
    "user.name=Example",
    "-c",
    "user.email=example@example.invalid",
    "commit",
    "-qm",
    "Initial fixture",
  );
  const baseRevision = await git("rev-parse", "HEAD");
  await rm(path.join(f.repoRoot, "src", "a.ts"));
  await writeFile(
    path.join(f.repoRoot, "src", "b.ts"),
    "export const value = 2;\n",
  );
  await git("add", "-A");
  await git(
    "-c",
    "user.name=Example",
    "-c",
    "user.email=example@example.invalid",
    "commit",
    "-qm",
    "Change fixture",
  );
  f.context.targetContract = {
    ...f.context.targetContract,
    diffTarget: {
      kind: "range",
      baseRevision,
      headRevision: await git("rev-parse", "HEAD"),
    },
  };
  const result = await f.write(
    f.draft({ reviewedFiles: ["src/b.ts", "src/a.ts"] }, true),
  );
  assert.deepEqual(result.coverage.reviewedFiles, ["src/a.ts", "src/b.ts"]);
  await assert.rejects(
    f.write(f.draft({ reviewedFiles: ["src/résumé.ts"] })),
    /source inventory/,
  );
});

test("Deep aggregates only supplied accepted results and preserves unknown versus empty", () => {
  const f = draftFixture(root, "worker");
  const artifacts = createDeepScanArtifacts(root);
  const worker = (id: string, files?: string[]) => ({
    id,
    resultPath: path.join(artifacts.workersRoot, id, "result.json"),
    result: draftApi.parsePersistedScanDraft(
      f.draft(files === undefined ? {} : { reviewedFiles: files }, true),
    ),
  });
  assert.deepEqual(
    aggregateDiscoveryCoverage(artifacts, [
      worker("one", ["src/b.ts", "./src/a.ts"]),
      worker("two", ["src/a.ts"]),
    ]).reviewedFiles,
    ["src/a.ts", "src/b.ts"],
  );
  assert.deepEqual(
    aggregateDiscoveryCoverage(artifacts, [
      worker("one", []),
      worker("two", []),
    ]).reviewedFiles,
    [],
  );
  for (const workers of [
    [],
    [worker("legacy")],
    [worker("one", ["src/a.ts"]), worker("legacy")],
  ])
    assert.equal(
      Object.hasOwn(
        aggregateDiscoveryCoverage(artifacts, workers),
        "reviewedFiles",
      ),
      false,
    );
});
