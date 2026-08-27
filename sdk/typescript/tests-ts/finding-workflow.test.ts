import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import {
  chmod,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import {
  FindingWorkflow,
  workflowDestination,
} from "../src/finding-workflow.js";
import { publishScanToCustomInternal } from "../src/custom-publish.js";
import { deduplicateScanInternal } from "../src/deduplication/scan.js";
import { resolvePluginPython, runWorkbench } from "../src/runtime.js";
import type { FindingsDocument, ScanManifest } from "../src/models.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "findings-workflow-"));
  directories.push(root);
  const scanDir = join(root, "scan");
  const repository = join(root, "repository");
  await mkdir(repository);
  await cp(join(PLUGIN_ROOT, "examples/completed-scan"), scanDir, {
    recursive: true,
  });
  if (process.platform !== "win32") await chmod(scanDir, 0o700);
  const environment = {
    PATH: process.env["PATH"],
    SystemRoot: process.env["SystemRoot"],
    TEMP: process.env["TEMP"],
    TMP: process.env["TMP"],
    CODEX_HOME: join(root, "codex"),
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
  };
  const document = JSON.parse(
    await readFile(join(scanDir, "findings.json"), "utf8"),
  ) as FindingsDocument;
  const workbenchOptions = {
    environment,
    pluginRoot: PLUGIN_ROOT,
    python: await resolvePluginPython({ environment }),
  };
  const history = async (args: readonly string[], input?: string) =>
    args[0] === "get-scan"
      ? {
          scan: {
            scanId: document.scanId,
            scanDir,
            targetPath: repository,
            progress: { status: "complete" },
          },
        }
      : await runWorkbench(workbenchOptions, args, input);
  return {
    root,
    repository,
    scanDir,
    environment,
    document,
    history,
    workbenchOptions,
  };
}

test("scan registration commits its workflow identity atomically and rolls back failed registration", async () => {
  const { root, repository, environment, workbenchOptions } = await fixture();
  const workflow = new FindingWorkflow("registered-workflow", environment);
  await workflow.bind({ repositoryPath: repository });
  await workflow.begin("scan");
  const register = async (workflowId: string, suffix: string) => {
    const directory = join(root, suffix);
    await mkdir(directory, { mode: 0o700 });
    return await runWorkbench(
      workbenchOptions,
      [
        "register-cli-scan",
        "--repository",
        repository,
        "--scan-dir",
        directory,
        "--registration-json-stdin",
      ],
      JSON.stringify({
        workflowId,
        recipe: {
          repository,
          mode: "standard",
          target: { kind: "repository", paths: [] },
          config: {},
        },
      }),
    );
  };
  const registered = await register("registered-workflow", "registered-scan");
  expect(
    await new FindingWorkflow("registered-workflow", environment).get(),
  ).toMatchObject({
    scanId: registered["scanId"],
    scanDir: registered["scanDir"],
    stages: { scan: { status: "running" } },
  });
  await expect(
    register("unknown-workflow", "rolled-back-scan"),
  ).rejects.toThrow("must be started");
  const history = await runWorkbench(workbenchOptions, [
    "list-scans",
    "--repository",
    repository,
  ]);
  expect(history["scans"]).toHaveLength(1);
  const retried = await register("registered-workflow", "retried-scan");
  expect(retried["scanId"]).not.toBe(registered["scanId"]);
  expect((await workflow.get())?.scanId).toBe(retried["scanId"] as string);
});

test.each(["running", "completed"])(
  "survives termination with a %s stage and resumes in a fresh process",
  async (status) => {
    const { environment } = await fixture();
    const source = `import { FindingWorkflow } from ${JSON.stringify(new URL("../src/finding-workflow.ts", import.meta.url).href)};
const workflow = new FindingWorkflow("interrupted", process.env);
const timer = setInterval(() => {}, 1000);
await workflow.run("publish", async () => {
  if (${JSON.stringify(status)} === "running") {
    process.stdout.write("ready\\n");
    await new Promise(() => {});
  }
  return { findingIds: [] };
});
process.stdout.write("ready\\n");`;
    const child = spawn(process.execPath, ["--eval", source], {
      env: environment,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    const closed = once(child, "close");
    let errors = "";
    child.stderr.on("data", (chunk) => {
      errors += String(chunk);
    });
    try {
      const ready = await Promise.race([
        once(child.stdout, "data").then(([data]) => String(data)),
        closed.then(() => {
          throw new Error(
            errors || "Workflow child exited before the checkpoint",
          );
        }),
      ]);
      expect(ready).toContain("ready");
      child.kill();
      await closed;
      const workflow = new FindingWorkflow("interrupted", environment);
      expect((await workflow.get())?.stages.publish.status).toBe(status);
      let attempts = 0;
      expect(
        await workflow.run("publish", async () => {
          attempts++;
          return { findingIds: [] };
        }),
      ).toEqual({ findingIds: [] });
      expect(attempts).toBe(status === "running" ? 1 : 0);
      expect(
        (await new FindingWorkflow("interrupted", environment).get())?.stages
          .publish,
      ).toEqual({ status: "completed", result: { findingIds: [] } });
    } finally {
      if (child.exitCode === null && child.signalCode === null) child.kill();
      await closed;
    }
  },
);

test("reuses publication after dedupe failure and persists a successful empty duplicate result", async () => {
  const { scanDir, environment, document, history } = await fixture();
  const original = await readFile(join(scanDir, "findings.json"), "utf8");
  const workflowId = "resume-example";
  const options = { workflowId, findingsUrl: "http://synthetic.test/service" };
  let publications = 0;
  let lookups = 0;
  let unavailable = true;
  const request = async (url: URL) => {
    if (url.pathname.endsWith("/bulk/findings")) {
      publications++;
      return Response.json(
        document.findings.map((finding) => finding.findingId),
      );
    }
    lookups++;
    if (unavailable) throw new Error("Synthetic lookup failure");
    return Response.json({
      finding: document.findings[0],
      potentialDuplicates: [],
    });
  };
  const receipt = await publishScanToCustomInternal(scanDir, options, {
    environment,
    fetch: request,
  });
  await expect(
    deduplicateScanInternal(document.scanId, options, {
      environment,
      fetch: request,
      runWorkbench: history,
    }),
  ).rejects.toThrow("Synthetic lookup failure");
  const workflow = new FindingWorkflow(workflowId, environment);
  expect((await workflow.get())?.stages).toMatchObject({
    scan: { status: "completed" },
    publish: { status: "completed", result: receipt },
    dedupe: { status: "failed", error: "Synthetic lookup failure" },
  });
  expect(publications).toBe(1);
  unavailable = false;
  const result = await deduplicateScanInternal(document.scanId, options, {
    environment,
    fetch: request,
    runWorkbench: history,
  });
  expect(result).toEqual({
    scanId: document.scanId,
    uniqueFindingIds: document.findings.map((finding) => finding.findingId),
    duplicateGroups: [],
    deduplicationStatus: "completed",
  });
  expect((await workflow.get())?.stages.dedupe).toEqual({
    status: "completed",
    result,
  });
  expect(
    await deduplicateScanInternal(document.scanId, options, {
      environment,
      runWorkbench: history,
      fetch: async () => {
        throw new Error("Completed stages must not make HTTP requests");
      },
    }),
  ).toEqual(result);
  expect(publications).toBe(1);
  expect(lookups).toBe(2);
  expect(await readFile(join(scanDir, "findings.json"), "utf8")).toBe(original);
});

test("an empty scan completes publication and dedupe and remains retrievable", async () => {
  const { scanDir, environment, document, history } = await fixture();
  document.findings = [];
  const content = JSON.stringify(document);
  await writeFile(join(scanDir, "findings.json"), content);
  const manifestPath = join(scanDir, "scan-manifest.json");
  const manifest = JSON.parse(
    await readFile(manifestPath, "utf8"),
  ) as ScanManifest;
  manifest.scan.artifacts!.find(
    (artifact) => artifact.path === "findings.json",
  )!.sha256 = createHash("sha256").update(content).digest("hex");
  await writeFile(manifestPath, JSON.stringify(manifest));
  const options = {
    workflowId: "empty-scan",
    findingsUrl: "http://synthetic.test",
  };
  let requests = 0;
  const fetch = async (_url: URL, init: RequestInit) => {
    requests++;
    expect(JSON.parse(init.body as string).findings).toEqual([]);
    return Response.json([]);
  };
  const result = await deduplicateScanInternal(document.scanId, options, {
    environment,
    runWorkbench: history,
    fetch,
  });
  expect(result).toEqual({
    scanId: document.scanId,
    uniqueFindingIds: [],
    duplicateGroups: [],
    deduplicationStatus: "completed",
  });
  expect(
    await deduplicateScanInternal(document.scanId, options, {
      environment,
      runWorkbench: history,
      fetch,
    }),
  ).toEqual(result);
  expect(requests).toBe(1);
  expect(
    (await new FindingWorkflow(options.workflowId, environment).get())?.stages
      .publish,
  ).toMatchObject({
    status: "completed",
    result: { findingIds: [], findingCount: 0 },
  });
});

test("failed publication stays unfinished, dry-run does not advance it, and retry records the receipt", async () => {
  const { scanDir, environment, document } = await fixture();
  const options = {
    workflowId: "publication-retry",
    findingsUrl: "http://synthetic.test",
  };
  await expect(
    publishScanToCustomInternal(scanDir, options, {
      environment,
      fetch: async () => new Response("", { status: 503 }),
    }),
  ).rejects.toThrow("HTTP 503");
  const workflow = new FindingWorkflow(options.workflowId, environment);
  const failed = await workflow.get();
  expect(failed?.stages.publish.status).toBe("failed");
  expect(failed?.stages.publish.result).toBeUndefined();
  await publishScanToCustomInternal(
    scanDir,
    { ...options, dryRun: true },
    { environment },
  );
  expect(await workflow.get()).toEqual(failed);
  const result = await publishScanToCustomInternal(scanDir, options, {
    environment,
    fetch: async () =>
      Response.json(document.findings.map((finding) => finding.findingId)),
  });
  expect((await workflow.get())?.stages.publish).toEqual({
    status: "completed",
    result,
  });
});

test("separates workflow identities and rejects different scans, destinations, and scopes", async () => {
  const { environment } = await fixture();
  const binding = {
    scanId: "scan-a",
    scanDir: "synthetic-artifacts",
    destination: workflowDestination(
      "http://synthetic:password@synthetic.test",
    ),
    scope: { repositoryId: "repository-a" },
  };
  const first = new FindingWorkflow("first", environment);
  await first.bind(binding);
  expect((await first.get())?.destination).toBe("http://synthetic.test/");
  await first.run("dedupe", async () => ({ duplicateGroups: [] }));
  for (const changed of [
    { scanId: "scan-b" },
    { destination: "http://other.test/" },
    { scope: { allRepositories: true as const } },
  ]) {
    await expect(first.bind({ ...binding, ...changed })).rejects.toThrow(
      "already bound to a different",
    );
    const separate = new FindingWorkflow(
      `separate-${Object.keys(changed)[0]}`,
      environment,
    );
    expect(
      (await separate.bind({ ...binding, ...changed })).stages.dedupe.status,
    ).toBe("pending");
  }
  expect((await first.get())?.stages.dedupe).toEqual({
    status: "completed",
    result: { duplicateGroups: [] },
  });
});

test("does not write workflow metadata into sealed artifacts", async () => {
  const { scanDir, environment } = await fixture();
  await expect(
    publishScanToCustomInternal(
      scanDir,
      { workflowId: "unsafe-location", findingsUrl: "http://synthetic.test" },
      {
        environment: {
          ...environment,
          CODEX_SECURITY_STATE_DIR: join(scanDir, "state"),
        },
        fetch: async () => {
          throw new Error("Must not publish");
        },
      },
    ),
  ).rejects.toThrow("outside the sealed scan artifacts");
});
