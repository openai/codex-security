import {
  chmod,
  cp,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { publishScanToCustomInternal as publishScanToCustom } from "../src/custom-publish.js";
import { FindingWorkflow } from "../src/finding-workflow.js";
import type { FindingsDocument } from "../src/models.js";
import { runWorkbench } from "../src/runtime.js";
import { FindingsService } from "../src/server/findings-service.js";
import { SqliteFindingsStore } from "../src/server/sqlite-store.js";
import {
  EMBEDDING_MODEL,
  EMBEDDING_DIMENSIONS,
} from "../src/server/embeddings.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "custom-publish-"));
  directories.push(root);
  const scan = join(root, "scan");
  await cp(join(PLUGIN_ROOT, "examples/completed-scan"), scan, {
    recursive: true,
  });
  if (process.platform !== "win32") await chmod(scan, 0o700);
  const source = await readFile(join(scan, "findings.json"), "utf8");
  const document = JSON.parse(source) as FindingsDocument;
  return {
    scan,
    source,
    document,
    environment: {
      ...process.env,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    },
  };
}

test("publishes complete sealed findings with their repository ID to a custom base URL", async () => {
  const { scan, source, document, environment } = await fixture();
  const controller = new AbortController();
  const ids = document.findings.map((finding) => finding.findingId);
  let calls = 0;
  const result = await publishScanToCustom(
    scan,
    {
      findingsUrl: "http://synthetic.test/service",
      expectedScanId: document.scanId,
      signal: controller.signal,
    },
    {
      environment,
      fetch: async (url, options) => {
        calls++;
        expect(String(url)).toBe(
          "http://synthetic.test/service/v1/bulk/findings",
        );
        expect(options).toEqual({
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": expect.stringMatching(/^publish-[a-f0-9]{64}$/u),
          },
          body: JSON.stringify({
            findings: document.findings,
            repositoryId: "target_sha256_example",
          }),
          signal: controller.signal,
        });
        return Response.json(ids, { status: 201 });
      },
    },
  );
  expect(result).toEqual({
    scanId: document.scanId,
    repositoryId: "target_sha256_example",
    findingIds: ids,
    findingCount: ids.length,
  });
  expect(calls).toBe(1);
  expect(await readFile(join(scan, "findings.json"), "utf8")).toBe(source);
});

test("dry-run previews the complete upload without HTTP or credentials", async () => {
  const { scan, document } = await fixture();
  const result = await publishScanToCustom(
    scan,
    { findingsUrl: "http://localhost:3000", dryRun: true },
    {
      fetch: async () => {
        throw new Error("dry-run must not send a request");
      },
    },
  );
  expect(result).toEqual({
    scanId: document.scanId,
    repositoryId: "target_sha256_example",
    findingIds: document.findings.map((finding) => finding.findingId),
    findingCount: document.findings.length,
    dryRun: true,
    findings: document.findings,
  });
});

test("does not retry failed uploads or report incomplete receipts as successful", async () => {
  const { scan, environment } = await fixture();
  for (const [receipt, status, message] of [
    [{}, 503, "HTTP 503"],
    [{}, 201, "did not acknowledge all"],
    [[], 201, "did not acknowledge all"],
    [["wrong-finding"], 201, "did not acknowledge all"],
  ] as const) {
    let calls = 0;
    await expect(
      publishScanToCustom(
        scan,
        { findingsUrl: "http://synthetic.test" },
        {
          environment,
          fetch: async () => {
            calls++;
            return Response.json(receipt, { status });
          },
        },
      ),
    ).rejects.toThrow(message);
    expect(calls).toBe(1);
  }
});

test("reuses a committed custom publication receipt after moving its artifacts", async () => {
  const { scan, document, environment } = await fixture();
  const options = { findingsUrl: "http://synthetic.test" };
  let requests = 0;
  const dependencies = {
    environment,
    fetch: async () => {
      requests++;
      return Response.json(
        document.findings.map((finding) => finding.findingId),
      );
    },
  };
  const result = await publishScanToCustom(scan, options, dependencies);
  const moved = `${scan}-moved`;
  await rename(scan, moved);
  expect(await publishScanToCustom(moved, options, dependencies)).toEqual(
    result,
  );
  expect(requests).toBe(1);
});

test.each(["before-commit", "after-commit"] as const)(
  "preserves accepted custom uploads when receipt persistence fails %s",
  async (failure) => {
    const { scan, document, environment } = await fixture();
    const ids = document.findings.map(({ findingId }) => findingId);
    const receipt = {
      scanId: document.scanId,
      repositoryId: "target_sha256_example",
      findingIds: ids,
      findingCount: ids.length,
    };
    const keys: (string | null)[] = [];
    let workflowId = "";
    let failCompletion = true;
    const workbench: typeof runWorkbench = async (options, args, input) => {
      if (args[0] === "finding-workflow") {
        const request = JSON.parse(input!);
        workflowId = request.id;
        if (
          failCompletion &&
          request.action === "complete" &&
          request.stage === "publish"
        ) {
          failCompletion = false;
          if (failure === "after-commit")
            await runWorkbench(options, args, input);
          throw new Error("publication checkpoint unavailable");
        }
      }
      return await runWorkbench(options, args, input);
    };
    const dependencies = {
      environment,
      runWorkbench: workbench,
      fetch: async (_url: URL, init: RequestInit) => {
        keys.push(new Headers(init.headers).get("Idempotency-Key"));
        return Response.json(ids, { status: 201 });
      },
    };
    const options = { findingsUrl: "http://synthetic.test" };
    const result = await publishScanToCustom(scan, options, dependencies);
    expect(result).toEqual({
      ...receipt,
      warnings: [expect.stringContaining("publication checkpoint unavailable")],
    });
    expect(keys).toHaveLength(1);
    const workflow = new FindingWorkflow(workflowId, environment);
    const stage = (await workflow.get())!.stages.publish;
    expect(stage.status).toBe(
      failure === "before-commit" ? "running" : "completed",
    );
    expect(stage.error).toBeUndefined();

    expect(await publishScanToCustom(scan, options, dependencies)).toEqual(
      receipt,
    );
    expect(keys).toHaveLength(failure === "before-commit" ? 2 : 1);
    expect(new Set(keys).size).toBe(1);
    expect((await workflow.get())!.stages.publish.status).toBe("completed");
  },
);

test("explicit workflow IDs remain bound to their original artifact directory", async () => {
  const { scan, document, environment } = await fixture();
  let requests = 0;
  const options = {
    findingsUrl: "http://synthetic.test",
    workflowId: "named-publication",
  };
  const dependencies = {
    environment,
    fetch: async () => {
      requests++;
      return Response.json(document.findings.map(({ findingId }) => findingId));
    },
  };
  await publishScanToCustom(scan, options, dependencies);
  const moved = `${scan}-moved`;
  await rename(scan, moved);
  await expect(
    publishScanToCustom(moved, options, dependencies),
  ).rejects.toThrow("different scanDir");
  expect(requests).toBe(1);
});

test("rejects mismatched or changed sealed artifacts before publication, including dry-run", async () => {
  const { scan, source } = await fixture();
  const dependencies = {
    fetch: async () => {
      throw new Error("must not upload invalid artifacts");
    },
  };
  await expect(
    publishScanToCustom(
      scan,
      {
        findingsUrl: "http://synthetic.test",
        expectedScanId: "wrong-scan",
      },
      dependencies,
    ),
  ).rejects.toThrow("do not match selected scan");
  await writeFile(join(scan, "findings.json"), source + "\n");
  for (const dryRun of [false, true]) {
    await expect(
      publishScanToCustom(
        scan,
        {
          findingsUrl: "http://synthetic.test",
          dryRun,
        },
        dependencies,
      ),
    ).rejects.toThrow();
  }
});

test("recovers a lost import acknowledgement without repeating embeddings", async () => {
  const { scan, document, environment } = await fixture();
  const store = new SqliteFindingsStore(environment);
  await store.initialize();
  let embeddings = 0;
  const service = new FindingsService(store, {
    embed: async (findings) => {
      embeddings++;
      return findings.map(() => ({
        model: EMBEDDING_MODEL,
        vector: Array.from({ length: EMBEDDING_DIMENSIONS }, (_, index) =>
          index === 0 ? 1 : 0,
        ),
      }));
    },
  });
  let requests = 0;
  const dependencies = {
    environment,
    fetch: async (_url: URL, init: RequestInit) => {
      const payload = JSON.parse(String(init.body));
      const ids = await service.insert(
        payload.findings,
        payload.repositoryId,
        new Headers(init.headers).get("Idempotency-Key") ?? undefined,
      );
      if (++requests === 1) throw new Error("connection closed after commit");
      return Response.json(ids, { status: 201 });
    },
  };
  const options = { findingsUrl: "http://synthetic.test" };
  await expect(
    publishScanToCustom(scan, options, dependencies),
  ).rejects.toThrow("after commit");
  const moved = `${scan}-moved`;
  await rename(scan, moved);
  expect(
    (await publishScanToCustom(moved, options, dependencies)).findingIds,
  ).toEqual(document.findings.map((finding) => finding.findingId));
  expect(requests).toBe(2);
  expect(embeddings).toBe(1);
});
