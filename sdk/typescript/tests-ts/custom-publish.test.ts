import { chmod, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { setImmediate as nextTurn } from "node:timers/promises";
import { afterEach, expect, test, mock } from "bun:test";
import { publishScanToCustomInternal as publishScanToCustom } from "../src/custom-publish.js";
import type { FindingsDocument } from "../src/models.js";
import { copyCompletedScanFixture } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { rejecting } from "./support/errors.js";
import type { PublicationTelemetry } from "../src/publication-telemetry.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "custom-publish-",
  false,
);
afterEach(cleanup);

async function fixture() {
  const scan = await temporaryDirectory();
  await copyCompletedScanFixture(scan);
  if (process.platform !== "win32") await chmod(scan, 0o700);
  const source = await readFile(join(scan, "findings.json"), "utf8");
  const document = JSON.parse(source) as FindingsDocument;
  return { scan, source, document };
}

test("publishes complete sealed findings with their repository ID to a custom base URL", async () => {
  const { scan, source, document } = await fixture();
  const controller = new AbortController();
  const ids = document.findings.map((finding) => finding.findingId);
  const observations: PublicationTelemetry[] = [];
  const fetchMock = mock(async (url: URL, options: RequestInit) => {
    expect(String(url)).toBe("http://synthetic.test/service/v1/bulk/findings");
    expect(options).toEqual({
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        findings: document.findings,
        repositoryId: "target_sha256_example",
      }),
      signal: controller.signal,
    });
    return Response.json(ids, { status: 201 });
  });
  const result = await publishScanToCustom(
    scan,
    {
      findingsUrl: "http://synthetic.test/service",
      expectedScanId: document.scanId,
      signal: controller.signal,
      onTelemetry: (event) => observations.push(event),
    },
    {
      fetch: fetchMock,
    },
  );
  expect(result).toEqual({
    scanId: document.scanId,
    repositoryId: "target_sha256_example",
    findingIds: ids,
    findingCount: ids.length,
    telemetry: expect.objectContaining({
      destination: "custom",
      outcome: "completed",
      attempted: true,
      counts: {
        selected: ids.length,
        submitted: ids.length,
        created: null,
        reused: null,
        acknowledged: ids.length,
        failed: 0,
      },
    }),
  });
  expect(observations).toEqual([result.telemetry!]);
  expect(Object.keys(result.telemetry!).sort()).toEqual([
    "attemptId",
    "attempted",
    "counts",
    "destination",
    "durationMs",
    "observedAt",
    "outcome",
    "schemaVersion",
    "startedAt",
  ]);
  expect(fetchMock).toHaveBeenCalledTimes(1);
  expect(await readFile(join(scan, "findings.json"), "utf8")).toBe(source);
});

test.each(["http://localhost:3000", "synthetic-invalid-url"])(
  "dry-run previews the complete upload without HTTP or credentials (%s)",
  async (findingsUrl) => {
    const { scan, document } = await fixture();
    const result = await publishScanToCustom(
      scan,
      { findingsUrl, dryRun: true },
      {
        fetch: rejecting("dry-run must not send a request"),
      },
    );
    expect(result).toEqual({
      scanId: document.scanId,
      repositoryId: "target_sha256_example",
      findingIds: document.findings.map((finding) => finding.findingId),
      findingCount: document.findings.length,
      dryRun: true,
      findings: document.findings,
      telemetry: expect.objectContaining({
        destination: "custom",
        outcome: "preview",
        attempted: false,
        counts: {
          selected: document.findings.length,
          submitted: 0,
          created: 0,
          reused: 0,
          acknowledged: 0,
          failed: 0,
        },
      }),
    });
  },
);

test("invalid publication URLs report a local failure before any submission", async () => {
  const { scan, document } = await fixture();
  const observations: PublicationTelemetry[] = [];
  const fetchMock = mock(rejecting("Invalid URL must not send a request"));
  await expect(
    publishScanToCustom(
      scan,
      {
        findingsUrl: "synthetic-invalid-url",
        onTelemetry: (event) => observations.push(event),
      },
      { fetch: fetchMock },
    ),
  ).rejects.toThrow(TypeError);
  expect(fetchMock).not.toHaveBeenCalled();
  expect(observations).toEqual([
    expect.objectContaining({
      outcome: "failed",
      attempted: false,
      counts: {
        selected: document.findings.length,
        submitted: 0,
        created: 0,
        reused: 0,
        acknowledged: 0,
        failed: 0,
      },
    }),
  ]);
});

test("does not retry failed uploads or report incomplete receipts as successful", async () => {
  const { scan } = await fixture();
  for (const [receipt, status, message] of [
    [{}, 503, "HTTP 503"],
    [{}, 201, "did not acknowledge all"],
    [[], 201, "did not acknowledge all"],
    [["wrong-finding"], 201, "did not acknowledge all"],
  ] as const) {
    const fetchMock = mock(async () => {
      return Response.json(receipt, { status });
    });
    const observed: PublicationTelemetry[] = [];
    await expect(
      publishScanToCustom(
        scan,
        {
          findingsUrl: "http://synthetic.test",
          onTelemetry: (event) => observed.push(event),
        },
        {
          fetch: fetchMock,
        },
      ),
    ).rejects.toThrow(message);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(observed).toEqual([
      expect.objectContaining({
        outcome: "indeterminate",
        attempted: true,
        counts: expect.objectContaining({
          acknowledged: null,
          created: null,
          failed: null,
        }),
      }),
    ]);
  }
});

test("keeps an aborted upload outcome indeterminate after submission", async () => {
  const { scan } = await fixture();
  const controller = new AbortController();
  const reason = new Error("Synthetic upload cancellation");
  const observed: PublicationTelemetry[] = [];
  const fetchMock = mock(async () => {
    controller.abort(reason);
    throw reason;
  });
  await expect(
    publishScanToCustom(
      scan,
      {
        findingsUrl: "http://synthetic.test",
        signal: controller.signal,
        onTelemetry: (event) => observed.push(event),
      },
      { fetch: fetchMock },
    ),
  ).rejects.toBe(reason);
  expect(fetchMock).toHaveBeenCalledTimes(1);
  expect(observed).toEqual([
    expect.objectContaining({
      outcome: "indeterminate",
      attempted: true,
      counts: expect.objectContaining({ acknowledged: null, failed: null }),
    }),
  ]);
});

test.each(["failed", "canceled"] as const)(
  "observes custom publication %s before preparation without replacing the error",
  async (outcome) => {
    const controller = new AbortController();
    const reason = new Error("Synthetic cancellation");
    if (outcome === "canceled") controller.abort(reason);
    const observed: PublicationTelemetry[] = [];
    const result = publishScanToCustom("/synthetic/missing/scan", {
      findingsUrl: "http://synthetic.test",
      signal: controller.signal,
      onTelemetry: (event) => {
        observed.push(event);
        throw new Error("Synthetic observer failure");
      },
    });
    await expect(result).rejects.toThrow();
    expect(observed).toEqual([
      expect.objectContaining({
        outcome,
        attempted: false,
        counts: expect.objectContaining({ selected: null, submitted: 0 }),
      }),
    ]);
  },
);

test.each(["throw", "reject", "pending"] as const)(
  "publication telemetry observers do not change preview results (%s)",
  async (behavior) => {
    const { scan } = await fixture();
    const observer = mock(() => {
      if (behavior === "throw") throw new Error("Synthetic observer failure");
      if (behavior === "reject")
        return Promise.reject(new Error("Synthetic observer rejection"));
      return new Promise<void>(() => {});
    });
    const result = await publishScanToCustom(scan, {
      findingsUrl: "http://synthetic.test",
      dryRun: true,
      onTelemetry: observer,
    });
    await nextTurn();
    expect(result.telemetry?.outcome).toBe("preview");
    expect(observer).toHaveBeenCalledTimes(1);
  },
);

test("rejects mismatched or changed sealed artifacts before publication, including dry-run", async () => {
  const { scan, source } = await fixture();
  const dependencies = {
    fetch: rejecting("must not upload invalid artifacts"),
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
