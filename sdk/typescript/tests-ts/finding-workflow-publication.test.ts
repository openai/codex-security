import { readFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { expect, test } from "bun:test";
import type { JsonObject } from "../src/config.js";
import { publishScanToCustomInternal } from "../src/custom-publish.js";
import {
  deduplicateScanDirectoryInternal,
  deduplicateScanInternal,
  type DeduplicateScanResult,
} from "../src/deduplication/scan.js";
import type { DeduplicationReviewer } from "../src/deduplication/deduplication-reviewer.js";
import type { ScanManifest } from "../src/models.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { scriptedWorkbench } from "./support/workbench-fakes.js";
import { workflowFixture } from "./support/workflow-fixture.js";

type Step = Parameters<typeof scriptedWorkbench>[0][number];

function publicationBinding(
  id: string,
  scanId: string,
  scanDir: string,
): Step[] {
  return [
    {
      request: {
        id,
        action: "bind",
        binding: {
          scanId,
          scanDir,
          artifactDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
          destination: "http://synthetic.test/",
        },
      },
    },
    { request: { id, action: "complete", stage: "scan", result: null } },
  ];
}

test("deduplicates an external scan through its bound workflow without reading scan history", async () => {
  await using fixture = await workflowFixture();
  const { scanDir, repository, environment, document } = fixture;
  const id = "external-directory";
  const options = {
    workflowId: id,
    findingsUrl: "http://synthetic.test/service",
    repository: relative(process.cwd(), repository),
    expectedScanId: document.scanId,
    allRepositories: true,
  };
  const result: DeduplicateScanResult = {
    scanId: document.scanId,
    uniqueFindingIds: document.findings.map((finding) => finding.findingId),
    duplicateGroups: [],
    deduplicationStatus: "completed",
  };
  const source = {
    repository,
    revision: "synthetic-revision",
    refsDigest: "synthetic-refs",
    content: "synthetic-content",
  };
  const binding = {
    scanId: document.scanId,
    scanDir,
    artifactDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
    destination: "http://synthetic.test/service/",
  };
  const workbench = scriptedWorkbench([
    {
      request: {
        id,
        action: "bind",
        binding: {
          repositoryPath: repository,
          ...binding,
          scope: { allRepositories: true },
        },
      },
    },
    { request: { id, action: "complete", stage: "scan", result: null } },
    { request: { id, action: "bind", binding } },
    { request: { id, action: "complete", stage: "scan", result: null } },
    {
      request: { id, action: "begin", stage: "publish" },
      response: {
        workflow: {
          stages: {
            publish: {
              status: "completed",
              result: {
                findingIds: document.findings.map(
                  (finding) => finding.findingId,
                ),
              },
            },
          },
        },
      },
    },
    {
      request: { id, action: "begin", stage: "dedupe" },
      response: { workflow: { stages: { dedupe: { status: "running" } } } },
    },
    {
      request: { id, action: "get" },
      response: { workflow: { stages: { dedupe: { status: "running" } } } },
    },
    { request: { id, action: "source", repository }, response: { source } },
    { request: { id, action: "source", repository }, response: { source } },
    {
      request: {
        id,
        action: "prepare-dedupe",
        stage: "dedupe",
        result,
        pendingWrite: { groups: [] },
      },
    },
    { request: { id, action: "complete", stage: "dedupe", result } },
  ]);
  const requests: string[] = [];
  expect(
    await deduplicateScanDirectoryInternal(scanDir, options, {
      environment,
      runWorkbench: (args, input) =>
        workbench.run(
          { environment, pluginRoot: PLUGIN_ROOT, python: "unused" },
          args,
          input,
        ),
      fetch: async (url, init) => {
        requests.push(String(url));
        expect(init.method).toBeUndefined();
        return Response.json({
          finding: document.findings[0],
          potentialDuplicates: [],
        });
      },
      reviewer: {
        async screen() {
          throw new Error("No review for an empty neighborhood");
        },
        async reviewPair() {
          throw new Error("No pair to review");
        },
      },
    }),
  ).toEqual(result);
  expect(requests).toEqual([
    `http://synthetic.test/service/v1/finding/${document.findings[0]!.findingId}/potential-duplicates?allRepositories=true`,
  ]);
  workbench.assertDone();
});

test("failed publication records its error, dry-run does not advance it, and retry records the receipt", async () => {
  await using fixture = await workflowFixture();
  const { scanDir, environment, document } = fixture;
  const manifest = JSON.parse(
    await readFile(join(scanDir, "scan-manifest.json"), "utf8"),
  ) as ScanManifest;
  const id = "publication-retry";
  const options = { workflowId: id, findingsUrl: "http://synthetic.test" };
  const result = {
    scanId: document.scanId,
    repositoryId: manifest.scan.target.targetId,
    findingIds: document.findings.map((finding) => finding.findingId),
    findingCount: document.findings.length,
  };
  const begin: Step = {
    request: { id, action: "begin", stage: "publish" },
    response: { workflow: { stages: { publish: { status: "running" } } } },
  };
  const workbench = scriptedWorkbench([
    ...publicationBinding(id, document.scanId, scanDir),
    begin,
    {
      request: {
        id,
        action: "fail",
        stage: "publish",
        error: expect.stringContaining("HTTP 503"),
      },
    },
    ...publicationBinding(id, document.scanId, scanDir),
    begin,
    { request: { id, action: "complete", stage: "publish", result } },
  ]);
  await expect(
    publishScanToCustomInternal(scanDir, options, {
      environment,
      runWorkbench: workbench.run,
      fetch: async () => new Response("", { status: 503 }),
    }),
  ).rejects.toThrow("HTTP 503");
  const dryRunWorkbench = scriptedWorkbench([]);
  expect(
    await publishScanToCustomInternal(
      scanDir,
      { ...options, dryRun: true },
      {
        environment,
        runWorkbench: dryRunWorkbench.run,
        fetch: async () => {
          throw new Error("Dry-run must not publish");
        },
      },
    ),
  ).toEqual({ ...result, dryRun: true, findings: document.findings });
  dryRunWorkbench.assertDone();
  expect(
    await publishScanToCustomInternal(scanDir, options, {
      environment,
      runWorkbench: workbench.run,
      fetch: async () => Response.json(result.findingIds),
    }),
  ).toEqual(result);
  workbench.assertDone();
});

test.each(["before-post", "before-write", "lost-ack", "lost-completion"])(
  "replays the exact saved group payload after %s without repeating reviews",
  async (failure) => {
    await using fixture = await workflowFixture();
    const { scanDir, repository, environment, document } = fixture;
    const originals = [
      document.findings[0]!,
      { ...document.findings[0]!, findingId: `csf_${"f".repeat(24)}` },
    ];
    const id = `write-${failure}`;
    const options = { workflowId: id, findingsUrl: "http://synthetic.test" };
    const groups = [originals.map((finding) => finding.findingId)];
    const result: DeduplicateScanResult = {
      scanId: document.scanId,
      uniqueFindingIds: [originals[0]!.findingId],
      duplicateGroups: groups,
      deduplicationStatus: "completed",
    };
    const source = {
      repository,
      revision: "synthetic-revision",
      refsDigest: "synthetic-refs",
      content: "synthetic-content",
    };
    const prefix: Step[] = [
      ...publicationBinding(id, document.scanId, scanDir),
      ...publicationBinding(id, document.scanId, scanDir),
      {
        request: { id, action: "begin", stage: "publish" },
        response: {
          workflow: {
            stages: {
              publish: {
                status: "completed",
                result: { findingIds: [originals[0]!.findingId] },
              },
            },
          },
        },
      },
      {
        request: { id, action: "begin", stage: "dedupe" },
        response: { workflow: { stages: { dedupe: { status: "running" } } } },
      },
    ];
    let prepared: JsonObject | undefined;
    const complete: Step = {
      request: { id, action: "complete", stage: "dedupe", result },
    };
    const workbench = scriptedWorkbench([
      ...prefix,
      {
        request: { id, action: "get" },
        response: { workflow: { stages: { dedupe: { status: "running" } } } },
      },
      { request: { id, action: "source", repository }, response: { source } },
      { request: { id, action: "source", repository }, response: { source } },
      {
        request: {
          id,
          action: "prepare-dedupe",
          stage: "dedupe",
          result,
          pendingWrite: { groups },
        },
        response(payload) {
          prepared = payload;
          if (failure === "before-post")
            throw new Error("Synthetic stop before posting");
          return {};
        },
      },
      ...(failure === "lost-completion"
        ? [
            {
              ...complete,
              error: new Error("Synthetic completion receipt failure"),
            },
          ]
        : []),
      {
        request: {
          id,
          action: "fail",
          stage: "dedupe",
          error: expect.any(String),
        },
      },
      ...prefix,
      {
        request: { id, action: "get" },
        response: {
          workflow: {
            stages: {
              dedupe: {
                status: "running",
                result,
                pendingWrite: { groups },
              },
            },
          },
        },
      },
      complete,
    ]);
    const history = async (args: readonly string[], input?: string) => {
      if (args[0] === "get-scan") {
        expect(args).toEqual(["get-scan", "--scan-id", document.scanId]);
        return {
          scan: {
            scanId: document.scanId,
            scanDir,
            targetPath: repository,
            progress: { status: "complete" },
          },
        };
      }
      return await workbench.run(
        { environment, pluginRoot: PLUGIN_ROOT, python: "unused" },
        args,
        input,
      );
    };
    let reviews = 0;
    const screeningDecision = {
      decision: "SAME" as const,
      rationale: "One correction covers both findings.",
    };
    const decision = {
      ...screeningDecision,
      canonicalFindingId: originals[0]!.findingId,
      mergedFinding: originals[0]!,
    };
    const reviewer: DeduplicationReviewer = {
      async screen(findings) {
        reviews++;
        expect(findings).toEqual(originals);
        return {
          decisions: { "pair-1": { ...screeningDecision } },
        };
      },
      async reviewPair(findings) {
        reviews++;
        expect(findings).toEqual(originals);
        return decision;
      },
    };
    const bodies: string[] = [];
    let lookups = 0;
    const fetch = async (url: URL, init: RequestInit) => {
      if (url.pathname.endsWith("/potential-duplicates")) {
        lookups++;
        return Response.json({
          finding: originals[0],
          potentialDuplicates: [originals[1]],
        });
      }
      expect(url.pathname).toBe("/v1/dedupe-groups");
      expect(prepared).toMatchObject({
        result,
        pendingWrite: JSON.parse(init.body as string),
      });
      bodies.push(init.body as string);
      if (bodies.length === 1 && failure === "before-write")
        return new Response("", { status: 503 });
      if (bodies.length === 1 && failure === "lost-ack")
        return new Response("incomplete acknowledgement", { status: 201 });
      return Response.json([]);
    };
    const dependencies = {
      environment,
      runWorkbench: history,
      reviewer,
      fetch,
    };
    await expect(
      deduplicateScanInternal(document.scanId, options, dependencies),
    ).rejects.toThrow();
    expect(
      await deduplicateScanInternal(document.scanId, options, dependencies),
    ).toEqual(result);
    expect(bodies).toHaveLength(failure === "before-post" ? 1 : 2);
    expect(new Set(bodies).size).toBe(1);
    expect(reviews).toBe(2);
    expect(lookups).toBe(1);
    workbench.assertDone();
  },
);
