import { readFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { expect, test } from "bun:test";
import type { JsonObject } from "../src/config.js";
import { CodexSecurityError, DeduplicationReviewError } from "../src/errors.js";
import type { CustomPublicationResult } from "../src/custom-publish.js";
import { publishScanToCustomInternal } from "../src/custom-publish.js";
import {
  deduplicateScanDirectoryInternal,
  deduplicateScanInternal,
  type DeduplicateScanResult,
} from "../src/deduplication/scan.js";
import type { DeduplicationReviewer } from "../src/deduplication/deduplication-reviewer.js";
import type { ScanManifest } from "../src/models.js";
import { FindingWorkflow } from "../src/finding-workflow.js";
import { runWorkbench } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { scriptedWorkbench } from "./support/workbench-fakes.js";
import { workflowFixture } from "./support/workflow-fixture.js";

type Step = Parameters<typeof scriptedWorkbench>[0][number];

test.each(["before-commit", "after-commit"])(
  "dedupe returns current publication recovery information outside its saved result (%s)",
  async (failure) => {
    await using fixture = await workflowFixture();
    const { scanDir, repository, environment, document } = fixture;
    const manifest = JSON.parse(
      await readFile(join(scanDir, "scan-manifest.json"), "utf8"),
    ) as ScanManifest;
    const id = "publication-recovery";
    const ids = document.findings.map((finding) => finding.findingId);
    const expected: DeduplicateScanResult = {
      scanId: document.scanId,
      uniqueFindingIds: ids,
      duplicateGroups: [],
      deduplicationStatus: "completed",
    };
    const publication = {
      scanId: document.scanId,
      repositoryId: manifest.scan.target.targetId,
      findingIds: ids,
      findingCount: ids.length,
      warnings: [expect.stringContaining("publication checkpoint unavailable")],
    };
    let failCompletion = true;
    let searches = 0;
    const keys: (string | null)[] = [];
    const execute = (args: string[], input?: string) =>
      runWorkbench(
        {
          environment,
          pluginRoot: PLUGIN_ROOT,
          python: Bun.which("python3") ?? Bun.which("python")!,
        },
        args,
        input,
      );
    const dependencies = {
      environment,
      runWorkbench: async (args: string[], input?: string) => {
        const request = JSON.parse(input!);
        if (
          failCompletion &&
          request.action === "complete" &&
          request.stage === "publish"
        ) {
          failCompletion = false;
          if (failure === "after-commit") await execute(args, input);
          throw new Error("publication checkpoint unavailable");
        }
        return execute(args, input);
      },
      fetch: async (url: URL, init: RequestInit) => {
        if (url.pathname === "/v1/bulk/findings") {
          keys.push(new Headers(init.headers).get("Idempotency-Key"));
          return Response.json(ids, { status: 201 });
        }
        expect(url.pathname).toEndWith("/potential-duplicates");
        searches++;
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
    };
    const options = {
      workflowId: id,
      findingsUrl: "http://synthetic.test",
      repository,
    };
    const first = await deduplicateScanDirectoryInternal(
      scanDir,
      options,
      dependencies,
    );
    expect(first).toEqual({ ...expected, publication });
    expect(keys).toHaveLength(1);
    expect(searches).toBe(ids.length);
    const workflow = new FindingWorkflow(id, environment);
    const state = (await workflow.get())!;
    expect(state.stages.publish.status).toBe(
      failure === "before-commit" ? "running" : "completed",
    );
    expect(state.stages.dedupe).toMatchObject({
      status: "completed",
      result: expected,
    });
    expect(state.stages.dedupe.result).toEqual(expected);
    if (failure === "before-commit") {
      failCompletion = true;
      expect(
        await deduplicateScanDirectoryInternal(scanDir, options, dependencies),
      ).toEqual({ ...expected, publication });
      expect(keys).toHaveLength(2);
      expect(searches).toBe(ids.length);
      expect((await workflow.get())!.stages.dedupe.result).toEqual(expected);
    }
    for (let retry = 0; retry < 2; retry++) {
      expect(
        await deduplicateScanDirectoryInternal(scanDir, options, dependencies),
      ).toEqual(expected);
      expect(keys).toHaveLength(failure === "before-commit" ? 3 : 1);
      expect(searches).toBe(ids.length);
    }
    expect(new Set(keys).size).toBe(1);
    expect((await workflow.get())!.stages.publish.status).toBe("completed");
  },
);

test.each(["native", "transport", "cancellation"])(
  "dedupe retains publication recovery when a later review fails (%s)",
  async (failure) => {
    await using fixture = await workflowFixture();
    const { scanDir, repository, environment, document } = fixture;
    const id = "publication-review-failure";
    const controller = new AbortController();
    const original =
      failure === "native"
        ? new DeduplicationReviewError({
            stage: "screening",
            model: "synthetic-model",
            category: "transport",
            attempts: 1,
            reason: "Review disconnected",
          })
        : failure === "transport"
          ? new Error("Review disconnected")
          : "SIGINT";
    let failCompletion = true;
    let failReview = true;
    let uploads = 0;
    let reviews = 0;
    const observed: CustomPublicationResult[] = [];
    const execute = (args: string[], input?: string) =>
      runWorkbench(
        {
          environment,
          pluginRoot: PLUGIN_ROOT,
          python: Bun.which("python3") ?? Bun.which("python")!,
        },
        args,
        input,
      );
    const dependencies = {
      environment,
      runWorkbench: async (args: string[], input?: string) => {
        const request = JSON.parse(input!);
        const result = await execute(args, input);
        if (
          failCompletion &&
          request.action === "complete" &&
          request.stage === "publish"
        ) {
          failCompletion = false;
          throw new Error("publication checkpoint unavailable");
        }
        return result;
      },
      onPublication: (receipt: CustomPublicationResult) => {
        observed.push(receipt);
        // Both kinds of observer failure must leave the actual review failure intact.
        if (failure === "native") throw new Error("Observer unavailable");
        return Promise.reject(new Error("Observer unavailable"));
      },
      fetch: async (url: URL) => {
        if (url.pathname === "/v1/bulk/findings") {
          uploads++;
          return Response.json(
            document.findings.map((finding) => finding.findingId),
            { status: 201 },
          );
        }
        expect(url.pathname).toEndWith("/potential-duplicates");
        return Response.json({
          finding: document.findings[0],
          potentialDuplicates: [
            { ...document.findings[0], findingId: `csf_${"f".repeat(24)}` },
          ],
        });
      },
      reviewer: {
        async screen() {
          reviews++;
          if (failReview) {
            failReview = false;
            if (failure === "cancellation") controller.abort(original);
            throw original;
          }
          return {
            decisions: {
              "pair-1": {
                decision: "DISTINCT" as const,
                rationale: "Different cause",
              },
            },
          };
        },
        async reviewPair(): Promise<never> {
          throw new Error("No nominated pair");
        },
      },
    };
    const options = {
      workflowId: id,
      findingsUrl: "http://synthetic.test",
      repository,
    };
    let caught: unknown;
    try {
      await deduplicateScanDirectoryInternal(
        scanDir,
        { ...options, signal: controller.signal },
        dependencies,
      );
    } catch (error) {
      caught = error;
    }
    if (failure === "cancellation") expect(caught).toBe(original);
    else {
      expect(caught).toBeInstanceOf(CodexSecurityError);
      if (failure === "native") {
        expect(caught).toBe(original);
        expect((caught as DeduplicationReviewError).metadata).toEqual(
          (original as DeduplicationReviewError).metadata,
        );
      } else expect((caught as Error).cause).toBe(original);
      expect((caught as CodexSecurityError).publication).toEqual(observed[0]);
    }
    expect(observed).toHaveLength(1);
    expect(observed[0]).toMatchObject({
      scanId: document.scanId,
      findingIds: document.findings.map((finding) => finding.findingId),
      warnings: [expect.stringContaining("publication checkpoint unavailable")],
    });
    const workflow = new FindingWorkflow(id, environment);
    expect((await workflow.get())!.stages.dedupe.status).toBe("failed");
    const corrected = await deduplicateScanDirectoryInternal(
      scanDir,
      options,
      dependencies,
    );
    expect(corrected.publication).toBeUndefined();
    expect(corrected.deduplicationStatus).toBe("completed");
    expect((await workflow.get())!.stages.dedupe.result).toEqual(corrected);
    expect(uploads).toBe(1);
    const completedReviews = reviews;
    expect(
      await deduplicateScanDirectoryInternal(scanDir, options, dependencies),
    ).toEqual(corrected);
    expect(reviews).toBe(completedReviews);
    expect(observed).toHaveLength(1);
  },
);

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
      response: { workflow: {} },
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
      response: { workflow: {} },
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
    {
      request: {
        id,
        action: "get-candidates",
        findingId: document.findings[0]!.findingId,
      },
      response: { candidatesJson: null },
    },
    {
      request: {
        id,
        action: "save-candidates",
        findingId: document.findings[0]!.findingId,
        candidates: { finding: document.findings[0], potentialDuplicates: [] },
      },
      response: {
        candidatesJson: JSON.stringify({
          finding: document.findings[0],
          potentialDuplicates: [],
        }),
      },
    },
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
      {
        request: {
          id,
          action: "get-candidates",
          findingId: originals[0]!.findingId,
        },
        response: { candidatesJson: null },
      },
      {
        request: {
          id,
          action: "save-candidates",
          findingId: originals[0]!.findingId,
          candidates: {
            finding: originals[0],
            potentialDuplicates: [originals[1]],
          },
        },
        response: {
          candidatesJson: JSON.stringify({
            finding: originals[0],
            potentialDuplicates: [originals[1]],
          }),
        },
      },
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
            {
              request: { id, action: "get" },
              response: {
                workflow: { stages: { dedupe: { status: "running" } } },
              },
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
      {
        request: { id, action: "dedupe-progress" },
        response: { progress: { candidateCount: 1, reviewCount: 0 } },
      },
      {
        request: {
          id,
          action: "fail",
          stage: "dedupe",
          error: expect.any(String),
          details: {
            recovery: {
              operationId: id,
              scanId: document.scanId,
              phase: "groups",
              candidateCount: 1,
              reviewCount: 0,
            },
          },
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
