import { expect, test } from "bun:test";
import { readDependencyCheckOutput } from "../src/dependency-reachability.js";
import { renderDependencyReport } from "../src/dependency-report-renderer.js";
import { createDependencyProgress } from "../src/dependency-progress.js";
import { createDependencyReportSubmission } from "../src/dependency-report-submission.js";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { produceRepresentativeReport } from "./support/dependency-report-producer.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

test("reviewed service, variant, open question, inspection and coverage evidence survive JSON save/load and rendering", async () => {
  await using repo = await scopedTemporaryDirectory("reviewed-report-");
  const { result, report } = await produceRepresentativeReport(repo.path);
  expect(result.accepted).toBe(true);
  expect(report).toBeDefined();
  const parsed = readDependencyCheckOutput(JSON.parse(JSON.stringify(report)));
  if (!("cve" in parsed)) throw new Error("Expected CVE report");
  expect(parsed.uses).toHaveLength(3);
  expect(parsed.coverage).toHaveLength(1);
  expect(parsed.uses[0]!.services?.[0]).toMatchObject({
    id: "catalog:cedar",
    name: "Cedar",
    source: "catalog/service_for_source#cedar",
  });
  const mapping = parsed.uses[0]!.services![0]!.evidence[0]!;
  expect(mapping).toMatchObject({
    kind: "receipt",
    selection: { textBlock: null, record: ["rows", 0] },
  });
  expect(parsed.uses[0]!.decidingEvidence).toContainEqual(mapping);
  expect(parsed.uses[0]).toMatchObject({
    inputSource: {
      exposure: "internet",
      endpoint: "https://cedar.example.invalid/documents",
    },
    runtimeContext: {
      launch: { basis: "configured" },
      mitigation: { state: "unknown" },
    },
    tags: [{ name: "documents" }],
    place: { workload: "cedar-web-stable" },
  });
  expect(parsed.uses[0]!.decidingEvidence).toContainEqual(
    parsed.uses[0]!.inputSource!.evidence[0]!,
  );
  expect(parsed.uses[1]).toMatchObject({
    inputSource: { exposure: "not_internet" },
    runtimeContext: { mitigation: { state: "enabled", basis: "configured" } },
  });
  expect(parsed.uses[2]!.inputSource).toBeUndefined();
  expect(parsed.coverage![0]).toMatchObject({
    location: "POST /parse → parser.open",
    handoff: { verified: "Submitted document bytes reach parser.open." },
    services: [{ id: "catalog:spruce" }],
    place: {
      workload: "spruce-parser-stable",
      deploymentBasis: "observed",
      platform: "linux/amd64",
    },
    inspections: [
      { outcome: "succeeded", target: { workload: "spruce-parser-stable" } },
    ],
    inputSource: {
      exposure: "internet",
      endpoint: "https://spruce.example.invalid/parse",
    },
    runtimeContext: { launch: { basis: "observed" } },
  });
  expect(Array.isArray(parsed.coverage![0]!.decidingEvidence)).toBe(true);
  expect(parsed.uses[0]!.inspections?.[0]).toMatchObject({
    outcome: "denied",
    target: { platform: "linux/amd64" },
  });
  expect(parsed.uses[1]!.place).toMatchObject({
    variant: "canary",
    platform: "linux/arm64",
  });
  const html = renderDependencyReport(parsed);
  expect(html).toContain("Cedar");
  expect(html).toContain("Spruce");
  expect(html).toContain("Requires more information");
  expect(html).toContain("decodeFrame(document)");
  expect(html).toContain("data-highlighted");
  expect(html).toContain("Access denied");
  expect(html).toContain("Publisher".toLowerCase());
  expect(html).toContain('id="coverage-1-1"');
  expect(html).toContain('data-exposure="internet"');
  expect(html).toContain('href="https://cedar.example.invalid/documents"');
  expect(html).toContain("codec-server --mode=default");
  expect(html).toContain("Services → advisories");
});
test("the reviewer rejects an internet-exposure claim for a different endpoint", async () => {
  await using repo = await scopedTemporaryDirectory(
    "reviewed-report-endpoint-",
  );
  const { result, report } = await produceRepresentativeReport(
    repo.path,
    false,
    true,
  );
  expect(result.accepted).toBe(false);
  expect(result.feedback).toContain("stable");
  expect(report).toBeUndefined();
});
test("a reviewer cannot accept a structured service association without citing its deciding original", async () => {
  await using repo = await scopedTemporaryDirectory("reviewed-report-reject-");
  const { result, report } = await produceRepresentativeReport(repo.path, true);
  expect(result.accepted).toBe(false);
  expect(result.feedback).toContain("structured finding reference");
  expect(report).toBeUndefined();
});

test("human progress labels an unknown use without changing the event enum", () => {
  const writes: string[] = [];
  const progress = createDependencyProgress({
    output: { write: (t) => writes.push(t) },
    now: () => 0,
    interactive: false,
    color: false,
  });
  const event = {
    type: "reviewed" as const,
    subject: "CVE-2099-44001",
    location: "src/handler.ts:3",
    locationKind: "caller" as const,
    verdict: "unknown" as const,
    component: "sample-codec",
    reason: "The effective setting is unverified.",
  };
  try {
    progress.emit(event);
    expect(writes.join("")).toContain("REQUIRES MORE INFORMATION");
    expect(event.verdict).toBe("unknown");
  } finally {
    progress.close();
  }
});

test("a failed catalog receipt cannot establish a service association", async () => {
  await using repo = await scopedTemporaryDirectory("failed-catalog-");
  await writeFile(join(repo.path, "worker.ts"), "decode(input);\n");
  const state = createDependencyReportSubmission({
    repository: repo.path,
    advisory: { cve: "CVE-2099-44001", advisories: [] },
    review: async () => {
      throw new Error("A failed catalog mapping must never reach review");
    },
  });
  try {
    const id = state.recordInventory(
      "catalog",
      { error: "access denied" },
      { tool: "service_for_source", outcome: "failed" },
    )!;
    const entry = state
      .readStatus({ inventoryReceipts: true })
      .inventoryReceipts!.find((r) => r.id === id)!;
    const queued = await state.queue({
      items: [
        {
          id: "worker",
          kind: "use",
          candidateIds: [],
          receiptIds: [id],
          use: {
            location: "worker.ts:1",
            component: "sample-codec",
            version: null,
            verdict: "unknown",
            deployment: "unknown",
            reason: "The selected copy is unverified.",
            evidence: [
              { path: "worker.ts", startLine: 1, endLine: 1, supports: [] },
            ],
            observations: [
              { server: "catalog", record: "lookup denied", supports: [] },
            ],
            services: [
              {
                id: "svc:cedar",
                name: "Cedar",
                source: "catalog/service_for_source",
                evidence: [
                  {
                    kind: "receipt",
                    receiptId: id,
                    originalPayloadSha256: entry.originalPayloadSha256,
                  },
                ],
              },
            ],
          },
        },
      ],
    });
    expect(queued.queued).toBe(false);
    expect(queued.feedback).toContain("not bound");
  } finally {
    await state.close();
  }
});
