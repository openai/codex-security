import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createDependencyReportSubmission } from "../../src/dependency-report-submission.js";
import { resolveDependencyServices } from "../../src/dependency-service-catalog.js";
import type {
  DependencyReviewReference,
  DependencyUse,
} from "../../src/dependency-reachability.js";
import { place } from "./dependency-report-fixtures.js";

type LookupRow = {
  id?: string;
  name?: string;
  sourcePath?: string;
  workload?: string;
  platformManifest?: string;
  endpoint?: string;
  exposure?: string;
  launchCommand?: string;
  mitigation?: string;
  containerUrl?: string;
  tags?: string[];
};
type ReviewPacket = {
  items: ({
    id: string;
    revision: number;
    hash: string;
    excerptIds: string[];
    receiptIds: string[];
  } & (
    | {
        kind: "use";
        use: Pick<
          DependencyUse,
          "services" | "inputSource" | "runtimeContext" | "tags" | "place"
        >;
      }
    | {
        kind: "unresolved" | "dismissed";
        services?: { id: string; name: string; source: string }[];
        place?: { workload?: string; platformManifest?: string };
        inputSource?: DependencyUse["inputSource"];
        runtimeContext?: DependencyUse["runtimeContext"];
        tags?: DependencyUse["tags"];
      }
  ))[];
  receipts: Record<
    string,
    {
      result?: LookupRow & { structuredContent?: LookupRow };
    }
  >;
};

/** Synthetic source and inventory, passed through the actual queue/reviewer/finalizer. */
export async function produceRepresentativeReport(
  repository: string,
  omitServiceReviewEvidence = false,
  mismatchedEndpoint = false,
) {
  await mkdir(join(repository, "src"), { recursive: true });
  await writeFile(
    join(repository, "src", "handler.ts"),
    [
      "import { decodeFrame } from 'sample-codec';",
      "export function upload(document: Uint8Array) {",
      "  const value = decodeFrame(document);",
      "  return authenticate(value);",
      "}",
      "export function canary(document: Uint8Array) {",
      "  if (!safeMode(document)) return;",
      "  return decodeFrame(document);",
      "}",
      "export function parse(document: Uint8Array) { return parser.open(document); }",
      "export function shared(document: Uint8Array) { return decodeFrame(document); }",
      "",
    ].join("\n"),
  );
  const cve = "CVE-2099-44001",
    advisoryUrl = "https://example.invalid/advisories/" + cve;
  const state = createDependencyReportSubmission({
    repository,
    advisory: { cve, advisories: [] },
    callerScope: "Assess the synthetic Cedar and Spruce document services.",
    review: async (prompt) => {
      const packet = JSON.parse(
        prompt.slice(prompt.lastIndexOf("\n") + 1),
      ) as ReviewPacket;
      return JSON.stringify({
        items: packet.items.map((item) => {
          const services =
            item.kind === "use" ? item.use.services : item.services;
          const mapped = (services ?? []).every((s) =>
            item.receiptIds.some((id) => {
              const row = packet.receipts[id]?.result;
              return (
                row?.id !== undefined &&
                s.id === `catalog:${row.id}` &&
                s.name === row.name &&
                s.source === `catalog/service_for_source#${row.id}` &&
                row.sourcePath === "src/handler.ts"
              );
            }),
          );
          const matchedWorkload =
            item.kind !== "unresolved" ||
            item.receiptIds.some((id) => {
              const row = packet.receipts[id]?.result;
              return (
                row?.workload === item.place?.workload &&
                row?.platformManifest === item.place?.platformManifest &&
                row?.workload !== undefined
              );
            });
          const facts = item.kind === "use" ? item.use : item;
          const rows = item.receiptIds.map((id) => {
            const value = packet.receipts[id]?.result;
            return value?.structuredContent ?? value;
          });
          const scoped = rows.filter(
            (row) => row?.workload && row.workload === facts.place?.workload,
          );
          const inputSource = facts.inputSource;
          const matchedSource =
            !inputSource ||
            scoped.some(
              (row) =>
                row !== undefined &&
                row.endpoint === inputSource.endpoint &&
                row.exposure === inputSource.exposure,
            );
          const matchedRuntime =
            !facts.runtimeContext ||
            scoped.some(
              (row) =>
                (!facts.runtimeContext?.launch ||
                  row?.launchCommand === facts.runtimeContext.launch.command) &&
                (!facts.runtimeContext?.mitigation ||
                  row?.mitigation === facts.runtimeContext.mitigation.state) &&
                (!facts.runtimeContext?.containerUrl ||
                  row?.containerUrl === facts.runtimeContext.containerUrl),
            );
          const matchedTags = (facts.tags ?? []).every((tag) =>
            scoped.some((row) => row?.tags?.includes(tag.name)),
          );
          const accepted =
            mapped &&
            matchedWorkload &&
            matchedSource &&
            matchedRuntime &&
            matchedTags;
          return {
            id: item.id,
            revision: item.revision,
            hash: item.hash,
            accepted,
            reason: accepted
              ? "The bound source, service and instance records support this scoped assessment."
              : !mapped
                ? "The original service record does not match."
                : !matchedSource
                  ? "The input endpoint or exposure does not match the original instance record."
                  : "The instance context does not match the original record.",
            citedVersion: item.kind === "use" ? "3.4.0" : null,
            evidenceIds: [
              ...item.excerptIds,
              ...(omitServiceReviewEvidence ? [] : item.receiptIds),
            ],
          };
        }),
      });
    },
  });
  try {
    const names = ["cedar", "spruce"] as const;
    const catalogAnswers = await resolveDependencyServices({
      servers: { catalog: { command: "synthetic-catalog" } },
      repository,
      requests: names.map((project) => ({ path: "src/handler.ts", project })),
      runtime: {},
      recordInventory: state.recordInventory,
      run: async (_prompt, _schema, runtime) => {
        const lookups = names.map((id, i) => {
          const name = id === "cedar" ? "Cedar" : "Spruce";
          const args = { path: "src/handler.ts", service: id };
          runtime.catalogLookup?.onResult({
            id: `synthetic-${id}`,
            type: "mcp_tool_call",
            status: "completed",
            server: "catalog",
            tool: "service_for_source",
            arguments: args,
            result: {
              structured_content: {
                rows: [{ id, name, sourcePath: args.path }],
              },
              content: [],
            },
          });
          return {
            requestId: `request-${i}`,
            reason: "The catalog record maps this source to the consumer.",
            server: "catalog",
            tool: "service_for_source",
            argumentsJson: JSON.stringify(args),
            textBlock: null,
            services: [
              {
                record: ["rows", 0],
                name: ["name"],
                id: ["id"],
                nameValue: name,
                idValue: id,
              },
            ],
          };
        });
        return JSON.stringify({ lookups, notFound: [], unresolved: [] });
      },
    });
    const selected = catalogAnswers.map((answer) => {
      if (
        !("services" in answer) ||
        !answer.services[0]?.receiptSelections?.[0]
      )
        throw new Error("The catalog selection was not recorded");
      return {
        service: answer.services[0],
        selection: answer.services[0].receiptSelections[0],
      };
    });
    const [cedar, spruce] = selected as [
      (typeof selected)[number],
      (typeof selected)[number],
    ];
    const denied = state.recordInventory(
      "artifacts",
      { error: "Registry returned 403." },
      {
        tool: "inspect_image",
        arguments: { digest: "sha256:" + "2".repeat(64) },
        outcome: "failed",
      },
    )!;
    const fallback = state.recordInventory(
      "artifacts",
      {
        structuredContent: {
          platform: "linux/arm64",
          manifest: "sha256:" + "3".repeat(64),
          patch: "vendor backport",
        },
      },
      {
        tool: "inspect_publisher_copy",
        arguments: { digest: "sha256:" + "3".repeat(64) },
      },
    )!;
    const runtime = state.recordInventory(
      "workloads",
      {
        structuredContent: {
          workload: "spruce-parser-stable",
          environment: "prod",
          platform: "linux/amd64",
          platformManifest: "sha256:" + "4".repeat(64),
          revision: "sample-revision",
          endpoint: "https://spruce.example.invalid/parse",
          exposure: "internet",
          launchCommand: "parser-worker --mode=safe",
          mitigation: "enabled",
          tags: ["documents"],
        },
      },
      {
        tool: "lookup_running_worker",
        arguments: { workload: "spruce-parser-stable" },
      },
    )!;
    const boundary = state.recordInventory(
      "workloads",
      {
        structuredContent: {
          workload: "cedar-web-stable",
          environment: "prod",
          endpoint: "https://cedar.example.invalid/documents",
          exposure: "internet",
          launchCommand: "codec-server --mode=default",
          mitigation: "unknown",
          containerUrl:
            "https://registry.example.invalid/images/cedar@sha256:" +
            "2".repeat(64),
          tags: ["documents"],
        },
      },
      {
        tool: "lookup_input_and_instance",
        arguments: { workload: "cedar-web-stable" },
      },
    )!;
    const canaryBoundary = state.recordInventory(
      "workloads",
      {
        structuredContent: {
          workload: "cedar-executor-canary",
          environment: "prod",
          endpoint: "queue:documents-canary",
          exposure: "not_internet",
          launchCommand: "codec-worker --mode=safe",
          mitigation: "enabled",
          containerUrl:
            "https://registry.example.invalid/images/cedar@sha256:" +
            "3".repeat(64),
          tags: ["documents"],
        },
      },
      {
        tool: "lookup_input_and_instance",
        arguments: { workload: "cedar-executor-canary" },
      },
    )!;
    const runtimeSelection = {
      receiptId: runtime,
      textBlock: null,
      record: [],
    };
    const receipt = (
      id: string,
      selection?: { textBlock: number | null; record: (string | number)[] },
    ): DependencyReviewReference => ({
      kind: "receipt",
      receiptId: id,
      originalPayloadSha256: state
        .readStatus({ inventoryReceipts: true })
        .inventoryReceipts!.find((r) => r.id === id)!.originalPayloadSha256,
      ...(selection && { selection }),
    });
    const association = ({ service, selection }: typeof cedar) => ({
      id: service.scope,
      name: service.name,
      source: service.source,
      evidence: [
        receipt(selection.receiptId, {
          textBlock: selection.textBlock,
          record: selection.record,
        }),
      ],
    });
    const observations = (...servers: string[]) =>
      servers.map((server) => ({
        server,
        record: `Synthetic ${server} lookup for the named item`,
        supports: [],
      }));
    const cite = (line: number) => ({
      path: "src/handler.ts",
      startLine: line,
      endLine: line,
      supports: [],
    });
    const index = "sha256:" + "1".repeat(64),
      amd = "sha256:" + "2".repeat(64),
      arm = "sha256:" + "3".repeat(64);
    const base: DependencyUse = {
      location: "POST /documents → decodeFrame",
      component: "sample-codec",
      version: "3.4.0",
      verdict: "unknown",
      deployment: "configured",
      reason:
        "The request document reaches decodeFrame before credential validation. The stable worker's effective decoder guard is unverified.",
      evidence: [cite(3), cite(4)],
      observations: observations("catalog", "artifacts", "workloads"),
      place: place({
        kind: "service",
        environment: "prod",
        workload: "cedar-web-stable",
        deploymentBasis: "configured",
        variant: "stable",
        role: "web",
        imageIndex: index,
        platformManifest: amd,
        platform: "linux/amd64",
        artifact: amd,
        dependencySelection:
          "The selected decoder implementation is not yet bound to the shipped JAR.",
      }),
      services: [association(cedar)],
      inputSource: {
        exposure: "internet",
        endpoint: mismatchedEndpoint
          ? "https://cedar.example.invalid/other"
          : "https://cedar.example.invalid/documents",
        evidence: [receipt(boundary)],
      },
      runtimeContext: {
        launch: { command: "codec-server --mode=default", basis: "configured" },
        mitigation: {
          state: "unknown",
          basis: "unknown",
          detail:
            "The effective guard on the stable process has not been observed.",
        },
        containerUrl:
          "https://registry.example.invalid/images/cedar@sha256:" +
          "2".repeat(64),
        evidence: [receipt(boundary)],
      },
      tags: [{ name: "documents", evidence: [receipt(boundary)] }],
      proof: {
        sink: {
          function: "decodeFrame",
          callSite: { path: "src/handler.ts", line: 3 },
        },
        conditions: [
          {
            label: "Request data reaches the decoder before authentication",
            status: "met",
            explanation: "The call precedes authenticate.",
            citations: [
              { path: "src/handler.ts", line: 3 },
              { path: "src/handler.ts", line: 4 },
            ],
          },
          {
            label: "Effective guard permits the affected mode",
            status: "unknown",
            explanation:
              "The admitted guard setting for this worker is unverified.",
            citations: [],
          },
        ],
      },
      openConditions: [
        {
          question: "Does the stable worker permit the affected decoder mode?",
          target: "Cedar prod stable linux/amd64",
          decidingCheck:
            "Read the admitted guard setting for the named revision.",
          ruledOutIf: "The worker rejects the affected mode before decoding.",
        },
      ],
      inspections: [
        {
          question: "Which dependency JAR shipped in the stable image?",
          target: {
            label: "Cedar stable",
            relationship: "target",
            environment: "prod",
            variant: "stable",
            imageIndex: index,
            platformManifest: amd,
            platform: "linux/amd64",
          },
          source: "artifact inventory",
          outcome: "denied",
          result: "Registry returned 403; the shipped JAR was not inspected.",
          evidence: [receipt(denied)],
        },
      ],
    };
    const canary: DependencyUse = {
      ...base,
      location: "Canary document worker",
      verdict: "ruled_out",
      reason:
        "The selected ARM publisher copy contains the verified vendor backport, which excludes this advisory for that manifest.",
      evidence: [cite(7), cite(8)],
      observations: observations("catalog", "artifacts", "workloads"),
      place: place({
        kind: "job",
        environment: "prod",
        workload: "cedar-executor-canary",
        deploymentBasis: "configured",
        variant: "canary",
        role: "executor",
        imageIndex: index,
        platformManifest: arm,
        platform: "linux/arm64",
        artifact: arm,
        patch: "Verified vendor backport; version label remains 3.4.0.",
      }),
      proof: undefined,
      inputSource: {
        exposure: "not_internet",
        endpoint: "queue:documents-canary",
        evidence: [receipt(canaryBoundary)],
      },
      runtimeContext: {
        launch: { command: "codec-worker --mode=safe", basis: "configured" },
        mitigation: {
          state: "enabled",
          basis: "configured",
          detail:
            "Safe mode is configured for this executor; the fix independently rules out this image.",
        },
        containerUrl:
          "https://registry.example.invalid/images/cedar@sha256:" +
          "3".repeat(64),
        evidence: [receipt(canaryBoundary)],
      },
      tags: [{ name: "documents", evidence: [receipt(canaryBoundary)] }],
      openConditions: [],
      inspections: [
        {
          question: "Does the selected canary copy include the vendor fix?",
          target: {
            label: "Cedar canary",
            relationship: "shared_artifact",
            platformManifest: arm,
            platform: "linux/arm64",
            imageIndex: index,
          },
          source: "digest-matched publisher copy",
          outcome: "succeeded",
          result:
            "The selected platform manifest contains the vendor backport.",
          evidence: [receipt(fallback)],
          transferBasis:
            "The publisher copy matches the identical canary platform-manifest digest.",
        },
      ],
    };
    const shared: DependencyUse = {
      ...base,
      location: "Shared document helper",
      deployment: "unknown",
      reason:
        "The shared helper reaches decodeFrame. Its callers' effective runtime policy remains unverified.",
      evidence: [cite(11)],
      observations: observations("catalog"),
      place: place({ kind: "library_caller" }),
      services: [association(cedar), association(spruce)],
      inputSource: undefined,
      runtimeContext: undefined,
      tags: undefined,
      proof: {
        sink: {
          function: "decodeFrame",
          callSite: { path: "src/handler.ts", line: 11 },
        },
        conditions: [],
      },
      inspections: [],
      openConditions: [
        {
          question: "Which runtime policy applies to each service caller?",
          target: "Cedar and Spruce callers",
          decidingCheck:
            "Match each caller to its effective launch configuration.",
        },
      ],
    };
    const lead = {
      id: "parser",
      kind: "unresolved" as const,
      candidateIds: [],
      location: "POST /parse → parser.open",
      reason:
        "Document bytes reach the parser; the selected implementation's handoff to decodeFrame remains unverified.",
      evidence: [cite(10)],
      observations: observations("catalog", "workloads"),
      services: [association(spruce)],
      inputSource: {
        exposure: "internet" as const,
        endpoint: "https://spruce.example.invalid/parse",
        evidence: [receipt(runtime, { textBlock: null, record: [] })],
      },
      runtimeContext: {
        launch: {
          command: "parser-worker --mode=safe",
          basis: "observed" as const,
        },
        mitigation: {
          state: "enabled" as const,
          basis: "observed" as const,
          detail:
            "The observed parser process uses safe mode; decoder dispatch remains unverified.",
        },
        evidence: [receipt(runtime, { textBlock: null, record: [] })],
      },
      tags: [
        {
          name: "documents",
          evidence: [receipt(runtime, { textBlock: null, record: [] })],
        },
      ],
      place: place({
        kind: "job",
        environment: "prod",
        workload: "spruce-parser-stable",
        variant: "stable",
        role: "parser",
        revision: "sample-revision",
        platform: "linux/amd64",
        platformManifest: "sha256:" + "4".repeat(64),
        artifact: "sha256:" + "4".repeat(64),
        deploymentBasis: "observed",
        deploymentDetail:
          "A running worker sample matches this revision and platform manifest.",
      }),
      inspections: [
        {
          question: "Which parser worker was observed running?",
          target: {
            label: "Spruce parser stable",
            relationship: "target" as const,
            workload: "spruce-parser-stable",
            environment: "prod",
            platform: "linux/amd64",
            platformManifest: "sha256:" + "4".repeat(64),
          },
          source: "workload inventory",
          outcome: "succeeded" as const,
          result:
            "The sample identifies the running parser worker and selected platform manifest; it does not bind the decoder implementation.",
          evidence: [receipt(runtime, { textBlock: null, record: [] })],
        },
      ],
      handoff: {
        verified: "Submitted document bytes reach parser.open.",
        missing:
          "Dispatch to an implementation calling decodeFrame is not established.",
      },
      openConditions: [
        {
          question:
            "Which registered parser implementation handles this input?",
          target: "Spruce document parser",
          decidingCheck:
            "Inspect provider registration and the selected plugin JAR.",
        },
      ],
    };
    const queued = await state.queue({
      items: [
        {
          id: "stable",
          kind: "use",
          candidateIds: [],
          use: base,
          receiptIds: [denied, boundary],
          receiptSelections: [cedar.selection],
        },
        {
          id: "canary",
          kind: "use",
          candidateIds: [],
          use: canary,
          receiptIds: [fallback, canaryBoundary],
          receiptSelections: [cedar.selection],
        },
        {
          id: "shared",
          kind: "use",
          candidateIds: [],
          use: shared,
          receiptSelections: [cedar.selection, spruce.selection],
        },
        { ...lead, receiptSelections: [spruce.selection, runtimeSelection] },
      ],
    });
    if (!queued.queued) throw new Error(queued.feedback);
    const status = state.readStatus();
    const result = await state.submit({
      reviewItems: status.items.map((i) => ({
        id: i.id,
        revision: i.revision,
      })),
      candidateGeneration: status.candidateGeneration,
      limitations: [],
    });
    if (!result.accepted) return { result, report: undefined };
    return {
      result,
      report: {
        ...state.publicReport(),
        cve,
        advisories: [advisoryUrl],
        advisoryDetails: [
          {
            id: cve,
            url: advisoryUrl,
            summary: "Decoder bounds check missing in affected mode",
            overview:
              "A malformed document frame can reach an unchecked decoder operation when the affected mode is enabled.",
            vulnerableFunctions: ["decodeFrame"],
            affected: [
              {
                package: { ecosystem: "npm", name: "sample-codec" },
                ranges: [
                  {
                    type: "SEMVER" as const,
                    events: [{ introduced: "0" }, { fixed: "1.2.2" }],
                  },
                ],
              },
            ],
          },
        ],
        usage: null,
      },
    };
  } finally {
    await state.close();
  }
}
