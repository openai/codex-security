import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { JsonValue } from "../../src/config.js";
import type { DependencyClaimReference } from "../../src/dependency-claims.js";
import {
  createDependencyReportSubmission,
  dependencyReviewQueueSchema,
} from "../../src/dependency-report-submission.js";
import {
  dependencyReachabilityReportSchema,
  readDependencyCheckOutput as readSavedReport,
} from "../../src/dependency-reachability.js";
import type { DependencyExcerpt } from "../../src/dependency-reachability.js";
import { scopedTemporaryDirectory } from "./temporary-directories.js";
import type { z } from "zod";

export { createDependencyReportSubmission };
export type Controller = ReturnType<typeof createDependencyReportSubmission>;
export type Options = Parameters<typeof createDependencyReportSubmission>[0];
export type UseInput = Extract<
  z.infer<typeof dependencyReviewQueueSchema>["items"][number],
  { kind: "use" }
>;
export interface ReviewRow extends DependencyClaimReference {
  kind?: string;
  supportingClaims?: DependencyClaimReference[];
  use?: UseInput["use"];
  excerptIds: string[];
  receiptIds: string[];
}
export interface ReviewPacket {
  items: ReviewRow[];
  excerpts: Record<string, DependencyExcerpt>;
  receipts: Record<string, { result: JsonValue }>;
  approvedClaims: (DependencyClaimReference & {
    payload: JsonValue;
    scope: JsonValue;
    evidence: {
      sources: Omit<DependencyExcerpt, "text">[];
      receipts: {
        selection?: { record: (string | number)[] };
        result?: JsonValue;
      }[];
    };
  })[];
}
export const advisory = { cve: "CVE-2024-1000", advisories: [] };
const scope = {
  code: "Configured writer adapter",
  places: ["fixture-production"],
};
export const sourceEvidence = (path: string) => ({
  path,
  startLine: 1,
  endLine: 2,
  supports: [],
});
export function draft(id: string, extra: Record<string, unknown> = {}) {
  return {
    id,
    scope,
    payload: {
      assumption: "The shared writer passes its mode argument unchanged.",
    },
    evidence: [{ path: "writer.ts", startLine: 1, endLine: 2 }],
    ...extra,
  };
}
export function use(
  id: string,
  file: string,
  supportingClaims: DependencyClaimReference[] = [],
  artifact?: string,
): UseInput {
  return {
    id,
    kind: "use",
    candidateIds: [],
    ...(supportingClaims.length ? { supportingClaims } : {}),
    use: {
      location: file + ":2",
      component: "image-writer",
      version: null,
      verdict: "ruled_out",
      deployment: artifact ? "configured" : "unknown",
      reason:
        "This exact caller selects PNG output, which excludes its TIFF write condition.",
      evidence: [sourceEvidence(file)],
      observations: [],
      proof: {
        sink: { function: "saveImage", callSite: { path: file, line: 2 } },
        conditions: [
          {
            label: "Selects TIFF output",
            status: "ruled_out",
            explanation: "The exact caller explicitly selects PNG.",
            citations: [{ path: file, line: 2 }],
          },
        ],
      },
      ...(artifact && {
        place: {
          kind: "service",
          environment: "fixture-production",
          revision: null,
          artifact,
          observationWindow: null,
          deploymentBasis: "configured",
          deploymentDetail: "The fixture selects this distinct artifact.",
          dependencySelection: null,
          patch: null,
          unresolvedQuestions: [],
        },
      }),
    },
  };
}
export async function withFixture<T>(
  reviewer: Options["review"],
  run: (state: Controller, repository: string) => Promise<T>,
  extra: Partial<Options> = {},
): Promise<T> {
  await using repo = await scopedTemporaryDirectory("claim-probe-");
  const repository = repo.path;
  const input = {
    "writer.ts":
      "export function saveImage(output, mode) {\n    return image.save(output, mode);\n}\n",
    "caller-a.ts":
      'import { saveImage } from "./writer";\nexport const start = (output) => saveImage(output, "PNG");\n',
    "caller-b.ts":
      'import { saveImage } from "./writer";\nexport const start = (output) => saveImage(output, "PNG");\n',
    "unrelated.ts": "export const metadata = 1;\n",
  };
  for (const [file, data] of Object.entries(input))
    await writeFile(join(repository, file), data);
  const state = createDependencyReportSubmission({
    repository,
    advisory,
    callerScope: "fixture-production",
    inventoryServers: { deployed: ["lookup"] },
    review: reviewer,
    ...extra,
  });
  try {
    return await run(state, repository);
  } finally {
    await state.close();
  }
}
export function block() {
  return {
    entered: Promise.withResolvers<unknown>(),
    release: Promise.withResolvers<unknown>(),
  };
}
export function packetPayload(prompt: string): ReviewPacket {
  return JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1)) as ReviewPacket;
}
export function claimRef(
  row: DependencyClaimReference,
): DependencyClaimReference {
  return { id: row.id, revision: row.revision, hash: row.hash };
}
export async function waitFor<T>(
  read: () => T | Promise<T>,
  match: (value: T) => boolean,
  label: string,
): Promise<T> {
  const until = Date.now() + 3000;
  let observed = await read();
  while (!match(observed) && Date.now() < until) {
    await Bun.sleep(5);
    observed = await read();
  }
  if (!match(observed))
    throw new Error(
      `Timed out waiting for ${label}: ${JSON.stringify(observed)}`,
    );
  return observed;
}
export function recordFixtureLookup(
  state: Controller,
  service: string,
  digest: string,
): string {
  return state.recordInventory(
    "deployed",
    { structuredContent: { matches: [{ service, digest }] } },
    { tool: "lookup", arguments: { service } },
  )!;
}
export function artifactSelection(receiptId: string) {
  return { receiptId, textBlock: null, record: ["matches", 0] };
}
export function readDependencyCheckOutput(value: unknown) {
  return dependencyReachabilityReportSchema.parse(readSavedReport(value));
}
