import {
  assembleExploitabilityReport,
  repositoryVulnerability,
  type AnalyzerBatch,
} from "../../src/exploitability/check-output.js";
import { repositoryIssueReportSchema } from "../../src/exploitability/reachability.js";
import type { DependencyTarget } from "../../src/exploitability/source-identity.js";
import type {
  DependencyReviewReference,
  Finding,
} from "../../src/exploitability/report/model.js";
type DependencyCoverageDisposition = Extract<
  Finding,
  { kind: "coverage" }
>["item"];
type ReviewedDependencyUse = Extract<Finding, { kind: "use" }>["item"];

export const sourceRef = (
  path = "src/handler.ts",
  line = 5,
): Extract<DependencyReviewReference, { kind: "source" }> => ({
  kind: "source",
  path,
  startLine: line,
  endLine: line,
});
export const receiptRef = (id: string, c = "a"): DependencyReviewReference => ({
  kind: "receipt",
  receiptId: id,
  originalPayloadSha256: c.repeat(64),
});
export const place = (
  override: Partial<ReviewedDependencyUse["place"]> = {},
): ReviewedDependencyUse["place"] => ({
  kind: "library_caller",
  environment: null,
  revision: null,
  artifact: null,
  observationWindow: null,
  deploymentBasis: "unknown",
  deploymentDetail: null,
  dependencySelection: null,
  patch: null,
  unresolvedQuestions: [],
  ...override,
});
export const service = (
  id: string,
  name: string,
  ref: DependencyReviewReference = sourceRef(),
) => ({ id, name, source: "synthetic service catalog", evidence: [ref] });
export function reviewed(
  n: number,
  override: Partial<ReviewedDependencyUse> = {},
): ReviewedDependencyUse {
  const ref = sourceRef(`src/handler-${n}.ts`, n + 1);
  return {
    location: `Handler ${n}`,
    component: "sample-codec",
    version: null,
    verdict: "unknown",
    deployment: "unknown",
    reason: `Handler ${n} reaches the codec; its selected runtime setting is unverified.`,
    evidence: [
      {
        path: ref.path,
        startLine: n + 1,
        endLine: n + 1,
        supports: [],
      },
    ],
    observations: [],
    place: place(),
    decidingEvidence: [ref],
    ...override,
  };
}
export function unresolved(
  n: number,
  override: Partial<DependencyCoverageDisposition> = {},
): DependencyCoverageDisposition {
  const ref = sourceRef(`src/parser-${n}.ts`, n + 1);
  return {
    kind: "unresolved",
    location: `Parser ${n}`,
    reason: `The parser ${n} handoff to the affected decoder is unverified.`,
    evidence: [
      {
        path: ref.path,
        startLine: n + 1,
        endLine: n + 1,
        supports: [],
      },
    ],
    observations: [],
    decidingEvidence: [ref],
    ...override,
  };
}
export function report(
  uses: ReviewedDependencyUse[],
  coverage: DependencyCoverageDisposition[] = [],
) {
  return {
    cve: "CVE-2099-44001",
    advisories: ["https://example.invalid/advisories/CVE-2099-44001"],
    usage: null,
    uses,
    coverage,
    limitations: [] as string[],
    assumptions: [] as string[],
    searches: [],
  };
}
type RepositoryFixture = ReturnType<typeof report> & {
  target?: DependencyTarget;
  claims?: unknown;
  claimEvidence?: unknown;
  advisoryDetails?: unknown;
};
export function repositoryBatch(input: RepositoryFixture): AnalyzerBatch {
  const { cve, target, ...issue } = input;
  return {
    status: "complete",
    target,
    vulnerabilities: [
      repositoryVulnerability(
        { kind: "advisory", id: cve },
        repositoryIssueReportSchema.parse(issue),
      ),
    ],
  };
}

// Renderer fixtures use their first cited finding as an approved result.
export function reviewedBatch(subject: string, batch: AnalyzerBatch) {
  const output = assembleExploitabilityReport(subject, [batch]);
  for (const issue of output.vulnerabilities) {
    if (issue.status !== "complete") continue;
    const finding = issue.findings[0];
    issue.result = {
      verdict: finding?.verdict ?? "unknown",
      reason: finding?.reason ?? "No reviewed caller was identified.",
      questions: [],
      findingRefs: finding ? [0] : [],
      review: { status: "approved" },
    };
  }
  return output;
}
export function repositoryReport(input: RepositoryFixture) {
  return reviewedBatch(input.cve, repositoryBatch(input));
}

// The CLI fixtures have no established exploit. Both calls must see the
// current vulnerability's own findings, including the empty repository case.
export function synthesisAnswer(prompt: string) {
  const original = /Original findings and coverage:\n([^\n]+)/u.exec(prompt);
  if (!original) return;
  if (prompt.includes("\n\nProposed result:"))
    return { status: "approved", reason: "Checked the cited findings." };
  const { findings } = JSON.parse(original[1]!);
  return {
    verdict: "unknown",
    reason: "Runtime reachability is unresolved.",
    questions: ["Which inputs reach the decoder?"],
    findingRefs: findings.map((_: unknown, index: number) => index),
  };
}

// Attach each excerpt via the same claim and source references as saved reports.
export function withExcerpts(
  input: ReturnType<typeof report>,
  ...excerpts: string[][]
) {
  const items = [...input.uses, ...input.coverage];
  const sources: Record<
    string,
    {
      path: string;
      startLine: number;
      endLine: number;
      commit?: string;
      excerpt: string;
    }
  > = {};
  const claims = excerpts.map((texts, i) => {
    const item = items[i]!;
    const ref = { id: `evidence-${i}`, revision: 1, hash: "b".repeat(64) };
    const sourceIds = texts.map((excerpt, j) => {
      const id = `cite-${i}-${j}`;
      const cite = item.evidence[j];
      if (!cite) throw new Error("Fixture excerpt without a citation");
      sources[id] = { ...cite, excerpt };
      return id;
    });
    return {
      ...ref,
      state: "approved",
      contextHash: "a".repeat(64),
      payload: { fact: "Source range reviewed." },
      scope: { location: item.location ?? null },
      dependencies: [],
      decision: { accepted: true, reason: "Source verified", evidenceKeys: [] },
      evidence: { sourceIds, receiptIds: [] },
    };
  });
  const bind = <
    T extends ReviewedDependencyUse | DependencyCoverageDisposition,
  >(
    item: T,
    i: number,
  ) => {
    const claim = claims[i];
    if (!claim) return item;
    const { id, revision, hash } = claim;
    return { ...item, supportingClaims: [{ id, revision, hash }] };
  };
  return {
    ...input,
    uses: input.uses.map(bind),
    coverage: input.coverage.map((c, i) => bind(c, input.uses.length + i)),
    claims,
    claimEvidence: { sources, receipts: {} },
  };
}
export function zeroReport() {
  const leads = ["stable", "canary"].map((variant, i) => {
    const ref = receiptRef(variant);
    const lead = unresolved(i + 1, {
      handoff: {
        verified: "Submitted bytes reach the parser entrypoint.",
        missing: "Dispatch to the affected decoder is not bound.",
      },
      openConditions: [
        {
          question: "Which registered provider handles this field?",
          target: variant,
          decidingCheck: "Inspect the registered parser.",
        },
      ],
      place: place({ kind: "job", variant }),
      runtimeContext: {
        launch: {
          command: `parser-worker --variant=${variant}`,
          basis: "configured",
        },
        mitigation: {
          state: i === 0 ? "enabled" : "disabled",
          basis: "configured",
          detail: "Admitted worker configuration.",
        },
        evidence: [ref],
      },
    });
    lead.decidingEvidence!.push(ref);
    return lead;
  });
  return report([], leads);
}
export function variantReport() {
  const index = "sha256:" + "1".repeat(64),
    amd = "sha256:" + "2".repeat(64),
    arm = "sha256:" + "3".repeat(64);
  const stable = reviewed(1, {
    location: "POST /documents → decodeFrame",
    verdict: "unknown",
    deployment: "confirmed",
    place: place({
      kind: "service",
      environment: "prod",
      deploymentBasis: "observed",
      variant: "stable",
      imageIndex: index,
      platformManifest: amd,
      platform: "linux/amd64",
      artifact: amd,
      observationWindow: "2026-01-01T00:00Z–01:00Z",
    }),
    proof: {
      sink: {
        function: "decodeFrame",
        callSite: { path: "src/handler-1.ts", line: 2 },
      },
      conditions: [
        {
          label: "Request reaches decoder before authentication",
          status: "met",
          explanation: "The decoder is called before credential validation.",
          citations: [{ path: "src/handler-1.ts", line: 2 }],
        },
        {
          label: "Production guard permits affected mode",
          status: "unknown",
          explanation: "The admitted guard setting is unverified.",
          citations: [],
        },
      ],
    },
    openConditions: [
      {
        question: "Is the affected mode enabled for the stable worker?",
        target: "Cedar prod stable linux/amd64",
        decidingCheck: "Read the admitted worker setting for this revision.",
        ruledOutIf: "The guard rejects the affected mode.",
      },
    ],
  });
  stable.services = [
    service("svc:cedar", "Cedar", stable.decidingEvidence[0]!),
  ];
  const canary = reviewed(2, {
    location: "Canary document worker",
    verdict: "ruled_out",
    deployment: "configured",
    reason:
      "The selected ARM platform manifest includes the verified vendor backport.",
    place: place({
      kind: "job",
      environment: "prod",
      deploymentBasis: "configured",
      variant: "canary",
      imageIndex: index,
      platformManifest: arm,
      platform: "linux/arm64",
      artifact: arm,
      patch: "Vendor backport verified; upstream version label is unchanged.",
    }),
  });
  canary.services = [
    service("svc:cedar", "Cedar", canary.decidingEvidence[0]!),
  ];
  const shared = reviewed(3, {
    location: "Shared document helper",
    reason:
      "The helper selects the codec; the caller-specific access policy is not recorded.",
  });
  shared.services = [
    service("svc:cedar", "Cedar", shared.decidingEvidence[0]!),
    service("svc:spruce", "Spruce", shared.decidingEvidence[0]!),
  ];
  const lead = unresolved(1, {
    location: "POST /parse → parser entrypoint",
    handoff: {
      verified: "Document bytes reach the parser entrypoint.",
      missing: "The enabled implementation has not been linked to decodeFrame.",
    },
    openConditions: [
      {
        question: "Does dispatch select the affected implementation?",
        target: "Spruce parser",
        decidingCheck:
          "Inspect the registered implementation and selected JAR.",
      },
    ],
  });
  lead.services = [service("svc:spruce", "Spruce", lead.decidingEvidence![0]!)];
  return report([stable, canary, shared], [lead]);
}
