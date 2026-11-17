import type {
  DependencyCoverageDisposition,
  DependencyReviewReference,
  ReviewedDependencyUse,
} from "../../src/dependency-reachability.js";

export const sourceRef = (
  path = "src/handler.ts",
  line = 5,
): DependencyReviewReference => ({
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
        path: (ref as Extract<DependencyReviewReference, { kind: "source" }>)
          .path,
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
        path: (ref as Extract<DependencyReviewReference, { kind: "source" }>)
          .path,
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
    schemaVersion: 2 as const,
    cve: "CVE-2099-44001",
    advisories: ["https://example.invalid/advisories/CVE-2099-44001"],
    usage: null,
    uses,
    coverage,
    limitations: [],
    assumptions: [],
    searches: [],
  };
}
export function broadReport() {
  const uses = Array.from({ length: 64 }, (_, i) => {
    const u = reviewed(i + 1, {
      verdict: i < 48 ? "unknown" : "ruled_out",
      reason:
        i < 48
          ? `Handler ${i + 1} reaches the codec; its runtime setting is unverified.`
          : `Handler ${i + 1} enforces an unaffected mode.`,
      place: place({
        kind: (["library_caller", "job", "service"] as const)[i % 3]!,
      }),
    });
    if (i % 7 !== 0)
      u.services = [
        service(
          `svc:${i % 6}`,
          `Service ${String.fromCharCode(65 + (i % 6))}`,
          u.decidingEvidence[0]!,
        ),
      ];
    if (i < 16) {
      const boundary = receiptRef(`source-boundary-${i + 1}`, "c");
      u.decidingEvidence.push(boundary);
      u.inputSource = {
        exposure: i < 8 ? "internet" : "not_internet",
        endpoint:
          i < 8 ? `POST /v1/document/${i + 1}` : `queue:document-${i + 1}`,
        evidence: [boundary],
      };
      u.tags = [{ name: "documents", evidence: [boundary] }];
    }
    return u;
  });
  const coverage = Array.from({ length: 24 }, (_, i) => {
    const c = unresolved(i + 1);
    if (i % 4 !== 0)
      c.services = [
        service(
          `svc:${i % 6}`,
          `Service ${String.fromCharCode(65 + (i % 6))}`,
          c.decidingEvidence![0]!,
        ),
      ];
    return c;
  });
  return report(uses, coverage);
}
export function zeroReport() {
  const index = "sha256:" + "7".repeat(64);
  const variants = [
    {
      name: "stable",
      platform: "linux/amd64",
      manifest: "sha256:" + "8".repeat(64),
      config:
        "The admitted worker enables the document renderer and the decoder guard.",
    },
    {
      name: "canary",
      platform: "linux/arm64",
      manifest: "sha256:" + "9".repeat(64),
      config:
        "The admitted worker disables the document renderer and the decoder guard.",
    },
  ];
  const leads = Array.from({ length: 5 }, (_, i) => {
    const variant = variants[i];
    const sampled = variant
      ? receiptRef(`workload-sample-${i + 1}`, "b")
      : undefined;
    const c = unresolved(i + 1, {
      handoff: {
        verified: "Submitted bytes reach the parser entrypoint.",
        missing: "Dispatch to the affected decoder is not bound.",
      },
      openConditions: [
        {
          question: "Which registered provider handles this field?",
          target: `Cedar worker variant ${i + 1}`,
          decidingCheck:
            "Inspect the provider registration in the exact platform artifact.",
        },
      ],
      ...(variant && sampled
        ? {
            place: place({
              kind: "job",
              environment: "prod",
              workload: `cedar-parser-${variant.name}`,
              variant: variant.name,
              role: "parser",
              revision: "sample-revision",
              deploymentBasis: "observed",
              imageIndex: index,
              platformManifest: variant.manifest,
              platform: variant.platform,
              artifact: variant.manifest,
              observationWindow: "2026-01-01T00:00Z–01:00Z",
              deploymentDetail:
                "A running worker sample matches the named revision and manifest.",
              dependencySelection:
                "The selected parser provider remains unbound.",
            }),
            inspections: [
              {
                question:
                  "Which worker and launch configuration were observed?",
                target: {
                  label: `Cedar ${variant.name}`,
                  relationship: "target" as const,
                  workload: `cedar-parser-${variant.name}`,
                  environment: "prod",
                  variant: variant.name,
                  imageIndex: index,
                  platformManifest: variant.manifest,
                  platform: variant.platform,
                  observationWindow: "2026-01-01T00:00Z–01:00Z",
                },
                source: "workload inventory",
                outcome: "succeeded" as const,
                result: `${variant.config} Configured launch: parser-worker --variant=${variant.name}.`,
                evidence: [sampled],
              },
            ],
            inputSource: {
              exposure: "internet" as const,
              endpoint: "POST /parse",
              evidence: [sampled],
            },
            runtimeContext: {
              launch: {
                command: `parser-worker --variant=${variant.name}`,
                basis: "configured" as const,
              },
              mitigation: {
                state:
                  variant.name === "stable"
                    ? ("enabled" as const)
                    : ("disabled" as const),
                basis: "configured" as const,
                detail: variant.config,
              },
              evidence: [sampled],
            },
            observations: [
              {
                server: "workloads",
                record: `Running ${variant.name} worker and admitted configuration`,
                supports: [],
              },
            ],
          }
        : {}),
    });
    if (sampled) c.decidingEvidence!.push(sampled);
    c.services = [service("svc:cedar", "Cedar", c.decidingEvidence![0]!)];
    return c;
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
      role: "web",
      imageIndex: index,
      platformManifest: amd,
      platform: "linux/amd64",
      artifact: amd,
      observationWindow: "2026-01-01T00:00Z–01:00Z",
      dependencySelection: "The selected provider JAR has not been identified.",
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
      role: "executor",
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
