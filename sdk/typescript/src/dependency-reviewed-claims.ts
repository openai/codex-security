import { z } from "zod";
import {
  DependencyAttemptStore,
  dependencyRecordHash,
  type StoredClaim,
} from "./dependency-attempt-store.js";
import { readDependencySourceCitation } from "./dependency-source-identity.js";
import type { discoverDependencyRepository } from "./dependency-discovery.js";
import type { DependencyEvidenceRecord } from "./dependency-evidence-sources.js";
import { isRecord } from "./record.js";
import { CodexSecurityError } from "./errors.js";
import {
  assertDependencyUseProofCitations,
  dependencyUseProofSchema,
  dependencyUseSchema,
} from "./dependency-stack-use.js";

type Discovery = Awaited<ReturnType<typeof discoverDependencyRepository>>;
const text = z.string().trim().min(1);
const source = z.strictObject({
  path: text,
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive(),
  supports: z.array(
    z.enum([
      "affected_copy",
      "affected_use",
      "attacker_control",
      "exclusion",
      "context",
    ]),
  ),
});
const receipt = z.strictObject({
  server: text,
  tool: text,
  sha256: z
    .string()
    .regex(/^[a-f0-9]{64}$/)
    .optional()
    .describe(
      "Use the host's response ID if earlier calls returned the same quote.",
    ),
  supports: z.array(z.enum(["running", "access"])).length(1),
  quote: text,
  reason: text,
});
const proposedUse = z.strictObject({
  scope: text,
  location: text
    .optional()
    .describe(
      "Specific consumer, service or build when discovered from source. For an unnamed root manifest, quote one running observation naming the service, package, version, Git revision and path to its cited manifest or caller.",
    ),
  placeKind: z
    .enum([
      "service",
      "job",
      "configured_build",
      "artifact",
      "library_caller",
      "unknown",
    ])
    .optional(),
  configured: z
    .boolean()
    .optional()
    .describe(
      "Set true when cited build or deployment configuration establishes the intended use.",
    ),
  verdict: dependencyUseSchema.shape.verdict,
  reason: text,
  version: text.nullable(),
  evidence: z.array(source).min(1),
  observations: z.array(receipt),
  proof: dependencyUseProofSchema,
  remainingQuestions: z.array(text),
});
export const investigationSchema = z.strictObject({
  uses: z.array(proposedUse),
  limitations: z.array(text),
});
export type Proposal = z.infer<typeof investigationSchema>;
export const reviewSchema = z.strictObject({
  decisions: z.array(
    z.strictObject({
      id: text,
      revision: z.number().int().positive(),
      hash: text,
      approved: z.boolean(),
      reason: text,
    }),
  ),
});
type Decision = z.infer<typeof reviewSchema>["decisions"][number];
export type Scope = {
  id: string;
  location: string;
  component: string;
  name?: string;
  manifest?: string;
  runtimeServices: string[];
  selectedVersion?: string;
  manifestLine?: number;
  selection?: { lockfile: string; line: number };
  discovery: Discovery;
};

/** Preserve both consumers when a repository contains two differently locked copies. */
export function reviewScopes(discoveries: Discovery[]): Scope[] {
  return discoveries.flatMap<Scope>((discovery, packageIndex) => {
    const projects = new Set(discovery.manifests.map((m) => m.project));
    const components = discovery.manifests.map((manifest) => ({
      location:
        manifest.project === "." &&
        manifest.name &&
        !projects.has(manifest.name)
          ? manifest.name
          : manifest.project,
      name: manifest.name,
      manifest: manifest.path,
      selectedVersion: manifest.selection?.version,
      manifestLine: manifest.line,
      selection: manifest.selection,
    }));
    if (!components.length)
      return [
        {
          id: `${packageIndex + 1}.1`,
          location: ".",
          runtimeServices: [],
          component: discovery.package.name,
          discovery,
        },
      ];
    // An exact project location wins over every display-name alias. Two
    // manifests can publish the same package name from different locations.
    const owners = new Map<string, number>();
    const exact = new Set(components.map((c) => c.location));
    for (const c of components)
      if (c.name) owners.set(c.name, (owners.get(c.name) ?? 0) + 1);
    return components.map((component, i) => ({
      runtimeServices: [
        component.location,
        ...(component.name &&
        !exact.has(component.name) &&
        owners.get(component.name) === 1
          ? [component.name]
          : []),
      ],
      ...component,
      id: `${packageIndex + 1}.${i + 1}`,
      component: discovery.package.name,
      discovery,
    }));
  });
}

/** Only returned content can support a claim. Requests and protocol metadata never do. */
function containsQuote(record: DependencyEvidenceRecord, quote: string) {
  const result = record.result;
  const content = result["content"];
  if (record.tool === "read_mcp_resource") {
    // Codex serializes the resource response and request metadata into one text block.
    const args = record.arguments;
    if (!isRecord(args) || !Array.isArray(content)) return false;
    return content.some((block: unknown) => {
      if (
        !isRecord(block) ||
        block["type"] !== "text" ||
        typeof block["text"] !== "string" ||
        /…\d+ (?:tokens|chars) truncated…/u.test(block["text"])
      )
        return false;
      try {
        const response: unknown = JSON.parse(block["text"]);
        return (
          isRecord(response) &&
          response["server"] === record.server &&
          response["uri"] === args["uri"] &&
          Array.isArray(response["contents"]) &&
          response["contents"].some(
            (item: unknown) =>
              isRecord(item) &&
              typeof item["text"] === "string" &&
              item["text"].includes(quote),
          )
        );
      } catch {
        return false;
      }
    });
  }
  if (
    Array.isArray(content) &&
    content.some((block: unknown) => {
      if (!isRecord(block)) return false;
      const text =
        block["type"] === "text"
          ? block["text"]
          : block["type"] === "resource" && isRecord(block["resource"])
            ? block["resource"]["text"]
            : undefined;
      return typeof text === "string" && text.includes(quote);
    })
  )
    return true;
  const data = result["structuredContent"] ?? result["structured_content"];
  if (data == null) return false;
  // A string value can contain quotes or newlines escaped by its JSON encoding.
  function hasString(value: unknown): boolean {
    if (typeof value === "string") return value.includes(quote);
    if (Array.isArray(value) || isRecord(value))
      return Object.values(value).some(hasString);
    return false;
  }
  return (
    hasString(data) ||
    [JSON.stringify(data), JSON.stringify(data, null, 2)].some((encoded) =>
      encoded.includes(quote),
    )
  );
}

/** Match complete identifiers, so e.g. 1.2.0 does not match a record for 11.2.0. */
function mentions(quote: string, value: string, sourcePath = false) {
  const escaped = value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  if (sourcePath) {
    // Accept checkout-relative paths only, including "./" and quoted names with spaces.
    return new RegExp(
      String.raw`(?:^|[\s"'=:,(\[{])(?:\./)?${escaped}(?=$|[\s"',;)\]}]|\.(?:\s|$))`,
      "u",
    ).test(quote);
  }
  return new RegExp(
    `(?<![\\p{L}\\p{N}_/+~-]|[\\p{L}\\p{N}]\\.)${escaped}(?![\\p{L}\\p{N}_/+~-]|\\.[\\p{L}\\p{N}])`,
    "u",
  ).test(quote);
}

function verifiedLocation(
  scope: Scope,
  use: Proposal["uses"][number],
  running: string[],
  covers: (path: string | undefined, line: number | undefined) => boolean,
) {
  const proposed = use.location;
  if (!scope.manifest) return proposed ?? scope.location;
  if (
    scope.location !== "." ||
    scope.name ||
    !proposed ||
    proposed === "." ||
    !use.version
  )
    return scope.location;
  if (
    scope.discovery.manifests.some(
      (m) => m.project === proposed || m.name === proposed,
    )
  )
    return scope.location;
  const paths = scope.discovery.callers
    .filter((c) => c.manifest === scope.manifest && covers(c.path, c.line))
    .map((c) => c.path);
  if (covers(scope.manifest, scope.manifestLine)) paths.push(scope.manifest);
  // Without a declared project name, the deployment itself must identify the
  // exact revision and a cited source path belonging to this manifest.
  const identity = [
    proposed,
    scope.discovery.revision,
    scope.component,
    use.version,
  ];
  const linked = running.some(
    (q) =>
      identity.every((id) => mentions(q, id)) &&
      paths.some((path) => mentions(q, path, true)),
  );
  return linked ? proposed : scope.location;
}

export async function verifyProposedUse(
  directory: string,
  scope: Scope,
  use: Proposal["uses"][number],
  signal: AbortSignal,
  affectedVersion?: boolean,
  records: readonly DependencyEvidenceRecord[] = [],
) {
  const revision = scope.discovery.revision;
  if (scope.selectedVersion && use.version !== scope.selectedVersion)
    throw new CodexSecurityError(
      `The version for ${scope.location} differs from its selected dependency version.`,
    );
  const evidence = await Promise.all(
    use.evidence.map(async ({ supports, ...range }) => ({
      ...(await readDependencySourceCitation(
        directory,
        revision,
        range,
        signal,
      )),
      supports,
    })),
  );
  const covers = (path: string | undefined, line: number | undefined) =>
    path !== undefined &&
    line !== undefined &&
    evidence.some(
      (ref) =>
        ref.path === path && ref.startLine <= line && line <= ref.endLine,
    );
  const citesSelection = covers(
    scope.selection?.lockfile,
    scope.selection?.line,
  );
  if (
    scope.manifest &&
    !covers(scope.manifest, scope.manifestLine) &&
    !citesSelection &&
    !scope.discovery.callers.some(
      (c) => c.manifest === scope.manifest && covers(c.path, c.line),
    )
  )
    throw new CodexSecurityError(
      `Cite the dependency selection or caller for this scope: ${scope.location}`,
    );
  assertDependencyUseProofCitations(use.proof, evidence, scope.location);
  const observations = use.observations.map((ref) => {
    const matches = records.filter(
      (record) =>
        record.server === ref.server &&
        record.tool === ref.tool &&
        (!ref.sha256 || record.sha256 === ref.sha256) &&
        containsQuote(record, ref.quote),
    );
    if (matches.length !== 1)
      throw new CodexSecurityError(
        `The quote must identify one recorded reply from ${ref.server}/${ref.tool}. Cite the exact response to the tool call.`,
      );
    return {
      ...ref,
      sha256: matches[0]!.sha256,
      originalPayloadSha256: dependencyRecordHash(matches[0]!.result),
    };
  });
  const quotes = (support: "running" | "access") =>
    observations
      .filter((r) => r.supports.includes(support))
      .map((r) => r.quote);
  const running = quotes("running"),
    access = quotes("access");
  const location = verifiedLocation(scope, use, running, covers);
  const names = [location, ...scope.runtimeServices].filter(
    (name) => name !== ".",
  );
  if (
    running.length &&
    (!use.version ||
      ![revision, scope.component, use.version].every((id) =>
        running.some((q) => mentions(q, id)),
      ) ||
      !running.some((q) => names.some((name) => mentions(q, name))))
  )
    throw new CodexSecurityError(
      "Cite returned evidence for this running service, source revision, dependency and version.",
    );
  if (
    access.length &&
    (!access.some((q) => names.some((name) => mentions(q, name))) ||
      observations.some(
        (a) =>
          a.supports.includes("access") &&
          observations.some(
            (r) =>
              r.supports.includes("running") &&
              r.sha256 === a.sha256 &&
              (r.quote.includes(a.quote) || a.quote.includes(r.quote)),
          ),
      ))
  )
    throw new CodexSecurityError(
      "Cite separate evidence of caller access to this service.",
    );
  const facts = new Set(evidence.flatMap((ref) => ref.supports));
  if (
    use.verdict === "potentially_exploitable" ||
    use.verdict === "exploitable"
  ) {
    if (use.proof.conditions.some((c) => c.status === "ruled_out"))
      throw new CodexSecurityError(
        "An affected use cannot have a disproved necessary condition.",
      );
    if (affectedVersion === false)
      throw new CodexSecurityError(
        `The frozen advisory excludes version ${use.version} of ${scope.component}.`,
      );
    if (
      !use.version ||
      !use.proof.sink ||
      !facts.has("affected_copy") ||
      !facts.has("affected_use")
    )
      throw new CodexSecurityError(
        "An affected use needs a selected version, affected-copy citation and applicable call-site citation.",
      );
  }
  if (use.verdict === "exploitable") {
    if (
      !facts.has("attacker_control") ||
      !use.proof.sink ||
      !use.proof.conditions.length ||
      use.proof.conditions.some((c) => c.status !== "met") ||
      !observations.some((ref) => ref.supports.includes("running")) ||
      !observations.some((ref) => ref.supports.includes("access"))
    )
      throw new CodexSecurityError(
        "An exploitable use needs cited attacker control, all advisory conditions met, and observations of this running workload and caller access.",
      );
  }
  const selectedCopyExcluded =
    affectedVersion === false &&
    scope.selectedVersion === use.version &&
    citesSelection;
  if (use.verdict === "ruled_out") {
    const disproved = use.proof.conditions.filter(
      (c) => c.status === "ruled_out",
    );
    const supported = disproved.some((c) =>
      c.citations.some((line) =>
        evidence.some(
          (ref) =>
            ref.supports.includes("exclusion") &&
            ref.path === line.path &&
            ref.startLine <= line.line &&
            ref.endLine >= line.line,
        ),
      ),
    );
    if (!facts.has("exclusion") || (!selectedCopyExcluded && !supported))
      throw new CodexSecurityError(
        "Ruling out a use needs a verified fixed dependency selection or an exclusion citation for a disproved advisory condition.",
      );
  }
  if (
    (use.verdict === "unknown" || use.verdict === "potentially_exploitable") &&
    !use.remainingQuestions.length
  )
    throw new CodexSecurityError(
      "An unresolved use must identify the missing deciding fact.",
    );
  return {
    ...use,
    selectedCopyExcluded,
    evidence,
    observations,
    location,
    component: scope.component,
    revision,
  };
}

export type VerifiedUse = Awaited<ReturnType<typeof verifyProposedUse>>;
type ReviewClaim =
  | { kind: "use"; use: VerifiedUse }
  | { kind: "coverage"; limitations: string[] };
export type Claim = StoredClaim<ReviewClaim>;
export function reference(claim: Pick<Claim, "id" | "revision" | "hash">) {
  return { id: claim.id, revision: claim.revision, hash: claim.hash };
}

export class DependencyReviewRejection extends CodexSecurityError {}

/** Commit approvals only if every decision still names the exact current claim. */
export function approveDependencyClaims(
  store: DependencyAttemptStore,
  claims: Claim[],
  decisions: Decision[],
) {
  return store.transaction(() => {
    const byId = new Map(decisions.map((row) => [row.id, row]));
    if (decisions.length !== claims.length || byId.size !== claims.length)
      throw new CodexSecurityError(
        "Independent review must decide every claim exactly once.",
      );
    return claims.map((claim) => {
      const current = store.claim<ReviewClaim>(claim.id),
        decision = byId.get(claim.id);
      if (
        !current ||
        !decision ||
        current.hash !== claim.hash ||
        current.revision !== claim.revision ||
        decision.hash !== current.hash ||
        decision.revision !== current.revision
      )
        throw new CodexSecurityError(
          "Independent review does not match the current claim revisions.",
        );
      if (!decision.approved)
        throw new DependencyReviewRejection(
          `Independent review rejected ${claim.id}: ${decision.reason}`,
        );
      store.set("dependency-review", claim.id, decision);
      return { ...reference(current), value: current.value, review: decision };
    });
  });
}

export function reportedUse(use: VerifiedUse, claim: Claim) {
  const running = use.observations.some((ref) =>
    ref.supports.includes("running"),
  );
  const decidingEvidence = [
    ...use.evidence.map(({ path, commit, startLine, endLine }) => ({
      kind: "source" as const,
      path,
      commit,
      startLine,
      endLine,
    })),
    ...use.observations.map((ref) => ({
      kind: "receipt" as const,
      receiptId: ref.sha256,
      originalPayloadSha256: ref.originalPayloadSha256,
    })),
  ];
  return {
    location: use.location,
    component: use.component,
    version: use.version,
    verdict: use.verdict,
    reason: use.reason,
    deployment: running
      ? ("confirmed" as const)
      : use.configured
        ? ("configured" as const)
        : ("unknown" as const),
    evidence: use.evidence.map(
      ({ path, commit, startLine, endLine, supports }) => ({
        path,
        commit,
        startLine,
        endLine,
        supports: supports.filter(
          (s) => s === "affected_copy" || s === "affected_use",
        ),
      }),
    ),
    observations: use.observations.map((ref) => ({
      server: ref.server,
      tool: ref.tool,
      sha256: ref.sha256,
      record: ref.quote,
      supports: ref.supports,
    })),
    place: {
      kind: use.placeKind ?? "unknown",
      environment: null,
      revision: use.revision,
      artifact: null,
      observationWindow: null,
      deploymentBasis: running
        ? ("observed" as const)
        : use.configured
          ? ("configured" as const)
          : ("unknown" as const),
      deploymentDetail: running
        ? use.observations
            .filter((r) => r.supports.includes("running"))
            .map((r) => r.quote)
            .join("\n")
        : null,
      dependencySelection: use.version,
      patch: null,
      unresolvedQuestions: use.remainingQuestions,
    },
    proof: use.proof,
    decidingEvidence,
    conclusionClaim: reference(claim),
  };
}
