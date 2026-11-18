import {
  assertReviewedPremises,
  claimInputs,
  premiseKey,
  type Premise,
} from "./dependency-review-queue.js";
import { z } from "zod";
import {
  DependencyAttemptStore,
  dependencyRecordHash,
  type StoredClaim,
} from "./dependency-attempt-store.js";
import {
  dependencyFindingDetailsShape,
  dependencyPlaceSchema,
  type DependencyReviewReference,
} from "./dependency-reachability.js";
import {
  dependencyGitCommitSchema,
  readDependencySourceCitation,
} from "./dependency-source-identity.js";
import type { discoverDependencyRepository } from "./dependency-discovery.js";
import {
  investigationServer,
  type DependencyEvidenceRecord,
} from "./dependency-evidence-sources.js";
import { dependencyPremiseRefSchema } from "./dependency-review-queue.js";
import {
  dependencyEvidencePayload,
  bindReceiptSelections,
  dependencyReceiptSelectionSchema,
  selectedReceiptReference,
  selectedReceiptKey,
  selectedReceiptValue,
  type DependencyReceiptSelection,
  selectDependencyEvidenceField,
} from "./dependency-graph-evidence.js";
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
  commit: dependencyGitCommitSchema
    .optional()
    .describe(
      "Omit to cite the checkout under investigation; use an immutable commit for historical context.",
    ),
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
  supports: z
    .array(
      z.enum(["running", "access", "affected_copy", "exclusion", "context"]),
    )
    .length(1),
  quote: text,
  reason: text,
});
const proposedUse = z.strictObject({
  scope: text,
  premises: z.array(dependencyPremiseRefSchema).optional(),
  component: text
    .optional()
    .describe(
      "Actual selected dependency. If this is an embedded or vendored component, cite this caller's selection of its containing artifact and the component name and version inside that artifact.",
    ),
  place: dependencyPlaceSchema
    .partial()
    .optional()
    .describe(
      "Structured deployment scope and dependency selection established by this use's citations.",
    ),
  ...dependencyFindingDetailsShape,
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
  receiptSelections: z.array(dependencyReceiptSelectionSchema).optional(),
  proof: dependencyUseProofSchema,
  remainingQuestions: z.array(text),
});
export const investigationSchema = z.strictObject({
  outOfScope: z.array(z.strictObject({ scope: text, reason: text })).optional(),
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
      evidenceKeys: z
        .array(text)
        .describe(
          "Choose only the source, receipt or approved premise IDs that decided this claim. Use [] for a coverage-only decision.",
        ),
      reason: text,
    }),
  ),
});
export type Decision = z.infer<typeof reviewSchema>["decisions"][number];
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
    const args = record.arguments;
    if (
      !isRecord(args) ||
      args["server"] !== record.server ||
      typeof args["uri"] !== "string"
    )
      return false;
    const truncated = /…\d+ (?:tokens|chars) truncated…/u;
    const matchesResource = (entries: unknown) =>
      Array.isArray(entries) &&
      entries.some(
        (item: unknown) =>
          isRecord(item) &&
          item["uri"] === args["uri"] &&
          typeof item["text"] === "string" &&
          !truncated.test(item["text"]) &&
          item["text"].includes(quote),
      );
    // Native clients deliver contents directly. Codex's built-in tool wraps the
    // response and request metadata together in a JSON text block.
    if (matchesResource(result["contents"])) return true;
    if (!Array.isArray(content)) return false;
    return content.some((block: unknown) => {
      if (
        !isRecord(block) ||
        block["type"] !== "text" ||
        typeof block["text"] !== "string" ||
        truncated.test(block["text"])
      )
        return false;
      try {
        const response: unknown = JSON.parse(block["text"]);
        return (
          isRecord(response) &&
          response["server"] === record.server &&
          response["uri"] === args["uri"] &&
          matchesResource(response["contents"])
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
  return containsJsonQuote(data, quote);
}

function containsJsonQuote(data: unknown, quote: string) {
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

/** A parent's version elsewhere in an inventory cannot select the embedded copy. */
function identifiesEmbeddedCopy(
  excerpt: string,
  component: string,
  version: string | null,
) {
  if (!version) return mentions(excerpt.toLowerCase(), component.toLowerCase());
  // Match package declarations and prose naming a version immediately after the
  // component, including adjacent name/version fields in a structured inventory.
  const literal = (value: string) =>
    value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const named = new RegExp(
    String.raw`(?<![\p{L}\p{N}_.+/-])${literal(component)}["'\s:@=,_-]+(?:["']?(?:upstream[_-]?)?version["'\s:=]+)?v?${literal(version)}(?![\p{L}\p{N}_+~-]|\.[\p{L}\p{N}])`,
    "iu",
  );
  if (named.test(excerpt)) return true;
  // JSON fields may appear in either order, with other metadata between them.
  for (const match of excerpt.matchAll(/\{[^{}]*\}/gu)) {
    try {
      const entry: unknown = JSON.parse(match[0]);
      if (
        isRecord(entry) &&
        ["name", "component", "package", "library"].some(
          (key) =>
            typeof entry[key] === "string" &&
            entry[key].toLowerCase() === component.toLowerCase(),
        ) &&
        entry["version"] === version
      )
        return true;
    } catch {
      /* Non-JSON build source uses the package declaration above. */
    }
  }
  return false;
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
    use.component ?? scope.component,
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
  callerScope?: string,
) {
  const revision = scope.discovery.revision;
  const component = use.component ?? scope.component;
  const embedded = component !== scope.component;
  if (
    !embedded &&
    scope.selectedVersion &&
    use.version !== scope.selectedVersion
  )
    throw new CodexSecurityError(
      `The version for ${scope.location} differs from its selected dependency version.`,
    );
  const evidence = await Promise.all(
    use.evidence.map(async ({ supports, commit, ...range }) => ({
      ...(await readDependencySourceCitation(
        directory,
        commit ?? revision,
        range,
        signal,
      )),
      supports,
    })),
  );
  if (
    evidence.some(
      (ref) =>
        ref.commit !== revision &&
        ref.supports.some((fact) => fact !== "context"),
    )
  )
    throw new CodexSecurityError(
      "Historical citations can explain a change. Cite the selected checkout for facts about its affected copy, use, or exclusion.",
    );
  if (embedded) {
    // A containing distribution and the library in its wheel or binary have
    // independently selected versions. Bind the nested identity to original
    // source before letting review decide the caller and advisory relationship.
    const byPath = new Map<string, string[]>();
    for (const ref of evidence) {
      if (ref.commit !== revision) continue;
      const excerpts = byPath.get(ref.path) ?? [];
      excerpts.push(ref.excerpt);
      byPath.set(ref.path, excerpts);
    }
    const excerpts = [...byPath.values()].map((lines) => lines.join("\n"));
    const parents = excerpts.filter((text) => {
      const name = text.toLowerCase().includes(scope.component.toLowerCase());
      // A filename can delimit its version with "-" rather than quotes.
      const version = scope.selectedVersion;
      return (
        name &&
        (!version ||
          mentions(text, version) ||
          mentions(text.replaceAll(/[-/@]/gu, " "), version))
      );
    });
    const bound = excerpts.some(
      (source) =>
        identifiesEmbeddedCopy(source, component, use.version) &&
        parents.some(
          (parent) =>
            parent === source ||
            source
              .match(/\b[a-f0-9]{64}\b/giu)
              ?.some((digest) => parent.includes(digest)),
        ),
    );
    if (!bound)
      throw new CodexSecurityError(
        "Cite the selected parent artifact or build and the embedded dependency and version it contains. Join separate records by their artifact digest.",
      );
  }
  const covers = (path: string | undefined, line: number | undefined) =>
    path !== undefined &&
    line !== undefined &&
    evidence.some(
      (ref) =>
        ref.commit === revision &&
        ref.path === path &&
        ref.startLine <= line &&
        line <= ref.endLine,
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
    if (
      ref.server === investigationServer &&
      ref.supports.some((s) => s === "running" || s === "access")
    )
      throw new CodexSecurityError(
        "Local investigation tool results cannot establish that a deployment ran or accepted an external caller.",
      );
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
  if (use.place?.revision && use.place.revision !== revision)
    throw new CodexSecurityError(
      "The reported place revision must agree with the selected checkout.",
    );
  if (use.place?.deploymentBasis === "observed" && !running.length)
    throw new CodexSecurityError(
      "An observed deployment requires a recorded running observation.",
    );
  if (
    use.place?.deploymentBasis === "assumed_not_deployed" &&
    (!use.place.deploymentDetail ||
      !callerScope?.includes(use.place.deploymentDetail) ||
      running.length)
  )
    throw new CodexSecurityError(
      "An assumption that the use is not deployed must identify the caller-supplied boundary.",
    );
  const selections: DependencyReceiptSelection[] = [
    ...(use.receiptSelections ?? []),
  ];
  function originalReference(ref: DependencyReviewReference): boolean {
    if (ref.kind === "source")
      return evidence.some(
        (source) =>
          source.path === ref.path &&
          source.commit === (ref.commit ?? revision) &&
          source.startLine <= ref.startLine &&
          ref.startLine <= ref.endLine &&
          ref.endLine <= source.endLine,
      );
    if (
      !observations.some(
        (r) =>
          r.sha256 === ref.receiptId &&
          r.originalPayloadSha256 === ref.originalPayloadSha256,
      )
    )
      return false;
    if (!ref.selection) return true;
    selections.push({ receiptId: ref.receiptId, ...ref.selection });
    const original = records.find((r) => r.sha256 === ref.receiptId)!;
    const payload = dependencyEvidencePayload(
      original,
      ref.selection.textBlock,
    );
    return (
      selectDependencyEvidenceField(payload, ref.selection.record) !== undefined
    );
  }
  const checkReferences = (
    refs: readonly DependencyReviewReference[] | undefined,
  ) => {
    if (refs?.some((ref) => !originalReference(ref)))
      throw new CodexSecurityError(
        "Reviewed finding details must cite source ranges or recorded receipts belonging to this use.",
      );
  };
  for (const attached of [
    ...(use.services ?? []),
    ...(use.inspections ?? []),
    ...(use.tags ?? []),
    use.inputSource,
    use.runtimeContext,
  ])
    checkReferences(attached?.evidence);
  for (const condition of use.openConditions ?? [])
    checkReferences(condition.assignee?.evidence);
  const recordById = new Map(records.map((r) => [r.sha256, r]));
  const boundReceipts = bindReceiptSelections(selections, (id) =>
    recordById.get(id),
  );
  const linkedObservations = observations.map((observation) => {
    const candidates = boundReceipts.filter(
      (row) => row.receiptId === observation.sha256,
    );
    if (!candidates.length) return { ...observation, evidenceKeys: undefined };
    const evidenceKeys = candidates
      .filter((row) => {
        const selected = selectedReceiptValue(
          recordById.get(row.receiptId)!,
          row.selection,
        );
        return containsJsonQuote(selected, observation.quote);
      })
      .map(selectedReceiptKey);
    if (!evidenceKeys.length)
      throw new CodexSecurityError(
        "The quoted observation is outside this use's selected receipt rows.",
      );
    return { ...observation, evidenceKeys };
  });
  const location = verifiedLocation(scope, use, running, covers);
  const names = [location, ...scope.runtimeServices].filter(
    (name) => name !== ".",
  );
  if (
    running.length &&
    (!use.version ||
      ![revision, component, use.version].every((id) =>
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
    if (!embedded && affectedVersion === false)
      throw new CodexSecurityError(
        `The frozen advisory excludes version ${use.version} of ${component}.`,
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
    !embedded &&
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
    observations: linkedObservations,
    ...(boundReceipts.length && { boundReceipts }),
    location,
    component,
    revision,
  };
}

export type VerifiedUse = Awaited<ReturnType<typeof verifyProposedUse>>;
type ReviewClaim =
  | Premise
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
  const byId = new Map(decisions.map((row) => [row.id, row]));
  if (decisions.length !== claims.length || byId.size !== claims.length)
    throw new CodexSecurityError(
      "Independent review must decide every claim exactly once.",
    );
  const reviewed = store.transaction(() =>
    claims.map((claim) => {
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
      const { sourceIds, receiptKeys, dependencies } = claimInputs(claim);
      assertReviewedPremises(store, dependencies);
      const allowed = new Set([
        ...sourceIds,
        ...receiptKeys,
        ...dependencies.map(premiseKey),
      ]);
      if (
        new Set(decision.evidenceKeys).size !== decision.evidenceKeys.length ||
        decision.evidenceKeys.some((key) => !allowed.has(key)) ||
        (decision.approved && allowed.size > 0 && !decision.evidenceKeys.length)
      )
        throw new DependencyReviewRejection(
          "Reviewer must select the deciding evidence from this claim's original evidence or approved premises: " +
            claim.id,
        );
      const use = claim.value.kind === "use" ? claim.value.use : undefined;
      if (
        decision.approved &&
        use?.verdict === "exploitable" &&
        ["running", "access"].some(
          (support) =>
            !use.observations.some(
              (r) =>
                r.supports.some((s) => s === support) &&
                (r.evidenceKeys ?? [r.sha256]).some((key) =>
                  decision.evidenceKeys.includes(key),
                ),
            ),
        )
      )
        throw new DependencyReviewRejection(
          "A positive review must select evidence for the running build and caller access.",
        );
      store.set("dependency-review", claim.id, decision);
      return { ...reference(current), value: current.value, review: decision };
    }),
  );
  const rejected = reviewed.filter((c) => !c.review.approved);
  if (rejected.length)
    throw new DependencyReviewRejection(
      rejected
        .map(
          (c) => "Independent review rejected " + c.id + ": " + c.review.reason,
        )
        .join("\n"),
    );
  return reviewed;
}

export function reportedUse(
  use: VerifiedUse,
  claim: Claim,
  evidenceKeys?: readonly string[],
  premiseEvidence: readonly DependencyReviewReference[] = [],
) {
  const running = use.observations.some((ref) =>
    ref.supports.includes("running"),
  );
  const decidingEvidence: DependencyReviewReference[] = [
    ...use.evidence
      .filter(
        (ref) =>
          !evidenceKeys || evidenceKeys.includes(dependencyRecordHash(ref)),
      )
      .map(({ path, commit, startLine, endLine }) => ({
        kind: "source" as const,
        path,
        commit,
        startLine,
        endLine,
      })),
    ...use.observations
      .filter(
        (ref) =>
          !ref.evidenceKeys &&
          (!evidenceKeys || evidenceKeys.includes(ref.sha256)),
      )
      .map((ref) => ({
        kind: "receipt" as const,
        receiptId: ref.sha256,
        originalPayloadSha256: ref.originalPayloadSha256,
      })),
    ...(use.boundReceipts ?? [])
      .filter(
        (row) =>
          !evidenceKeys || evidenceKeys.includes(selectedReceiptKey(row)),
      )
      .map(selectedReceiptReference),
    ...premiseEvidence,
  ];
  return {
    location: use.location,
    component: use.component,
    version: use.version,
    verdict: use.verdict,
    reason: use.reason,
    deployment: running
      ? ("confirmed" as const)
      : use.configured || use.place?.deploymentBasis === "configured"
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
      record: ref.quote,
      supports: ref.supports.filter(
        (s) => s === "running" || s === "access" || s === "affected_copy",
      ),
    })),
    ...(use.services && { services: use.services }),
    ...(use.openConditions && { openConditions: use.openConditions }),
    ...(use.inspections && { inspections: use.inspections }),
    ...(use.inputSource && { inputSource: use.inputSource }),
    ...(use.runtimeContext && { runtimeContext: use.runtimeContext }),
    ...(use.tags && { tags: use.tags }),
    place: {
      kind: use.placeKind ?? "unknown",
      environment: null,
      artifact: null,
      observationWindow: null,
      deploymentBasis: running
        ? ("observed" as const)
        : use.configured || use.place?.deploymentBasis === "configured"
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
      ...use.place,
      ...(running && { deploymentBasis: "observed" as const }),
      revision: use.revision,
      unresolvedQuestions: [
        ...new Set([
          ...use.remainingQuestions,
          ...(use.place?.unresolvedQuestions ?? []),
        ]),
      ],
    },
    proof: use.proof,
    decidingEvidence: [
      ...new Map(
        decidingEvidence.map((ref) => [dependencyRecordHash(ref), ref]),
      ).values(),
    ],
    conclusionClaim: reference(claim),
  };
}
