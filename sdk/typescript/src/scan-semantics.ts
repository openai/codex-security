import { createHash } from "node:crypto";
export type JsonObject = Record<string, unknown>;

export interface SemanticScan {
  scanId: string;
  complete?: boolean;
  handoffClaimToken?: string;
  scope?: JsonObject;
  threatModel?: JsonObject;
  findings: JsonObject[];
  coverage: JsonObject;
}

/** Project canonical documents into the same semantic input used by normal drafts. */
export function semanticScanDraft(
  scanId: string,
  scan: JsonObject,
  findings: JsonObject[],
  coverage: JsonObject,
): SemanticScan {
  const scope = isObject(scan["scope"])
    ? structuredClone(scan["scope"])
    : undefined;
  if (scope) {
    delete scope["includePaths"];
    delete scope["excludePaths"];
  }
  const semanticCoverage = structuredClone(coverage);
  for (const field of [
    "documentType",
    "schemaVersion",
    "scanId",
    "mode",
    "includePaths",
    "excludePaths",
    "receiptRefs",
    "inventoryStrategy",
  ])
    delete semanticCoverage[field];
  return {
    scanId,
    ...(scan["complete"] === false ? { complete: false } : {}),
    ...(scope && Object.keys(scope).length > 0 ? { scope } : {}),
    ...(isObject(scan["threatModel"])
      ? { threatModel: structuredClone(scan["threatModel"]) }
      : {}),
    findings: findings.map((finding) => {
      const semantic = structuredClone(finding);
      for (const field of ["findingId", "occurrenceId", "fingerprints"])
        delete semantic[field];
      return semantic;
    }),
    coverage: semanticCoverage,
  };
}

function withoutPreviousFindings(finding: JsonObject): JsonObject {
  const result = structuredClone(finding);
  if (isObject(result["provenance"]))
    delete result["provenance"]["previousFindings"];
  return result;
}

/** Preserve both original sources and details synthesized after those sources. */
export function preserveFindingDetails(
  current: JsonObject,
  previous: JsonObject,
): void {
  if (current["identity"] === undefined && previous["identity"] !== undefined) {
    current["identity"] = structuredClone(previous["identity"]);
  }
  const provenance = requireObject(
    current["provenance"],
    "saved finding provenance",
  );
  const oldProvenance = isObject(previous["provenance"])
    ? previous["provenance"]
    : {};
  for (const field of [
    "sourceFindingIds",
    "sourceFindings",
    "previousFindings",
    "originalCandidates",
  ] as const) {
    const values = exactUnion(
      Array.isArray(provenance[field]) ? provenance[field] : [],
      Array.isArray(oldProvenance[field]) ? oldProvenance[field] : [],
    );
    if (values.length) provenance[field] = values;
  }
  if (!containsSavedFinding(current, previous)) {
    const original = withoutPreviousFindings(previous);
    if (isObject(original["provenance"]))
      delete original["provenance"]["sourceFindings"];
    provenance["previousFindings"] = exactUnion(
      Array.isArray(provenance["previousFindings"])
        ? provenance["previousFindings"]
        : [],
      [original],
    );
  }
}

export function containsSavedFinding(
  current: JsonObject,
  previous: JsonObject,
): boolean {
  const original = withoutPreviousFindings(previous);
  if (current["identity"] === undefined) delete original["identity"];
  return containsSavedValue(current, original);
}

export function containsSavedValue(
  current: unknown,
  previous: unknown,
): boolean {
  if (Array.isArray(previous)) {
    return (
      Array.isArray(current) &&
      previous.every((value) =>
        current.some((entry) => containsSavedValue(entry, value)),
      )
    );
  }
  if (isObject(previous)) {
    return (
      isObject(current) &&
      Object.entries(previous).every(([key, value]) =>
        containsSavedValue(current[key], value),
      )
    );
  }
  return current === previous;
}

export function exactUnion<Value>(...groups: Value[][]): Value[] {
  const seen = new Set<string>();
  return groups.flat().filter((value) => {
    const key = JSON.stringify(value);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function scanFindingIdentity(finding: JsonObject): string {
  const identity = finding["identity"] as JsonObject | undefined;
  if (identity)
    return JSON.stringify([
      finding["ruleId"],
      identity["anchor"],
      identity["instance"] ?? null,
    ]);
  const location = (finding["locations"] as JsonObject[])[0]!;
  return JSON.stringify([
    finding["ruleId"],
    location["path"],
    location["startLine"],
    location["endLine"] ?? null,
  ]);
}

export function validateFindingSemantics(findings: JsonObject[]): void {
  for (const [findingIndex, finding] of findings.entries()) {
    const severity = finding["severity"] as JsonObject;
    if (
      severity["score"] !== undefined &&
      typeof severity["scoringSystem"] !== "string"
    ) {
      throw new Error(
        `scan draft: findings[${findingIndex}].severity.scoringSystem is required with severity.score.`,
      );
    }

    const locations = finding["locations"] as JsonObject[];
    for (const [locationIndex, location] of locations.entries()) {
      if (
        typeof location["endLine"] === "number" &&
        location["endLine"] < (location["startLine"] as number)
      ) {
        throw new Error(
          `scan draft: findings[${findingIndex}].locations[${locationIndex}].endLine ` +
            "must not precede startLine.",
        );
      }
    }

    const evidenceIds = new Set<string>();
    for (const [evidenceName, evidenceCatalog] of [
      ["codeEvidence", finding["codeEvidence"]],
      ["code_evidence", finding["code_evidence"]],
    ] as const) {
      for (const [evidenceIndex, evidence] of (
        (evidenceCatalog as JsonObject[] | undefined) ?? []
      ).entries()) {
        const id = evidence["id"] as string;
        if (evidenceIds.has(id)) {
          throw new Error(
            `scan draft: findings[${findingIndex}].${evidenceName}[${evidenceIndex}].id ` +
              `duplicates ${id}.`,
          );
        }
        evidenceIds.add(id);
        if (
          typeof evidence["endLine"] === "number" &&
          evidence["endLine"] < (evidence["startLine"] as number)
        ) {
          throw new Error(
            `scan draft: findings[${findingIndex}].${evidenceName}[${evidenceIndex}].endLine ` +
              "must not precede startLine.",
          );
        }
      }
    }

    const referencedSections: Array<[string, unknown]> = [
      ["rootCause", finding["rootCause"]],
      ["root_cause", finding["root_cause"]],
      ["validation", finding["validation"]],
      ["attackPath", finding["attackPath"]],
    ];
    if (isObject(finding["attackPath"])) {
      for (const sectionName of [
        "dataFlow",
        "dataflow",
        "data_flow",
        "reachability",
      ]) {
        referencedSections.push([
          `attackPath.${sectionName}`,
          finding["attackPath"][sectionName],
        ]);
      }
    }
    for (const [sectionName, section] of referencedSections) {
      if (!isObject(section)) continue;
      for (const referencesName of ["evidenceRefs", "evidence_refs"]) {
        const references = section[referencesName];
        if (references === undefined) continue;
        if (
          !Array.isArray(references) ||
          references.some(
            (reference) =>
              typeof reference !== "string" || !evidenceIds.has(reference),
          )
        ) {
          throw new Error(
            `scan draft: findings[${findingIndex}].${sectionName}.${referencesName} ` +
              "must refer to that finding's existing code-evidence IDs.",
          );
        }
      }
    }
  }
}

export function validateCoverageSemantics(coverage: JsonObject): void {
  if (coverage["completeness"] !== "complete") return;
  if ((coverage["deferred"] as unknown[]).length > 0) {
    throw new Error(
      "scan draft: complete coverage cannot contain deferred work.",
    );
  }
  if (
    (coverage["surfaces"] as JsonObject[]).some(
      (surface) => surface["disposition"] === "needs_follow_up",
    )
  ) {
    throw new Error(
      "scan draft: complete coverage cannot contain needs_follow_up surfaces.",
    );
  }
}

export function requireObject(value: unknown, context: string): JsonObject {
  if (!isObject(value)) throw new Error(`${context} must be an object.`);
  return value;
}

export function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export interface SemanticScanContext {
  targetContract?: Readonly<JsonObject>;
  mode?: string;
  scope?: string;
  targetRevision?: string;
}

export interface PreparedScanDraft {
  manifest: JsonObject;
  findings: JsonObject;
  coverage: JsonObject;
}

/** Build ordinary canonical documents from host-bound target metadata and validated semantics. */
export function prepareSemanticScanDraft(
  context: SemanticScanContext,
  input: SemanticScan,
  hardening?: { portfolioPath: "hardening/hardening.md" },
): PreparedScanDraft {
  const contract = requireObject(
    context.targetContract,
    "scan draft: authoritative target contract",
  );
  const trustedTarget = requireObject(
    contract["target"],
    "scan draft: authoritative target",
  );
  const trustedScope = requireObject(
    contract["scope"],
    "scan draft: authoritative scope",
  );
  const target = buildTarget(context, contract, trustedTarget);
  const scope = buildScope(context, trustedScope, input.scope);
  return {
    findings: { findings: prepareScanFindings(input.findings, context.mode) },
    coverage: buildCoverage(context, contract, input.coverage, scope, target),
    manifest: {
      scan: {
        ...(input.complete === false ? { complete: false } : {}),
        target,
        scope,
        ...(input.threatModel === undefined
          ? {}
          : { threatModel: input.threatModel }),
        ...(hardening === undefined ? {} : { hardening }),
      },
    },
  };
}

function buildTarget(
  context: SemanticScanContext,
  contract: JsonObject,
  trustedTarget: JsonObject,
): JsonObject {
  const allowedKinds = trustedTarget["allowedKinds"];
  if (
    !Array.isArray(allowedKinds) ||
    !allowedKinds.length ||
    !allowedKinds.every((kind) => typeof kind === "string")
  ) {
    throw new Error(
      "scan draft: the authoritative target has no allowed target kind.",
    );
  }
  if (
    typeof trustedTarget["targetId"] !== "string" ||
    !trustedTarget["targetId"] ||
    typeof trustedTarget["displayName"] !== "string" ||
    !trustedTarget["displayName"]
  ) {
    throw new Error(
      "scan draft: the authoritative target identity is incomplete.",
    );
  }

  const target: JsonObject = {
    kind: allowedKinds[0],
    targetId: trustedTarget["targetId"],
    displayName: trustedTarget["displayName"],
  };
  if (context.mode === "diff") {
    const diffTarget = requireObject(
      contract["diffTarget"],
      "scan draft: authoritative diff target",
    );
    for (const field of ["baseRevision", "headRevision"] as const) {
      const value = diffTarget[field];
      if (typeof value !== "string" || !value) {
        throw new Error(
          `scan draft: authoritative diff target is missing ${field}.`,
        );
      }
      target[field] = value;
    }
    if (diffTarget["kind"] === "working_tree") {
      if (
        typeof diffTarget["contentDigest"] !== "string" ||
        !diffTarget["contentDigest"]
      ) {
        throw new Error(
          "scan draft: authoritative working-tree target has no snapshot digest.",
        );
      }
      target["snapshotDigest"] = diffTarget["contentDigest"];
    } else if (
      diffTarget["kind"] === "commit" ||
      diffTarget["kind"] === "range"
    ) {
      const digest = createHash("sha256")
        .update("codex-security-diff/v1\0")
        .update(diffTarget["kind"])
        .update("\0")
        .update(target["baseRevision"] as string)
        .update("\0")
        .update(target["headRevision"] as string)
        .digest("hex");
      target["snapshotDigest"] = `codex-security-snapshot/v1:sha256:${digest}`;
    } else {
      throw new Error(
        "scan draft: the authoritative diff target kind is invalid.",
      );
    }
  } else {
    if (context.targetRevision && context.targetRevision !== "unversioned") {
      target["revision"] = context.targetRevision;
    }
    if (trustedTarget["requiredSnapshotDigest"] !== undefined) {
      if (
        typeof trustedTarget["requiredSnapshotDigest"] !== "string" ||
        !trustedTarget["requiredSnapshotDigest"]
      ) {
        throw new Error(
          "scan draft: the authoritative target snapshot digest is invalid.",
        );
      }
      target["snapshotDigest"] = trustedTarget["requiredSnapshotDigest"];
    }
  }
  return target;
}

function buildScope(
  context: SemanticScanContext,
  trustedScope: JsonObject,
  semanticScope?: JsonObject,
): JsonObject {
  const includePaths = trustedScope["requiredIncludePaths"];
  const excludePaths = trustedScope["requiredExcludePaths"];
  const resolvedIncludePaths =
    includePaths === undefined
      ? [
          typeof trustedScope["requestedPath"] === "string"
            ? trustedScope["requestedPath"]
            : (context.scope ?? "."),
        ]
      : requireTextArray(
          includePaths,
          "scan draft: authoritative included scope",
        );
  const resolvedExcludePaths =
    excludePaths === undefined
      ? []
      : requireTextArray(
          excludePaths,
          "scan draft: authoritative excluded scope",
        );

  return {
    ...semanticScope,
    includePaths: resolvedIncludePaths,
    excludePaths: resolvedExcludePaths,
  };
}

export function prepareScanFindings(
  findings: JsonObject[],
  mode?: string,
): JsonObject[] {
  const generatedIdentities = findings.map((finding, index) => {
    if (finding["identity"] !== undefined) return undefined;
    const candidateId = (finding["extensions"] as JsonObject | undefined)?.[
      "candidateId"
    ];
    const identitySource =
      typeof candidateId === "string" && candidateId.trim()
        ? candidateId
        : (finding["title"] as string);
    const extensions = finding["extensions"] as JsonObject | undefined;
    const siblingSource = [
      extensions?.["reportId"],
      extensions?.["ledgerRowId"],
    ].find(
      (value): value is string =>
        typeof value === "string" && Boolean(value.trim()),
    );
    return {
      anchor: semanticIdentifier(identitySource, `finding-${index + 1}`),
      stableInstanceSource: siblingSource,
      siblingSource: siblingSource ?? (finding["title"] as string),
    };
  });
  const anchorCounts = new Map<string, number>();
  for (const [index, finding] of findings.entries()) {
    const generatedIdentity = generatedIdentities[index];
    const authoredIdentity = finding["identity"] as JsonObject | undefined;
    const anchor =
      generatedIdentity?.anchor ?? (authoredIdentity?.["anchor"] as string);
    const ruleScopedAnchor = `${finding["ruleId"]}\0${anchor}`;
    anchorCounts.set(
      ruleScopedAnchor,
      (anchorCounts.get(ruleScopedAnchor) ?? 0) + 1,
    );
  }

  const identified: JsonObject[] = findings.map((finding, index) => {
    const generatedIdentity = generatedIdentities[index];
    if (generatedIdentity === undefined) return { ...finding };
    const identity: JsonObject = { anchor: generatedIdentity.anchor };
    const ruleScopedAnchor = `${finding["ruleId"]}\0${generatedIdentity.anchor}`;
    if (
      generatedIdentity.stableInstanceSource !== undefined ||
      (anchorCounts.get(ruleScopedAnchor) ?? 0) > 1
    ) {
      const baseInstance = semanticIdentifier(
        generatedIdentity.siblingSource,
        `finding-${index + 1}`,
      );
      identity["instance"] = baseInstance;
    }
    return {
      ...finding,
      identity,
    };
  });
  if (mode !== "deep") return identified;

  // Keep distinct findings when independent scans reuse an ID.
  // Add a numeric suffix to make each ID unique.
  const reserved = new Set(identified.map(scanFindingIdentity));
  const used = new Set<string>();
  return identified.map((finding) => {
    const key = scanFindingIdentity(finding);
    if (!used.has(key)) {
      used.add(key);
      return finding;
    }
    const identity = finding["identity"] as JsonObject;
    const baseInstance = identity["instance"] ?? "saved";
    let suffix = 2;
    const distinct: JsonObject & { identity: JsonObject } = {
      ...finding,
      identity: { ...identity },
    };
    do {
      distinct.identity["instance"] = `${baseInstance}-${suffix}`;
      suffix += 1;
    } while (
      reserved.has(scanFindingIdentity(distinct)) ||
      used.has(scanFindingIdentity(distinct))
    );
    const provenance = finding["provenance"] as JsonObject;
    distinct["provenance"] = {
      ...provenance,
      preservedIdentity:
        provenance["preservedIdentity"] ?? structuredClone(identity),
    };
    used.add(scanFindingIdentity(distinct));
    return distinct;
  });
}

function buildCoverage(
  context: SemanticScanContext,
  contract: JsonObject,
  semanticCoverage: JsonObject,
  scope: JsonObject,
  target: JsonObject,
): JsonObject {
  const surfaces = semanticCoverage["surfaces"] as JsonObject[];
  const reservedSurfaceIds = new Set(
    surfaces.flatMap((surface) =>
      typeof surface["id"] === "string" ? [surface["id"]] : [],
    ),
  );
  const surfaceIds = new Set<string>();
  const normalizedSurfaces = surfaces.map((surface, index) => {
    const explicitId = typeof surface["id"] === "string";
    const baseId = explicitId
      ? (surface["id"] as string)
      : `surface_${semanticIdentifier(surface["label"] as string, String(index + 1))}`;
    let id = baseId;
    if (surfaceIds.has(id) || (!explicitId && reservedSurfaceIds.has(id))) {
      let suffix = 2;
      do {
        id = `${baseId}-${suffix}`;
        suffix += 1;
      } while (surfaceIds.has(id) || reservedSurfaceIds.has(id));
    }
    surfaceIds.add(id);
    return {
      ...surface,
      id,
      receiptRefs: surface["receiptRefs"] ?? [],
    };
  });
  const deferred = semanticCoverage["deferred"] as JsonObject[];
  // Reserve later owned identities before deriving any earlier missing ones.
  const deferredIds = new Set(
    deferred.flatMap((item) =>
      typeof item["id"] === "string" ? [item["id"]] : [],
    ),
  );
  const reservedCandidateIds = new Set(
    deferred.flatMap((item) =>
      typeof item["candidateId"] === "string" ? [item["candidateId"]] : [],
    ),
  );
  const normalizedDeferred = deferred.map((item) => {
    if (typeof item["id"] === "string") return item;

    const candidateId = item["candidateId"];
    const baseId =
      typeof candidateId === "string"
        ? candidateId
        : `deferred-${createHash("sha256")
            .update(
              JSON.stringify([
                item["reason"],
                item["paths"] ?? [],
                item["surfaceIds"] ?? [],
              ]),
            )
            .digest("hex")
            .slice(0, 16)}`;
    let id = baseId;
    let suffix = 2;
    while (
      deferredIds.has(id) ||
      (typeof candidateId !== "string" && reservedCandidateIds.has(id))
    ) {
      id = `${baseId}-${suffix}`;
      suffix += 1;
    }
    deferredIds.add(id);
    return { ...item, id };
  });
  const openQuestions = semanticCoverage["openQuestions"] as
    Array<string | JsonObject> | undefined;

  return {
    ...semanticCoverage,
    mode: coverageMode(context, contract),
    inventoryStrategy: inventoryStrategy(context, scope, target),
    includePaths: scope["includePaths"],
    excludePaths: scope["excludePaths"],
    surfaces: normalizedSurfaces,
    deferred: normalizedDeferred,
    ...(openQuestions === undefined
      ? {}
      : {
          openQuestions: openQuestions.map((question) =>
            typeof question === "string"
              ? { question: question.trim() }
              : question,
          ),
        }),
  };
}

function coverageMode(
  context: SemanticScanContext,
  contract: JsonObject,
): string {
  if (context.mode === "diff") {
    const diff = requireObject(
      contract["diffTarget"],
      "scan draft: authoritative diff target",
    );
    const modes: Record<string, string> = {
      commit: "commit",
      range: "branch_diff",
      working_tree: "working_tree",
    };
    const mode = modes[String(diff["kind"])];
    if (!mode)
      throw new Error(
        "scan draft: the authoritative diff coverage mode is invalid.",
      );
    return mode;
  }

  const trustedScope = requireObject(
    contract["scope"],
    "scan draft: authoritative scope",
  );
  const includes = trustedScope["requiredIncludePaths"];
  const scoped = Array.isArray(includes)
    ? includes.length !== 1 || includes[0] !== "."
    : typeof trustedScope["requestedPath"] === "string" &&
      trustedScope["requestedPath"] !== ".";
  if (scoped) return "scoped_path";
  return context.mode === "deep" ? "deep_repository" : "repository";
}

function inventoryStrategy(
  context: SemanticScanContext,
  scope: JsonObject,
  target: JsonObject,
): string {
  if (context.mode === "diff") return "diff";
  const includePaths = scope["includePaths"] as string[];
  if (includePaths.length !== 1 || includePaths[0] !== ".")
    return "scoped_path";
  if (context.mode === "deep") return "repository";
  if (target["kind"] === "directory_snapshot") return "directory";
  return "repository";
}

function requireTextArray(value: unknown, context: string): string[] {
  if (
    !Array.isArray(value) ||
    value.some((entry) => typeof entry !== "string" || !entry)
  ) {
    throw new Error(`${context} must contain an array of nonempty paths.`);
  }
  return [...value];
}

function semanticIdentifier(value: string, fallback: string): string {
  const identifier = value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/gu, "")
    .toLowerCase()
    .replace(/[^a-z0-9._/-]+/gu, "-")
    .replace(/^-+|-+$/gu, "");
  return identifier || fallback;
}
