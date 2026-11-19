import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { prepareContinuumAws } from "./continuum-aws.js";
import { selectFindingValidationArtifact } from "./continuum-validation-evidence.js";
import type { Finding } from "./models.js";
import {
  type ValidationProvider,
  type ValidationProviderAssessment,
  type ValidationProviderContext,
  type ValidationClaimMatch,
  unavailableAssessment,
} from "./validation-provider.js";

const execFileAsync = promisify(execFile);
const TERMINAL_WITHOUT_ISSUE = new Set(["DISCARDED", "NOT_PURSUED"]);
const MAX_CONCURRENT_POLLS = 4;

export type ContinuumAwsLauncher = (
  operation: string,
  args: readonly string[],
  signal?: AbortSignal,
) => Promise<Record<string, unknown>>;

export interface ContinuumValidationOptions {
  environmentId: string;
  awsProfile?: string;
  awsRegion?: string;
  waitMinutes?: number;
  consoleBaseUrl?: string;
  launcher?: ContinuumAwsLauncher;
  now?: () => Date;
  delay?: (milliseconds: number, signal?: AbortSignal) => Promise<void>;
}

type AnyFinding = Finding | Record<string, unknown>;

function object(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function text(value: unknown): string | undefined {
  if (typeof value === "string" && value.trim()) return value.trim();
  return undefined;
}

function safeText(value: unknown, limit = 320): string {
  return (text(value) ?? "not returned").replace(/\s+/gu, " ").slice(0, limit);
}

function severityLevel(finding: AnyFinding): string {
  const severity = object(finding["severity"]);
  return (
    text(severity["level"]) ??
    text(finding["severity"]) ??
    "unknown"
  ).toLowerCase();
}

function occurrence(finding: AnyFinding): string {
  return (
    text(finding["occurrenceId"]) ??
    text(finding["findingId"]) ??
    text(finding["id"]) ??
    "supplied-finding"
  );
}

function locations(finding: AnyFinding) {
  const detailed = Array.isArray(finding["codeEvidence"])
    ? finding["codeEvidence"]
    : [];
  const broad = Array.isArray(finding["locations"]) ? finding["locations"] : [];
  const suppliedLocation = text(finding["location"]);
  const fallback =
    broad.length > 0 || detailed.length > 0
      ? []
      : text(finding["path"] ?? finding["filePath"])
        ? [
            {
              path: text(finding["path"] ?? finding["filePath"]),
              startLine: finding["lineNumber"],
              endLine: finding["endLine"],
            },
          ]
        : suppliedLocation
          ? [
              (() => {
                const match = /^(.*?):(\d+)(?:-(\d+))?$/u.exec(
                  suppliedLocation,
                );
                return match
                  ? {
                      path: match[1],
                      startLine: Number(match[2]),
                      endLine: Number(match[3] ?? match[2]),
                    }
                  : { path: suppliedLocation };
              })(),
            ]
          : [];
  const priorities: Record<string, number> = {
    sink: 0,
    outcome: 0,
    root_control: 0,
    vulnerable: 0,
    source: 3,
    user_input: 3,
    entrypoint: 4,
  };
  return [...detailed, ...broad, ...fallback]
    .map((raw, index) => {
      const row = object(raw);
      const path = text(row["path"]) ?? text(row["filePath"]);
      const role = (text(row["role"]) ?? "").toLowerCase();
      return {
        path,
        start:
          typeof row["startLine"] === "number" ? row["startLine"] : undefined,
        end: typeof row["endLine"] === "number" ? row["endLine"] : undefined,
        role,
        priority: priorities[role] ?? (index < detailed.length ? 2 : 5),
        index,
      };
    })
    .filter((row): row is typeof row & { path: string } => !!row.path)
    .sort(
      (left, right) =>
        left.priority - right.priority || left.index - right.index,
    );
}

function severityId(level: string): number {
  return (
    (
      {
        unknown: 0,
        informational: 1,
        low: 2,
        medium: 3,
        high: 4,
        critical: 5,
      } as Record<string, number>
    )[level] ?? 0
  );
}

/** Convert a code finding to sink-first OCSF 2002. */
export function findingToOcsf(
  finding: AnyFinding,
  now = new Date(),
): Record<string, unknown> {
  const id = occurrence(finding);
  const title = text(finding["title"]) ?? id;
  const summary = text(finding["summary"]) ?? title;
  const selected = locations(finding);
  if (selected.length === 0)
    throw new Error(`${id} has no code location with real lines`);
  const affected = selected.map(({ path, start, end }) => ({
    file: { name: path.split("/").at(-1), path, type_id: 1 },
    ...(start === undefined ? {} : { start_line: start }),
    ...(end === undefined && start === undefined
      ? {}
      : { end_line: end ?? start }),
  }));
  const cwes = object(finding["taxonomy"])["cwe"];
  const firstCwe = Array.isArray(cwes) ? text(cwes[0]) : text(cwes);
  const vulnerability: Record<string, unknown> = {
    title,
    desc: summary,
    affected_code: affected,
    ...(firstCwe
      ? { cwe: { uid: firstCwe, caption: firstCwe } }
      : { advisory: { uid: id, classification: "Codex Security finding" } }),
  };
  return {
    activity_id: 1,
    category_uid: 2,
    class_uid: 2002,
    cloud: { provider: "AWS" },
    finding_info: { uid: id, title, desc: summary },
    metadata: {
      product: {
        name: "Codex Security",
        vendor_name: "OpenAI",
        version: "validation-provider/1",
      },
      version: "1.9.0",
    },
    message: summary,
    osint: [{ type_id: 0, value: "Codex Security finding" }],
    severity_id: severityId(severityLevel(finding)),
    time: now.getTime(),
    type_uid: 200201,
    vulnerabilities: [vulnerability],
  };
}

export function deterministicClientToken(
  environmentId: string,
  finding: AnyFinding,
): string {
  const sink = locations(finding)[0];
  const identity = JSON.stringify([
    "ocsf-v2",
    environmentId,
    occurrence(finding),
    sink?.path,
    sink?.start,
    sink?.end,
  ]);
  return `codex-${createHash("sha256").update(identity).digest("hex").slice(0, 40)}`;
}

function proofClaimMatch(
  proof: unknown,
  finding: AnyFinding,
): ValidationClaimMatch {
  const raw = JSON.stringify(proof).toLowerCase();
  const semantic = locations(finding).reduce(
    (value, { path }) => value.replaceAll(path.toLowerCase(), ""),
    raw,
  );
  const title = [
    finding["title"],
    finding["summary"],
    object(finding["taxonomy"])["category"],
  ]
    .map((value) => text(value)?.toLowerCase() ?? "")
    .join(" ");
  const concepts: Record<string, readonly string[]> = {
    injection: ["injection", "query", "template", "interpreter"],
    authorization: ["authorization", "cross-user", "ownership", "idor"],
    exposure: ["disclosure", "exposure", "secret", "credential"],
    availability: ["availability", "resource", "exhaust", "latency", "denial"],
  };
  const claim = new Set(
    Object.entries(concepts)
      .filter(([, words]) => words.some((word) => title.includes(word)))
      .map(([name]) => name),
  );
  const demonstrated = new Set(
    Object.entries(concepts)
      .filter(([, words]) => words.some((word) => semantic.includes(word)))
      .map(([name]) => name),
  );
  const pathMatch = locations(finding).some(({ path }) =>
    raw.includes(path.toLowerCase()),
  );
  const overlaps = [...claim].some((value) => demonstrated.has(value));
  if (claim.size === 0 || demonstrated.size === 0) return "unknown";
  if (
    (!pathMatch && !overlaps) ||
    (claim.size > 0 && demonstrated.size > 0 && !overlaps)
  )
    return "different_flaw";
  return [...demonstrated].some((value) => !claim.has(value))
    ? "on_target_escalated"
    : "on_target";
}

export const assessClaimMatch = proofClaimMatch;

function evidenceRows(artifact: Record<string, unknown>) {
  const body = object(artifact["body"]);
  const signals = object(body["prevalidationSignals"])["signals"];
  return Array.isArray(signals) ? signals.map(object) : [];
}

function severityFactors(
  reasoning: unknown,
  evidence?: Record<string, unknown>,
): string {
  const rows = evidence ? evidenceRows(evidence) : [];
  const likelihood = rows.find(
    (row) => text(row["dimension"]) === "LIKELIHOOD_ASSESSMENT",
  );
  const impact = rows.find(
    (row) => text(row["dimension"]) === "IMPACT_ASSESSMENT",
  );
  const likelihoodBand = text(
    object(likelihood?.["computed"])["likelihoodBand"],
  );
  const impactBand = text(object(impact?.["computed"])["impactBand"]);
  if (likelihoodBand && impactBand)
    return `likelihood ${safeText(likelihoodBand, 80)} × impact ${safeText(impactBand, 80)}`;

  const value = text(reasoning);
  if (!value) return "likelihood and impact not returned";
  const match =
    /likelihood\s*=\s*([^.;]+?)\s+x\s+impact\s*=\s*([^.;]+?)(?:\s*->|[.;]|$)/iu.exec(
      value,
    );
  return match
    ? `likelihood ${safeText(match[1], 80)} × impact ${safeText(match[2], 80)}`
    : safeText(value, 180);
}

function basisLabel(value: unknown): "GRAPH" | "CODE" | "INFERRED" {
  const raw = text(value) ?? "";
  if (/graph|inventory|deployment/iu.test(raw)) return "GRAPH";
  if (/source|code|finding/iu.test(raw)) return "CODE";
  return "INFERRED";
}

function evidenceSignal(artifact: Record<string, unknown>): string {
  const body = object(artifact["body"]);
  const prevalidation = object(body["prevalidationSignals"]);
  const rows = evidenceRows(artifact).filter(
    (row) => row["conclusion"] !== undefined,
  );
  const likelihood = rows.find(
    (row) => text(row["dimension"]) === "LIKELIHOOD_ASSESSMENT",
  );
  const preconditions = object(likelihood?.["preconditions"]);
  const selectedPrecondition = [
    "reachableFromAttacker",
    "configurationNeeded",
    "accessLevel",
    "userInteractionRequired",
  ]
    .map((name) => [name, object(preconditions[name])] as const)
    .find(([, row]) => row["value"] !== undefined);
  if (selectedPrecondition) {
    const [name, row] = selectedPrecondition;
    const rawBasis = row["basis"] ?? row["reason"];
    const basis = basisLabel(rawBasis);
    const reason = safeText(row["reason"], 180);
    return `Basis: ${basis} — ${name}: ${safeText(String(row["value"]), 80)} (${reason}).`;
  }

  const preferred =
    rows.find((row) =>
      /barrier|enabler|precondition|reach|control/iu.test(
        text(row["dimension"]) ?? "",
      ),
    ) ?? rows[0];
  if (!preferred)
    return "Basis: INFERRED — No likelihood precondition was returned.";
  const rawBasis = safeText(preferred["basis"] ?? preferred["reason"], 180);
  const basis = basisLabel(rawBasis);
  const graphState = safeText(
    body["graphStatus"] ?? prevalidation["graphStatus"],
    40,
  );
  const caution =
    basis === "GRAPH" &&
    /not.?reachable|unreachable|barrier/iu.test(
      `${preferred["dimension"]} ${preferred["conclusion"]}`,
    ) &&
    /empty|degraded|unavailable|not returned/iu.test(graphState)
      ? " Caution: this not-reachable conclusion comes from an empty or degraded graph."
      : "";
  return `Basis: ${basis} — ${safeText(preferred["dimension"], 80)}: ${safeText(preferred["conclusion"], 180)} (${rawBasis}).${caution}`;
}

function verdictFrom(artifact: Record<string, unknown>): string {
  const body = object(artifact["body"]);
  const validation = object(body["validationEvidence"] ?? body);
  return safeText(
    validation["exploitable"] ??
      validation["verdict"] ??
      validation["terminalStatus"],
    80,
  );
}

function proofType(artifact: Record<string, unknown>): string {
  const body = object(artifact["body"]);
  const validation = object(body["validationEvidence"] ?? body);
  const proof = object(validation["executedProof"]);
  if (Object.keys(proof).length === 0)
    return Object.keys(validation).length > 0
      ? "validation evidence"
      : "no validation evidence returned";
  return proof["code"] !== undefined ? "executed proof" : "validation evidence";
}

function defaultDelay(
  milliseconds: number,
  signal?: AbortSignal,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, milliseconds);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        reject(signal.reason);
      },
      { once: true },
    );
  });
}

export class ContinuumValidationProvider implements ValidationProvider {
  readonly name = "continuum";
  readonly version = "1";
  readonly #options: ContinuumValidationOptions;

  constructor(options: ContinuumValidationOptions) {
    if (!options.environmentId)
      throw new Error("Continuum validation requires environment_id");
    this.#options = options;
  }

  async #launcher(
    context: ValidationProviderContext,
  ): Promise<ContinuumAwsLauncher> {
    if (this.#options.launcher) return this.#options.launcher;
    const aws = await prepareContinuumAws(
      context.repositoryPath,
      process.env,
      context.signal,
      undefined,
      context.resolveHostPaths,
    );
    return async (operation, args, signal) => {
      const common = [
        "continuum",
        operation,
        ...args,
        "--output",
        "json",
        "--no-cli-pager",
        ...(this.#options.awsProfile
          ? ["--profile", this.#options.awsProfile]
          : []),
        ...(this.#options.awsRegion
          ? ["--region", this.#options.awsRegion]
          : []),
      ];
      const { stdout } = await execFileAsync(aws.executable, common, {
        cwd: aws.cwd,
        env: aws.environment,
        signal,
        maxBuffer: Number.POSITIVE_INFINITY,
        windowsHide: true,
      });
      return object(JSON.parse(stdout));
    };
  }

  async validate(
    supplied: Finding | Record<string, unknown> | string,
    context: ValidationProviderContext,
  ): Promise<ValidationProviderAssessment> {
    return (await this.validateBatch([supplied], context))[0]!;
  }

  async validateBatch(
    supplied: readonly (Finding | Record<string, unknown> | string)[],
    context: ValidationProviderContext,
  ): Promise<ValidationProviderAssessment[]> {
    const now = this.#options.now ?? (() => new Date());
    const deadline =
      now().getTime() + (this.#options.waitMinutes ?? 45) * 60_000;
    const delay = this.#options.delay ?? defaultDelay;
    let launch: ContinuumAwsLauncher;
    try {
      launch = await this.#launcher(context);
    } catch (error) {
      launch = async () => {
        throw error;
      };
    }
    const submittedAt = now();
    const submissions = await Promise.all(
      supplied.map(async (item) => {
        if (typeof item === "string") {
          return {
            assessment: unavailableAssessment(
              this,
              "not submittable: no structured item or code location",
            ),
          };
        }
        try {
          const ocsf = findingToOcsf(item, submittedAt);
          const token = deterministicClientToken(
            this.#options.environmentId,
            item,
          );
          const created = await this.#call(
            launch,
            "create-code-finding",
            [
              "--cli-input-json",
              JSON.stringify({
                environmentId: this.#options.environmentId,
                clientToken: token,
                ocsfDocument: ocsf,
              }),
            ],
            context,
            deadline,
            delay,
            now,
          );
          const findingId = text(created["findingId"]);
          if (!findingId)
            throw new Error("CreateCodeFinding returned no findingId");
          return { item, findingId, created };
        } catch (error) {
          const reason = error instanceof Error ? error.message : String(error);
          return {
            assessment: unavailableAssessment(
              this,
              /no code location/iu.test(reason)
                ? `not submittable: ${reason}`
                : safeText(reason, 240),
            ),
          };
        }
      }),
    );

    const results: ValidationProviderAssessment[] = new Array(supplied.length);
    let pending = submissions.flatMap((submission, index) => {
      if (submission.assessment) {
        results[index] = submission.assessment;
        return [];
      }
      return [index];
    });
    while (pending.length > 0 && now().getTime() < deadline) {
      let next = 0;
      // Rotate a single polling round across all items before waiting again.
      await Promise.all(
        Array.from(
          { length: Math.min(MAX_CONCURRENT_POLLS, pending.length) },
          async () => {
            for (;;) {
              const index = pending[next++];
              if (index === undefined) return;
              const submission = submissions[index]!;
              const assessment = await this.#poll(
                submission.item!,
                submission.findingId!,
                submission.created!,
                context,
                launch,
                deadline,
                delay,
                now,
                submittedAt,
              );
              if (assessment) results[index] = assessment;
            }
          },
        ),
      );
      pending = pending.filter((index) => !results[index]);
      if (pending.length > 0 && now().getTime() < deadline) {
        try {
          await delay(
            Math.min(5_000, deadline - now().getTime()),
            context.signal,
          );
        } catch (error) {
          for (const index of pending)
            results[index] = unavailableAssessment(this, error);
          pending = [];
        }
      }
    }
    for (const index of pending) {
      results[index] = unavailableAssessment(
        this,
        `timed out waiting for Continuum validation evidence for ${submissions[index]!.findingId}`,
      );
    }
    return results.map((assessment, index) => {
      const item = supplied[index];
      const finding = typeof item === "string" ? {} : item!;
      const record = assessment.record ?? {
        itemId: occurrence(finding),
        provider: this.name,
        verdict: "UNAVAILABLE",
        severityBefore: severityLevel(finding),
        severityAfter: severityLevel(finding),
        reasons: [],
        claimMatch: "unknown" as const,
        freshness: { stale: false, reasons: [] },
        unavailable: assessment.unavailable,
      };
      return { ...assessment, record };
    });
  }

  async #call(
    launch: ContinuumAwsLauncher,
    operation: string,
    args: readonly string[],
    context: ValidationProviderContext,
    deadline: number,
    delay: (milliseconds: number, signal?: AbortSignal) => Promise<void>,
    now: () => Date,
  ): Promise<Record<string, unknown>> {
    let backoff = 1_000;
    for (;;) {
      if (now().getTime() >= deadline)
        throw new Error("Continuum validation deadline reached");
      const timeout = AbortSignal.timeout(
        Math.max(1, Math.ceil(deadline - now().getTime())),
      );
      const signal = context.signal
        ? AbortSignal.any([context.signal, timeout])
        : timeout;
      try {
        return await launch(operation, args, signal);
      } catch (error) {
        if (
          !/throttl|rate exceeded|too many requests/iu.test(
            error instanceof Error ? error.message : String(error),
          ) ||
          now().getTime() + backoff > deadline
        )
          throw error;
        await delay(backoff, context.signal);
        backoff = Math.min(backoff * 2, 10_000);
      }
    }
  }

  async #poll(
    finding: AnyFinding,
    findingId: string,
    created: Record<string, unknown>,
    context: ValidationProviderContext,
    launch: ContinuumAwsLauncher,
    deadline: number,
    delay: (milliseconds: number, signal?: AbortSignal) => Promise<void>,
    now: () => Date,
    submittedAt: Date,
  ): Promise<ValidationProviderAssessment | undefined> {
    let issueId: string | undefined;
    let issue: Record<string, unknown> = {};
    let validationArtifact: Record<string, unknown> | undefined;
    let likelihoodArtifact: Record<string, unknown> | undefined;
    let status = "SUBMITTED";
    try {
      {
        const current = await this.#call(
          launch,
          "get-code-finding",
          [
            "--environment-id",
            this.#options.environmentId,
            "--finding-id",
            findingId,
          ],
          context,
          deadline,
          delay,
          now,
        );
        status = text(current["status"]) ?? status;
        if (TERMINAL_WITHOUT_ISSUE.has(status)) {
          const reason = safeText(
            current["statusMessage"] ??
              current["discardReason"] ??
              current["statusReason"],
          );
          return this.#report(
            finding,
            findingId,
            undefined,
            status,
            "not returned",
            "not returned",
            `Continuum discarded the submitted location: ${reason}`,
            "Basis: INFERRED — No likelihood precondition was returned.",
            "INFERRED",
            "unknown",
            now(),
            false,
          );
        }
        issueId =
          text(current["duplicateOfIssueId"]) ??
          text(current["createdIssueId"]) ??
          text(current["mergedIntoIssueId"]) ??
          text(created["duplicateOfIssueId"]) ??
          text(created["createdIssueId"]);
        if (issueId) {
          issue = await this.#call(
            launch,
            "get-code-issue",
            [
              "--environment-id",
              this.#options.environmentId,
              "--issue-id",
              issueId,
            ],
            context,
            deadline,
            delay,
            now,
          );
          for (const kind of ["EVIDENCE", "VALIDATION_EVIDENCE"] as const) {
            const listed = await this.#call(
              launch,
              "list-code-issue-artifacts",
              [
                "--environment-id",
                this.#options.environmentId,
                "--issue-id",
                issueId,
                "--artifact-type",
                kind,
              ],
              context,
              deadline,
              delay,
              now,
            );
            const items = Array.isArray(listed["items"])
              ? listed["items"].map(object)
              : [];
            const selected = items.sort((a, b) =>
              String(b["createdAt"] ?? "").localeCompare(
                String(a["createdAt"] ?? ""),
              ),
            )[0];
            const artifactId = text(selected?.["artifactId"]);
            if (artifactId) {
              const artifact = await this.#call(
                launch,
                "get-code-issue-artifact",
                [
                  "--environment-id",
                  this.#options.environmentId,
                  "--issue-id",
                  issueId,
                  "--artifact-id",
                  artifactId,
                ],
                context,
                deadline,
                delay,
                now,
              );
              if (kind === "EVIDENCE") likelihoodArtifact = artifact;
              else
                validationArtifact = selectFindingValidationArtifact(
                  artifact,
                  findingId,
                )?.artifact;
            }
          }
        }
      }
      if (!validationArtifact || !likelihoodArtifact || !issueId) return;
      const verdict = verdictFrom(validationArtifact);
      const body = object(validationArtifact["body"]);
      const validationBody = object(body["validationEvidence"] ?? body);
      // A retained issue caption must not override proof of a different flaw.
      const claimEvidence =
        validationBody["perFindingResults"] !== undefined ||
        validationBody["executedProof"] !== undefined ||
        validationBody["sourceAnalysis"] !== undefined
          ? validationArtifact
          : {
              validation: validationArtifact,
              name: issue["name"],
              synopsis: issue["synopsis"],
            };
      const match = proofClaimMatch(claimEvidence, finding);
      const validatedAt = new Date(
        text(validationArtifact["createdAt"]) ?? now(),
      );
      const issueTime = new Date(
        text(issue["updatedAt"] ?? issue["createdAt"]) ?? validatedAt,
      );
      const scorerTime = new Date(
        text(likelihoodArtifact["createdAt"]) ?? validatedAt,
      );
      const stale =
        validatedAt.getTime() < submittedAt.getTime() ||
        issueTime.getTime() < submittedAt.getTime() ||
        scorerTime.getTime() < submittedAt.getTime();
      const reason = `Basis: CODE — Continuum returned ${verdict} using ${proofType(validationArtifact)}. Basis: INFERRED — The proof-to-claim comparison was ${match}. Raw proof code, payloads, commands, and console output are intentionally omitted.`;
      return this.#report(
        finding,
        issueId,
        issueId,
        verdict,
        safeText(issue["severity"], 40),
        severityFactors(issue["severityReasoning"], likelihoodArtifact),
        reason,
        likelihoodArtifact
          ? evidenceSignal(likelihoodArtifact)
          : "Basis: INFERRED — No likelihood precondition was returned.",
        basisLabel(
          issue["severityReasoning"] ??
            evidenceRows(likelihoodArtifact ?? {}).flatMap((row) =>
              Object.values(object(row["preconditions"])).map(
                (value) => object(value)["basis"],
              ),
            ),
        ),
        match,
        validatedAt,
        stale,
        evidenceRows(likelihoodArtifact).flatMap((row) =>
          Object.entries({
            ...object(row["preconditions"]),
            ...object(row["impactDimensions"]),
          }).map(([name, raw]) => ({
            basis: basisLabel(object(raw)["basis"]),
            reason: `${name}: ${safeText(String(object(raw)["value"]), 80)} — ${safeText(object(raw)["reason"], 180)}`,
          })),
        ),
      );
    } catch (error) {
      return unavailableAssessment(
        this,
        safeText(error instanceof Error ? error.message : error, 240),
      );
    }
  }

  #report(
    finding: AnyFinding,
    referenceId: string,
    issueId: string | undefined,
    verdict: string,
    severity: string,
    factors: string,
    reason: string,
    signal: string,
    severityBasis: "GRAPH" | "CODE" | "INFERRED",
    match: ValidationClaimMatch,
    validatedAt: Date,
    stale = false,
    preconditions: Array<{
      basis: "GRAPH" | "CODE" | "INFERRED";
      reason: string;
    }> = [],
  ): ValidationProviderAssessment {
    const base = (
      this.#options.consoleBaseUrl ??
      "https://console.aws.amazon.com/continuum/home"
    ).replace(/\/$/u, "");
    const referenceUrl = issueId
      ? `${base}#/environments/${encodeURIComponent(this.#options.environmentId)}/issues/${encodeURIComponent(issueId)}`
      : undefined;
    const title = safeText(finding["title"], 160);
    const summary = safeText(finding["summary"], 300);
    const exposure = /reachableFromAttacker: true/iu.test(signal)
      ? /EXPOSED|internet|public/iu.test(signal)
        ? "internet-exposed"
        : "reachable from attacker"
      : /NOT_EXPOSED/iu.test(signal)
        ? "not internet-exposed"
        : "exposure unknown";
    const report = [
      `Codex: ${severityLevel(finding)}, exposure unknown → Continuum: ${match === "different_flaw" || match === "unknown" ? `${severityLevel(finding)} (Codex retained)` : severity.toLowerCase()}, ${exposure} (basis ${basisLabel(signal.split("—")[0])}).`,
      "",
      `**What Codex said:** ${title} (${severityLevel(finding)}). ${summary}`,
      "",
      `**What Continuum says:** ${verdict}; severity ${severity}; ${factors} (basis: ${severityBasis}).`,
      "",
      `**Freshness:** validated at ${validatedAt.toISOString()}; ${stale ? "possibly stale: evidence predates submission" : "current at submission"}. Deployment source identity is not compared.`,
      "",
      `**Claim match:** ${match} (basis: INFERRED).${match === "different_flaw" ? " Not validated: Continuum proved a related flaw. Codex severity is retained." : ""}`,
      "",
      `**Main barrier or enabler:** ${signal}`,
      "",
      reason,
      "",
      ...(/not.?reachable|unreachable|barrier|NOT_EXPOSED/iu.test(signal)
        ? [
            "This issue may be real but not reachable in the observed deployment; consider lower priority without changing its truth state.",
            "",
          ]
        : []),
      ...(referenceUrl ? [`**Issue:** ${referenceUrl}`, ""] : []),
    ].join("\n");
    return {
      disposition: "reportable",
      report,
      record: {
        itemId: occurrence(finding),
        provider: this.name,
        verdict,
        severityBefore: severityLevel(finding),
        severityAfter:
          match === "different_flaw" || match === "unknown"
            ? severityLevel(finding)
            : severity.toLowerCase(),
        providerSeverity: severity.toLowerCase(),
        reasons: [
          { basis: severityBasis, reason: factors },
          { basis: basisLabel(signal.split("—")[0]), reason: signal },
          {
            basis: match === "unknown" ? "INFERRED" : "CODE",
            reason: `Continuum verdict: ${verdict}`,
          },
          { basis: "INFERRED", reason: `Claim comparison: ${match}` },
          ...preconditions,
        ],
        claimMatch: match,
        issueUrl: referenceUrl,
        freshness: {
          validatedAt: validatedAt.toISOString(),
          stale,
          reasons: stale ? ["Evidence predates this submission."] : [],
        },
      },
      provenance: {
        provider: this.name,
        providerVersion: this.version,
        referenceId,
        referenceUrl,
        validatedAt: validatedAt.toISOString(),
      },
    };
  }
}

export function continuumProviderFromConfig(
  config: Record<string, unknown>,
): ContinuumValidationProvider {
  return new ContinuumValidationProvider({
    environmentId: text(config["environment_id"]) ?? "",
    awsProfile: text(config["aws_profile"]),
    awsRegion: text(config["aws_region"]),
    waitMinutes:
      typeof config["wait_minutes"] === "number"
        ? config["wait_minutes"]
        : undefined,
    consoleBaseUrl: text(config["console_base_url"]),
  });
}
