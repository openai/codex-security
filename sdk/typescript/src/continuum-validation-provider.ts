import {
  prepareContinuumSubmissions,
  type ContinuumReceipt,
  type ContinuumRequest,
} from "./continuum-submissions.js";
import { repositoryFilePath } from "./scanner-import.js";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { prepareContinuumAws } from "./continuum-aws.js";
import {
  selectFindingValidationArtifact,
  singleFindingValidationIssue,
} from "./continuum-validation-evidence.js";
import type { Finding } from "./models.js";
import {
  type ValidationProvider,
  type ValidationProviderAssessment,
  type ValidationProviderContext,
  type ValidationClaimMatch,
  type ValidationBasis,
  type ValidationResultScope,
  unavailableAssessment,
} from "./validation-provider.js";

const execFileAsync = promisify(execFile);
const TERMINAL_WITHOUT_ISSUE = new Set(["DISCARDED", "NOT_PURSUED"]);
// Bound both creation and polling: each request can launch an AWS CLI process.
async function forEachPending(
  indices: number[],
  operation: (index: number) => Promise<void>,
) {
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(4, indices.length) }, async () => {
      while (next < indices.length) await operation(indices[next++]!);
    }),
  );
}
type Submission = ContinuumReceipt & { issueId?: string; issueArn?: string };

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

function continuumIssueUrl(
  { environmentId, consoleBaseUrl }: ContinuumValidationOptions,
  { issueId, issueArn }: Submission,
): string | undefined {
  const region = /^arn:[^:]+:continuum:([a-z0-9-]+):/u.exec(
    issueArn ?? "",
  )?.[1];
  if (!issueId || !region) return;
  const base =
    consoleBaseUrl ?? `https://${region}.console.aws.amazon.com/continuum`;
  return `${base.replace(/\/$/u, "")}/environments/${encodeURIComponent(environmentId)}/code-vulnerabilities/issues/${encodeURIComponent(issueId)}?region=${region}`;
}

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
      const path =
        repositoryFilePath(row["path"]) ?? repositoryFilePath(row["filePath"]);
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

function basisLabel(value: unknown): ValidationBasis {
  const raw = text(value);
  if (!raw) return "INFERRED";
  const known = raw.toUpperCase();
  return ["GRAPH", "CODE", "FINDING", "INFERRED"].includes(known)
    ? known
    : safeText(raw, 80);
}

function attackerReachability(
  artifact: Record<string, unknown>,
): boolean | undefined {
  const likelihood = evidenceRows(artifact).find(
    (row) => row["dimension"] === "LIKELIHOOD_ASSESSMENT",
  );
  const value = object(
    object(likelihood?.["preconditions"])["reachableFromAttacker"],
  )["value"];
  return typeof value === "boolean" ? value : undefined;
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
    const rawBasis = row["basis"];
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
  const rawBasis = safeText(preferred["basis"], 80);
  const basis = basisLabel(preferred["basis"]);
  const graphState = safeText(
    body["graphStatus"] ?? prevalidation["graphStatus"],
    40,
  );
  const caution =
    basis === "GRAPH" &&
    attackerReachability(artifact) === false &&
    /empty|degraded|unavailable|not returned/iu.test(graphState)
      ? " Caution: this not-reachable conclusion comes from an empty or degraded graph."
      : "";
  return `Basis: ${basis} — ${safeText(preferred["dimension"], 80)}: ${safeText(preferred["conclusion"], 180)} (${rawBasis}).${caution}`;
}

function validationBody(artifact: Record<string, unknown>) {
  const body = object(artifact["body"]);
  return object(body["validationEvidence"] ?? body);
}

interface ContinuumOutcome {
  verdict: string;
  terminalStatus?: string;
  statusMessage?: string;
  disposition: ValidationProviderAssessment["disposition"];
  unavailable?: string;
}

function validationOutcome(
  artifact: Record<string, unknown>,
): ContinuumOutcome {
  const validation = validationBody(artifact);
  const verdict =
    text(validation["exploitable"]) ?? text(validation["verdict"]) ?? "UNKNOWN";
  const terminalStatus = text(validation["terminalStatus"]);
  // Older artifacts can carry an explicit verdict without a run status.
  const conclusive =
    (terminalStatus === undefined || terminalStatus === "COMPLETED") &&
    (verdict === "EXPLOITABLE" || verdict === "NOT_EXPLOITABLE");
  const failed =
    terminalStatus === "FAILED" || terminalStatus === "NO_SOURCE_AVAILABLE";
  return {
    verdict,
    terminalStatus,
    disposition: conclusive ? "reportable" : "deferred",
    ...(failed && {
      unavailable: `Continuum validation ended with ${terminalStatus}.`,
    }),
  };
}

function proofType(artifact: Record<string, unknown>): string {
  const validation = validationBody(artifact);
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
        env: { ...aws.environment, AWS_CLI_FILE_ENCODING: "UTF-8" },
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
    const wait = Math.ceil((this.#options.waitMinutes ?? 45) * 60_000);
    const deadline = now().getTime() + wait;
    const delay = this.#options.delay ?? defaultDelay;
    const signal = AbortSignal.timeout(wait);
    context = {
      ...context,
      signal: context.signal
        ? AbortSignal.any([context.signal, signal])
        : signal,
    };
    const results: ValidationProviderAssessment[] = new Array(supplied.length);
    const submissions: (Submission | undefined)[] = new Array(supplied.length);
    let pending = supplied.map((_, index) => index);
    let request: ContinuumRequest;
    try {
      const launch = await this.#launcher(context);
      request = (operation, args) =>
        this.#call(launch, operation, args, context, deadline, delay, now);
      const submit = await prepareContinuumSubmissions(
        request,
        this.#options.environmentId,
        context.repositoryPath,
        context.signal,
      );
      await forEachPending(pending, async (index) => {
        try {
          const item = supplied[index]!;
          if (typeof item === "string")
            throw new Error(
              "not submittable: no structured item or code location",
            );
          const time = now();
          submissions[index] = await submit(findingToOcsf(item, time), time);
        } catch (error) {
          results[index] = unavailableAssessment(this, error);
        }
      });
      pending = pending.filter((index) => !results[index]);
    } catch (error) {
      for (const index of pending)
        results[index] = unavailableAssessment(this, error);
      pending = [];
    }
    while (pending.length > 0 && now().getTime() < deadline) {
      await forEachPending(pending, async (index) => {
        const assessment = await this.#poll(
          supplied[index] as AnyFinding,
          submissions[index]!,
          request,
        );
        if (assessment) results[index] = assessment;
      });
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
      const submission = submissions[index];
      if (!submission) return { ...assessment, record };
      const { submittedAt, ...ids } = submission;
      const issueUrl = continuumIssueUrl(this.#options, submission);
      const issue = issueUrl ? `[${ids.issueArn}](${issueUrl})` : ids.issueArn;
      return {
        ...assessment,
        report: [
          assessment.report.trimEnd(),
          `AWS finding: ${ids.findingArn}`,
          ...(issue ? [`AWS issue: ${issue}`] : []),
        ].join("\n\n"),
        record: {
          ...record,
          ...ids,
          issueUrl,
          submittedAt: submittedAt.toISOString(),
        },
        provenance: {
          ...assessment.provenance,
          referenceId: ids.issueId ?? ids.findingId,
          referenceUrl: issueUrl,
        },
      };
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
      context.signal?.throwIfAborted();
      try {
        return await launch(operation, args, context.signal);
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
    submission: Submission,
    request: ContinuumRequest,
  ): Promise<ValidationProviderAssessment | undefined> {
    const { findingId, findingArn, submittedAt } = submission;
    let issueId: string | undefined;
    let issue: Record<string, unknown> = {};
    let validationArtifact: Record<string, unknown> | undefined;
    let likelihoodArtifact: Record<string, unknown> | undefined;
    let resultScope: ValidationResultScope = "finding";
    let issueFindingCount: number | undefined;
    try {
      {
        const current = await request("get-code-finding", [
          "--environment-id",
          this.#options.environmentId,
          "--finding-id",
          findingId,
        ]);
        if (current["findingArn"] !== findingArn)
          throw new Error("Continuum returned another finding while polling.");
        const status = text(current["status"]);
        if (status && TERMINAL_WITHOUT_ISSUE.has(status)) {
          const statusMessage = text(
            current["statusMessage"] ??
              current["discardReason"] ??
              current["statusReason"],
          );
          return this.#report(finding, submittedAt, {
            verdict: status,
            statusMessage,
            disposition: "not_applicable",
          });
        }
        // CreateCodeFinding returns the finding identity before any issue is linked.
        // GetCodeFinding supplies the issue association as processing progresses.
        issueId =
          text(current["mergedIntoIssueId"]) ??
          text(current["duplicateOfIssueId"]) ??
          text(current["createdIssueId"]);
        delete submission.issueId;
        delete submission.issueArn;
        if (issueId) {
          issue = await request("get-code-issue", [
            "--environment-id",
            this.#options.environmentId,
            "--issue-id",
            issueId,
          ]);
          const scope = findingArn.slice(
            0,
            -("/code-findings/" + findingId).length,
          );
          const issueArn = scope + "/code-issues/" + issueId;
          if (issue["issueArn"] !== issueArn || issue["issueId"] !== issueId)
            throw new Error(
              "Continuum returned a different issue while polling.",
            );
          submission.issueId = issueId;
          submission.issueArn = issueArn;
          const ids = issue["findingIds"];
          if (!Array.isArray(ids) || !ids.includes(findingId)) return;
          issueFindingCount = new Set(ids).size;
          let issueFallback: Record<string, unknown> | undefined;
          let soleFindingFallback: Record<string, unknown> | undefined;
          for (const kind of ["EVIDENCE", "VALIDATION_EVIDENCE"] as const) {
            const listed = await request("list-code-issue-artifacts", [
              "--environment-id",
              this.#options.environmentId,
              "--issue-id",
              issueId,
              "--artifact-type",
              kind,
            ]);
            const items = Array.isArray(listed["items"])
              ? listed["items"].map(object)
              : [];
            items.sort((a, b) =>
              String(b["createdAt"] ?? "").localeCompare(
                String(a["createdAt"] ?? ""),
              ),
            );
            for (const candidate of items) {
              const artifactId = text(candidate["artifactId"]);
              if (!artifactId) continue;
              const artifact = await request("get-code-issue-artifact", [
                "--environment-id",
                this.#options.environmentId,
                "--issue-id",
                issueId,
                "--artifact-id",
                artifactId,
              ]);
              if (kind === "EVIDENCE") {
                likelihoodArtifact = artifact;
                break;
              }
              const selected = selectFindingValidationArtifact(
                artifact,
                findingId,
              );
              if (selected?.scope === "finding") {
                validationArtifact = selected.artifact;
                break;
              }
              if (
                selected?.scope === "issue" &&
                singleFindingValidationIssue(issue, issueId, {
                  scope,
                  id: findingId,
                })
              ) {
                soleFindingFallback ??= selected.artifact;
                continue;
              }
              // Keep issue proof separate. Search all histories first: an older
              // explicit result for this finding must beat this fallback.
              const outcome = validationOutcome(artifact);
              if (
                !issueFallback &&
                artifact["artifactType"] === "VALIDATION_EVIDENCE" &&
                (outcome.verdict !== "UNKNOWN" || outcome.terminalStatus)
              )
                issueFallback = artifact;
            }
          }
          validationArtifact ??= soleFindingFallback;
          if (!validationArtifact && issueFallback) {
            validationArtifact = issueFallback;
            resultScope = "issue";
          }
        }
      }
      if (!validationArtifact || !issueId) return;
      const outcome = validationOutcome(validationArtifact);
      if (!likelihoodArtifact && outcome.disposition === "reportable") return;
      return this.#report(finding, submittedAt, outcome, {
        issue,
        validationArtifact,
        likelihoodArtifact,
        resultScope,
        issueFindingCount,
      });
    } catch (error) {
      return unavailableAssessment(this, error);
    }
  }

  #report(
    finding: AnyFinding,
    submittedAt: Date,
    {
      verdict,
      terminalStatus,
      statusMessage,
      disposition,
      unavailable,
    }: ContinuumOutcome,
    {
      issue = {},
      validationArtifact = {},
      likelihoodArtifact = {},
      resultScope = "finding",
      issueFindingCount,
    }: {
      issue?: Record<string, unknown>;
      validationArtifact?: Record<string, unknown>;
      likelihoodArtifact?: Record<string, unknown>;
      resultScope?: ValidationResultScope;
      issueFindingCount?: number;
    } = {},
  ): ValidationProviderAssessment {
    const conclusive = disposition === "reportable";
    const validation = validationBody(validationArtifact);
    // A retained issue caption must not override proof of a different flaw.
    const claimEvidence = validation["perFindingResults"] ??
      validation["executedProof"] ??
      validation["exploitArtifact"] ??
      validation["sourceAnalysis"] ?? {
        name: issue["name"],
        synopsis: issue["synopsis"],
      };
    const match =
      conclusive && resultScope === "finding"
        ? proofClaimMatch(claimEvidence, finding)
        : "unknown";

    const artifactTime = Date.parse(
      text(validationArtifact["createdAt"]) ?? "",
    );
    const validatedAt =
      conclusive && Number.isFinite(artifactTime)
        ? new Date(artifactTime).toISOString()
        : undefined;
    const olderArtifact = artifactTime < submittedAt.getTime();
    const stale =
      olderArtifact ||
      [
        issue["updatedAt"] ?? issue["createdAt"],
        likelihoodArtifact["createdAt"],
      ].some((time) => Date.parse(text(time) ?? "") < submittedAt.getTime());
    const joinedValidatedIssue =
      conclusive && resultScope === "issue" && olderArtifact;
    const reason = !conclusive
      ? (statusMessage ?? "The finding still needs validation.")
      : resultScope === "issue"
        ? `Continuum returned ${verdict} for the issue using ${proofType(validationArtifact)}. This is not proof for the submitted finding individually. Raw proof code, payloads, commands, and console output are intentionally omitted.`
        : `Basis: CODE — Continuum returned ${verdict} using ${proofType(validationArtifact)}. Basis: INFERRED — The proof-to-claim comparison was ${match}. Raw proof code, payloads, commands, and console output are intentionally omitted.`;
    const providerSeverity = text(issue["severity"])?.toLowerCase();
    const severityBefore = severityLevel(finding);
    const matched = match === "on_target" || match === "on_target_escalated";
    const regrade = matched && providerSeverity !== undefined;
    const severityAfter = regrade ? providerSeverity : severityBefore;
    const severityBasis = "INFERRED";
    const factors = severityFactors(
      issue["severityReasoning"],
      likelihoodArtifact,
    );
    const signal = evidenceSignal(likelihoodArtifact);
    const reachableFromAttacker = attackerReachability(likelihoodArtifact);
    const preconditions = evidenceRows(likelihoodArtifact).flatMap((row) =>
      Object.entries({
        ...object(row["preconditions"]),
        ...object(row["impactDimensions"]),
      }).map(([name, raw]) => ({
        basis: basisLabel(object(raw)["basis"]),
        reason: `${name}: ${safeText(String(object(raw)["value"]), 80)} — ${safeText(object(raw)["reason"], 180)}`,
      })),
    );
    const title = safeText(finding["title"], 160);
    const summary = safeText(finding["summary"], 300);
    const exposure =
      reachableFromAttacker === true
        ? "reachable from attacker"
        : reachableFromAttacker === false
          ? "not reachable from attacker"
          : "exposure unknown";
    const signalBasis = basisLabel(/^Basis: (.*?) —/u.exec(signal)?.[1]);
    const providerResult = terminalStatus
      ? `${verdict} (validation run ${terminalStatus})`
      : verdict;
    const freshness = validatedAt
      ? `validated at ${validatedAt}${stale ? "" : ", current at submission"}`
      : "validation time unknown";
    const scopeDescription =
      resultScope === "issue"
        ? `Continuum grouped this finding with ${(issueFindingCount ?? 1) - 1} other findings into this issue. This is an issue-level result, not an individual validation of this finding. Codex severity is retained.${joinedValidatedIssue ? " This finding joined an issue Continuum had already validated; the issue proof predates this submission." : ""}`
        : "Continuum result for this finding.";
    const report = [
      `**Result scope:** ${scopeDescription}`,
      "",
      regrade
        ? `Codex: ${severityBefore}, exposure unknown → Continuum: ${severityAfter}, ${exposure} (basis ${signalBasis}).`
        : `Codex finding severity: ${severityBefore} (retained).${providerSeverity ? ` Continuum issue severity: ${providerSeverity}. Issue ${exposure} (basis ${signalBasis}).` : ""}`,
      "",
      `**What Codex said:** ${title} (${severityBefore}). ${summary}`,
      "",
      `**What Continuum says${resultScope === "issue" ? " for the issue" : ""}:** ${providerResult}. ${factors} (basis: ${severityBasis}).`,
      "",
      `**Freshness:** ${freshness}${stale ? ", possibly stale because evidence predates submission" : ""}. Deployment source identity is not compared.`,
      "",
      `**Claim match:** ${match} (basis: INFERRED).${match === "different_flaw" ? " Not validated: Continuum proved a related flaw. Codex severity is retained." : ""}`,
      "",
      `**Main barrier or enabler${resultScope === "issue" ? " for the issue" : ""}:** ${signal}`,
      "",
      reason,
      "",
      ...(matched && reachableFromAttacker === false
        ? [
            "This issue may be real but not reachable in the observed deployment; consider lower priority without changing its truth state.",
            "",
          ]
        : []),
    ].join("\n");
    return {
      disposition,
      ...(unavailable && { unavailable }),
      report,
      record: {
        itemId: occurrence(finding),
        provider: this.name,
        verdict,
        ...(terminalStatus && { terminalStatus }),
        ...(statusMessage && { statusMessage }),
        ...(unavailable && { unavailable }),
        severityBefore,
        severityAfter,
        ...(providerSeverity && { providerSeverity }),
        resultScope,
        ...(issueFindingCount !== undefined && { issueFindingCount }),
        joinedValidatedIssue,
        ...(reachableFromAttacker !== undefined && { reachableFromAttacker }),
        reasons: [
          { basis: severityBasis, reason: factors },
          { basis: signalBasis, reason: signal },
          {
            basis: match === "unknown" ? "INFERRED" : "CODE",
            reason: `Continuum ${resultScope} verdict: ${providerResult}${statusMessage ? `. ${statusMessage}` : ""}`,
          },
          { basis: "INFERRED", reason: `Claim comparison: ${match}` },
          ...preconditions,
        ],
        claimMatch: match,
        freshness: {
          ...(validatedAt && { validatedAt }),
          stale,
          reasons: stale ? ["Evidence predates this submission."] : [],
        },
      },
      provenance: {
        provider: this.name,
        providerVersion: this.version,
        ...(validatedAt && { validatedAt }),
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
