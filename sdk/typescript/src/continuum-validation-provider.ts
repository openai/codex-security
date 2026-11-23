import {
  prepareContinuumSubmissions,
  type ContinuumReceipt,
  type ContinuumRequest,
} from "./continuum-submissions.js";
import { repositoryFilePath } from "./scanner-import.js";
import { errorMessage } from "./errors.js";
import { compareTimestamps } from "./timestamps.js";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { setTimeout as waitFor } from "node:timers/promises";
import { prepareContinuumAws } from "./continuum-aws.js";
import { selectFindingValidationArtifact } from "./continuum-validation-evidence.js";
import type { Finding } from "./models.js";
import { resourceNames } from "./validation-provider-report.js";
import {
  type ValidationProvider,
  type ValidationProviderAssessment,
  type ValidationProviderContext,
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

class ScoreReadError extends Error {}

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
  const document = {
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
  if (/^.{65537}/su.test(summary))
    throw new Error("Continuum descriptions are limited to 65,536 characters.");
  if (Buffer.byteLength(JSON.stringify(document)) > 256 * 1024)
    throw new Error("Continuum OCSF document exceeds 256 KiB.");
  return document;
}

function evidenceRows(artifact: Record<string, unknown>) {
  const body = object(artifact["body"]);
  const signals = object(body["prevalidationSignals"])["signals"];
  return Array.isArray(signals) ? signals.map(object) : [];
}

function createdAt(artifact: Record<string, unknown>) {
  const time = text(artifact["createdAt"]) ?? "";
  return Number.isFinite(Date.parse(time)) ? time : "";
}

function linkedScore(
  issue: Record<string, unknown>,
  proof: Record<string, unknown>,
  score: Record<string, unknown>,
): boolean {
  const validated = createdAt(proof);
  const scored = createdAt(score);
  const updated = text(issue["updatedAt"]) ?? "";
  if (!(
    compareTimestamps(validated, scored) <= 0 &&
    compareTimestamps(scored, updated) <= 0
  ))
    return false;
  const rows = evidenceRows(score);
  if (
    rows.some(
      ({ subjectRef }) =>
        typeof subjectRef !== "string" ||
        (subjectRef !== issue["issueId"] && subjectRef !== issue["issueArn"]),
    )
  )
    return false;
  const signals = rows.filter((row) => row["dimension"] === "EXPLOITABILITY");
  const reference = object(signals[0]?.["exploitability"]);
  return (
    signals.length === 1 &&
    reference["sourceValidationArtifactId"] === proof["artifactId"] &&
    reference["verdict"] === validationOutcome(proof).verdict
  );
}

function severityFactors(evidence: Record<string, unknown>) {
  const rows = evidenceRows(evidence);
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

  return "likelihood and impact not returned";
}

function basisLabel(value: unknown): ValidationBasis {
  const raw = text(value);
  if (!raw) return "INFERRED";
  const known = raw.toUpperCase();
  return ["GRAPH", "CODE", "FINDING", "INFERRED"].includes(known)
    ? known
    : safeText(raw, 80);
}

function reachability(score: Record<string, unknown>) {
  const likelihood = evidenceRows(score).find(
    (row) => row["dimension"] === "LIKELIHOOD_ASSESSMENT",
  );
  const row = object(
    object(likelihood?.["preconditions"])["reachableFromAttacker"],
  );
  const value = typeof row["value"] === "boolean" ? row["value"] : undefined;
  const basis = basisLabel(row["basis"]);
  const body = object(score["body"]);
  const graphState = text(
    body["graphStatus"] ?? object(body["prevalidationSignals"])["graphStatus"],
  );
  const caution =
    basis === "GRAPH" &&
    value === false &&
    graphState &&
    /empty|degraded|unavailable/iu.test(graphState)
      ? " Continuum reports an empty or degraded graph."
      : "";
  const signal =
    row["value"] === undefined
      ? "No issue reachability signal was returned."
      : `Basis: ${basis} — reachableFromAttacker: ${value ?? "unknown"} (${safeText(resourceNames(text(row["reason"]) ?? ""), 180)}).${caution}`;
  return { value, basis, signal };
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

async function* issueArtifacts(
  request: ContinuumRequest,
  issueArgs: readonly string[],
  kind: "VALIDATION_EVIDENCE" | "EVIDENCE",
) {
  const listed = await request("list-code-issue-artifacts", [
    ...issueArgs,
    "--artifact-type",
    kind,
  ]);
  if (listed["nextToken"] || listed["NextToken"])
    throw new Error("Expected a complete Continuum issue artifact list.");
  const items = Array.isArray(listed["items"])
    ? listed["items"].map(object)
    : [];
  items.sort((a, b) => {
    const left = createdAt(a);
    const right = createdAt(b);
    if (!left) return right ? 1 : 0;
    if (!right) return -1;
    return compareTimestamps(right, left);
  });
  for (const [index, candidate] of items.entries()) {
    const id = text(candidate["artifactId"]);
    if (!id) continue;
    const artifact = await request("get-code-issue-artifact", [
      ...issueArgs,
      "--artifact-id",
      id,
    ]);
    if (artifact["artifactId"] !== id || artifact["artifactType"] !== kind)
      throw new Error("Continuum returned a different artifact while polling.");
    const next = items[index + 1];
    const tied =
      next && compareTimestamps(createdAt(next), createdAt(candidate)) === 0;
    yield { artifact, tied };
  }
}

interface SelectedValidation {
  artifact: Record<string, unknown>;
  outcome: ContinuumOutcome;
  scope: ValidationResultScope;
}

async function selectValidation(
  artifacts: ReturnType<typeof issueArtifacts>,
  findingId: string,
): Promise<SelectedValidation | undefined> {
  let issueFallback: SelectedValidation | undefined;
  const applicable: SelectedValidation[] = [];
  const siblings: SelectedValidation[] = [];
  for await (const { artifact, tied } of artifacts) {
    const member = selectFindingValidationArtifact(artifact, findingId);
    if (member?.scope === "finding") {
      applicable.push({
        artifact,
        outcome: validationOutcome(member.artifact),
        scope: "finding",
      });
    } else {
      const outcome = validationOutcome(artifact);
      if (outcome.terminalStatus || outcome.verdict !== "UNKNOWN") {
        const results = validationBody(artifact)["perFindingResults"];
        // A newer issue run supersedes earlier member results unless the
        // bundle explicitly reports results only for other members.
        const siblingOnly =
          Array.isArray(results) &&
          results.length > 0 &&
          results.every((item) => {
            const id = text(object(item)["findingId"]);
            return id && id !== findingId;
          });
        (siblingOnly ? siblings : applicable).push({
          artifact,
          outcome,
          scope: "issue",
        });
      }
    }
    if (tied) continue;
    if (applicable.length) return uniqueValidation(applicable);
    issueFallback ??= uniqueValidation(siblings);
    siblings.length = 0;
  }
  return issueFallback;
}

function uniqueValidation(
  candidates: SelectedValidation[],
): SelectedValidation | undefined {
  const ids = [
    ...new Set(candidates.map(({ artifact }) => text(artifact["artifactId"]))),
  ].sort();
  if (ids.length < 2) return candidates[0];
  // Preserve the time so remediation can avoid selecting a superseded result.
  return {
    artifact: { createdAt: createdAt(candidates[0]!.artifact) },
    scope: "issue",
    outcome: {
      verdict: "UNKNOWN",
      disposition: "deferred",
      unavailable: `Continuum validation artifacts have the same timestamp (${ids.join(", ")}). Retry when a newer result is available.`,
    },
  };
}

function defaultDelay(milliseconds: number, signal?: AbortSignal) {
  return waitFor(milliseconds, undefined, { signal });
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
    if (supplied.length === 0) return [];
    const now = this.#options.now ?? (() => new Date());
    const wait = Math.ceil((this.#options.waitMinutes ?? 45) * 60_000);
    const deadline = now().getTime() + wait;
    const delay = this.#options.delay ?? defaultDelay;
    const signal = AbortSignal.timeout(wait);
    const timedOut = () => signal.aborted || now().getTime() >= deadline;
    context = {
      ...context,
      signal: context.signal
        ? AbortSignal.any([context.signal, signal])
        : signal,
    };
    const results: ValidationProviderAssessment[] = new Array(supplied.length);
    const submissions: (Submission | undefined)[] = new Array(supplied.length);
    const invalid = new Set<number>();
    let pending = supplied.map((_, index) => index);
    let request: ContinuumRequest;
    try {
      // Prepare AWS once, after the first valid document. Only active senders
      // retain serialized findings while the shared setup runs.
      const prepare = async () => {
        const launch = await this.#launcher(context);
        request = (operation, args) =>
          this.#call(launch, operation, args, context, deadline, delay, now);
        return prepareContinuumSubmissions(
          request,
          this.#options.environmentId,
          context.repositoryPath,
          context.signal,
          context.checkSubmissionTarget,
        );
      };
      let ready: ReturnType<typeof prepare> | undefined;
      await forEachPending(pending, async (index) => {
        const item = supplied[index]!;
        const time = now();
        let document: Record<string, unknown>;
        try {
          if (typeof item === "string")
            throw new Error(
              "not submittable: no structured item or code location",
            );
          document = findingToOcsf(item, time);
        } catch (error) {
          invalid.add(index);
          const reason = error instanceof Error ? error.message : String(error);
          results[index] = unavailableAssessment(
            this,
            `${reason} No upload attempted for this finding. Correct the input before submitting again.`,
          );
          return;
        }
        try {
          const submit = await (ready ??= prepare());
          submissions[index] = await submit(document, now());
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
    // A finished verdict remains useful if its linked score misses the deadline.
    const waiting = new Map<number, ValidationProviderAssessment>();
    while (pending.length > 0 && !timedOut()) {
      await forEachPending(pending, async (index) => {
        const submission = submissions[index]!;
        const previousIssue = submission.issueArn;
        try {
          const assessment = await this.#poll(
            supplied[index] as AnyFinding,
            submission,
            request,
            timedOut,
          );
          if (assessment && "waiting" in assessment)
            waiting.set(index, assessment.waiting);
          else {
            waiting.delete(index);
            if (assessment) results[index] = assessment;
          }
        } catch (error) {
          if (timedOut() && submission.issueArn === previousIssue) {
            const partial = waiting.get(index);
            if (partial) {
              results[index] = partial;
              return;
            }
          }
          results[index] = unavailableAssessment(this, error);
        }
      });
      pending = pending.filter((index) => !results[index]);
      if (pending.length > 0 && !timedOut()) {
        try {
          await delay(
            Math.min(5_000, deadline - now().getTime()),
            context.signal,
          );
        } catch (error) {
          if (signal.aborted) break;
          for (const index of pending)
            results[index] = unavailableAssessment(this, error);
          pending = [];
        }
      }
    }
    for (const index of pending) {
      results[index] =
        waiting.get(index) ??
        unavailableAssessment(
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
        ...(invalid.has(index) && { invalidInput: true }),
        severityBefore: severityLevel(finding),
        severityAfter: severityLevel(finding),
        reasons: [],
        claimMatch: "unknown" as const,
        freshness: { stale: false, reasons: [] },
        unavailable: assessment.unavailable,
      };
      record.disposition = assessment.disposition;
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
    timedOut: () => boolean,
  ): Promise<
    | ValidationProviderAssessment
    | { waiting: ValidationProviderAssessment }
    | undefined
  > {
    const { findingId, findingArn, submittedAt } = submission;
    const environmentArgs = ["--environment-id", this.#options.environmentId];
    const current = await request("get-code-finding", [
      ...environmentArgs,
      "--finding-id",
      findingId,
    ]);
    if (current["findingArn"] !== findingArn)
      throw new Error("Continuum returned another finding while polling.");
    const sourceId = text(current["sourceFindingId"]);
    if (sourceId !== undefined && sourceId !== occurrence(finding))
      throw new Error(
        "Continuum returned another source finding while polling.",
      );
    const status = text(current["status"]);
    const terminal = status && TERMINAL_WITHOUT_ISSUE.has(status);
    const issueId =
      text(current["mergedIntoIssueId"]) ??
      text(current["duplicateOfIssueId"]) ??
      text(current["createdIssueId"]);
    if (terminal || issueId !== submission.issueId) {
      delete submission.issueId;
      delete submission.issueArn;
    }
    if (terminal) {
      return this.#report(finding, submittedAt, {
        verdict: status,
        statusMessage: text(
          current["statusMessage"] ??
            current["discardReason"] ??
            current["statusReason"],
        ),
        disposition: "not_applicable",
      });
    }
    if (!issueId) return;
    // Keep the finding's current link even if reading a merge destination
    // fails. A retry must not restore a verdict from the previous issue.
    const scope = findingArn.slice(0, -("/code-findings/" + findingId).length);
    const issueArn = scope + "/code-issues/" + issueId;
    submission.issueId = issueId;
    submission.issueArn = issueArn;
    const issueArgs = [...environmentArgs, "--issue-id", issueId];
    const issue = await request("get-code-issue", issueArgs);
    if (issue["issueArn"] !== issueArn || issue["issueId"] !== issueId)
      throw new Error("Continuum returned a different issue while polling.");
    const ids = issue["findingIds"];
    if (!Array.isArray(ids) || !ids.includes(findingId)) return;
    const validation = await selectValidation(
      issueArtifacts(request, issueArgs, "VALIDATION_EVIDENCE"),
      findingId,
    );
    if (!validation) return;
    const { outcome, artifact, scope: resultScope } = validation;
    const currentEvidence =
      compareTimestamps(createdAt(artifact), submittedAt.toISOString()) >= 0;
    if (!currentEvidence && (status === "SUBMITTED" || status === "VALIDATING"))
      return;
    const issueVerdict = validationOutcome(artifact).verdict;
    const details = {
      issue,
      validationArtifact: artifact,
      resultScope,
      issueFindingCount: new Set(ids).size,
      issueVerdict: resultScope === "finding" ? issueVerdict : undefined,
    };
    // An inconclusive or historical run cannot supply current scoring.
    if (
      outcome.disposition !== "reportable" ||
      issueVerdict === "UNKNOWN" ||
      !currentEvidence
    )
      return this.#report(finding, submittedAt, outcome, details);

    // A score describes the issue, even if this member has a different verdict.
    // AWS can expose validation before publishing the corresponding score.
    const readScore: ContinuumRequest = (...args) =>
      request(...args).catch((error: unknown) => {
        throw new ScoreReadError(errorMessage(error));
      });
    try {
      let score: Record<string, unknown> | undefined;
      for await (const { artifact: candidate, tied } of issueArtifacts(
        readScore,
        issueArgs,
        "EVIDENCE",
      )) {
        if (linkedScore(issue, artifact, candidate)) {
          // Two eligible scores with the same time cannot be ordered. Leave
          // scoring pending until a newer, unambiguous score arrives.
          if (score && score["artifactId"] !== candidate["artifactId"]) break;
          score = candidate;
        }
        if (score && !tied)
          return this.#report(finding, submittedAt, outcome, {
            ...details,
            score,
          });
      }
    } catch (error) {
      if (!timedOut()) {
        if (!(error instanceof ScoreReadError)) throw error;
        return this.#report(
          finding,
          submittedAt,
          {
            ...outcome,
            unavailable: `Could not read the linked issue score. ${error.message}`,
          },
          { ...details, scoringPending: true },
        );
      }
    }
    return {
      waiting: this.#report(finding, submittedAt, outcome, {
        ...details,
        scoringPending: true,
      }),
    };
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
      score,
      scoringPending,
      resultScope = "finding",
      issueFindingCount,
      issueVerdict,
    }: {
      issue?: Record<string, unknown>;
      validationArtifact?: Record<string, unknown>;
      score?: Record<string, unknown>;
      scoringPending?: boolean;
      resultScope?: ValidationResultScope;
      issueFindingCount?: number;
      issueVerdict?: string;
    } = {},
  ): ValidationProviderAssessment {
    const conclusive = disposition === "reportable";
    const validationArtifactId = text(validationArtifact["artifactId"]);
    const evidenceCreatedAt = createdAt(validationArtifact) || undefined;
    const validatedAt = conclusive ? evidenceCreatedAt : undefined;
    const submitted = submittedAt.toISOString();
    const olderArtifact =
      compareTimestamps(evidenceCreatedAt ?? "", submitted) < 0;
    const stale =
      olderArtifact ||
      compareTimestamps(
        text(issue["updatedAt"] ?? issue["createdAt"]) ?? "",
        submitted,
      ) < 0;
    const joinedValidatedIssue =
      conclusive && resultScope === "issue" && olderArtifact;
    const severity = severityLevel(finding);
    const providerSeverity = text(issue["severity"])?.toLowerCase();
    const status = terminalStatus ? ` (validation run ${terminalStatus})` : "";
    const verdictText = `Continuum ${resultScope} verdict: ${verdict}${status}`;
    const reasons = [{ basis: "INFERRED", reason: verdictText }];
    const report = [
      `**${safeText(finding["title"], 160)}**`,
      resultScope === "issue"
        ? "Continuum returned an issue-level result. The submitted finding has no individual verdict."
        : "Continuum returned a result for the submitted finding.",
      verdictText,
      `Codex finding severity: ${severity} (retained).`,
    ];
    if (statusMessage) report.push(statusMessage);
    if (unavailable && !terminalStatus) report.push(unavailable);
    if (validationArtifactId) {
      report.push(
        "Codex has not independently verified that this result reproduces the submitted flaw. Deployment source identity is not compared.",
      );
      if (issueVerdict)
        report.push(`Continuum issue verdict: ${issueVerdict}.`);
      if (providerSeverity)
        report.push(`Continuum issue severity: ${providerSeverity}.`);
      if (issueFindingCount)
        report.push(`Findings in issue: ${issueFindingCount}.`);
      report.push(
        `Validation artifact: ${validationArtifactId} (${evidenceCreatedAt ?? "creation time unknown"}).`,
      );
      if (stale)
        report.push(
          "Evidence is possibly stale because it predates submission.",
        );
      if (joinedValidatedIssue)
        report.push(
          "This finding joined an issue Continuum had already validated. The issue proof predates this submission.",
        );
      if (terminalStatus === "FAILED")
        report.push(
          "To investigate the failed run, ask AWS privately for worker logs for this validation artifact.",
        );
    }
    let reachableFromAttacker: boolean | undefined;
    if (score) {
      const factors = severityFactors(score);
      const { basis: signalBasis, signal, value } = reachability(score);
      reachableFromAttacker = value;
      const exposure =
        reachableFromAttacker === true
          ? "reachable from attacker"
          : reachableFromAttacker === false
            ? "not reachable from attacker"
            : "exposure unknown";
      report.push(
        `Issue ${exposure} (basis ${signalBasis}).`,
        `Issue scoring at ${createdAt(score)}: ${factors}.`,
        signal,
      );
      reasons.push(
        { basis: "INFERRED", reason: factors },
        { basis: signalBasis, reason: signal },
        ...evidenceRows(score).flatMap((row) =>
          Object.entries({
            ...object(row["preconditions"]),
            ...object(row["impactDimensions"]),
          }).map(([name, raw]) => ({
            basis: basisLabel(object(raw)["basis"]),
            reason: `${name}: ${safeText(String(object(raw)["value"]), 80)} — ${safeText(object(raw)["reason"], 180)}`,
          })),
        ),
      );
    } else if (scoringPending) {
      unavailable ??=
        "Continuum timed out waiting for an unambiguous linked issue score. Retry validation to refresh the score.";
      disposition = "deferred";
      reasons.push({ basis: "INFERRED", reason: unavailable });
      report.push(unavailable);
    }
    return {
      disposition,
      ...(unavailable && { unavailable }),
      report: report.join("\n\n"),
      record: {
        itemId: occurrence(finding),
        provider: this.name,
        verdict,
        ...(terminalStatus && { terminalStatus }),
        validationArtifactId,
        ...(score && { scoringArtifactId: text(score["artifactId"]) }),
        ...(scoringPending && { scoringPending }),
        ...(statusMessage && { statusMessage }),
        ...(unavailable && { unavailable }),
        severityBefore: severity,
        severityAfter: severity,
        ...(providerSeverity && { providerSeverity }),
        ...(issueVerdict && { issueVerdict }),
        resultScope,
        ...(issueFindingCount !== undefined && { issueFindingCount }),
        joinedValidatedIssue,
        ...(reachableFromAttacker !== undefined && { reachableFromAttacker }),
        reasons,
        claimMatch: "unknown",
        freshness: {
          ...(evidenceCreatedAt && { evidenceCreatedAt }),
          ...(validatedAt && { validatedAt }),
          ...(score && { scoredAt: createdAt(score) }),
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
