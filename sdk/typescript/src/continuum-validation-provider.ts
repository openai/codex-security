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
  type ValidationBasis,
  type ValidationItemRecord,
  type ValidationIssueResult,
  unavailableAssessment,
} from "./validation-provider.js";

import {
  validationBody,
  validationText,
} from "./validation-provider-report.js";

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
  return validationText(text(value) ?? "not returned", limit);
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

function evidenceRows(artifact: Record<string, unknown>) {
  const body = object(artifact["body"]);
  const signals = object(body["prevalidationSignals"])["signals"];
  return Array.isArray(signals) ? signals.map(object) : [];
}

function basisLabel(value: unknown): ValidationBasis {
  const raw = text(value);
  if (!raw) return "INFERRED";
  const known = raw.toUpperCase();
  return ["GRAPH", "CODE", "FINDING", "INFERRED"].includes(known)
    ? known
    : safeText(raw, 80);
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

function proofType(
  artifact: Record<string, unknown>,
): NonNullable<ValidationIssueResult["checkedBy"]> {
  const body = object(artifact["body"]);
  const validation = object(body["validationEvidence"] ?? body);
  const proof = object(validation["executedProof"]);
  return Object.keys(proof).length > 0
    ? "executed proof"
    : validation["sourceAnalysis"] !== undefined
      ? "source analysis"
      : "validation evidence";
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

    const pendingIssues = new Map<string, ValidationIssueResult>();
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
                pendingIssues,
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
      const submission = submissions[index]!;
      results[index] = this.#assessment(
        submission.item!,
        {
          state: "pending",
          issue: pendingIssues.get(submission.findingId!),
          reasons: [],
          unavailable: "Continuum has not finished within the waiting period.",
        },
        now(),
      );
    }
    return results.map((assessment, index) => {
      const item = supplied[index];
      if (assessment.record) return assessment;
      return this.#assessment(
        typeof item === "string" ? {} : item!,
        {
          state: "unavailable",
          reasons: [],
          unavailable: assessment.unavailable,
        },
        now(),
      );
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
    pendingIssues: Map<string, ValidationIssueResult>,
  ): Promise<ValidationProviderAssessment | undefined> {
    const call = (operation: string, args: string[]) =>
      this.#call(launch, operation, args, context, deadline, delay, now);
    const environmentArgs = ["--environment-id", this.#options.environmentId];
    try {
      const current = await call("get-code-finding", [
        ...environmentArgs,
        "--finding-id",
        findingId,
      ]);
      const status = text(current["status"]) ?? "SUBMITTED";
      if (TERMINAL_WITHOUT_ISSUE.has(status)) {
        const reason = safeText(
          current["statusMessage"] ??
            current["discardReason"] ??
            current["statusReason"],
        );
        return this.#assessment(
          finding,
          {
            state: "declined",
            reasons: [
              {
                basis: "INFERRED",
                reason: `Continuum declined the finding (${status}): ${reason}`,
              },
            ],
          },
          now(),
        );
      }
      if (["SUBMITTED", "VALIDATING"].includes(status)) return;
      const issueId =
        text(current["mergedIntoIssueId"]) ??
        text(current["duplicateOfIssueId"]) ??
        text(current["createdIssueId"]) ??
        text(created["mergedIntoIssueId"]) ??
        text(created["duplicateOfIssueId"]) ??
        text(created["createdIssueId"]);
      if (!issueId) return;
      const issueArgs = [...environmentArgs, "--issue-id", issueId];
      const issue = await call("get-code-issue", issueArgs);
      // Preserve identity and membership checks, without attributing proof to a member.
      const arn = text(current["findingArn"]);
      const suffix = `/code-findings/${findingId}`;
      const scope = arn?.endsWith(suffix)
        ? arn.slice(0, -suffix.length)
        : undefined;
      const ids = issue["findingIds"];
      if (
        !scope?.endsWith(`:environments/${this.#options.environmentId}`) ||
        issue["issueArn"] !== `${scope}/code-issues/${issueId}` ||
        issue["issueId"] !== issueId ||
        !Array.isArray(ids) ||
        !ids.every((id) => typeof id === "string") ||
        !ids.includes(findingId)
      )
        throw new Error(
          "Continuum returned an issue with inconsistent identity or finding membership",
        );
      const result: ValidationIssueResult = {
        id: issueId,
        url: this.#issueUrl(issueId),
        title: safeText(issue["name"] ?? issue["synopsis"], 400),
        severity: text(issue["severity"])?.toLowerCase(),
        findingCount: new Set(ids).size,
      };
      pendingIssues.set(findingId, result);
      const artifacts: Record<string, unknown>[] = [];
      for (const kind of ["VALIDATION_EVIDENCE", "EVIDENCE"]) {
        const listed = await call("list-code-issue-artifacts", [
          ...issueArgs,
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
        const latest = items[0];
        const artifactId = text(latest?.["artifactId"]);
        if (!artifactId) return;
        const artifact = await call("get-code-issue-artifact", [
          ...issueArgs,
          "--artifact-id",
          artifactId,
        ]);
        if (artifact["artifactType"] !== kind)
          throw new Error("Continuum returned an unexpected artifact type");
        artifact["createdAt"] ??= latest?.["createdAt"];
        artifacts.push(artifact);
      }
      const [validation, scoring] = artifacts as [
        Record<string, unknown>,
        Record<string, unknown>,
      ];
      const likelihood = evidenceRows(scoring).find(
        (row) => row["dimension"] === "LIKELIHOOD_ASSESSMENT",
      );
      const reachability = object(
        object(likelihood?.["preconditions"])["reachableFromAttacker"],
      );
      result.verdict = verdictFrom(validation);
      result.checkedBy = proofType(validation);
      result.validatedAt = text(validation["createdAt"]);
      result.scoredAt = text(scoring["createdAt"]);
      result.validationBeforeSubmission = result.validatedAt
        ? new Date(result.validatedAt).getTime() < submittedAt.getTime()
        : undefined;
      result.scoringBeforeSubmission = result.scoredAt
        ? new Date(result.scoredAt).getTime() < submittedAt.getTime()
        : undefined;
      result.reachableFromAttacker =
        typeof reachability["value"] === "boolean"
          ? reachability["value"]
          : undefined;
      result.reachabilityBasis = basisLabel(reachability["basis"]);
      result.reachabilityReason = text(reachability["reason"])
        ? safeText(reachability["reason"], 400)
        : undefined;
      // A named result is supplemental, from the newest artifact only.
      const selected = selectFindingValidationArtifact(validation, findingId);
      const specific =
        selected?.scope === "finding"
          ? verdictFrom(selected.artifact)
          : undefined;
      const reasons = evidenceRows(scoring).flatMap((row) =>
        Object.entries({
          ...object(row["preconditions"]),
          ...object(row["impactDimensions"]),
        }).map(([name, raw]) => ({
          basis: basisLabel(object(raw)["basis"]),
          reason: `${name}: ${safeText(String(object(raw)["value"]), 80)} — ${safeText(object(raw)["reason"], 400)}`,
        })),
      );
      return this.#assessment(
        finding,
        {
          state: "validated",
          issue: result,
          ...(specific && specific !== "not returned"
            ? { findingResult: { verdict: specific } }
            : {}),
          reasons,
        },
        now(),
      );
    } catch (error) {
      return this.#assessment(
        finding,
        {
          state: "unavailable",
          issue: pendingIssues.get(findingId),
          reasons: [],
          unavailable:
            "Continuum could not return a result; check host permissions, connectivity and service availability.",
        },
        now(),
      );
    }
  }

  #issueUrl(id: string): string {
    const base = (
      this.#options.consoleBaseUrl ??
      "https://console.aws.amazon.com/continuum/home"
    ).replace(/\/$/u, "");
    return `${base}#/environments/${encodeURIComponent(this.#options.environmentId)}/issues/${encodeURIComponent(id)}`;
  }

  #assessment(
    finding: AnyFinding,
    fields: Omit<ValidationItemRecord, "itemId" | "provider" | "codexSeverity">,
    now: Date,
  ): ValidationProviderAssessment {
    const record: ValidationItemRecord = {
      itemId: occurrence(finding),
      provider: this.name,
      codexSeverity: severityLevel(finding),
      ...fields,
    };
    return {
      disposition:
        fields.state === "validated" || fields.state === "declined"
          ? "reportable"
          : "deferred",
      report: validationBody([record]),
      ...(fields.unavailable ? { unavailable: fields.unavailable } : {}),
      record,
      provenance: {
        provider: this.name,
        providerVersion: this.version,
        referenceId: record.issue?.id,
        referenceUrl: record.issue?.url,
        validatedAt: record.issue?.validatedAt ?? now.toISOString(),
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
