import { decodeUtf8 } from "./utf8";
import assessmentSchema from "../../../schemas/patch-risk-assessment.schema.json";
import { validateAgainstSchema, type ContractSchema } from "./contract-schema";
import { readFile } from "./helper-files";
import { decodePosixBytes } from "./posix-path";
import { JsonSyntaxError, object, parseJson, pythonRepr } from "./python-json";
import { parsedPath } from "./resolve-security-md";

interface Assessment {
  recommendation: "merge" | "revise" | "no_op" | "block" | "hold_for_evidence";
  workflowLabel: string;
  impact: { rating: string };
  regressionLikelihood: { rating: string };
  regressionProtection: { rating: string; exactHeadChecksPassed: boolean };
  recoverability: { rating: string };
  confidence: { rating: string };
  applicability: { status: string };
  statusQuoRisk: { rating: string };
  affectedRuntimeRoots: string[];
  autoMergeExclusions: string[];
  materialBoundaries: { result: string }[];
  validation: { status: string }[];
  unknowns: { decisionCritical: boolean }[];
  evidencePlan: unknown[];
}

const nonApplicable = new Set([
  "no_live_effect",
  "wrong_owner",
  "duplicate",
  "superseded",
]);

export function validatePatchRiskAssessment(value: unknown): string[] {
  if (!object(value)) return ["assessment must be a JSON object"];
  try {
    validateAgainstSchema(
      value,
      assessmentSchema as ContractSchema,
      "patch-risk-assessment.schema",
    );
  } catch (error) {
    return [error instanceof Error ? error.message : String(error)];
  }
  const assessment = value as unknown as Assessment;
  const {
    recommendation,
    workflowLabel,
    unknowns,
    evidencePlan,
    materialBoundaries: boundaries,
  } = assessment;
  const applicability = assessment.applicability.status;
  const affirmativeFailure =
    assessment.regressionLikelihood.rating === "critical" ||
    boundaries.some((item) => item.result === "contradicted") ||
    assessment.validation.some((item) => item.status === "failed");
  const errors: string[] = [];

  if (recommendation === "merge") {
    if (
      !["auto_merge_candidate", "human_review_required"].includes(workflowLabel)
    )
      errors.push(
        "merge requires an auto-merge or human-review workflow label",
      );
    if (applicability !== "confirmed")
      errors.push("merge requires confirmed applicability");
    if (unknowns.some((item) => item.decisionCritical))
      errors.push("merge cannot retain a decision-critical unknown");
    if (boundaries.some((item) => item.result !== "supported"))
      errors.push("merge requires every material boundary to be supported");
    if (assessment.validation.some((item) => item.status === "failed"))
      errors.push("merge cannot retain a failed validation");
    if (evidencePlan.length)
      errors.push("merge cannot retain an evidence plan");
  } else if (workflowLabel !== recommendation) {
    errors.push("non-merge workflow label must match the recommendation");
  }

  if (recommendation === "hold_for_evidence") {
    if (!unknowns.some((item) => item.decisionCritical))
      errors.push("hold_for_evidence requires a decision-critical unknown");
    if (!evidencePlan.length)
      errors.push("hold_for_evidence requires a bounded evidence plan");
    if (affirmativeFailure)
      errors.push("hold_for_evidence cannot defer an established defect");
  } else if (evidencePlan.length) {
    errors.push("only hold_for_evidence may include an evidence plan");
  }

  if (recommendation === "no_op") {
    if (!nonApplicable.has(applicability))
      errors.push("no_op requires an established non-applicable disposition");
    if (unknowns.some((item) => item.decisionCritical))
      errors.push("no_op cannot retain a decision-critical unknown");
  } else if (nonApplicable.has(applicability)) {
    errors.push("an established non-applicable disposition requires no_op");
  }

  if (["revise", "block"].includes(recommendation) && !affirmativeFailure)
    errors.push(`${recommendation} requires affirmative failure evidence`);

  if (workflowLabel === "auto_merge_candidate") {
    const requirements: Record<string, boolean> = {
      "impact.rating": assessment.impact.rating === "low",
      "regressionLikelihood.rating":
        assessment.regressionLikelihood.rating === "low",
      "regressionProtection.rating":
        assessment.regressionProtection.rating === "strong",
      "regressionProtection.exactHeadChecksPassed":
        assessment.regressionProtection.exactHeadChecksPassed,
      "recoverability.rating": assessment.recoverability.rating === "easy",
      "confidence.rating": assessment.confidence.rating === "high",
      "applicability.status": applicability === "confirmed",
      affectedRuntimeRoots: assessment.affectedRuntimeRoots.length > 0,
      "statusQuoRisk.rating": assessment.statusQuoRisk.rating !== "unknown",
      autoMergeExclusions: assessment.autoMergeExclusions.length === 0,
      unknowns: unknowns.length === 0,
      validation: assessment.validation.every(
        (item) => item.status === "passed",
      ),
    };
    for (const [field, passed] of Object.entries(requirements))
      if (!passed) errors.push(`auto_merge_candidate gate failed: ${field}`);
  }
  return errors;
}

function readAssessment(path: string): unknown {
  let contents: Buffer;
  try {
    contents = readFile(path === "-" ? 0 : parsedPath(path));
  } catch (error) {
    throw new Error(
      `cannot read assessment: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const text =
    path === "-"
      ? decodePosixBytes(contents)
      : decodeUtf8(contents).replace(/\r\n?/gu, "\n");
  try {
    return parseJson(text, true);
  } catch (error) {
    if (error instanceof JsonSyntaxError)
      throw new Error(`cannot read assessment: ${error.message}`);
    throw error;
  }
}

function report(message: string): void {
  // Match Python's UTF-8 stderr when a diagnostic contains an unpaired surrogate.
  console.error(
    message.replace(
      /[\ud800-\udfff]/gu,
      (character) =>
        `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
    ),
  );
}

export function validatePatchRiskAssessmentCommand(args: string[]): number {
  const usage =
    "usage: launch_codex_security_mcp[.cmd] --helper validate-patch-risk-assessment [-h] assessment";
  const argumentError = (message: string) => {
    report(`${usage}\nvalidate-patch-risk-assessment: error: ${message}`);
    return 2;
  };
  let path: string | undefined;
  let positional = false;
  const extra: string[] = [];
  for (const arg of args) {
    if (!positional && arg === "--") {
      positional = true;
      continue;
    }
    if (!positional) {
      const option = arg.split("=", 1)[0];
      if (
        ["--h", "--he", "--hel", "--help"].includes(option) ||
        arg.startsWith("-h")
      ) {
        if (
          arg.startsWith(`${option}=`) &&
          (option === "-h" || option.startsWith("--"))
        )
          return argumentError(
            `argument -h/--help: ignored explicit argument ${pythonRepr(arg.slice(option.length + 1))}`,
          );
        console.log(
          `${usage}\n\nValidate a patch-risk assessment.\n\npositional arguments:\n  assessment  Assessment JSON path, or - for stdin.\n\noptions:\n  -h, --help  show this help message and exit`,
        );
        return 0;
      }
      if (
        arg.startsWith("-") &&
        arg !== "-" &&
        !arg.includes(" ") &&
        !/^-(?:\p{Decimal_Number}+|\p{Decimal_Number}*\.\p{Decimal_Number}+)\n?$/u.test(
          arg,
        )
      ) {
        extra.push(arg);
        continue;
      }
    }
    if (path === undefined) path = arg;
    else extra.push(arg);
  }
  if (path === undefined)
    return argumentError("the following arguments are required: assessment");
  if (extra.length)
    return argumentError(`unrecognized arguments: ${extra.join(" ")}`);
  try {
    const errors = validatePatchRiskAssessment(readAssessment(path));
    for (const error of errors) report(error);
    return errors.length ? 1 : 0;
  } catch (error) {
    report(error instanceof Error ? error.message : String(error));
    return 1;
  }
}
