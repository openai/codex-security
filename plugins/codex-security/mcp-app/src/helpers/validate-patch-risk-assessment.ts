import { parseArgs } from "node:util";
import Ajv2020 from "ajv/dist/2020.js";
import { decodeUtf8 } from "./utf8";
import assessmentSchema from "../../../schemas/patch-risk-assessment.schema.json";
import {
  filesystemErrorMessage,
  normalizePath,
  readFile,
} from "./helper-files";
import { decodePosixBytes } from "./posix-path";
import { escapeControls, object, parseJson } from "./json";

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

const ajv = new Ajv2020({ strict: false });
const assessmentValidator = ajv.compile(assessmentSchema);

const nonApplicable = new Set([
  "no_live_effect",
  "wrong_owner",
  "duplicate",
  "superseded",
]);

export function validatePatchRiskAssessment(value: unknown): string[] {
  if (!object(value)) return ["assessment must be a JSON object"];
  if (!assessmentValidator(value))
    return [
      ajv.errorsText(assessmentValidator.errors, {
        dataVar: "patch-risk-assessment.schema",
      }),
    ];
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
    contents = readFile(path === "-" ? 0 : normalizePath(path));
  } catch (error) {
    throw new Error(`cannot read assessment: ${filesystemErrorMessage(error)}`);
  }
  const text =
    path === "-"
      ? decodePosixBytes(contents)
      : decodeUtf8(contents).replace(/\r\n?/gu, "\n");
  try {
    const value = parseJson(text);
    // JSON syntax is already valid; check each object's decoded member names.
    const objects: Set<string>[] = [];
    for (let index = 0; index < text.length; index++) {
      if (text[index] === "{") objects.push(new Set());
      else if (text[index] === "}") objects.pop();
      else if (text[index] === '"') {
        const start = index;
        for (index++; text[index] !== '"'; index++)
          if (text[index] === "\\") index++;
        if (!/^\s*:/u.test(text.slice(index + 1))) continue;
        const key = JSON.parse(text.slice(start, index + 1)) as string;
        const keys = objects.at(-1)!;
        if (keys.has(key))
          throw new Error(`duplicate JSON object key: ${escapeControls(key)}`);
        keys.add(key);
      }
    }
    return value;
  } catch (error) {
    if (error instanceof SyntaxError)
      throw new Error(`cannot read assessment: ${error.message}`);
    throw error;
  }
}

export function validatePatchRiskAssessmentCommand(args: string[]): number {
  const usage =
    "usage: launch_codex_security_mcp[.cmd] --helper validate-patch-risk-assessment [-h] assessment";
  let path: string;
  try {
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: { help: { type: "boolean", short: "h" } },
    });
    if (values.help) {
      console.log(
        `${usage}\n\nValidate a patch-risk assessment.\n\npositional arguments:\n  assessment  Assessment JSON path, or - for stdin.\n\noptions:\n  -h, --help  show this help message and exit`,
      );
      return 0;
    }
    if (positionals.length !== 1)
      throw new Error("exactly one assessment path or - for stdin is required");
    path = positionals[0]!;
  } catch (error) {
    console.error(
      `${usage}\n${error instanceof Error ? error.message : String(error)}`,
    );
    return 2;
  }
  try {
    const errors = validatePatchRiskAssessment(readAssessment(path));
    for (const error of errors) console.error(error);
    return errors.length ? 1 : 0;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    return 1;
  }
}
