import { realpath } from "node:fs/promises";
import { join, relative } from "node:path";
import { z } from "zod";
import { portableRelativePath } from "./contract.js";
import { CodexSecurityError } from "./errors.js";
import { readRegularInputFile } from "./prompt-files.js";
import { relativePathIsOutside } from "./targets.js";

const verdict = z.enum(["exploitable", "ruled_out", "unknown"]);
const evidence = z.strictObject({
  path: z.string().min(1).describe("Repository-relative source path."),
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive(),
});
const use = z.strictObject({
  location: z
    .string()
    .min(1)
    .describe("Service or path where the dependency is used."),
  component: z.string().min(1),
  version: z.string().nullable(),
  verdict,
  deployment: z
    .enum(["confirmed", "configured", "unknown"])
    .describe(
      "Confirmed requires evidence that this use is running. Build or deployment configuration alone is configured.",
    ),
  reason: z.string().min(1),
  evidence: z.array(evidence).min(1),
});

export const dependencyAssessmentSchema = z.strictObject({
  status: verdict.describe(
    "Overall checkout verdict. Use unknown when the evidence is insufficient to decide.",
  ),
  uses: z
    .array(use)
    .describe("One assessment per distinct use of the affected dependency."),
  limitations: z.array(z.string()),
});

export async function validateDependencyAssessment(
  value: unknown,
  repository: string,
  signal?: AbortSignal,
): Promise<z.infer<typeof dependencyAssessmentSchema>> {
  const assessment = dependencyAssessmentSchema.parse(value);
  const lineCounts = new Map<string, number>();
  for (const use of assessment.uses) {
    for (const { path, startLine, endLine } of use.evidence) {
      signal?.throwIfAborted();
      let lines = lineCounts.get(path);
      if (lines === undefined) {
        const file = await realpath(
          join(repository, portableRelativePath(path, "Evidence path")),
        );
        if (relativePathIsOutside(relative(repository, file))) {
          throw new CodexSecurityError(
            `Evidence path leaves the checkout: ${path}`,
          );
        }
        const source = await readRegularInputFile(file, repository);
        // A trailing newline terminates the last line; it does not add a line.
        lines = source ? source.replace(/\n$/u, "").split("\n").length : 0;
        lineCounts.set(path, lines);
      }
      if (startLine > endLine || endLine > lines) {
        throw new CodexSecurityError(
          `Invalid evidence range ${path}:${startLine}-${endLine} (file has ${lines} lines).`,
        );
      }
    }
  }
  signal?.throwIfAborted();

  if (assessment.uses.some((use) => use.verdict === "exploitable")) {
    assessment.status = "exploitable";
  } else if (
    assessment.status === "exploitable" ||
    assessment.uses.length === 0 ||
    assessment.uses.some((use) => use.verdict === "unknown")
  ) {
    assessment.status = "unknown";
  }
  return assessment;
}

const tokens = z.number().int().nonnegative();
export const dependencyReachabilityReportSchema =
  dependencyAssessmentSchema.extend({
    cve: z.string(),
    advisories: z.array(z.string()),
    usage: z
      .object({
        input_tokens: tokens,
        cached_input_tokens: tokens,
        cache_write_input_tokens: tokens,
        output_tokens: tokens,
        reasoning_output_tokens: tokens,
      })
      .nullable(),
  });
