import { z } from "zod";

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
