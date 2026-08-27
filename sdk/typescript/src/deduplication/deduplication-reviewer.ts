import { z } from "incur";
import { readFileSync } from "node:fs";
import Ajv2020, { type ValidateFunction } from "ajv/dist/2020.js";
import type { Finding } from "../models.js";
import type { CodexReviewRunner } from "./codex-review.js";
import { pairReviewPrompt, screeningPrompt } from "./deduplication-prompts.js";

const rationale = z.string().refine((value) => value.trim().length > 0);
const sameSchema = z.object({
  decision: z.literal("SAME"),
  rationale,
  canonicalFindingId: z.string(),
  mergedFinding: z.record(z.string(), z.unknown()),
});
const distinctSchema = z.object({
  decision: z.literal("DISTINCT"),
  rationale,
  canonicalFindingId: z.null().optional(),
  mergedFinding: z.null().optional(),
});
const reviewSchema = z.discriminatedUnion("decision", [
  sameSchema,
  distinctSchema,
]);
const findingIds = z.tuple([z.string(), z.string()]);
const screeningSchema = z
  .object({
    decisions: z.array(
      z.discriminatedUnion("decision", [
        sameSchema.extend({ findingIds }).strict(),
        distinctSchema.extend({ findingIds }).strict(),
      ]),
    ),
  })
  .strict();

let validateMergedFinding: ValidateFunction<Finding> | undefined;

function requireMergedFinding(result: DuplicateDecision): void {
  if (result.decision !== "SAME") return;
  if (validateMergedFinding === undefined) {
    const schema = JSON.parse(
      readFileSync(
        new URL(
          "../../_bundled_plugin/schemas/findings.schema.json",
          import.meta.url,
        ),
        "utf8",
      ),
    );
    validateMergedFinding = new Ajv2020({ strict: false }).compile<Finding>(
      schema.properties.findings.items,
    );
  }
  if (
    !validateMergedFinding(result.mergedFinding) ||
    result.mergedFinding["findingId"] !== result.canonicalFindingId
  )
    throw new Error(
      "Every SAME decision requires a generated mergedFinding in the Finding schema with the canonical finding's identity.",
    );
}

export type ScreeningResult = z.infer<typeof screeningSchema>;
export type DuplicateDecision = z.infer<typeof reviewSchema>;

export interface DeduplicationReviewer {
  screen(findings: readonly Finding[]): Promise<ScreeningResult>;
  reviewPair(findings: readonly Finding[]): Promise<DuplicateDecision>;
}

export function pairKey(ids: readonly string[]): string {
  return JSON.stringify([...ids].sort());
}

export function validateReview(
  value: unknown,
  findings: readonly Finding[],
): DuplicateDecision {
  const result = reviewSchema.parse(value);
  requireMergedFinding(result);
  if (
    result.decision === "SAME" &&
    !findings.some((finding) => finding.findingId === result.canonicalFindingId)
  ) {
    throw new Error(
      "The canonical finding must belong to the assigned findings.",
    );
  }
  return result;
}

export function validateScreening(
  value: unknown,
  findings: readonly Finding[],
): ScreeningResult {
  const result = screeningSchema.parse(value);
  const anchor = findings[0]!.findingId;
  const required = new Set(
    findings.slice(1).map((finding) => pairKey([anchor, finding.findingId])),
  );
  const seen = new Set<string>();
  for (const recommendation of result.decisions) {
    requireMergedFinding(recommendation);
    const pair = recommendation.findingIds;
    const key = pairKey(pair);
    if (pair[0] === pair[1] || !required.has(key) || seen.has(key)) {
      throw new Error(
        "Submit each assigned anchor-neighbor pair exactly once.",
      );
    }
    if (
      recommendation.decision === "SAME" &&
      !pair.includes(recommendation.canonicalFindingId)
    ) {
      throw new Error(
        "The canonical finding must belong to its assigned pair.",
      );
    }
    seen.add(key);
  }
  if ([...required].some((key) => !seen.has(key))) {
    throw new Error(
      "Submit a decision for every assigned anchor-neighbor pair.",
    );
  }
  return result;
}

export class CodexDeduplicationReviewer implements DeduplicationReviewer {
  constructor(private readonly runner: Pick<CodexReviewRunner, "run">) {}

  async screen(findings: readonly Finding[]): Promise<ScreeningResult> {
    return await this.runner.run({
      model: "gpt-5.6-luna",
      effort: "xhigh",
      prompt: screeningPrompt(findings),
      schema: z.toJSONSchema(screeningSchema, { target: "openapi-3.0" }),
      validate: (value) => validateScreening(value, findings),
    });
  }

  async reviewPair(findings: readonly Finding[]): Promise<DuplicateDecision> {
    return await this.runner.run({
      model: "gpt-5.6-sol",
      effort: "xhigh",
      prompt: pairReviewPrompt(findings),
      schema: {
        type: "object",
        ...z.toJSONSchema(reviewSchema, { target: "openapi-3.0" }),
      },
      validate: (value) => validateReview(value, findings),
    });
  }
}
