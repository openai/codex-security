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
const screeningSameSchema = z.object({
  decision: z.literal("SAME"),
  rationale,
});
const screeningDistinctSchema = z.object({
  decision: z.literal("DISTINCT"),
  rationale,
});
const screeningDecisionSchema = z.discriminatedUnion("decision", [
  screeningSameSchema.strict(),
  screeningDistinctSchema.strict(),
]);
// The host assigns exact slot names; finding IDs stay out of model output.
const screeningSchema = z
  .object({
    decisions: z.record(z.string(), screeningDecisionSchema),
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

export function screeningPairSlot(index: number): string {
  return `pair-${index + 1}`;
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
  const required = findings
    .slice(1)
    .map((_finding, index) => screeningPairSlot(index));
  const submitted = Object.keys(result.decisions);
  if (
    submitted.length !== required.length ||
    required.some((slot) => !Object.hasOwn(result.decisions, slot))
  ) {
    throw new Error("Submit exactly the assigned screening pair slots.");
  }
  return result;
}

function screeningToolSchema(neighborCount: number): object {
  const decisionSchema = z.toJSONSchema(screeningDecisionSchema, {
    target: "openapi-3.0",
  });
  const slots = Array.from({ length: neighborCount }, (_value, index) =>
    screeningPairSlot(index),
  );
  return {
    type: "object",
    properties: {
      decisions: {
        type: "object",
        properties: Object.fromEntries(
          slots.map((slot) => [slot, decisionSchema]),
        ),
        required: slots,
        additionalProperties: false,
      },
    },
    required: ["decisions"],
    additionalProperties: false,
  };
}

export class CodexDeduplicationReviewer implements DeduplicationReviewer {
  constructor(private readonly runner: Pick<CodexReviewRunner, "run">) {}

  async screen(findings: readonly Finding[]): Promise<ScreeningResult> {
    return await this.runner.run({
      stage: "screening",
      model: "gpt-5.6-luna",
      effort: "xhigh",
      prompt: screeningPrompt(findings),
      schema: screeningToolSchema(findings.length - 1),
      validate: (value) => validateScreening(value, findings),
    });
  }

  async reviewPair(findings: readonly Finding[]): Promise<DuplicateDecision> {
    return await this.runner.run({
      stage: "pair-review",
      model: "gpt-5.6-sol",
      effort: "high",
      prompt: pairReviewPrompt(findings),
      schema: {
        type: "object",
        ...z.toJSONSchema(reviewSchema, { target: "openapi-3.0" }),
      },
      validate: (value) => validateReview(value, findings),
    });
  }
}
