import { z } from "incur";
import type { Finding } from "../../models.js";
import { CodexReviewRunner } from "./codex-review.js";
import {
  groupReviewPrompt,
  pairReviewPrompt,
  screeningPrompt,
} from "./deduplication-prompts.js";

const rationale = z.string().refine((value) => value.trim().length > 0);
const decision = z.enum(["SAME", "DISTINCT"]);
const screeningSchema = z
  .object({
    decisions: z.array(
      z
        .object({
          findingIds: z.tuple([z.string(), z.string()]),
          decision,
          rationale,
        })
        .strict(),
    ),
  })
  .strict();
const reviewSchema = z.object({ decision, rationale }).strict();

export type ScreeningResult = z.infer<typeof screeningSchema>;
export type DuplicateDecision = z.infer<typeof reviewSchema>;

export interface DeduplicationReviewer {
  screen(findings: readonly Finding[]): Promise<ScreeningResult>;
  reviewPair(findings: readonly Finding[]): Promise<DuplicateDecision>;
  reviewGroup(findings: readonly Finding[]): Promise<DuplicateDecision>;
}

export function pairKey(ids: readonly string[]): string {
  return JSON.stringify([...ids].sort());
}

export function validateScreening(
  value: unknown,
  findings: readonly Finding[],
): ScreeningResult {
  const result = screeningSchema.parse(value);
  const anchor = findings[0]!.findingId;
  const allowed = new Set(findings.map((finding) => finding.findingId));
  const required = new Set(
    findings.slice(1).map((finding) => pairKey([anchor, finding.findingId])),
  );
  const seen = new Set<string>();
  for (const recommendation of result.decisions) {
    const pair = recommendation.findingIds;
    const key = pairKey(pair);
    if (
      pair[0] === pair[1] ||
      pair.some((id) => !allowed.has(id)) ||
      seen.has(key) ||
      (!required.has(key) && recommendation.decision !== "SAME")
    ) {
      throw new Error(
        "Submit each assigned pair once; additional SAME pairs must use supplied findings.",
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
  constructor(
    private readonly runner: Pick<
      CodexReviewRunner,
      "run"
    > = new CodexReviewRunner(),
  ) {}

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
    return await this.review(pairReviewPrompt(findings));
  }

  async reviewGroup(findings: readonly Finding[]): Promise<DuplicateDecision> {
    return await this.review(groupReviewPrompt(findings));
  }

  private async review(prompt: string): Promise<DuplicateDecision> {
    return await this.runner.run({
      model: "gpt-5.6-sol",
      effort: "ultra",
      prompt,
      schema: z.toJSONSchema(reviewSchema, { target: "openapi-3.0" }),
      validate: (value) => reviewSchema.parse(value),
    });
  }
}
