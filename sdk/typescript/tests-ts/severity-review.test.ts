import { expect, test } from "bun:test";
import {
  reviewSeverity,
  type SeverityDecision,
} from "../src/severity-review.js";

// Listed from lowest to highest independently of the runtime ordering.
const levels = [
  null,
  "informational",
  "low",
  "medium",
  "high",
  "critical",
] as const;

test("three independent reviews vote by normalized severity, with deterministic ties", async () => {
  for (const first of levels) {
    for (const second of levels) {
      for (const third of levels) {
        const votes = [first, second, third] as const;
        const answers: SeverityDecision[] = votes.map((level, index) => ({
          findingId: "example-finding",
          decision: level === null ? "excluded" : "assessed",
          level,
          rubricLabel: level === null ? null : `${level}-${index}`,
          rationale: `Review ${index + 1}`,
          confidence: index === 0 ? "low" : "high",
          reviewTrigger: `Missing fact ${index + 1}`,
        }));
        let calls = 0;
        const result = await reviewSeverity(async () => answers[calls++]!);
        const expected =
          first === second || first === third
            ? first
            : second === third
              ? second
              : levels[
                  Math.max(...votes.map((level) => levels.indexOf(level)))
                ];
        expect(calls).toBe(3);
        expect(result).toBe(answers.find(({ level }) => level === expected)!);
      }
    }
  }
});

test.each([
  [["low"], "low"],
  [["low", "high"], "high"],
  [["low", "low", "high", "high"], "high"],
  [["critical", "low", "low", "high", "high", "informational"], "high"],
  [[null, null, "low", "low"], "low"],
  [
    ["low", "low", "low", "low", "low", "high", "high", "high", "high", "high"],
    "high",
  ],
] as [SeverityDecision["level"][], SeverityDecision["level"]][])(
  "votes across %j",
  async (votes, expected) => {
    let calls = 0;
    const result = await reviewSeverity(async () => {
      const level = votes[calls++]!;
      return {
        findingId: "example",
        decision: level === null ? "excluded" : "assessed",
        level,
        rubricLabel: level,
        rationale: "Synthetic review",
        confidence: null,
        reviewTrigger: null,
      };
    }, votes.length);
    expect(calls).toBe(votes.length);
    expect(result.level).toBe(expected);
  },
);
