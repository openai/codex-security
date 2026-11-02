import { expect, test } from "bun:test";
import { reviewDependencyEvidence } from "../src/dependency-reachability.js";

const advisory = {
  cve: "CVE-2024-1000",
  advisories: [
    {
      url: "https://example.invalid/advisory",
      summary: "Affected decoder",
      packages: [],
    },
  ],
};
const files = [
  {
    path: "app/lock",
    lines: [
      { number: 4, text: "version = 1" },
      { number: 6, text: "fixed = true" },
    ],
  },
];
const use = {
  location: "app",
  component: "parser",
  version: "1",
  verdict: "ruled_out" as const,
  deployment: "unknown",
  reason: "The source includes a fix.",
  evidenceIds: [2],
};

test("unmatched source produces an unknown assessment without model usage", async () => {
  const result = await reviewDependencyEvidence(
    advisory,
    { files: [], complete: false, limitations: [] },
    {},
  );
  expect(result).toMatchObject({ status: "unknown", uses: [], usage: null });
  expect(result.limitations.length).toBeGreaterThan(0);
});

test("incomplete coverage prevents a clean bill of health for the whole checkout", async () => {
  const options = {
    codex: {
      startThread: () => ({
        run: async () => ({
          finalResponse: JSON.stringify({ uses: [use], limitations: [] }),
        }),
      }),
    },
  };
  const complete = await reviewDependencyEvidence(
    advisory,
    { files, complete: true, limitations: [] },
    options,
  );
  expect(complete.status).toBe("ruled_out");
  expect(complete.uses[0]?.evidence).toEqual([
    { path: "app/lock", startLine: 6, endLine: 6 },
  ]);
  const partial = await reviewDependencyEvidence(
    advisory,
    { files, complete: false, limitations: [] },
    options,
  );
  expect(partial.status).toBe("unknown");
  expect(partial.uses[0]?.verdict).toBe("ruled_out");
});

test("rejects a citation to an excerpt that was never supplied", async () => {
  const options = {
    codex: {
      startThread: () => ({
        run: async () => ({
          finalResponse: JSON.stringify({
            uses: [
              {
                ...use,
                evidenceIds: [3],
              },
            ],
            limitations: [],
          }),
        }),
      }),
    },
  };
  await expect(
    reviewDependencyEvidence(
      advisory,
      { files, complete: true, limitations: [] },
      options,
    ),
  ).rejects.toThrow("Unknown source excerpt");
});
