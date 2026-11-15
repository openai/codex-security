import { expect, test } from "bun:test";
import { reviewDependencyAdvisoryDispute } from "../src/dependency-advisory-review.js";

const advisory = {
  id: "advisory-metadata",
  details: "Conflicting descriptions",
};
const dispute = {
  question: "Which decoder condition does the captured fix establish?",
  interpretations: ["Malformed input is required", "Any input is affected"],
};
const evidence = [
  {
    id: "captured-fix",
    origin: "Pinned fixing source",
    excerpt: "check(size);",
  },
  {
    id: "captured-primary",
    origin: "Primary advisory",
    excerpt: "Malformed input",
  },
];
const interpretation = {
  component: "example-decoder",
  affectedVersions: "before 2.0",
  operations: ["decode"],
  conditions: ["malformed input", "unpatched copy"],
  exclusions: ["patched copy"],
  evidenceIds: ["captured-fix"],
};

function review(result: unknown) {
  return reviewDependencyAdvisoryDispute({
    advisory,
    dispute,
    evidence,
    review: async () => JSON.stringify(result),
  });
}

test("advisory reviewer schema offers captured receipt IDs, not metadata labels", async () => {
  const result = await reviewDependencyAdvisoryDispute({
    advisory,
    dispute,
    evidence,
    review: async (_prompt, schema) => {
      const output = schema as {
        properties: {
          interpretations: {
            items: {
              properties: { evidenceIds: { items: { enum: string[] } } };
            };
          };
        };
      };
      expect(
        output.properties.interpretations.items.properties.evidenceIds.items
          .enum,
      ).toEqual(["captured-fix", "captured-primary"]);
      return JSON.stringify({
        decision: "resolved",
        reason: "The captured primary and fix settle the disputed condition.",
        interpretations: [interpretation],
      });
    },
  });
  expect(result.interpretations[0]).toEqual(interpretation);
  expect(result.searchOperations).toEqual(["decode"]);
});

test("unresolved advisory review retains combined search operations", async () => {
  const alternatives = [
    interpretation,
    {
      ...interpretation,
      operations: ["decode", "readHeader"],
      conditions: ["possibly any input"],
      evidenceIds: ["captured-primary"],
    },
  ];
  const result = await review({
    decision: "unresolved",
    reason: "The supplied records do not settle the competing condition.",
    interpretations: alternatives,
  });
  expect(result.interpretations).toEqual(alternatives);
  expect(result.searchOperations).toEqual(["decode", "readHeader"]);
});

test("an advisory label is a valid evidence ID when its text was actually supplied", async () => {
  const captured = {
    ...interpretation,
    evidenceIds: ["advisory-metadata"],
  };
  const result = await reviewDependencyAdvisoryDispute({
    advisory,
    dispute,
    evidence: [
      {
        id: "advisory-metadata",
        origin: "Host-captured advisory text",
        excerpt: "The decoder requires malformed input.",
      },
    ],
    review: async () =>
      JSON.stringify({
        decision: "resolved",
        reason: "The supplied advisory text settles the prerequisite.",
        interpretations: [captured],
      }),
  });
  expect(result.interpretations).toEqual([captured]);
});

test("advisory review identifies metadata IDs that were not supplied as receipts", async () => {
  await expect(
    review({
      decision: "unresolved",
      reason: "The metadata and captured source disagree.",
      interpretations: [
        {
          ...interpretation,
          evidenceIds: ["advisory-metadata", "captured-fix"],
        },
        { ...interpretation, evidenceIds: ["unsupplied-reference"] },
      ],
    }),
  ).rejects.toThrow(
    'interpretations[0].evidenceIds contains unknown evidence ID "advisory-metadata"',
  );
  try {
    await review({
      decision: "resolved",
      reason: "A metadata label alone cannot supply a source receipt.",
      interpretations: [
        { ...interpretation, evidenceIds: ["advisory-metadata"] },
      ],
    });
    throw new Error("Expected the unsupplied evidence ID to be rejected");
  } catch (error) {
    expect(String(error)).toContain(
      'Available evidence IDs: ["captured-fix","captured-primary"]',
    );
  }
});

test("advisory review explains both invalid cardinality and unknown receipts", async () => {
  await expect(
    review({
      decision: "unresolved",
      reason: "The alternatives remain unresolved.",
      interpretations: [
        { ...interpretation, evidenceIds: ["unsupplied-reference"] },
      ],
    }),
  ).rejects.toThrow(
    'Unresolved decision requires at least two interpretations; received 1. interpretations[0].evidenceIds contains unknown evidence ID "unsupplied-reference"',
  );
});

test("resolved advisory review still requires exactly one interpretation", async () => {
  await expect(
    review({
      decision: "resolved",
      reason: "A resolved decision must identify the supported interpretation.",
      interpretations: [interpretation, interpretation],
    }),
  ).rejects.toThrow(
    "Resolved decision requires exactly one interpretation; received 2.",
  );
});
