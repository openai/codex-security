import assert from "node:assert/strict";
import { join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import * as z from "zod/v4";
import { importSource } from "./import-module.ts";

const { projectArtifactToolSchema } = await importSource(
  join(import.meta.dirname, "../src/artifact-schema-loader.ts"),
);

const document = {
  $id: "codex-security://schemas/advertisement-fixture.json",
  $defs: {
    input: {
      type: "object",
      properties: {
        scope: {
          type: "object",
          properties: {
            includePaths: false,
            summary: { type: "string", minLength: 1 },
          },
          propertyNames: { pattern: "^[a-zA-Z]+$" },
          additionalProperties: true,
        },
        findings: {
          type: "array",
          items: {
            type: "object",
            properties: {
              findingId: false,
              title: { type: "string", minLength: 1 },
              confirmed: { const: false },
            },
            required: ["title"],
            additionalProperties: true,
          },
        },
      },
      required: ["findings"],
      additionalProperties: false,
      examples: [
        {
          findings: [
            { title: "Fixture", extension: { properties: { kept: false } } },
          ],
        },
      ],
    },
  },
} satisfies z.core.JSONSchema.JSONSchema;

const original = structuredClone(document.$defs.input);
const validator = projectArtifactToolSchema(z.fromJSONSchema(original));
const advertised = validator.toJSONSchema({ io: "input" });
assert.equal(original.properties.scope.properties.includePaths, false);
assert.equal(
  document.$defs.input.properties.scope.properties.includePaths,
  false,
);
assert.equal(
  Object.hasOwn(advertised.properties.scope.properties, "includePaths"),
  false,
);
assert.equal(
  Object.hasOwn(advertised.properties.findings.items.properties, "findingId"),
  false,
);
assert.deepEqual(advertised.properties.scope.propertyNames, {
  allOf: [{ pattern: "^[a-zA-Z]+$" }, { not: { enum: ["includePaths"] } }],
});
assert.deepEqual(validator.meta().examples, document.$defs.input.examples);

const ajv = new Ajv2020({ strict: false });
const authoredValidation = ajv.compile(original);
const advertisedValidation = ajv.compile(advertised);
for (const [input, expected] of [
  [{ findings: [] }, true],
  [
    {
      findings: [{ title: "Fixture", confirmed: false, extra: "retained" }],
      scope: { summary: "Reviewed", extension: true },
    },
    true,
  ],
  [{ findings: [], scope: { includePaths: [] } }, false],
  [{ findings: [], scope: { includePaths: null } }, false],
  [{ findings: [{ title: "Fixture", findingId: "host-owned" }] }, false],
  [{ findings: [{ title: "Fixture", findingId: false }] }, false],
  [{ findings: [{ title: "Fixture", confirmed: true }] }, false],
  [{ findings: [{}] }, false],
  [{ findings: [], scope: { "invalid-key": true } }, false],
  [{ findings: [], extra: true }, false],
] as const) {
  const label = JSON.stringify(input);
  assert.equal(authoredValidation(input), expected, `authored: ${label}`);
  assert.equal(advertisedValidation(input), expected, `advertised: ${label}`);
  assert.equal(
    validator.safeParse(input).success,
    expected,
    `runtime: ${label}`,
  );
}

// Keep examples in the native JSON-schema input that the projector visits.
const nativeFixture = z
  .object({
    findings: z.array(z.looseObject({ title: z.string() })),
  })
  .meta({ examples: structuredClone(document.$defs.input.examples) });
const nativeInputBefore = structuredClone(
  z.toJSONSchema(nativeFixture, { io: "input" }),
);
assert.deepEqual(nativeInputBefore.examples, document.$defs.input.examples);
const nativeProjected = projectArtifactToolSchema(nativeFixture);
assert.deepEqual(
  nativeProjected.toJSONSchema({ io: "input" }).examples,
  document.$defs.input.examples,
);
assert.deepEqual(
  z.toJSONSchema(nativeFixture, { io: "input" }),
  nativeInputBefore,
);
