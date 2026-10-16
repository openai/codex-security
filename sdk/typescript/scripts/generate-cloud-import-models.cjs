// The checked-in versioned schema is exported from the Cloud API contract.
const { readFileSync, writeFileSync } = require("node:fs");
const { resolve } = require("node:path");
const { format } = require("prettier");
const { compile } = require("json-schema-to-typescript");
const root = resolve(__dirname, "..");
(async () => {
  const schema = JSON.parse(
    readFileSync(resolve(root, "schemas/cloud-import-v1.schema.json"), "utf8"),
  );
  const generated = await compile(
    {
      ...schema,
      type: "object",
      properties: Object.fromEntries(
        ["CreateImportedScan", "ImportedScanReceipt", "ImportDestinations"].map(
          (name) => [name, { $ref: `#/$defs/${name}` }],
        ),
      ),
      additionalProperties: false,
    },
    "CloudImportProtocolV1",
    {
      bannerComment:
        "/* Generated from cloud-import-v1.schema.json. Run node scripts/generate-cloud-import-models.cjs. */",
      ignoreMinAndMaxItems: true,
      unknownAny: true,
    },
  );
  const source = await format(generated, {
    parser: "typescript",
    printWidth: 80,
  });
  const output = resolve(root, "src/cloud-import-models.ts");
  if (process.argv.includes("--check")) {
    if (readFileSync(output, "utf8") !== source)
      throw new Error("Cloud import models are out of date.");
  } else writeFileSync(output, source);
})();
