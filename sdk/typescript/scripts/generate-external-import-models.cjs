const { readFileSync, writeFileSync } = require("node:fs");
const { resolve } = require("node:path");
const { compile } = require("json-schema-to-typescript");
const { format } = require("prettier");

async function generate() {
  const schema = JSON.parse(
    readFileSync(
      resolve(__dirname, "../schemas/external-findings.schema.json"),
      "utf8",
    ),
  );
  const types = await compile(schema, "ExternalFindingContracts", {
    bannerComment:
      "/* Generated from schemas/external-findings.schema.json. Run pnpm generate:external-import-models. */",
    format: false,
    ignoreMinAndMaxItems: true,
    unknownAny: true,
  });
  const output = await format(
    `${types}\nexport type ExternalFindingEvidence = ImportedFindingEvidence;\n`,
    { parser: "typescript" },
  );
  const target = resolve(__dirname, "../src/external-import-models.ts");
  if (process.argv.includes("--check")) {
    if (readFileSync(target, "utf8").replaceAll("\r\n", "\n") !== output)
      throw new Error(
        "External import models are stale. Run pnpm generate:external-import-models.",
      );
  } else writeFileSync(target, output);
}
generate().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
