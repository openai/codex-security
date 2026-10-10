const { readFileSync, writeFileSync } = require("node:fs");
const { resolve } = require("node:path");
const { compileFromFile } = require("json-schema-to-typescript");
const { format } = require("prettier");

async function main() {
  const schemas = resolve(__dirname, "../../../plugins/codex-security/schemas");
  const model = await compileFromFile(
    resolve(schemas, "sca-result.schema.json"),
    {
      bannerComment:
        "/* Generated from the plugin JSON Schemas. Run `pnpm generate:models`. */",
      format: false,
      ignoreMinAndMaxItems: true,
      unknownAny: true,
    },
  );
  const result = await format(model, { parser: "typescript", printWidth: 80 });
  const output = resolve(__dirname, "../src/sca-types.ts");
  if (process.argv.includes("--check")) {
    if (readFileSync(output, "utf8").replaceAll("\r\n", "\n") !== result) {
      throw new Error(
        "src/sca-types.ts is out of date. Run `pnpm generate:models`.",
      );
    }
  } else writeFileSync(output, result);
}
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
