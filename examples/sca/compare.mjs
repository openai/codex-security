import { readFile } from "node:fs/promises";
import { compareScaResults } from "../../sdk/typescript/dist/index.js";

const [base, head] = process.argv.slice(2);
if (!base || !head) {
  throw new Error(
    "Usage: node examples/sca/compare.mjs <base-sca-result.json> <head-sca-result.json>",
  );
}
console.log(
  JSON.stringify(
    compareScaResults(
      JSON.parse(await readFile(base, "utf8")),
      JSON.parse(await readFile(head, "utf8")),
    ),
    null,
    2,
  ),
);
