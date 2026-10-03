import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createScaUpdateHandoff } from "../../sdk/typescript/dist/index.js";

const [resultPath, directory, ...matchIds] = process.argv.slice(2);
if (!resultPath || !directory || matchIds.length === 0) {
  throw new Error(
    "Usage: node examples/sca/handoff.mjs <sca-result.json> <new-handoff-directory> <match-id> [...match-ids]",
  );
}
const result = JSON.parse(await readFile(resultPath, "utf8"));
const handoff = createScaUpdateHandoff(result, matchIds);
const output = resolve(directory);
await mkdir(output, { mode: 0o700 });
await writeFile(join(output, "issues.md"), handoff.findingText);
await writeFile(join(output, "validation.md"), handoff.validationInstructions);
console.log(`Review the update request in ${output} before starting patch.`);
