import { join, resolve } from "node:path";
import { createSecurity } from "../../sdk/typescript/dist/index.js";

const [repository, output] = process.argv.slice(2);
if (!repository || !output) {
  throw new Error(
    "Usage: node examples/sca/run.mjs <repository> <output-directory>",
  );
}
await using security = createSecurity();
const result = await security.scanDependencies({
  repositoryPath: resolve(repository),
  outputDir: resolve(output),
});
console.log(`${result.matches.length} advisory matches; ${result.status}.`);
console.log(join(result.outputDir, "report.md"));
// Advisory matches are report-only. Incomplete execution is a separate failure.
if (result.status !== "completed") process.exitCode = 2;
