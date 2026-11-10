/** Build verified per-finding results for the workbench before it seals a scan. */
import { relative, sep } from "node:path";
import { readFileSync } from "node:fs";
import { ownerRepository } from "../src/owner-evidence.js";
import {
  findingSchema,
  ownerResults,
  scanOwnerDecision,
} from "../src/owner-report.js";
import {
  enclosingGitWorktreeRoot,
  normalizeRepository,
} from "../src/targets.js";

const [, , repository, revision] = process.argv;
if (!repository || !revision)
  throw new Error("Expected a checkout and scan revision.");
const target = await normalizeRepository(repository);
const signal = AbortSignal.timeout(8_000);
const git = await ownerRepository(target, process.env, signal);
if (git.revision !== revision)
  throw new Error("Owner checkout differs from the scan revision.");
const root = await enclosingGitWorktreeRoot(target, signal, {
  requireIfPresent: true,
});
const prefix = relative(root ?? target, target)
  .split(sep)
  .join("/");
const findings = findingSchema
  .array()
  .parse(JSON.parse(readFileSync(0, "utf8")));
for (const finding of findings) {
  finding.sourceRevision = revision;
  if (prefix) {
    for (const location of finding.locations)
      location.path = prefix + "/" + location.path;
  }
}
const results = await ownerResults(git, findings, signal, scanOwnerDecision);
process.stdout.write(JSON.stringify(results));
