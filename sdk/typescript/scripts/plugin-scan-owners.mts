/** Verify committed ownership evidence before the workbench seals the scan. */
import { readFileSync } from "node:fs";
import { once } from "node:events";
import {
  findingsAtScanRevision,
  ownerRepository,
} from "../src/owner-evidence.js";
import { findingSchema, ownerResult } from "../src/owner-report.js";

const [, , repository, revision] = process.argv;
if (!repository || !revision)
  throw new Error("Expected a checkout and scan revision.");
const signal = AbortSignal.timeout(8_000);
const inputs = findingSchema.array().parse(JSON.parse(readFileSync(0, "utf8")));
const findings = await findingsAtScanRevision(
  repository,
  revision,
  inputs,
  signal,
);
const git = await ownerRepository(repository, process.env, signal);
if (git.revision !== revision)
  throw new Error("Owner checkout differs from the scan revision.");
for (const finding of findings) {
  const { findingId, occurrenceId, status, reason, suggestions } =
    await ownerResult(git, finding, signal, { kind: "scan" });
  // Flush each completed occurrence so a later timeout cannot discard its result.
  if (
    !process.stdout.write(
      JSON.stringify({ findingId, occurrenceId, status, reason, suggestions }) +
        "\n",
    )
  )
    await once(process.stdout, "drain", { signal });
}
