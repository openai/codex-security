/** Verify committed ownership evidence before the workbench seals the scan. */
import { readFileSync } from "node:fs";
import { once } from "node:events";
import { findingsAtScanRevision, ownerRepository } from "./owner-evidence.js";
import {
  decisionSchema,
  findingSchema,
  ownerResult,
  ownerResults,
} from "./owner-report.js";

import { pathToFileURL } from "node:url";
import { z } from "zod";
import type { OwnerResolver } from "./types.js";

export const ownerResolver: OwnerResolver = {
  findingsAtScanRevision,
  decisionJsonSchema: () => z.toJSONSchema(decisionSchema),
  async prepare(repository, findings, environment, signal) {
    const inputs = findingSchema.array().parse(findings);
    const git = await ownerRepository(repository, environment, signal);
    return {
      revision: git.revision,
      resolve: (policy) => ownerResults(git, inputs, signal, policy),
    };
  },
};

async function main() {
  const [, , repository, revision] = process.argv;
  if (!repository || !revision)
    throw new Error("Expected a checkout and scan revision.");
  const signal = AbortSignal.timeout(8_000);
  const inputs = findingSchema
    .array()
    .parse(JSON.parse(readFileSync(0, "utf8")));
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
    let warning: string | undefined;
    const { findingId, occurrenceId, status, reason, suggestions } =
      await ownerResult(git, finding, signal, {
        kind: "scan",
        onWarning: (message) => {
          warning = message;
        },
      });
    // Flush each completed occurrence so a later timeout cannot discard its result.
    if (
      !process.stdout.write(
        JSON.stringify({
          findingId,
          occurrenceId,
          status,
          reason,
          suggestions,
          warning,
        }) + "\n",
      )
    )
      await once(process.stdout, "drain", { signal });
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url)
  await main();
