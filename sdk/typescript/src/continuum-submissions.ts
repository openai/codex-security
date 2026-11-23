import { hash } from "node:crypto";
import { readFile, realpath, rm } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { singleRepositorySource } from "./continuum-collector.js";
import { readHostedGitRemotes } from "./hosted-git-remotes.js";
import { hostedRepositoryMatches } from "./hosted-git-repository.js";
import { commandGitProtectionRoots } from "./local-git-metadata.js";
import { withPublicationLock, writeAtomicJson } from "./publication-state.js";
import {
  canonicalConfigPath,
  codexSecurityStateDirectory,
  requireOutputOutsideRepositories,
} from "./runtime.js";
import { gitMarkerRoot, nullIfMissingFile } from "./targets.js";

export type ContinuumRequest = (
  operation: string,
  args: readonly string[],
) => Promise<Record<string, unknown>>;

const receipt = z.object({
  findingId: z.string().min(1),
  findingArn: z.string(),
});
const accepted = receipt.extend({ time: z.number().int() });
const pending = z.object({
  ocsfDocument: z.object({ time: z.number().int() }),
});

export type ContinuumReceipt = z.infer<typeof receipt> & { submittedAt: Date };

/** Verify the target once per batch, before transferring any findings. */
export async function prepareContinuumSubmissions(
  request: ContinuumRequest,
  environmentId: string,
  repositoryPath: string,
  signal?: AbortSignal,
  checkSubmissionTarget?: (signal?: AbortSignal) => Promise<void>,
) {
  const repository = await realpath(repositoryPath);
  if ((await gitMarkerRoot(repository, signal, "nearest")) !== repository) {
    throw new Error(
      "Continuum validation requires a scan of the Git repository root.",
    );
  }
  const roots = [
    repository,
    ...(await commandGitProtectionRoots(repository, process.env, signal)),
  ];
  const environment = await request("get-environment", [
    "--environment-id",
    environmentId,
  ]);
  const arn = z.string().parse(environment["environmentArn"]);
  if (!arn.endsWith(`:environments/${environmentId}`)) {
    throw new Error("Continuum returned a different environment.");
  }
  const source = await singleRepositorySource(environment, (id) =>
    request("get-integration", ["--integration-id", id]),
  );
  if (!source.gitOnly)
    throw new Error(
      "Continuum validation requires a single Git source to match submitted file paths.",
    );
  const remotes = await readHostedGitRemotes(
    repository,
    roots,
    process.env,
    signal,
  );
  if (!remotes?.some((remote) => hostedRepositoryMatches(source, remote))) {
    throw new Error(
      `The Continuum repository ${source.url} does not match the scan checkout.`,
    );
  }
  const state = await canonicalConfigPath(
    join(codexSecurityStateDirectory(), "continuum-submissions"),
  );
  requireOutputOutsideRepositories(roots, state, "state");
  let checked: Promise<void> | undefined;
  return async (
    document: Record<string, unknown>,
    now: Date,
  ): Promise<ContinuumReceipt> => {
    const key = hash(
      "sha256",
      JSON.stringify([arn, source.url, { ...document, time: 0 }]),
    );
    const file = join(state, key + ".request.json");
    const receiptPath = join(state, key + ".receipt.json");
    return withPublicationLock(state, key, signal, async () => {
      const saved = await readFile(receiptPath, "utf8").catch(
        nullIfMissingFile,
      );
      const send = async () => {
        // Share the expensive scan snapshot check across new and replayed
        // requests. Accepted receipts can still be polled after a commit.
        if (checkSubmissionTarget)
          await (checked ??= checkSubmissionTarget(signal));
        const raw = await readFile(file, "utf8").catch(nullIfMissingFile);
        // AWS replays a token only with the identical document, including its time.
        const time =
          raw == null
            ? now.getTime()
            : pending.parse(JSON.parse(raw)).ocsfDocument.time;
        const ocsfDocument = { ...document, time };
        const clientToken = hash("sha256", JSON.stringify([key, time]));
        const input = { environmentId, clientToken, ocsfDocument };
        if (raw != null && raw !== JSON.stringify(input))
          throw new Error(
            "The saved Continuum request does not match this finding.",
          );
        if (raw == null) await writeAtomicJson(file, input);
        const result = receipt.parse(
          await request("create-code-finding", [
            "--cli-input-json",
            "file://" + file,
          ]),
        );
        return { ...result, time };
      };
      const result =
        saved == null ? await send() : accepted.parse(JSON.parse(saved));
      const { time, findingArn, findingId } = result;
      if (findingArn !== arn + "/code-findings/" + findingId)
        throw new Error(
          "Continuum returned a finding for a different environment.",
        );
      if (saved == null) await writeAtomicJson(receiptPath, result);
      await rm(file, { force: true });
      return { findingArn, findingId, submittedAt: new Date(time) };
    });
  };
}
