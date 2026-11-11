import { execFile as execFileCallback } from "node:child_process";
import { promisify } from "node:util";
import { z } from "zod";
import {
  continuumIssueFormat,
  findingIdentity,
  issueIdentity,
} from "./continuum-findings.js";
import { CodexSecurityError } from "./errors.js";
import { localGitProtectionRoots } from "./local-git-metadata.js";
import { array, record } from "./scanner-import.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";

const execFile = promisify(execFileCallback);
const continuumId = z
  .string()
  .regex(
    /^[a-z0-9]{1,64}$/u,
    "Use a short Continuum ID with lowercase letters and digits.",
  );
export const continuumEnvironmentId = continuumId.describe(
  "Short Continuum environment ID.",
);
const nativeRecord = z.record(z.string(), z.unknown());
export const continuumIssueExport = z.object({
  format: z.literal(continuumIssueFormat),
  environmentId: continuumEnvironmentId,
  issues: z.array(
    z.object({ issue: nativeRecord, findings: z.array(nativeRecord) }),
  ),
});

interface ContinuumCollectionOptions {
  environmentId: string;
  profile?: string;
  region?: string;
  cwd: string;
  environment: NodeJS.ProcessEnv;
  signal?: AbortSignal;
}

type AwsCommand = (args: string[]) => Promise<Record<string, unknown>>;

async function awsCommand({
  cwd,
  environment,
  signal,
}: ContinuumCollectionOptions): Promise<AwsCommand> {
  const roots = await localGitProtectionRoots(cwd, environment, signal);
  const aws = await resolveTrustedExecutable("aws", environment, roots);
  if (!aws)
    throw new CodexSecurityError(
      "Install AWS CLI v2.38.5 or later outside the checkout and sign in to the Continuum account.",
    );
  return async (args) => {
    const command = execFile(aws.executable, args, {
      cwd,
      env: aws.environment,
      signal,
      maxBuffer: Infinity,
      windowsHide: true,
    });
    command.child.stdin?.end();
    const { stdout } = await command;
    return record(JSON.parse(stdout), `AWS Continuum ${args[1]} response`);
  };
}

export async function collectContinuumIssues(
  options: ContinuumCollectionOptions,
  runAws?: AwsCommand,
): Promise<z.infer<typeof continuumIssueExport>> {
  const { environmentId, profile, region, signal } = options;
  signal?.throwIfAborted();
  const run = runAws ?? (await awsCommand(options));
  const scopeArgs = [
    "--environment-id",
    environmentId,
    "--output",
    "json",
    "--no-cli-pager",
    ...(profile === undefined ? [] : ["--profile", profile]),
    ...(region === undefined ? [] : ["--region", region]),
  ];
  const request = (operation: string, ...args: string[]) => {
    signal?.throwIfAborted();
    return run(["continuum", operation, ...scopeArgs, ...args]);
  };

  // Let the AWS CLI assemble every page. A continuation token means the
  // capture is incomplete and cannot be published as the environment's report.
  const list = await request("list-code-issues");
  if (Object.hasOwn(list, "nextToken") || Object.hasOwn(list, "NextToken"))
    throw new CodexSecurityError("Expected a complete Continuum issue list.");

  const issues: z.infer<typeof continuumIssueExport>["issues"] = [];
  const seenIssues = new Set<string>();
  const fetchedFindings = new Map<string, Record<string, unknown>>();
  let environmentScope: string | undefined;
  for (const summary of array(list["items"], "Continuum issue list")) {
    const selected = issueIdentity(summary);
    if (
      selected.environmentId !== environmentId ||
      (environmentScope !== undefined && environmentScope !== selected.scope) ||
      seenIssues.has(selected.id)
    )
      throw new CodexSecurityError(
        "The Continuum issue list contains a duplicate issue or an issue from another environment.",
      );
    environmentScope = selected.scope;
    seenIssues.add(selected.id);
    const issue = await request("get-code-issue", "--issue-id", selected.id);
    if (issueIdentity(issue).arn !== selected.arn)
      throw new CodexSecurityError(
        `Unexpected detail for Continuum issue ${selected.id}.`,
      );

    const ids = z.array(continuumId).nonempty().parse(issue["findingIds"]);
    if (new Set(ids).size !== ids.length)
      throw new CodexSecurityError(
        `Duplicate finding IDs on Continuum issue ${selected.id}.`,
      );
    const findings: Record<string, unknown>[] = [];
    for (const id of ids) {
      let finding = fetchedFindings.get(id);
      if (!finding) {
        finding = await request("get-code-finding", "--finding-id", id);
        const identity = findingIdentity(finding);
        if (identity.id !== id || identity.scope !== selected.scope)
          throw new CodexSecurityError(
            `Unexpected detail for Continuum finding ${id}.`,
          );
        fetchedFindings.set(id, finding);
      }
      findings.push(finding);
    }
    issues.push({ issue, findings });
  }
  signal?.throwIfAborted();
  return { format: continuumIssueFormat, environmentId, issues };
}
