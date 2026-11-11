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
import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";
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
  sourceRepositoryUrl: z.string(),
  issues: z.array(
    z.object({
      issue: nativeRecord,
      findings: z.array(nativeRecord),
      evidenceArtifacts: z.array(nativeRecord).optional(),
    }),
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

const environmentSources = z.object({
  configuration: z
    .object({
      codeConfiguration: z
        .object({
          sourceConfiguration: z
            .object({ repositorySources: z.array(z.unknown()).optional() })
            .optional(),
        })
        .optional(),
    })
    .optional(),
});
const repositorySource = z.object({
  integrationId: continuumId,
  repository: z.string().regex(/^[a-z0-9_.-]+(?:\/[a-z0-9_.-]+)+$/iu),
});
const gitLabIntegration = z.object({
  providerDetails: z.object({
    gitlab: z.object({ instanceUrl: z.string().startsWith("https://") }),
  }),
});

async function singleRepositoryUrl(
  environment: Record<string, unknown>,
  getIntegration: (id: string) => Promise<Record<string, unknown>>,
): Promise<string> {
  const { configuration } = environmentSources.parse(environment);
  const repositories =
    configuration?.codeConfiguration?.sourceConfiguration?.repositorySources ??
    [];
  if (repositories.length !== 1)
    throw new CodexSecurityError(
      `Continuum collection requires exactly one configured Git repository. This environment has ${repositories.length}.`,
    );
  const { integrationId, repository } = repositorySource.parse(repositories[0]);
  const integration = await getIntegration(integrationId);
  const type = integration["integrationType"];
  if (type !== "GITHUB" && type !== "GITLAB")
    throw new CodexSecurityError(
      "Expected a GitHub or GitLab integration for the Continuum repository.",
    );
  const base =
    type === "GITHUB"
      ? "https://github.com"
      : gitLabIntegration.parse(integration).providerDetails.gitlab.instanceUrl;
  return declaredScannerRepositoryUrl(
    `${base.replace(/\/$/u, "")}/${repository}`,
    "Continuum",
  );
}

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
  const awsArgs = [
    "--output",
    "json",
    "--no-cli-pager",
    ...(profile === undefined ? [] : ["--profile", profile]),
    ...(region === undefined ? [] : ["--region", region]),
  ];
  const request = (operation: string, scope: string[], ...args: string[]) => {
    signal?.throwIfAborted();
    return run(["continuum", operation, ...scope, ...awsArgs, ...args]);
  };
  const environmentArgs = ["--environment-id", environmentId];
  const sourceRepositoryUrl = await singleRepositoryUrl(
    await request("get-environment", environmentArgs),
    (id) => request("get-integration", ["--integration-id", id]),
  );

  // Let the AWS CLI assemble every page. A continuation token means the
  // capture is incomplete and cannot be published as the environment's report.
  const list = await request("list-code-issues", environmentArgs);
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
    const issue = await request(
      "get-code-issue",
      environmentArgs,
      "--issue-id",
      selected.id,
    );
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
        finding = await request(
          "get-code-finding",
          environmentArgs,
          "--finding-id",
          id,
        );
        const identity = findingIdentity(finding);
        if (identity.id !== id || identity.scope !== selected.scope)
          throw new CodexSecurityError(
            `Unexpected detail for Continuum finding ${id}.`,
          );
        fetchedFindings.set(id, finding);
      }
      findings.push(finding);
    }
    const evidenceArtifacts: Record<string, unknown>[] = [];
    if (issue["evidenceAvailability"] !== "NONE") {
      const issueArgs = ["--issue-id", selected.id];
      const artifacts = await request(
        "list-code-issue-artifacts",
        environmentArgs,
        ...issueArgs,
        "--artifact-type",
        "EVIDENCE",
      );
      if (
        Object.hasOwn(artifacts, "nextToken") ||
        Object.hasOwn(artifacts, "NextToken")
      )
        throw new CodexSecurityError(
          "Expected a complete Continuum issue evidence list.",
        );
      for (const item of array(
        artifacts["items"],
        "Continuum issue artifacts",
      )) {
        const artifactId = continuumId.parse(
          record(item, "Continuum issue artifact summary")["artifactId"],
        );
        const artifact = await request(
          "get-code-issue-artifact",
          environmentArgs,
          ...issueArgs,
          "--artifact-id",
          artifactId,
        );
        if (
          artifact["artifactId"] !== artifactId ||
          artifact["artifactType"] !== "EVIDENCE"
        )
          throw new CodexSecurityError(
            `Unexpected Continuum evidence artifact ${artifactId} for issue ${selected.id}.`,
          );
        evidenceArtifacts.push(artifact);
      }
    }
    issues.push({ issue, findings, evidenceArtifacts });
  }
  signal?.throwIfAborted();
  return {
    format: continuumIssueFormat,
    environmentId,
    sourceRepositoryUrl,
    issues,
  };
}
