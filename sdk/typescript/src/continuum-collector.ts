import { execFile as execFileCallback } from "node:child_process";
import { promisify } from "node:util";
import { z } from "zod";
import { prepareContinuumAws } from "./continuum-aws.js";
import {
  continuumIssueFormat,
  findingIdentity,
  issueIdentity,
  readPatch,
} from "./continuum-findings.js";
import { CodexSecurityError } from "./errors.js";
import { array, record } from "./scanner-import.js";
import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";

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
export const continuumFindingId = continuumId.describe(
  "Short Continuum finding ID.",
);
const nativeRecord = z.record(z.string(), z.unknown());
const continuumIssueExport = z.object({
  format: z.literal(continuumIssueFormat),
  environmentId: continuumEnvironmentId,
  sourceRepositoryUrl: z.string(),
  issues: z.array(
    z.object({
      issue: z.looseObject({ artifacts: z.array(nativeRecord) }),
      findings: z.array(nativeRecord),
    }),
  ),
});

export const continuumImportOutput = z.union([
  continuumIssueExport,
  nativeRecord,
]);

interface ContinuumCollectionOptions {
  environmentId: string;
  profile?: string;
  region?: string;
  cwd: string;
  sourceRoot?: string;
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
            .object({
              repositorySources: z.array(z.unknown()).optional(),
              s3Sources: z.array(z.unknown()).optional(),
            })
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

async function singleRepositorySource(
  environment: Record<string, unknown>,
  getIntegration: (id: string) => Promise<Record<string, unknown>>,
) {
  const { configuration } = environmentSources.parse(environment);
  const sources = configuration?.codeConfiguration?.sourceConfiguration;
  const repositories = sources?.repositorySources ?? [];
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
  return {
    url: declaredScannerRepositoryUrl(
      `${base.replace(/\/$/u, "")}/${repository}`,
      "Continuum",
    ),
    // Mixed environments do not identify the Git source by the patch's AWS source name.
    includePatches: !sources?.s3Sources?.length,
  };
}

async function awsCommand({
  cwd,
  environment,
  signal,
  sourceRoot,
}: ContinuumCollectionOptions): Promise<AwsCommand> {
  const aws = await prepareContinuumAws(cwd, environment, signal, sourceRoot);
  return async (args) => {
    const command = execFile(aws.executable, args, {
      cwd: aws.cwd,
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

async function continuumRequests(
  options: ContinuumCollectionOptions,
  runAws?: AwsCommand,
) {
  const { profile, region, signal } = options;
  signal?.throwIfAborted();
  const run = runAws ?? (await awsCommand(options));
  const awsArgs = [
    "--output",
    "json",
    "--no-cli-pager",
    ...(profile === undefined ? [] : ["--profile", profile]),
    ...(region === undefined ? [] : ["--region", region]),
  ];
  return (operation: string, scope: string[], ...args: string[]) => {
    signal?.throwIfAborted();
    return run(["continuum", operation, ...scope, ...awsArgs, ...args]);
  };
}

type ContinuumRequest = Awaited<ReturnType<typeof continuumRequests>>;

async function getIssueArtifact(
  request: ContinuumRequest,
  scope: string[],
  issueId: string,
  artifactId: string,
  artifactType: string,
) {
  const artifact = await request(
    "get-code-issue-artifact",
    scope,
    "--issue-id",
    issueId,
    "--artifact-id",
    artifactId,
  );
  if (
    artifact["artifactId"] !== artifactId ||
    artifact["artifactType"] !== artifactType
  )
    throw new CodexSecurityError(
      `Unexpected Continuum artifact ${artifactId} for issue ${issueId}.`,
    );
  return artifact;
}

function requireCompleteList(response: Record<string, unknown>, name: string) {
  if (
    Object.hasOwn(response, "nextToken") ||
    Object.hasOwn(response, "NextToken")
  )
    throw new CodexSecurityError(`Expected a complete Continuum ${name} list.`);
}

export async function collectContinuumFinding(
  options: ContinuumCollectionOptions & {
    findingId: string;
    sourceRoot: string;
    repositoryName?: string;
    warn?: (message: string) => void;
  },
  runAws?: AwsCommand,
): Promise<Record<string, unknown>> {
  const { environmentId, findingId, repositoryName, warn, signal } = options;
  const request = await continuumRequests(options, runAws);
  const scope = ["--environment-id", environmentId];
  const finding = await request(
    "get-code-finding",
    scope,
    "--finding-id",
    findingId,
  );
  const identity = findingIdentity(finding);
  if (finding["environmentId"] !== environmentId || identity.id !== findingId)
    throw new CodexSecurityError(
      `Unexpected detail for Continuum finding ${findingId}.`,
    );

  const linkedIssue =
    finding["createdIssueId"] || finding["duplicateOfIssueId"];
  if (!linkedIssue) return finding;
  const issueId = continuumId.parse(linkedIssue);
  const list = await request(
    "list-code-issue-artifacts",
    scope,
    "--issue-id",
    issueId,
    "--artifact-type",
    "PATCH",
  );
  requireCompleteList(list, "issue artifact");
  const artifactIds = array(list["items"], "Continuum issue artifacts")
    .map((item) =>
      continuumId.parse(
        record(item, "Continuum issue artifact summary")["artifactId"],
      ),
    )
    .sort();
  const patches = [];
  for (const artifactId of artifactIds) {
    const artifact = await getIssueArtifact(
      request,
      scope,
      issueId,
      artifactId,
      "PATCH",
    );
    const body = record(artifact["body"], "Continuum artifact body");
    const patch = record(
      body["patch"],
      `Continuum artifact ${artifactId} patch body`,
    );
    if (
      repositoryName !== undefined &&
      patch["repositoryName"] !== repositoryName
    ) {
      if (!patch["repositoryName"])
        warn?.(
          `Skipped Continuum patch ${artifactId}: AWS did not identify its repository.`,
        );
      continue;
    }
    patches.push(readPatch({ ...patch, artifactId }));
  }
  signal?.throwIfAborted();
  return patches.length ? { finding, patches } : finding;
}

export async function collectContinuumIssues(
  options: ContinuumCollectionOptions,
  runAws?: AwsCommand,
): Promise<z.infer<typeof continuumIssueExport>> {
  const { environmentId, signal } = options;
  const request = await continuumRequests(options, runAws);
  const environmentArgs = ["--environment-id", environmentId];
  const { url: sourceRepositoryUrl, includePatches } =
    await singleRepositorySource(
      await request("get-environment", environmentArgs),
      (id) => request("get-integration", ["--integration-id", id]),
    );

  // Let the AWS CLI assemble every page. A continuation token means the
  // capture is incomplete and cannot be published as the environment's report.
  const list = await request("list-code-issues", environmentArgs);
  requireCompleteList(list, "issue");

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
    const issueArtifacts: Record<string, unknown>[] = [];
    if (issue["evidenceAvailability"] !== "NONE") {
      const issueArgs = ["--issue-id", selected.id];
      const artifacts = await request(
        "list-code-issue-artifacts",
        environmentArgs,
        ...issueArgs,
      );
      requireCompleteList(artifacts, "issue artifact");
      for (const item of array(
        artifacts["items"],
        "Continuum issue artifacts",
      )) {
        const summary = record(item, "Continuum issue artifact summary");
        const type = summary["artifactType"];
        if (
          type !== "EVIDENCE" &&
          type !== "VALIDATION_EVIDENCE" &&
          !(includePatches && type === "PATCH")
        )
          continue;
        const artifactId = continuumId.parse(summary["artifactId"]);
        issueArtifacts.push(
          await getIssueArtifact(
            request,
            environmentArgs,
            selected.id,
            artifactId,
            type,
          ),
        );
      }
    }
    issues.push({
      issue: { ...issue, artifacts: issueArtifacts },
      findings,
    });
  }
  signal?.throwIfAborted();
  return {
    format: continuumIssueFormat,
    environmentId,
    sourceRepositoryUrl,
    issues,
  };
}
