export interface PatchReviewRequest {
  branch: string;
  title: string;
  body: string;
}

/** Internal provider operations; Git transport is supplied separately. */
export interface PatchReviewPublisher {
  readonly label: string;
  /** Return the existing review URL, or an empty string when none exists. */
  findExisting(branch: string): Promise<string>;
  createDraft(request: PatchReviewRequest): Promise<string>;
}

export type RunPatchReviewCommand = (
  command: "gh" | "glab",
  args: readonly string[],
) => Promise<string>;

export async function publishPatchReview({
  publisher,
  pushBranch,
  ...request
}: PatchReviewRequest & {
  publisher: PatchReviewPublisher;
  pushBranch(branch: string): Promise<void>;
}): Promise<string> {
  const existing = await publisher.findExisting(request.branch);
  if (existing) return existing;
  await pushBranch(request.branch);
  return publisher.createDraft(request);
}

/** Preserve the CLI's default routing, including native gh repository selection. */
export function resolvePatchReviewPublisher(
  remote: string,
  environment: NodeJS.ProcessEnv,
  run: RunPatchReviewCommand,
): PatchReviewPublisher {
  const host = remoteHost(remote);
  const gitlabHost =
    environment["GITLAB_HOST"] ||
    environment["GITLAB_URI"] ||
    environment["GL_HOST"];
  const gitlab =
    host === "gitlab.com" ||
    (host !== undefined &&
      gitlabHost !== undefined &&
      host ===
        remoteHost(
          gitlabHost.includes("://") ? gitlabHost : `https://${gitlabHost}`,
        ));
  return gitlab
    ? createGitLabPatchPublisher({ project: remote, run })
    : createGitHubPatchPublisher(run);
}

export function createGitHubPatchPublisher(
  run: RunPatchReviewCommand,
): PatchReviewPublisher {
  return {
    label: "Pull request",
    findExisting: (branch) =>
      run("gh", [
        "pr",
        "list",
        "--head",
        branch,
        "--state",
        "all",
        "--json",
        "url",
        "--jq",
        ".[0].url // empty",
      ]),
    createDraft: ({ branch, title, body }) =>
      run("gh", [
        "pr",
        "create",
        "--draft",
        "--head",
        branch,
        "--title",
        title,
        "--body",
        body,
      ]),
  };
}

export function createGitLabPatchPublisher({
  project,
  run,
}: {
  /** Review project URL, independent of the Git push destination. */
  project: string;
  run: RunPatchReviewCommand;
}): PatchReviewPublisher {
  const repository = project.includes("://")
    ? project
    : `ssh://${project.replace(":", "/")}`;
  return {
    label: "Merge request",
    findExisting: (branch) =>
      run("glab", [
        "mr",
        "list",
        "--all",
        "--source-branch",
        branch,
        "--output",
        "json",
        "--jq",
        "map(select(.source_project_id == .target_project_id))[0].web_url // empty",
        "--repo",
        repository,
      ]),
    createDraft: ({ branch, title, body }) =>
      run("glab", [
        "mr",
        "create",
        "--draft",
        "--head",
        repository,
        "--source-branch",
        branch,
        "--title",
        title,
        "--description",
        gitlabPatchDescription(body),
        "--yes",
        "--repo",
        repository,
      ]),
  };
}

function gitlabPatchDescription(body: string): string {
  // GitLab ignores quick actions inside its native fenced blockquotes. Choose
  // a fence the report cannot close after quick-action CR removal; preserve its
  // original bytes and end the outer quote at EOF.
  let fenceLength = 3;
  for (const match of body.replaceAll("\r", "").matchAll(/^[ \t]*(>+)/gmu))
    fenceLength = Math.max(fenceLength, match[1]!.length + 1);
  return `${">".repeat(fenceLength)}\n${body}`;
}

function remoteHost(remote: string): string | undefined {
  if (remote.includes("://")) return new URL(remote).hostname.toLowerCase();
  return /^(?:[^@/]+@)?([^:/]+):[^/]/u.exec(remote)?.[1]?.toLowerCase();
}
