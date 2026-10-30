import { execFile as execFileCallback } from "node:child_process";
import { dirname } from "node:path";
import { promisify } from "node:util";
import { CodexSecurityError, errorMessage } from "./errors.js";
import {
  gitRemoteMatchesSource,
  localGitProtectionRoots,
} from "./external-findings-local.js";
import { repositoryUrlKey } from "./external-import-contract.js";
import { requireExternalImports } from "./external-imports-feature.js";
import {
  azureReposHttpsUrl,
  isGitHubCloudHost,
  isGitHubSshOverHttps,
  parseGitRemote,
} from "./git-remote.js";
import { isRecord } from "./record.js";
import { array, record, relativePath, requiredText } from "./scanner-import.js";
import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";
import { completeSonarPages, type SonarCapture } from "./sonar-findings.js";
import { gitOutput } from "./targets.js";
import {
  inspectTrustedExecutable,
  resolveTrustedExecutable,
} from "./trusted-executable.js";
import { isSafeNonNegativeInteger } from "./value.js";

const execFile = promisify(execFileCallback);

export interface SonarCollectionOptions {
  cwd: string;
  project?: string;
  branch?: string;
  pullRequest?: string;
  issueKeys?: readonly string[];
  environment?: NodeJS.ProcessEnv;
  signal?: AbortSignal;
}

type SonarCommand = (args: string[]) => Promise<Record<string, unknown>>;

async function sonarCommand(
  options: SonarCollectionOptions,
  protectedRoots: string[],
): Promise<SonarCommand> {
  const { environment = process.env, signal } = options;
  const trusted = await resolveTrustedExecutable(
    "sonar",
    environment,
    protectedRoots,
  );
  if (!trusted) {
    throw new CodexSecurityError(
      "Install the SonarQube CLI (sonar) and run 'sonar auth login', or import a saved Sonar export.",
    );
  }
  const git = await inspectTrustedExecutable(
    "git",
    trusted.environment,
    protectedRoots,
  );
  return async (args) => {
    signal?.throwIfAborted();
    let stdout: string;
    try {
      ({ stdout } = await execFile(trusted.executable, args, {
        // Authentication and raw API calls use the signed-in connection independently of checkout configuration.
        cwd: dirname(trusted.executable),
        env: git.environment,
        signal,
        maxBuffer: Infinity,
      }));
    } catch (error) {
      signal?.throwIfAborted();
      // Sonar reports authentication failures on stdout in JSON mode.
      if (
        args[0] === "auth" &&
        isRecord(error) &&
        typeof error["stdout"] === "string" &&
        error["stdout"].trim()
      ) {
        throw new CodexSecurityError(
          `Sonar authentication check failed. ${error["stdout"].trim()}\n${errorMessage(error)}\nCheck 'sonar auth status' or run 'sonar auth login'.`,
          { cause: error },
        );
      }
      throw error;
    }
    return record(JSON.parse(stdout), `sonar ${args[0]} response`);
  };
}

async function checkoutOrigin(
  options: SonarCollectionOptions,
  protectedRoots: string[],
): Promise<string | undefined> {
  try {
    const origin = await gitOutput(
      options.cwd,
      ["remote", "get-url", "--all", "--", "origin"],
      options.signal,
      undefined,
      undefined,
      "utf8",
      protectedRoots,
      options.environment,
    );
    if (/[\s\\\p{Cc}?#]/u.test(origin)) return;
    const remote = parseGitRemote(origin);
    if (!remote) return;
    const { url } = remote;
    // Git passes literal SSH paths to upload-pack. URL.pathname collapses dot segments.
    const path = remote.scpStyle
      ? remote.path
      : /^[^:/]+:\/\/[^/]+\/(.+)$/u.exec(origin)?.[1];
    if (!path) return;
    const hostname = url.hostname.toLowerCase();
    let candidate: string | undefined;
    if (url.protocol === "http:" || url.protocol === "https:") {
      candidate = `${url.origin}/${path}`;
    } else if (url.username === "git" && isGitHubSshOverHttps(url)) {
      candidate = `https://github.com/${path}`;
    } else if (
      url.protocol === "ssh:" &&
      url.username === "git" &&
      (!url.port || url.port === "22") &&
      (isGitHubCloudHost(hostname) ||
        ["gitlab.com", "bitbucket.org"].includes(hostname))
    ) {
      candidate = `https://${hostname}/${path}`;
    } else {
      candidate = azureReposHttpsUrl(url, path);
    }
    if (!candidate) return;
    const source = declaredScannerRepositoryUrl(
      candidate.replace(/\.git$/iu, ""),
      "Sonar",
      "local",
    );
    return gitRemoteMatchesSource(origin, source, "sonar") ? source : undefined;
  } catch {
    options.signal?.throwIfAborted();
    return undefined;
  }
}

const selectProjectHint =
  "Select the Sonar project with --sonar-project KEY. The checkout's Git origin must identify one project in the signed-in Sonar organization for automatic discovery.";

async function projectFromOrigin(
  sonar: SonarCommand,
  origin: string,
  organization: string,
  selected?: string,
  selectedId?: string,
): Promise<string | undefined> {
  const response = await sonar([
    "api",
    "get",
    `/dop-translation/project-bindings?${new URLSearchParams({ url: origin })}`,
  ]);
  const bindings = array(response["bindings"], "Sonar repository bindings");
  if (selectedId !== undefined) {
    return bindings.some(
      (item) => isRecord(item) && item["projectId"] === selectedId,
    )
      ? selected
      : undefined;
  }
  if (selected === undefined && bindings.length !== 1) return;
  for (const binding of bindings) {
    const id = requiredText(
      record(binding, "Sonar repository binding")["projectId"],
      "Sonar bound project ID",
    );
    if (id.includes(",")) continue;
    const result = await sonar([
      "api",
      "get",
      `/api/components/search_projects?${new URLSearchParams({ projectIds: id, organization })}`,
    ]);
    const components = array(result["components"], "Sonar bound projects");
    const component = components.length === 1 ? components[0] : undefined;
    if (
      !isRecord(component) ||
      (component["id"] !== undefined && component["id"] !== id) ||
      (component["organization"] !== undefined &&
        component["organization"] !== organization)
    )
      continue;
    const project = requiredText(component["key"], "Sonar bound project key");
    if (selected === undefined || selected === project) return project;
  }
  return undefined;
}

async function resolveProject(
  sonar: SonarCommand,
  organization: string,
  origin: string | undefined,
  selected: string | undefined,
  signal?: AbortSignal,
): Promise<{ project: string; repositoryUrl?: string }> {
  let selectedId: string | undefined;
  if (selected !== undefined) {
    // The handoff or user has already selected this project.
    const component = await sonar([
      "api",
      "get",
      `/api/navigation/component?${new URLSearchParams({ component: selected, organization })}`,
    ]).catch(() => {
      // Some token sessions cannot read browser navigation metadata.
      signal?.throwIfAborted();
      return undefined;
    });
    if (
      component &&
      ((component["key"] !== undefined && component["key"] !== selected) ||
        (component["organization"] !== undefined &&
          component["organization"] !== organization))
    ) {
      throw new CodexSecurityError(
        "Sonar returned a different project or organization. Check --sonar-project and the organization in 'sonar auth status'.",
      );
    }
    if (component?.["key"] === selected) {
      const alm = component["alm"];
      if (isRecord(alm) && alm["url"])
        return {
          project: selected,
          repositoryUrl: declaredScannerRepositoryUrl(
            alm["url"],
            "Sonar",
            "local",
          ),
        };
      if (typeof component["id"] === "string") selectedId = component["id"];
    }
  }
  if (origin !== undefined) {
    try {
      const project = await projectFromOrigin(
        sonar,
        origin,
        organization,
        selected,
        selectedId,
      );
      if (project !== undefined) return { project, repositoryUrl: origin };
    } catch (error) {
      signal?.throwIfAborted();
      if (selected === undefined)
        throw new CodexSecurityError(
          `${selectProjectHint}\n${errorMessage(error)}`,
          { cause: error },
        );
    }
  }
  if (selected !== undefined) return { project: selected };
  throw new CodexSecurityError(selectProjectHint);
}

/** Fetch native SonarQube Cloud evidence through the developer's existing CLI session. */
export async function collectSonarIssues(
  options: SonarCollectionOptions,
  runSonar?: SonarCommand,
): Promise<SonarCapture> {
  requireExternalImports(options.environment);
  options.signal?.throwIfAborted();
  const { pullRequest } = options;
  let { branch } = options;
  if (branch !== undefined && pullRequest !== undefined)
    throw new CodexSecurityError(
      "Select either a Sonar branch or a pull request.",
    );
  for (const [label, value] of [
    ["branch", branch],
    ["pull request", pullRequest],
    ["project", options.project],
  ] as const) {
    if (value !== undefined) requiredText(value, `Sonar ${label}`);
  }
  const keys = new Set(options.issueKeys);
  if (options.issueKeys !== undefined && keys.size === 0)
    throw new CodexSecurityError("The Sonar issue selection is empty.");
  for (const key of keys) {
    if (!key.trim() || key.includes(","))
      throw new CodexSecurityError(
        "Provide individual, nonempty Sonar issue keys.",
      );
  }
  const environment = options.environment ?? process.env;
  if (options.project?.includes(","))
    throw new CodexSecurityError("Select one Sonar project key.");
  const protectedRoots = [options.cwd, process.cwd()];
  for (const root of new Set(protectedRoots)) {
    protectedRoots.push(
      ...(await localGitProtectionRoots(root, environment, options.signal)),
    );
  }
  const origin = await checkoutOrigin(options, protectedRoots);
  if (options.project === undefined && origin === undefined)
    throw new CodexSecurityError(selectProjectHint);
  const sonar = runSonar ?? (await sonarCommand(options, protectedRoots));
  const auth = await sonar(["auth", "status", "--format", "json"]);
  if (auth["status"] !== "connected")
    throw new CodexSecurityError(
      `Sonar CLI is not connected (${String(auth["status"])}). Run 'sonar auth login'.`,
    );
  const server = requiredText(auth["server"], "Sonar server").replace(
    /\/$/u,
    "",
  );
  if (
    !["https://sonarcloud.io", "https://sonarqube.us"].includes(server) ||
    !auth["org"]
  )
    throw new CodexSecurityError(
      "Connect the Sonar CLI to a SonarQube Cloud organization with 'sonar auth login'.",
    );
  const organization = requiredText(auth["org"], "Sonar organization");
  const { project, repositoryUrl } = await resolveProject(
    sonar,
    organization,
    origin,
    options.project,
    options.signal,
  );
  if (project.includes(","))
    throw new CodexSecurityError("Select one Sonar project key.");
  if (branch === undefined && pullRequest === undefined) {
    const response = await sonar([
      "api",
      "get",
      `/api/project_branches/list?${new URLSearchParams({ project })}`,
    ]);
    const main = array(response["branches"], "Sonar branches").find(
      (item) => isRecord(item) && item["isMain"] === true,
    );
    if (
      !isRecord(main) ||
      typeof main["name"] !== "string" ||
      !main["name"].trim()
    )
      throw new CodexSecurityError(
        "Sonar did not return its main branch. Select the source branch with --sonar-branch.",
      );
    branch = main["name"];
  }
  const query = new URLSearchParams({
    organization,
    componentKeys: project,
    impactSoftwareQualities: "SECURITY",
    additionalFields: "rules",
    ps: "100",
  });
  if (branch !== undefined) query.set("branch", branch);
  if (pullRequest !== undefined) query.set("pullRequest", pullRequest);
  if (keys.size) query.set("issues", [...keys].join(","));
  else query.set("issueStatuses", "OPEN,CONFIRMED");
  const pages: Record<string, unknown>[] = [];
  for (let index = 1; ; index++) {
    options.signal?.throwIfAborted();
    query.set("p", String(index));
    const page = await sonar(["api", "get", `/api/issues/search?${query}`]);
    const issues = array(page["issues"], "Sonar issues");
    const paging = record(page["paging"], "Sonar paging");
    const size = paging["pageSize"],
      total = paging["total"];
    if (
      paging["pageIndex"] !== index ||
      !isSafeNonNegativeInteger(size) ||
      size === 0 ||
      !isSafeNonNegativeInteger(total) ||
      (!issues.length && index * size < total)
    ) {
      throw new CodexSecurityError(
        `Incomplete pagination in Sonar issues page ${index}.`,
      );
    }
    pages.push(page);
    if (total > 10_000)
      throw new CodexSecurityError(
        "Sonar issue search returns at most 10,000 results. Narrow the selection with --sonar-issue KEY or select a different branch or pull request.",
      );
    if (index * size >= total) break;
  }
  const missing = new Set(keys);
  for (const { issues } of completeSonarPages(pages)) {
    for (const issue of issues) {
      const key = requiredText(issue["key"], "Sonar issue key");
      if (issue["project"] !== project || (keys.size && !keys.has(key)))
        throw new CodexSecurityError(
          `Sonar returned issue ${key} outside the selected project or issue keys.`,
        );
      missing.delete(key);
    }
  }
  if (missing.size)
    throw new CodexSecurityError(
      `Selected Sonar security issues were not returned for this project and ref: ${[...missing].join(", ")}.`,
    );
  let projectBase: string | undefined;
  if (
    origin &&
    repositoryUrl &&
    repositoryUrlKey(origin) === repositoryUrlKey(repositoryUrl) &&
    branch !== undefined
  ) {
    // Only the analysis can place native paths within a bound repository.
    try {
      const metadata = await sonar([
        "api",
        "get",
        `/api/project_analyses/search?${new URLSearchParams({ project, branch, ps: "1" })}`,
      ]);
      const analysis = array(metadata["analyses"], "Sonar analyses")[0];
      const base = isRecord(analysis)
        ? analysis["relativePathFromScmRoot"]
        : undefined;
      projectBase =
        base === "" || base === "." ? "" : (relativePath(base) ?? undefined);
    } catch {
      options.signal?.throwIfAborted();
    }
  }
  return {
    format: "sonar-issues/v1",
    server,
    organization,
    project,
    branch,
    pullRequest,
    repositoryUrl,
    projectBase,
    pages,
  };
}
