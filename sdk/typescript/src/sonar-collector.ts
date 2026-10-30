import { execFile as execFileCallback } from "node:child_process";
import { promisify } from "node:util";
import { CodexSecurityError, errorMessage } from "./errors.js";
import { localGitProtectionRoots } from "./external-findings-local.js";
import { repositoryUrlKey } from "./external-import-contract.js";
import { requireExternalImports } from "./external-imports-feature.js";
import {
  isGitHubCloudHost,
  isGitHubSshOverHttps,
  parseGitRemote,
} from "./git-remote.js";
import { isRecord } from "./record.js";
import { array, record, relativePath, requiredText } from "./scanner-import.js";
import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";
import { completeSonarPages, type SonarCapture } from "./sonar-findings.js";
import { gitOutput } from "./targets.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";
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
  const { cwd, environment = process.env, signal } = options;
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
  return async (args) => {
    signal?.throwIfAborted();
    let stdout: string;
    try {
      ({ stdout } = await execFile(trusted.executable, args, {
        cwd,
        env: trusted.environment,
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
    if (/[\r\n]/u.test(origin)) return;
    const remote = parseGitRemote(origin);
    if (!remote || remote.url.search || remote.url.hash) return;
    const { url, path } = remote;
    let base: string;
    if (url.protocol === "http:" || url.protocol === "https:") {
      base = url.origin;
    } else if (url.username === "git" && isGitHubSshOverHttps(url)) {
      base = "https://github.com";
    } else if (
      url.protocol === "ssh:" &&
      url.username === "git" &&
      (!url.port || url.port === "22") &&
      (isGitHubCloudHost(url.hostname) ||
        ["gitlab.com", "bitbucket.org"].includes(url.hostname))
    ) {
      base = `https://${url.hostname}`;
    } else {
      return;
    }
    return declaredScannerRepositoryUrl(
      `${base}/${path.replace(/\.git$/iu, "")}`,
      "Sonar",
      "local",
    );
  } catch {
    options.signal?.throwIfAborted();
    return undefined;
  }
}

async function discoverProject(
  sonar: SonarCommand,
  server: string,
  organization: string,
): Promise<string> {
  const links = await sonar(["link", "list"]);
  const projects = array(links["projects"], "Sonar project links").map(
    (entry) => record(entry, "Sonar project link"),
  );
  const paging = links["paging"];
  if (
    projects.length !== 1 ||
    (isRecord(paging) && paging["hasNextPage"] === true)
  ) {
    const candidates = projects
      .map((project) => project["projectKey"])
      .join(", ");
    throw new CodexSecurityError(
      `Select a Sonar project with --sonar-project KEY.${candidates ? ` Linked projects: ${candidates}.` : " No unique project is linked to this checkout."}`,
    );
  }
  const project = projects[0]!;
  if (
    (project["serverUrl"] !== server &&
      project["serverUrl"] !== server + "/") ||
    (project["organization"] && project["organization"] !== organization)
  ) {
    throw new CodexSecurityError(
      "The linked project uses another Sonar connection. Switch to its server and organization with 'sonar auth login'.",
    );
  }
  return requiredText(project["projectKey"], "Linked Sonar project key");
}

/** Use a Sonar binding before attributing findings to the checkout's Git origin. */
async function repositoryBinding(
  sonar: SonarCommand,
  project: string,
  organization: string,
  origin: string | undefined,
  signal?: AbortSignal,
): Promise<{
  repositoryUrl?: string;
  matchesCheckout: boolean;
  diagnostic?: string;
}> {
  let componentId: string | undefined;
  let navigationError: string | undefined;
  try {
    const component = await sonar([
      "api",
      "get",
      `/api/navigation/component?${new URLSearchParams({ component: project, organization })}`,
    ]);
    if (
      (component["key"] && component["key"] !== project) ||
      (component["organization"] && component["organization"] !== organization)
    )
      return { matchesCheckout: false };
    const alm = component["alm"];
    const repositoryUrl =
      isRecord(alm) && alm["url"]
        ? declaredScannerRepositoryUrl(alm["url"], "Sonar", "local")
        : undefined;
    if (repositoryUrl) {
      return {
        repositoryUrl,
        matchesCheckout: Boolean(
          origin &&
          repositoryUrlKey(origin) === repositoryUrlKey(repositoryUrl),
        ),
      };
    }
    if (typeof component["id"] === "string") componentId = component["id"];
  } catch (error) {
    signal?.throwIfAborted();
    navigationError = errorMessage(error);
  }
  if (!origin) return { matchesCheckout: false, diagnostic: navigationError };
  try {
    const response = await sonar([
      "api",
      "get",
      `/dop-translation/project-bindings?${new URLSearchParams({ url: origin })}`,
    ]);
    const ids = array(response["bindings"], "Sonar project bindings").flatMap(
      (binding) =>
        isRecord(binding) && typeof binding["projectId"] === "string"
          ? [binding["projectId"]]
          : [],
    );
    let matches = componentId !== undefined && ids.includes(componentId);
    if (componentId === undefined) {
      // Token sessions can read the CLI's binding lookup even when navigation requires a browser session.
      for (const id of ids) {
        const result = await sonar([
          "api",
          "get",
          `/api/components/search_projects?${new URLSearchParams({ projectIds: id, organization })}`,
        ]);
        if (
          array(result["components"], "Sonar bound projects").some(
            (item) => isRecord(item) && item["key"] === project,
          )
        ) {
          matches = true;
          break;
        }
      }
    }
    return {
      repositoryUrl: matches ? origin : undefined,
      matchesCheckout: matches,
      diagnostic: matches ? undefined : navigationError,
    };
  } catch (error) {
    signal?.throwIfAborted();
    return {
      matchesCheckout: false,
      diagnostic: [navigationError, errorMessage(error)]
        .filter(Boolean)
        .join("\n"),
    };
  }
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
  for (const key of keys) {
    if (!key.trim() || key.includes(","))
      throw new CodexSecurityError(
        "Provide individual, nonempty Sonar issue keys.",
      );
  }
  const environment = options.environment ?? process.env;
  const protectedRoots = [options.cwd, process.cwd()];
  for (const root of new Set(protectedRoots)) {
    protectedRoots.push(
      ...(await localGitProtectionRoots(root, environment, options.signal)),
    );
  }
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
  const project =
    options.project ?? (await discoverProject(sonar, server, organization));
  if (project.includes(","))
    throw new CodexSecurityError("Select one Sonar project key.");
  const binding = await repositoryBinding(
    sonar,
    project,
    organization,
    await checkoutOrigin(options, protectedRoots),
    options.signal,
  );
  if (options.project === undefined && !binding.matchesCheckout) {
    throw new CodexSecurityError(
      `Sonar could not verify that linked project ${JSON.stringify(project)} belongs to this checkout's origin. Rerun with --sonar-project KEY to confirm the source project.${binding.diagnostic ? `\n${binding.diagnostic}` : ""}`,
    );
  }
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
  if (binding.matchesCheckout && branch !== undefined) {
    // A Git-discovered link anchors at the checkout root even for a nested analysis.
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
    repositoryUrl: binding.repositoryUrl,
    projectBase,
    pages,
  };
}
