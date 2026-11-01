import { execFile as execFileCallback } from "node:child_process";
import { dirname, resolve } from "node:path";
import { promisify } from "node:util";
import { CodexSecurityError, errorMessage } from "./errors.js";
import {
  boundSonarWorktree,
  sonarRepositoryForRemote,
  sonarCheckoutMatchesSource,
  localGitProtectionRoots,
} from "./external-findings-local.js";
import { repositoryUrlKey } from "./external-import-contract.js";
import {
  forwardExternalImportSetting,
  requireExternalImports,
} from "./external-imports-feature.js";
import { isRecord } from "./record.js";
import { array, record, relativePath, requiredText } from "./scanner-import.js";
import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";
import {
  completeSonarPages,
  mergeSonarIssueScope,
  type SonarCapture,
} from "./sonar-findings.js";
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
  sourceRepositoryUrl?: string | undefined;
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
    if (
      !(await boundSonarWorktree(
        options.cwd,
        protectedRoots,
        options.environment,
        options.signal,
      ))
    )
      return;
    const origin = await gitOutput(
      options.cwd,
      ["remote", "get-url", "--", "origin"],
      options.signal,
      undefined,
      undefined,
      "utf8",
      protectedRoots,
      options.environment,
    );
    return sonarRepositoryForRemote(origin);
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

async function verifySelectedProject(
  sonar: SonarCommand,
  selected: string,
  organization: string,
) {
  const result = await sonar([
    "api",
    "get",
    `/api/components/show?${new URLSearchParams({ component: selected })}`,
  ]);
  const component = result["component"];
  if (
    !isRecord(component) ||
    component["key"] !== selected ||
    component["organization"] !== organization ||
    component["qualifier"] !== "TRK"
  )
    throw new CodexSecurityError(
      "Sonar could not verify the selected project in the signed-in organization. Check --sonar-project and 'sonar auth status'.",
    );
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
      if (isRecord(alm) && alm["url"]) {
        await verifySelectedProject(sonar, selected, organization);
        return {
          project: selected,
          repositoryUrl: declaredScannerRepositoryUrl(
            alm["url"],
            "Sonar",
            "local",
          ),
        };
      }
      if (
        component["organization"] === organization &&
        typeof component["id"] === "string"
      )
        selectedId = component["id"];
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
  if (selected !== undefined) {
    await verifySelectedProject(sonar, selected, organization);
    return { project: selected };
  }
  throw new CodexSecurityError(selectProjectHint);
}

async function activeSonarConnection(sonar: SonarCommand) {
  const auth = await sonar(["auth", "status", "--format", "json"]);
  if (auth["status"] !== "connected")
    throw new CodexSecurityError(
      `Sonar CLI is not connected (${String(auth["status"])}). Run 'sonar auth login'.`,
    );
  const url = URL.parse(requiredText(auth["server"], "Sonar server"));
  const server = url?.origin;
  if (
    !server ||
    url?.href !== server + "/" ||
    !["https://sonarcloud.io", "https://sonarqube.us"].includes(server) ||
    !auth["org"]
  )
    throw new CodexSecurityError(
      "Connect the Sonar CLI to a SonarQube Cloud organization with 'sonar auth login'.",
    );
  const organization = requiredText(auth["org"], "Sonar organization");
  return { server, organization };
}

async function latestAnalysisBase(
  sonar: SonarCommand,
  project: string,
  branch: string,
  signal?: AbortSignal,
) {
  try {
    const metadata = await sonar([
      "api",
      "get",
      `/api/project_analyses/search?${new URLSearchParams({ project, branch, ps: "1" })}`,
    ]);
    const analysis = array(metadata["analyses"], "Sonar analyses")[0];
    if (
      !isRecord(analysis) ||
      typeof analysis["key"] !== "string" ||
      !analysis["key"].trim()
    )
      return;
    const base = analysis["relativePathFromScmRoot"];
    const path = base === "" || base === "." ? "" : relativePath(base);
    if (path !== null) return { key: analysis["key"], path };
  } catch {
    signal?.throwIfAborted();
  }
  return undefined;
}

function exactIssueBatches(
  server: string,
  query: URLSearchParams,
  keys: Set<string>,
): Set<string>[] {
  if (!keys.size) return [keys];
  // RFC 9110 §4.1 recommends support for URIs up to 8,000 octets. URLSearchParams
  // emits ASCII, including three bytes for each encoded comma between issue keys.
  const prefix = `${server}/api/issues/search?${query}&p=10000&issues=`.length;
  const batches: Set<string>[] = [];
  let batch = new Set<string>();
  let size = prefix;
  for (const key of keys) {
    const encoded =
      new URLSearchParams({ issues: key }).toString().length - "issues=".length;
    if (batch.size && size + 3 + encoded > 8_000) {
      batches.push(batch);
      batch = new Set();
      size = prefix;
    }
    size += encoded + (batch.size ? 3 : 0);
    batch.add(key);
  }
  batches.push(batch);
  return batches;
}

/** Fetch native SonarQube Cloud evidence through the developer's existing CLI session. */
export async function collectSonarIssues(
  options: SonarCollectionOptions,
  runSonar?: SonarCommand,
): Promise<SonarCapture> {
  const suppliedEnvironment = options.environment ?? process.env;
  requireExternalImports(suppliedEnvironment);
  const environment: NodeJS.ProcessEnv = Object.create(null);
  for (const name in suppliedEnvironment)
    environment[name] = suppliedEnvironment[name];
  forwardExternalImportSetting(suppliedEnvironment, environment);
  options = { ...options, cwd: resolve(options.cwd), environment };
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
  if (options.project?.includes(","))
    throw new CodexSecurityError("Select one Sonar project key.");
  const protectedRoots = [options.cwd];
  for (const root of new Set([options.cwd, process.cwd()])) {
    protectedRoots.push(
      ...(await localGitProtectionRoots(root, environment, options.signal)),
    );
  }
  const expected =
    options.sourceRepositoryUrl === undefined
      ? undefined
      : declaredScannerRepositoryUrl(
          options.sourceRepositoryUrl,
          "Sonar",
          "local",
        );
  const origin = await checkoutOrigin(options, protectedRoots);
  const checkExpectedRepository = (boundUrl: string | undefined) => {
    if (
      expected &&
      boundUrl &&
      repositoryUrlKey(expected) !== repositoryUrlKey(boundUrl)
    )
      throw new CodexSecurityError(
        "The selected Sonar repository does not match --source-repository-url.",
      );
  };
  if (options.project === undefined) checkExpectedRepository(origin);
  if (options.project === undefined && origin === undefined)
    throw new CodexSecurityError(selectProjectHint);
  const sonar = runSonar ?? (await sonarCommand(options, protectedRoots));
  const { server, organization } = await activeSonarConnection(sonar);
  const { project, repositoryUrl } = await resolveProject(
    sonar,
    organization,
    origin,
    options.project,
    options.signal,
  );
  checkExpectedRepository(repositoryUrl);
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
  let analysis;
  if (branch !== undefined && repositoryUrl !== undefined) {
    const matched =
      (origin &&
        repositoryUrlKey(origin) === repositoryUrlKey(repositoryUrl)) ||
      (await sonarCheckoutMatchesSource(
        options.cwd,
        repositoryUrl,
        protectedRoots,
        environment,
        options.signal,
      ).catch(() => {
        options.signal?.throwIfAborted();
        return false;
      }));
    if (matched)
      analysis = await latestAnalysisBase(
        sonar,
        project,
        branch,
        options.signal,
      );
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
  const pages: Record<string, unknown>[] = [];
  const queryPageCounts: number[] = [];
  const missing = new Set(keys);
  const scope = {
    organization,
    project,
    ...(branch === undefined ? {} : { branch }),
    ...(pullRequest === undefined ? {} : { pullRequest }),
  };
  for (const batch of exactIssueBatches(server, query, keys)) {
    if (batch.size) query.set("issues", [...batch].join(","));
    else query.set("issueStatuses", "OPEN,CONFIRMED");
    const queryPages: Record<string, unknown>[] = [];
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
      queryPages.push(page);
      if (total > 10_000)
        throw new CodexSecurityError(
          "Sonar issue search returns at most 10,000 results. Narrow the selection with --sonar-issue KEY or select a different branch or pull request.",
        );
      if (index * size >= total) break;
    }

    for (const { issues } of completeSonarPages(queryPages)) {
      for (const issue of issues) {
        const key = requiredText(issue["key"], "Sonar issue key");
        if (issue["project"] !== project || (batch.size && !batch.has(key)))
          throw new CodexSecurityError(
            `Sonar returned issue ${key} outside the selected project or issue keys.`,
          );
        mergeSonarIssueScope(scope, issue);
        missing.delete(key);
      }
    }
    pages.push(...queryPages);
    queryPageCounts.push(queryPages.length);
  }
  if (missing.size)
    throw new CodexSecurityError(
      `Selected Sonar security issues were not returned for this project and ref: ${[...missing].join(", ")}.`,
    );
  // Keep native paths when a newer analysis may have changed their repository base during collection.
  const latest =
    analysis && branch !== undefined
      ? await latestAnalysisBase(sonar, project, branch, options.signal)
      : undefined;
  const projectBase =
    analysis && latest?.key === analysis.key && latest.path === analysis.path
      ? analysis.path
      : undefined;
  const active = await activeSonarConnection(sonar);
  if (active.server !== server || active.organization !== organization)
    throw new CodexSecurityError(
      "The active Sonar connection changed during collection. Select the intended connection and collect again.",
    );
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
    ...(queryPageCounts.length > 1 ? { queryPageCounts } : {}),
  };
}
