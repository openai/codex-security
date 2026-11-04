import { execFile as execFileCallback } from "node:child_process";
import { promisify } from "node:util";
import { Octokit } from "@octokit/core";
import { githubRepositoryParts } from "./github-identifiers.js";
import { CodexSecurityError, errorMessage } from "./errors.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";
import { isGitHubCloudHost } from "./git-remote.js";

const execFile = promisify(execFileCallback);
type GitHubAlert = Awaited<ReturnType<typeof fetchGitHubAlert>>;

export const GITHUB_ALERT_STATES = [
  "open",
  "closed",
  "dismissed",
  "fixed",
  "all",
] as const;

export interface GitHubImportConnectionOptions {
  /** Defaults to GH_HOST or github.com. */
  githubHost?: string;
  /** Omit to use the authenticated GitHub CLI, including its token environment. */
  githubToken?: string;
  signal?: AbortSignal;
}

export interface GitHubCodeScanningImportOptions extends GitHubImportConnectionOptions {
  /** GitHub repository in OWNER/REPO form. */
  repository: string;
  /** Exact alert numbers, regardless of state. Omit to list matching alerts. */
  alertNumbers?: readonly number[];
  /** State used when listing alerts (default: open). */
  state?: (typeof GITHUB_ALERT_STATES)[number];
  /** Git reference to inspect; omitted lists the default branch. */
  ref?: string;
}

export interface ImportedGitHubCodeScanningAlert {
  source: "github-code-scanning";
  repository: string;
  number: number;
  url: string;
  /** Upstream evidence, not a validated or sealed Codex Security finding. */
  alert: GitHubAlert;
}

export interface GitHubImportDependencies {
  environment?: NodeJS.ProcessEnv;
  currentDirectory?: string;
  createGitHub?: (host: string, signal?: AbortSignal) => Promise<Octokit>;
}

export async function createAuthenticatedGitHub(
  host: string,
  options: {
    environment?: NodeJS.ProcessEnv;
    currentDirectory?: string;
    token?: string;
    signal?: AbortSignal;
  } = {},
): Promise<Octokit> {
  options.signal?.throwIfAborted();
  host = host.toLowerCase();
  let token = options.token;
  if (token === undefined) {
    const trusted = await resolveTrustedExecutable(
      "gh",
      options.environment ?? process.env,
      options.currentDirectory ?? process.cwd(),
    );
    if (trusted === null) {
      throw new CodexSecurityError(
        "GitHub CLI is required. Install gh and sign in first.",
      );
    }
    try {
      const { stdout } = await execFile(
        trusted.executable,
        ["auth", "token", "--hostname", host],
        { env: trusted.environment, signal: options.signal },
      );
      token = stdout.trim();
    } catch {
      options.signal?.throwIfAborted();
      throw new CodexSecurityError(
        "GitHub sign-in is required. Run 'gh auth login' first.",
      );
    }
  }
  if (token.trim().length === 0) {
    throw new CodexSecurityError("GitHub access token must not be empty.");
  }
  return new Octokit({
    auth: token,
    baseUrl: isGitHubCloudHost(host)
      ? `https://api.${host}`
      : `https://${host}/api/v3`,
  });
}

export function githubImportHost(
  githubHost: string | undefined,
  environment: NodeJS.ProcessEnv,
): string {
  const host =
    githubHost?.trim() ?? (environment["GH_HOST"]?.trim() || "github.com");
  if (!host) throw new CodexSecurityError("GitHub host must not be empty.");
  return host;
}

export function githubImportClient(
  host: string,
  options: GitHubImportConnectionOptions,
  dependencies: GitHubImportDependencies,
  environment: NodeJS.ProcessEnv,
): Promise<Octokit> {
  return dependencies.createGitHub
    ? dependencies.createGitHub(host, options.signal)
    : createAuthenticatedGitHub(host, {
        token: options.githubToken,
        environment,
        currentDirectory: dependencies.currentDirectory,
        signal: options.signal,
      });
}

export function githubImportError(
  error: unknown,
  signal: AbortSignal | undefined,
  messages: { operation: string; denied: string; notFound: string },
): CodexSecurityError {
  signal?.throwIfAborted();
  if (error instanceof CodexSecurityError) return error;
  const status =
    typeof error === "object" && error !== null && "status" in error
      ? error.status
      : undefined;
  switch (status) {
    case 401:
      return new CodexSecurityError("GitHub authentication failed.");
    case 403:
      return new CodexSecurityError(messages.denied);
    case 404:
      return new CodexSecurityError(messages.notFound);
    case 429:
      return new CodexSecurityError(
        "GitHub request was rate limited. Wait and retry.",
      );
    default:
      return new CodexSecurityError(
        `GitHub ${messages.operation} request failed${typeof status === "number" ? ` (HTTP ${status})` : ""}: ${errorMessage(error)}`,
      );
  }
}

export async function importGitHubCodeScanningAlerts(
  options: GitHubCodeScanningImportOptions,
  dependencies: GitHubImportDependencies = {},
): Promise<ImportedGitHubCodeScanningAlert[]> {
  options.signal?.throwIfAborted();
  const repository = options.repository.trim();
  const parts = githubRepositoryParts(repository);
  if (!parts)
    throw new CodexSecurityError("GitHub repository must be OWNER/REPO.");
  const [owner, repo] = parts;
  const numbers = [...new Set(options.alertNumbers ?? [])];
  if (numbers.some((number) => !Number.isSafeInteger(number) || number < 1)) {
    throw new CodexSecurityError(
      "GitHub alert numbers must be positive integers.",
    );
  }
  const state = options.state ?? "open";
  if (!GITHUB_ALERT_STATES.includes(state)) {
    throw new CodexSecurityError("GitHub alert state is invalid.");
  }
  if (numbers.length > 0 && state !== "open") {
    throw new CodexSecurityError(
      "--github-state only filters lists; use it without --github-alert.",
    );
  }
  const ref = options.ref?.trim();
  if (ref === "") {
    throw new CodexSecurityError("GitHub reference must not be empty.");
  }
  const environment = dependencies.environment ?? process.env;
  const host = githubImportHost(options.githubHost, environment);

  try {
    const github = await githubImportClient(
      host,
      options,
      dependencies,
      environment,
    );
    const selected = new Map<number, GitHubAlert["most_recent_instance"]>();
    if (numbers.length === 0 || ref !== undefined) {
      let page = 1;
      while (true) {
        options.signal?.throwIfAborted();
        // Octokit's list route omits GitHub's "closed" state.
        const response = await github.request<
          Pick<GitHubAlert, "number" | "most_recent_instance">[]
        >({
          method: "GET",
          url: "/repos/{owner}/{repo}/code-scanning/alerts",
          owner,
          repo,
          per_page: 100,
          page,
          ref,
          state: numbers.length > 0 || state === "all" ? undefined : state,
          request: { signal: options.signal, redirect: "error" },
        });
        for (const alert of response.data) {
          if (numbers.length === 0 || numbers.includes(alert.number)) {
            selected.set(alert.number, alert.most_recent_instance);
          }
        }
        if (
          !response.headers.link?.includes('rel="next"') ||
          (numbers.length > 0 && selected.size === numbers.length)
        )
          break;
        page += 1;
      }
      if (numbers.some((number) => !selected.has(number))) {
        throw new CodexSecurityError(
          "One or more selected GitHub alerts were not found on the requested reference.",
        );
      }
    }
    const alerts: ImportedGitHubCodeScanningAlert[] = [];
    for (const number of numbers.length > 0 ? numbers : selected.keys()) {
      options.signal?.throwIfAborted();
      const alert = await fetchGitHubAlert(
        github,
        owner,
        repo,
        number,
        options.signal,
      );
      // Detail requests use the default branch; retain the listed ref's evidence.
      const instance = selected.get(number);
      alerts.push({
        source: "github-code-scanning",
        repository,
        number,
        url: alert.html_url,
        alert:
          instance === undefined
            ? alert
            : { ...alert, most_recent_instance: instance },
      });
    }
    return alerts;
  } catch (error) {
    throw githubImportError(error, options.signal, {
      operation: "code scanning",
      denied:
        "GitHub denied code scanning access. Check repository permissions, code scanning availability, and API rate limits.",
      notFound:
        "GitHub repository or code scanning alert was not found or is not accessible.",
    });
  }
}

async function fetchGitHubAlert(
  github: Octokit,
  owner: string,
  repo: string,
  alertNumber: number,
  signal?: AbortSignal,
) {
  const response = await github.request(
    "GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}",
    {
      owner,
      repo,
      alert_number: alertNumber,
      request: { signal, redirect: "error" },
    },
  );
  return response.data;
}
