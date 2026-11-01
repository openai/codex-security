import type { Octokit } from "@octokit/core";
import {
  CANONICAL_GHSA_ID,
  githubRepositoryParts,
} from "./github-identifiers.js";
import { CodexSecurityError } from "./errors.js";
import { requireExternalImports } from "./external-imports-feature.js";
import {
  githubImportHost,
  githubImportClient,
  githubImportError,
  type GitHubImportConnectionOptions,
  type GitHubImportDependencies,
} from "./github.js";

export const GITHUB_ADVISORY_STATES = [
  "published",
  "draft",
  "triage",
  "closed",
] as const;

export interface GitHubAdvisoryImportOptions extends GitHubImportConnectionOptions {
  /** Source repository, or the selected target for explicit global advisory IDs. */
  repository: string;
  /** Exact GHSA IDs. Required for the global advisory API. */
  advisoryIds?: readonly string[];
  /** Repository advisories by default; global never enumerates the database. */
  source?: "repository" | "global";
  /** Repository list state (default: published). Exact IDs ignore state. */
  state?: (typeof GITHUB_ADVISORY_STATES)[number];
}

type RepositoryAdvisory = Awaited<ReturnType<typeof fetchRepositoryAdvisory>>;
type GlobalAdvisory = Awaited<ReturnType<typeof fetchGlobalAdvisory>>;

export interface ImportedGitHubAdvisory {
  source: "github-security-advisory";
  selection: "repository" | "global";
  repository: string;
  githubHost: string;
  ghsaId: string;
  url: string;
  /** Upstream disclosure, not proof that the selected repository is affected. */
  advisory: RepositoryAdvisory | GlobalAdvisory;
}

/** Read repository disclosures or explicitly selected public GHSA records. */
export async function importGitHubAdvisories(
  options: GitHubAdvisoryImportOptions,
  dependencies: GitHubImportDependencies = {},
): Promise<ImportedGitHubAdvisory[]> {
  options.signal?.throwIfAborted();
  const environment = dependencies.environment ?? process.env;
  requireExternalImports(environment);
  const repository = options.repository.trim();
  const parts = githubRepositoryParts(repository);
  if (!parts)
    throw new CodexSecurityError("GitHub repository must be OWNER/REPO.");
  const [owner, repo] = parts;
  const ids = [
    ...new Set(
      (options.advisoryIds ?? []).map((id) =>
        id
          .trim()
          .toLowerCase()
          .replace(/^ghsa-/u, "GHSA-"),
      ),
    ),
  ];
  if (ids.some((id) => !CANONICAL_GHSA_ID.test(id)))
    throw new CodexSecurityError(
      "GitHub advisory IDs must use GHSA-xxxx-xxxx-xxxx form.",
    );
  const source = options.source ?? "repository";
  const state = options.state ?? "published";
  if (source !== "repository" && source !== "global")
    throw new CodexSecurityError(
      "GitHub advisory source must be repository or global.",
    );
  if (!GITHUB_ADVISORY_STATES.includes(state))
    throw new CodexSecurityError("GitHub advisory state is invalid.");
  if (source === "global" && ids.length === 0)
    throw new CodexSecurityError(
      "Select explicit GHSA IDs for global advisories; database-wide import is not supported.",
    );
  if (ids.length > 0 && state !== "published")
    throw new CodexSecurityError(
      "--github-state only filters repository lists; omit it when selecting exact GHSA IDs.",
    );
  const host = githubImportHost(options.githubHost, environment);

  try {
    const github = await githubImportClient(
      host,
      options,
      dependencies,
      environment,
    );
    const advisories: (RepositoryAdvisory | GlobalAdvisory)[] = [];
    if (ids.length > 0) {
      for (const id of ids) {
        options.signal?.throwIfAborted();
        advisories.push(
          source === "global"
            ? await fetchGlobalAdvisory(github, id, options.signal)
            : await fetchRepositoryAdvisory(
                github,
                owner,
                repo,
                id,
                options.signal,
              ),
        );
      }
    } else {
      let after: string | undefined;
      const cursors = new Set<string>();
      do {
        options.signal?.throwIfAborted();
        const response = await github.request(
          "GET /repos/{owner}/{repo}/security-advisories",
          {
            owner,
            repo,
            state,
            per_page: 100,
            after,
            request: { signal: options.signal, redirect: "error" },
          },
        );
        advisories.push(...response.data);
        const next = response.headers.link
          ?.split(",")
          .find((link) => /;\s*rel="next"/u.test(link));
        const nextUrl = next?.match(/<([^>]+)>/u)?.[1];
        // Keep requests on the authenticated route; only carry over the cursor.
        after = nextUrl
          ? (new URL(nextUrl).searchParams.get("after") ?? undefined)
          : undefined;
        if (next && (!after || cursors.has(after)))
          throw new CodexSecurityError(
            "GitHub returned invalid advisory pagination.",
          );
        if (after) cursors.add(after);
      } while (after !== undefined);
    }
    return advisories.map((advisory) => ({
      source: "github-security-advisory",
      selection: source,
      repository,
      githubHost: host,
      ghsaId: advisory.ghsa_id,
      url: advisory.html_url,
      advisory,
    }));
  } catch (error) {
    throw githubImportError(error, options.signal, {
      operation: "security advisory",
      denied:
        "GitHub denied security advisory access. Check repository advisory permissions and API rate limits.",
      notFound:
        "GitHub repository or security advisory was not found or is not accessible.",
    });
  }
}

async function fetchRepositoryAdvisory(
  github: Octokit,
  owner: string,
  repo: string,
  id: string,
  signal?: AbortSignal,
) {
  const response = await github.request(
    "GET /repos/{owner}/{repo}/security-advisories/{ghsa_id}",
    {
      owner,
      repo,
      ghsa_id: id,
      request: { signal, redirect: "error" },
    },
  );
  return response.data;
}

async function fetchGlobalAdvisory(
  github: Octokit,
  id: string,
  signal?: AbortSignal,
) {
  const response = await github.request("GET /advisories/{ghsa_id}", {
    ghsa_id: id,
    request: { signal, redirect: "error" },
  });
  return response.data;
}
