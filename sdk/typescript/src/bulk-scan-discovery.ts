import { createHash } from "node:crypto";
import { lstat, mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { stdin } from "node:process";
import { Writable } from "node:stream";
import { checkbox, confirm, input, search, Separator } from "@inquirer/prompts";
import { Octokit } from "@octokit/core";
import Papa from "papaparse";
import { createAuthenticatedGitHub } from "./github.js";
import { expandHome } from "./runtime.js";

const GITHUB_REPOSITORIES_QUERY = `
  query($owner: String!, $cursor: String) {
    repositoryOwner(login: $owner) {
      repositories(
        first: 100
        after: $cursor
        isArchived: false
        isFork: false
        orderBy: { field: PUSHED_AT, direction: DESC }
      ) {
        nodes {
          nameWithOwner
          pushedAt
          defaultBranchRef { target { oid } }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
`;

interface GitHubRepository {
  fullName: string;
  url: string;
  revision: string;
}

interface GitHubRepositoriesResponse {
  repositoryOwner: {
    repositories: {
      nodes: Array<{
        nameWithOwner: string;
        pushedAt: string;
        defaultBranchRef: { target: { oid: string } } | null;
      }>;
      pageInfo: { hasNextPage: boolean; endCursor: string | null };
    };
  } | null;
}

export interface BulkScanPrompt {
  isInteractive(): boolean;
  write(value: string): void;
  confirm(
    question: string,
    defaultValue?: boolean,
    signal?: AbortSignal,
  ): Promise<boolean>;
  input(
    question: string,
    defaultValue?: string,
    signal?: AbortSignal,
  ): Promise<string>;
  select<Value extends string>(
    question: string,
    options: readonly { label: string; value: Value; short?: string }[],
    presentation?: { header?: string },
    signal?: AbortSignal,
  ): Promise<Value>;
  checkbox<Value extends string>(
    question: string,
    options: readonly { label: string; value: Value; short?: string }[],
    presentation?: { header?: string; required?: boolean },
    signal?: AbortSignal,
  ): Promise<Value[]>;
}

export interface BulkScanDiscoveryDependencies {
  prompt: BulkScanPrompt;
  now(): number;
  currentDirectory(): string;
  githubHost?: string;
  createGitHub(host: string, signal?: AbortSignal): Promise<Octokit>;
}

export interface BulkScanWizardResult {
  inputPath: string;
  outputDir: string;
  githubHost: string;
}

interface PromptOutput {
  write(value: string): unknown;
  readonly isTTY?: boolean;
  readonly columns?: number;
}

export function createBulkScanDiscoveryDependencies(options: {
  output: PromptOutput;
  now(): number;
  currentDirectory(): string;
}): BulkScanDiscoveryDependencies {
  return {
    prompt: createTerminalPrompt(options.output),
    now: options.now,
    currentDirectory: options.currentDirectory,
    ...(process.env["GH_HOST"]?.trim()
      ? { githubHost: process.env["GH_HOST"].trim() }
      : {}),
    createGitHub: (host, signal) =>
      createAuthenticatedGitHub(host, {
        environment: process.env,
        currentDirectory: options.currentDirectory(),
        signal,
      }),
  };
}

export async function runBulkScanWizard(
  dependencies: BulkScanDiscoveryDependencies,
  signal?: AbortSignal,
): Promise<BulkScanWizardResult | null> {
  const { prompt } = dependencies;
  if (!prompt.isInteractive()) {
    throw new Error(
      "Interactive repository selection requires a terminal. Provide a CSV with 'codex-security bulk-scan repositories.csv --output-dir ./security-scans'.",
    );
  }
  signal?.throwIfAborted();

  const githubHost = dependencies.githubHost ?? "github.com";
  const github = await dependencies.createGitHub(githubHost, signal);
  const owner = await selectGitHubOwner(github, prompt, signal);
  prompt.write("\nFinding active repositories...\n");
  const discovered = await discoverGitHubRepositories(
    github,
    githubHost,
    owner,
    dependencies.now() - 90 * 86_400_000,
    signal,
  );
  if (discovered.length === 0) {
    prompt.write("\nNo repositories matched your selection.\n");
    return null;
  }

  prompt.write(`\nFound ${discovered.length} repositories.\n`);
  const repositories = await selectGitHubRepositories(discovered, prompt);

  const outputDir = resolve(
    dependencies.currentDirectory(),
    expandHome(
      await prompt.input(
        "Where should scan results be saved?",
        "./security-scans",
      ),
    ),
  );
  const inputPath = join(outputDir, "repositories.csv");
  await validateWizardOutput(outputDir);
  prompt.write(
    `\nReady to scan ${repositories.length} repositories?\n` +
      `Results: ${outputDir}\nRepository list: ${inputPath}\n`,
  );
  if (!(await prompt.confirm("Start scanning?"))) {
    prompt.write("\nScan canceled.\n");
    return null;
  }
  signal?.throwIfAborted();

  await mkdir(outputDir, { recursive: true, mode: 0o700 });
  await writeFile(
    inputPath,
    `${Papa.unparse(
      repositories.map(({ fullName, url, revision }) => ({
        id: repositoryId(fullName),
        repository: url,
        revision,
      })),
    )}\n`,
    { flag: "wx", mode: 0o600, ...(signal === undefined ? {} : { signal }) },
  );
  return { inputPath, outputDir, githubHost };
}

async function selectGitHubOwner(
  github: Octokit,
  prompt: BulkScanPrompt,
  signal?: AbortSignal,
): Promise<string> {
  const [firstPage, user] = await Promise.all([
    github.request("GET /user/orgs", { per_page: 100, request: { signal } }),
    github.request("GET /user", { request: { signal } }),
  ]);
  const organizations = [...firstPage.data];
  let response = firstPage;
  let page = 1;
  while (response.headers.link?.includes('rel="next"')) {
    signal?.throwIfAborted();
    response = await github.request("GET /user/orgs", {
      per_page: 100,
      page: ++page,
      request: { signal },
    });
    organizations.push(...response.data);
  }
  const personal = user.data.login;
  const owners = [personal, ...organizations.map(({ login }) => login)].sort();
  if (owners.length > 1) {
    return await prompt.select(
      "Which account or organization should we scan?",
      owners.map((owner) => ({ label: owner, value: owner })),
    );
  }
  prompt.write(`\nFinding repositories in ${personal}.\n`);
  return personal;
}

async function selectGitHubRepositories(
  repositories: GitHubRepository[],
  prompt: BulkScanPrompt,
): Promise<GitHubRepository[]> {
  const selected = new Set<string>();
  while (selected.size < repositories.length) {
    const choice = await prompt.select(
      "Select repositories to scan (type to filter)",
      [
        {
          label: selected.size
            ? `Done (${selected.size} selected)`
            : `All ${repositories.length} repositories`,
          value: "",
        },
        ...repositories
          .filter(({ fullName }) => !selected.has(fullName))
          .map(({ fullName }) => ({ label: fullName, value: fullName })),
      ],
    );
    if (!choice) break;
    selected.add(choice);
  }
  return selected.size
    ? repositories.filter(({ fullName }) => selected.has(fullName))
    : repositories;
}

async function discoverGitHubRepositories(
  github: Octokit,
  host: string,
  owner: string,
  cutoff: number,
  signal?: AbortSignal,
): Promise<GitHubRepository[]> {
  const repositories: GitHubRepository[] = [];
  let cursor: string | null = null;

  do {
    signal?.throwIfAborted();
    const result: GitHubRepositoriesResponse = await github.graphql(
      GITHUB_REPOSITORIES_QUERY,
      { owner, cursor, request: { signal } },
    );
    const connection = result.repositoryOwner?.repositories;
    if (connection === undefined) {
      throw new Error("GitHub could not list repositories for this account.");
    }

    for (const repository of connection.nodes) {
      if (Date.parse(repository.pushedAt) < cutoff) return repositories;
      if (repository.defaultBranchRef === null) continue;
      repositories.push({
        fullName: repository.nameWithOwner,
        url: `https://${host}/${repository.nameWithOwner}.git`,
        revision: repository.defaultBranchRef.target.oid.toLowerCase(),
      });
    }
    cursor = connection.pageInfo.hasNextPage
      ? connection.pageInfo.endCursor
      : null;
  } while (cursor !== null);

  return repositories;
}

function repositoryId(fullName: string): string {
  const id = fullName.replace("/", "--");
  if (id.length <= 128) return id;
  const hash = createHash("sha256").update(fullName).digest("hex").slice(0, 16);
  return `${id.slice(0, 111)}-${hash}`;
}

async function validateWizardOutput(outputDir: string): Promise<void> {
  let metadata;
  try {
    metadata = await lstat(outputDir);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (!metadata.isDirectory()) {
    throw new Error("The scan output must be a real directory.");
  }

  for (const name of ["repositories.csv", "manifest.json"]) {
    try {
      await lstat(join(outputDir, name));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw error;
    }
    throw new Error(
      "The selected output directory already contains a repository list or scan. Choose a new directory or resume the existing scan.",
    );
  }
}

function createTerminalPrompt(output: PromptOutput): BulkScanPrompt {
  const context = (signal?: AbortSignal) => {
    const stream = new Writable({
      write(chunk: Buffer, _encoding, callback) {
        output.write(chunk.toString("utf8"));
        callback();
      },
    });
    Object.defineProperty(stream, "columns", {
      configurable: true,
      get: () => output.columns,
    });
    return { input: stdin, output: stream, signal };
  };

  return {
    isInteractive: () => stdin.isTTY === true && output.isTTY === true,
    write: (value) => {
      output.write(value);
    },
    confirm: (message, defaultValue = false, signal) =>
      confirm({ message, default: defaultValue }, context(signal)),
    input: (message, defaultValue, signal) =>
      input({ message, default: defaultValue }, context(signal)),
    checkbox: (message, options, presentation, signal) =>
      checkbox(
        {
          message,
          choices: [
            ...(presentation?.header === undefined
              ? []
              : [new Separator(presentation.header)]),
            ...options.map(({ label, value, short }) => ({
              name: label,
              value,
              ...(short === undefined ? {} : { short }),
            })),
          ],
          required: presentation?.required,
        },
        context(signal),
      ),
    select: (message, options, presentation, signal) =>
      search(
        {
          message,
          ...(presentation?.header === undefined
            ? {}
            : {
                theme: {
                  style: {
                    searchTerm: (term: string) =>
                      `${term}\n  ${presentation.header}`,
                  },
                },
              }),
          source: (term) =>
            options
              .filter(({ label }) =>
                label.toLowerCase().includes(term?.toLowerCase() ?? ""),
              )
              .map(({ label, value, short }) => ({
                name: label,
                value,
                ...(short === undefined ? {} : { short }),
              })),
        },
        context(signal),
      ),
  };
}
