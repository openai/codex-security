import { lstat, readFile, realpath, stat } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import { isNumberObject } from "node:util/types";
import { environmentEntry } from "./auth.js";
import { CodexSecurityError } from "./errors.js";
import {
  forwardExternalImportSetting,
  requireExternalImports,
} from "./external-imports-feature.js";
import type {
  ExternalFindings,
  ExternalSourceRepository,
} from "./external-findings.js";
import {
  cloudRepositoryUrlKey,
  repositoryUrlKey,
} from "./external-import-contract.js";
import type {
  ExternalFindingEvidence,
  Provider,
} from "./external-import-models.js";
import { parseGitRemote } from "./git-remote.js";
import { isRecord } from "./record.js";
import {
  bundledPluginRoot,
  canonicalConfigPath,
  canonicalizeModelSafePath,
  expandHome,
  requireOutputOutsideRepositories,
  runWorkbench,
  workbenchEnvironment,
  type WorkbenchCommandOptions,
} from "./runtime.js";
import {
  abortable,
  gitMarkerRoot,
  gitOutput,
  gitProtectionRoots,
  normalizeRepository,
  nullIfMissingPath,
} from "./targets.js";

/** A scanner source record, independent of a Codex assessment or completed scan. */
export interface StoredExternalFinding {
  id: string;
  repository: string;
  provider: Provider;
  sourceKey: string;
  sourceFindingId: string;
  evidence: ExternalFindingEvidence;
  assessment: { state: "not_assessed" };
  version: number;
  createdAt: string;
  updatedAt: string;
}

export interface NormalizedLocalImportOptions {
  /** Local checkout or source directory to associate with these records. */
  repository: string;
  provider: Provider;
  /** Stable scanner organization/project/branch namespace across imports. */
  sourceKey: string;
}

export interface LocalExternalImportDependencies {
  environment?: NodeJS.ProcessEnv;
  signal?: AbortSignal;
  runWorkbench?: typeof runWorkbench;
  /** Repository references supplied by a reader outside its projected evidence. */
  sourceRepositories?: readonly ExternalSourceRepository[];
}

export interface LocalExternalImportPreview extends ExternalFindings {
  repository: string;
  source: { provider: Provider; source_key: string };
}

export interface LocalExternalImportResult {
  repository: string;
  read: number;
  ready: number;
  excluded: ExternalFindings["excluded"];
  findings: StoredExternalFinding[];
  counts: { created: number; updated: number; unchanged: number };
}

export interface PreparedLocalExternalImport {
  preview: LocalExternalImportPreview;
  import(): Promise<LocalExternalImportResult>;
}

function requireIdentity(
  value: unknown,
  field: string,
): asserts value is string {
  if (typeof value !== "string" || !value.trim() || value.includes("\0"))
    throw new CodexSecurityError(
      `${field} must be nonempty and contain no NUL characters.`,
    );
}

/** Compare transport forms without changing retained scanner evidence. */
function remoteRepositoryKey(
  value: string,
  provider: Provider,
): string | undefined {
  if (/^[A-Za-z]:[\\/]/u.test(value)) return undefined;
  let remote;
  try {
    remote = parseGitRemote(value);
  } catch {
    return undefined;
  }
  if (
    !remote ||
    ![
      "http:",
      "https:",
      "ssh:",
      "git:",
      "ftp:",
      "ftps:",
      "git+ssh:",
      "ssh+git:",
    ].includes(remote.url.protocol)
  )
    return undefined;
  const url = remote.url;
  const ssh = ["ssh:", "git+ssh:", "ssh+git:"].includes(url.protocol);
  const protocol = url.protocol === "http:" ? "http:" : "https:";
  const githubSshOverHttps =
    ssh &&
    url.hostname.toLowerCase() === "ssh.github.com" &&
    url.port === "443";
  const hostname = githubSshOverHttps ? "github.com" : url.hostname;
  const port =
    githubSshOverHttps ||
    (ssh && url.port === "22") ||
    (url.protocol === "git:" && url.port === "9418") ||
    (url.protocol === "ftp:" && url.port === "21") ||
    (url.protocol === "ftps:" && url.port === "990")
      ? ""
      : url.port;
  // A GitHub source identifies a case-insensitive repository on custom Enterprise
  // hosts too; other providers can refer to VCS hosts with case-sensitive paths.
  const key = provider === "github" ? cloudRepositoryUrlKey : repositoryUrlKey;
  return key(
    `${protocol}//${hostname}${port ? `:${port}` : ""}/${remote.path}`,
  );
}

async function bareMetadataRoots(
  repository: string,
  signal?: AbortSignal,
): Promise<string[]> {
  const roots: string[] = [];
  let directory = repository;
  for (;;) {
    signal?.throwIfAborted();
    const present = async (name: string) =>
      (await abortable(
        () => lstat(join(directory, name)).catch(nullIfMissingPath),
        signal,
      )) !== null;
    // Git also discovers bare repositories and linked metadata without .git.
    const head = await abortable(
      () => lstat(join(directory, "HEAD")).catch(nullIfMissingPath),
      signal,
    );
    if (
      (head?.isFile() || head?.isSymbolicLink()) &&
      ((await present("commondir")) ||
        ((await present("objects")) && (await present("refs"))))
    )
      roots.push(directory);
    const parent = dirname(directory);
    if (parent === directory) return roots;
    directory = parent;
  }
}

async function metadataPointer(
  path: string,
  prefix: string,
  context: { directory: string; environment: NodeJS.ProcessEnv },
  signal?: AbortSignal,
): Promise<string | undefined> {
  const metadata = await abortable(
    () => stat(path).catch(nullIfMissingPath),
    signal,
  );
  if (!metadata?.isFile()) return undefined;
  const text = await abortable(() => readFile(path, "utf8"), signal);
  if (!text.startsWith(prefix) || (prefix === "" && text.length === 0))
    return undefined;
  const payload = text.slice(prefix.length).replace(/[\r\n]+$/u, "");
  if (prefix !== "" && payload.length === 0) return undefined;
  // Git checks emptiness before consuming the path as a NUL-terminated string.
  const value = payload.split("\0", 1)[0]!;
  // Preserve filesystem traversal through links before '..'.
  let target = isAbsolute(value) ? value : `${dirname(path)}${sep}${value}`;
  if (process.platform === "win32") {
    const drive = /^[A-Za-z]:(?![\\/])/u.exec(value)?.[0].toUpperCase();
    if (drive !== undefined) {
      const directory =
        context.directory.slice(0, 2).toUpperCase() === drive
          ? context.directory
          : environmentEntry(context.environment, `=${drive}`) || `${drive}\\`;
      target = resolve(directory, value.slice(2));
    } else if (isAbsolute(value)) target = resolve(context.directory, value);
  }
  return (
    (await abortable(
      () => realpath(target).catch(nullIfMissingPath),
      signal,
    )) ?? undefined
  );
}

async function associatedMetadataRoots(
  directory: string,
  context: { directory: string; environment: NodeJS.ProcessEnv },
  signal?: AbortSignal,
  configurationDirectory?: string,
): Promise<string[]> {
  const head = await abortable(
    () => lstat(join(directory, "HEAD")).catch(nullIfMissingPath),
    signal,
  );
  if (!head || (!head.isFile() && !head.isSymbolicLink())) return [];
  const commonMarker = join(directory, "commondir");
  const hasCommon = await abortable(
    () => lstat(commonMarker).catch(nullIfMissingPath),
    signal,
  );
  const common = hasCommon
    ? await metadataPointer(commonMarker, "", context, signal)
    : undefined;
  if (hasCommon && common === undefined) return [];
  const storage = common ?? directory;
  for (const name of ["objects", "refs"]) {
    const metadata = await abortable(
      () => stat(join(storage, name)).catch(nullIfMissingPath),
      signal,
    );
    if (!metadata?.isDirectory()) return [];
  }
  const roots = common === undefined ? [directory] : [directory, common];
  if (
    process.platform === "win32" &&
    configurationDirectory !== undefined &&
    configurationDirectory !== context.directory
  ) {
    // Git rereads commondir after changing to the discovered repository root.
    roots.push(
      ...(await associatedMetadataRoots(
        directory,
        {
          ...context,
          directory: await abortable(
            () => canonicalConfigPath(configurationDirectory),
            signal,
          ),
        },
        signal,
      )),
    );
  }
  return roots;
}

async function localGitProtectionRoots(
  repository: string,
  environment: NodeJS.ProcessEnv,
  signal?: AbortSignal,
): Promise<string[]> {
  const roots = new Set(
    await abortable(() => gitProtectionRoots(repository, signal), signal),
  );
  const context = {
    directory: await abortable(() => canonicalConfigPath(repository), signal),
    environment,
  };
  const paths = new Set([resolve(repository), context.directory]);
  for (const path of paths) {
    for (const root of await bareMetadataRoots(path, signal)) {
      roots.add(root);
      for (const associated of await associatedMetadataRoots(
        root,
        context,
        signal,
        root,
      ))
        roots.add(associated);
    }
    let directory = path;
    for (;;) {
      signal?.throwIfAborted();
      const marker = join(directory, ".git");
      const metadata = await abortable(
        () => stat(marker).catch(nullIfMissingPath),
        signal,
      );
      if (metadata !== null) {
        roots.add(directory);
        const gitDirectory = metadata.isDirectory()
          ? await abortable(() => realpath(marker), signal)
          : await metadataPointer(marker, "gitdir: ", context, signal);
        if (gitDirectory !== undefined)
          for (const associated of await associatedMetadataRoots(
            gitDirectory,
            context,
            signal,
            directory,
          ))
            roots.add(associated);
      }
      const parent = dirname(directory);
      if (parent === directory) break;
      directory = parent;
    }
  }
  for (const root of [...roots])
    roots.add(await abortable(() => canonicalConfigPath(root), signal));
  return [...roots];
}

async function hasGitMetadata(
  repository: string,
  signal?: AbortSignal,
): Promise<boolean> {
  return (
    (await abortable(
      () => gitMarkerRoot(repository, signal, "nearest"),
      signal,
    )) !== null || (await bareMetadataRoots(repository, signal)).length !== 0
  );
}

async function requireMatchingRepository(
  repository: string,
  provider: Provider,
  sources: readonly ExternalSourceRepository[],
  protectedRoots: WorkbenchCommandOptions["protectedRoot"],
  environment: WorkbenchCommandOptions["environment"],
  signal?: AbortSignal,
): Promise<void> {
  if (sources.length === 0) return;
  if (!(await hasGitMetadata(repository, signal))) return;
  const gitProtectedRoots = [
    ...(typeof protectedRoots === "string"
      ? [protectedRoots]
      : (protectedRoots ?? [])),
    await abortable(() => canonicalConfigPath(process.cwd()), signal),
  ];
  const readGit = (args: readonly string[]) =>
    abortable(
      () =>
        gitOutput(
          repository,
          args,
          signal,
          { LC_ALL: "C" },
          undefined,
          "utf8",
          gitProtectedRoots,
          environment,
        ),
      signal,
    );
  let remoteNames: string;
  try {
    remoteNames = await readGit(["remote"]);
  } catch (error) {
    signal?.throwIfAborted();
    // A local source directory need not be a Git checkout.
    if (
      error instanceof Error &&
      "code" in error &&
      error.code === 128 &&
      "stderr" in error &&
      typeof error.stderr === "string" &&
      (error.stderr.trimEnd() ===
        "fatal: not a git repository (or any of the parent directories): .git" ||
        /^fatal: not a git repository \(or any parent up to mount point [^\r\n]+\)\r?\nStopping at filesystem boundary \(GIT_DISCOVERY_ACROSS_FILESYSTEM not set\)\.$/u.test(
          error.stderr.trimEnd(),
        ))
    )
      return;
    throw error;
  }
  const remotes: string[] = [];
  for (const name of remoteNames.split(/\r?\n/u).filter(Boolean)) {
    const urls = await readGit(["remote", "get-url", "--all", "--", name]);
    remotes.push(...urls.split(/\r?\n/u));
  }
  const githubRepositories = new Set(
    sources.flatMap((source) => {
      if (source.platform !== "github") return [];
      const key = remoteRepositoryKey(source.url, "github");
      return key === undefined ? [] : [key];
    }),
  );
  for (const source of sources) {
    const githubKey = remoteRepositoryKey(source.url, "github");
    const sourceProvider =
      source.platform === "github" ||
      (githubKey !== undefined && githubRepositories.has(githubKey))
        ? "github"
        : provider;
    const remoteKeys = new Set(
      remotes.flatMap((remote) => {
        const key = remoteRepositoryKey(remote, sourceProvider);
        return key === undefined ? [] : [key];
      }),
    );
    if (remoteKeys.size === 0) continue;
    const key = remoteRepositoryKey(source.url, sourceProvider);
    if (key === undefined || !remoteKeys.has(key))
      throw new CodexSecurityError(
        `Imported repository ${JSON.stringify(source.url)} does not match a configured remote of ${repository}. Select the matching local repository.`,
      );
  }
}

async function localContext(
  selectedRepository: string,
  dependencies: LocalExternalImportDependencies,
  mode: "import" | "read" = "import",
) {
  dependencies.signal?.throwIfAborted();
  const selected = dependencies.environment ?? process.env;
  const environment = workbenchEnvironment(selected);
  forwardExternalImportSetting(selected, environment);
  requireExternalImports(environment);
  const path = expandHome(selectedRepository, environment);
  const repository =
    mode === "read"
      ? await abortable(() => canonicalConfigPath(path), dependencies.signal)
      : await normalizeRepository(path, dependencies.signal);
  const protectedRoot = [
    ...new Set([
      repository,
      ...(await abortable(
        () => localGitProtectionRoots(path, environment, dependencies.signal),
        dependencies.signal,
      )),
      ...(await abortable(
        () =>
          localGitProtectionRoots(
            process.cwd(),
            environment,
            dependencies.signal,
          ),
        dependencies.signal,
      )),
    ]),
  ];
  requireOutputOutsideRepositories(
    protectedRoot,
    await abortable(
      () => canonicalizeModelSafePath(environment.CODEX_SECURITY_STATE_DIR),
      dependencies.signal,
    ),
    "runtime",
  );
  return {
    repository,
    options: {
      pluginRoot: await abortable(
        () => bundledPluginRoot(),
        dependencies.signal,
      ),
      environment,
      protectedRoot,
      signal: dependencies.signal,
      failureMessage: "Could not access imported local findings",
    },
  };
}

/** Prepare scanner evidence without writing state or performing a security assessment. */
export async function prepareNormalizedLocalImport(
  input: ExternalFindings,
  options: NormalizedLocalImportOptions,
  dependencies: LocalExternalImportDependencies = {},
): Promise<PreparedLocalExternalImport> {
  dependencies.signal?.throwIfAborted();
  requireExternalImports(dependencies.environment);
  requireIdentity(options.sourceKey, "Source key");
  const current = structuredClone(input);
  const identities = new Set<string>();
  for (const finding of current.findings) {
    requireIdentity(finding.source_finding_id, "Source finding id");
    if (identities.has(finding.source_finding_id))
      throw new CodexSecurityError(
        `Duplicate source finding id ${JSON.stringify(finding.source_finding_id)}.`,
      );
    identities.add(finding.source_finding_id);
    if (!isRecord(finding.evidence))
      throw new CodexSecurityError("Imported evidence must be an object.");
  }
  const { repository, options: workbenchOptions } = await localContext(
    options.repository,
    dependencies,
  );
  const sources = new Map<string, ExternalSourceRepository>();
  for (const { evidence } of current.findings) {
    const url = evidence.details?.repository?.url;
    if (url) sources.set(url, { url });
  }
  for (const source of dependencies.sourceRepositories ?? []) {
    // A reader's explicit platform also applies to the same URL in typed evidence.
    if (sources.get(source.url)?.platform !== "github")
      sources.set(source.url, source);
  }
  await requireMatchingRepository(
    repository,
    options.provider,
    [...sources.values()],
    workbenchOptions.protectedRoot,
    workbenchOptions.environment,
    dependencies.signal,
  );
  dependencies.signal?.throwIfAborted();
  const preview = {
    ...structuredClone(current),
    repository,
    source: { provider: options.provider, source_key: options.sourceKey },
  };
  const payload = JSON.stringify(
    {
      repository,
      provider: options.provider,
      sourceKey: options.sourceKey,
      findings: current.findings,
    },
    (_key, value: unknown) => {
      if (isNumberObject(value)) value = +value;
      if (typeof value === "number" && !Number.isFinite(value))
        throw new TypeError(
          "Stored finding JSON cannot contain non-finite numbers.",
        );
      return value;
    },
  );
  return {
    preview,
    async import() {
      dependencies.signal?.throwIfAborted();
      const protectedRoot = [
        ...new Set([
          ...workbenchOptions.protectedRoot,
          ...(await abortable(
            () =>
              localGitProtectionRoots(
                process.cwd(),
                workbenchOptions.environment,
                dependencies.signal,
              ),
            dependencies.signal,
          )),
        ]),
      ];
      requireOutputOutsideRepositories(
        protectedRoot,
        await abortable(
          () =>
            canonicalizeModelSafePath(
              workbenchOptions.environment.CODEX_SECURITY_STATE_DIR,
            ),
          dependencies.signal,
        ),
        "runtime",
      );
      const result = await abortable(() => {
        dependencies.signal?.throwIfAborted();
        return (dependencies.runWorkbench ?? runWorkbench)(
          { ...workbenchOptions, protectedRoot },
          ["store-external-findings"],
          payload,
        );
      }, dependencies.signal);
      return {
        repository,
        read: current.read,
        ready: current.findings.length,
        excluded: current.excluded,
        findings: result["findings"] as unknown as StoredExternalFinding[],
        counts: result["counts"] as LocalExternalImportResult["counts"],
      };
    },
  };
}

/** Read imported source records, including evidence that has not been assessed by Codex. */
export async function listLocalExternalFindings(
  selection: { repository: string; id?: string },
  dependencies: LocalExternalImportDependencies = {},
): Promise<StoredExternalFinding[]> {
  dependencies.signal?.throwIfAborted();
  requireExternalImports(dependencies.environment);
  if (selection.id !== undefined) requireIdentity(selection.id, "Finding id");
  const { repository, options } = await localContext(
    selection.repository,
    dependencies,
    "read",
  );
  const result = await abortable(() => {
    dependencies.signal?.throwIfAborted();
    return (dependencies.runWorkbench ?? runWorkbench)(
      options,
      ["list-external-findings"],
      JSON.stringify({ repository, id: selection.id }),
    );
  }, dependencies.signal);
  return result["findings"] as unknown as StoredExternalFinding[];
}
