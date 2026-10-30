import { lstat, readFile, realpath, stat } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import { isNumberObject } from "node:util/types";
import { environmentEntry } from "./auth.js";
import { CodexSecurityError } from "./errors.js";
import {
  forwardExternalImportSetting,
  requireExternalImports,
} from "./external-imports-feature.js";
import {
  hasNoExternalRecords,
  hasScannerDiagnostics,
  NoPublishableFindingsError,
  snapshotImportOptions,
  type ExternalFindings,
  type ExternalSourceRepository,
} from "./external-findings.js";
import {
  cloudRepositoryUrlKey,
  repositoryUrlKey,
  validateExternalReport,
} from "./external-import-contract.js";
import type {
  ExternalFindingEvidence,
  Provider,
} from "./external-import-models.js";
import { isGitHubCloudHost, parseGitRemote } from "./git-remote.js";
import { inspectorReportRepository } from "./inspector-findings.js";
import { isRecord } from "./record.js";
import { dependabotRepository } from "./github-dependabot-findings.js";
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
  /** Full Inspector project ARNs mapped to independently verified repository URLs. */
  inspectorProjectMap?: ReadonlyMap<string, string>;
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
  report?: ExternalFindings["report"];
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

const gitTransportPorts: Readonly<Record<string, string>> = {
  "http:": "80",
  "https:": "443",
  "ssh:": "22",
  "git+ssh:": "22",
  "ssh+git:": "22",
  "git:": "9418",
  "ftp:": "21",
  "ftps:": "990",
};

/** Compare transport forms without changing retained scanner evidence. */
function remoteRepository(
  value: string,
  provider: Provider,
  bound: boolean,
): { key: string; account?: string; homeRelative?: boolean } | undefined {
  if (/^[A-Za-z]:[\\/]/u.test(value)) return undefined;
  const transport = bound
    ? /^(?:ssh|git\+ssh|ssh\+git|git):\/\/([^/]*)(.*)$/isu.exec(value)
    : null;
  const authority = transport?.[1];
  const http = bound && /^https?:\/\//iu.test(value.trimStart());
  // Git decodes the authority before locating its path. An encoded delimiter
  // cannot prove a match to another spelling through WHATWG URL's hostname.
  if (
    authority &&
    (/%2f|[?#]/iu.test(authority) ||
      authority.slice(authority.lastIndexOf("@") + 1).includes("%"))
  )
    return { key: value };
  let remote;
  try {
    remote = parseGitRemote(value);
  } catch {
    return transport || http ? { key: "\0" + value } : undefined;
  }
  if (!remote || !Object.hasOwn(gitTransportPorts, remote.url.protocol))
    return undefined;
  const { url, path, scpStyle } = remote;
  const ssh = url.protocol.includes("ssh");
  const protocol = url.protocol === "http:" ? "http:" : "https:";
  const githubSshOverHttps =
    ssh &&
    url.hostname.toLowerCase() === "ssh.github.com" &&
    url.port === "443";
  const hostname = githubSshOverHttps ? "github.com" : url.hostname;
  const port =
    githubSshOverHttps || url.port === gitTransportPorts[url.protocol]
      ? ""
      : url.port;
  // A GitHub source identifies a case-insensitive repository on custom Enterprise
  // hosts too; other providers can refer to VCS hosts with case-sensitive paths.
  const key = provider === "github" ? cloudRepositoryUrlKey : repositoryUrlKey;
  const origin = `${protocol}//${hostname}${port ? `:${port}` : ""}/`;
  if (!bound) return { key: key(origin + path) };

  if (!ssh && url.protocol !== "git:") {
    if (url.protocol === "http:" || url.protocol === "https:") {
      // libcurl and WHATWG differ on backslashes and encoded dot segments.
      const raw = /^https?:\/\/[^/\\?#\s]+(\/[^\\?#]*)?(?:[?#].*)?$/iu.exec(
        value,
      );
      if (!raw || /\/(?:%2e|\.%2e|%2e\.|%2e%2e)(?:\/|$)/iu.test(raw[1] ?? ""))
        return { key: "\0" + value };
    }
    const suffix = /[?#].*$/su.exec(value)?.[0] ?? "";
    // HTTP sends the query and omits fragment text from repository requests.
    if (suffix && !["http:", "https:"].includes(url.protocol))
      return { key: key(origin + path) + "\0" };
    return {
      key:
        key(origin + path) + suffix.replace(/#.*$/su, "#").replace(/\/$/u, ""),
    };
  }

  // Git passes the original path (including dot segments, '?' and '#') to upload-pack.
  const literal = (raw: string) => {
    const bytes = Buffer.from(raw).toString("latin1");
    return scpStyle
      ? bytes
      : bytes.replace(/%(?!00)([\da-f]{2})/giu, (_, hex: string) =>
          String.fromCharCode(parseInt(hex, 16)),
        );
  };
  if (!scpStyle && !transport) return { key: value };
  const gitPath = literal(transport?.[2] ?? path);
  const login = scpStyle
    ? /^([^@/:\s?#]+)@/u.exec(value)?.[1]
    : /^(.*)@/u.exec(authority ?? "")?.[1];
  const homeRelative =
    /^\/?~(?:\/|$)/u.test(gitPath) || (scpStyle && !/^[~/]/u.test(gitPath));
  const suffix = /[?#].*$/su.exec(gitPath);
  // Express upload-pack bytes as a URL path for comparison with the HTTP source.
  const name = gitPath
    .slice(0, suffix?.index)
    .replace(/^\//u, "")
    .replace(
      /[%\x00-\x20\x7f-\xff]/gu,
      (byte) =>
        "%" + byte.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0"),
    );
  const repository = suffix
    ? key(origin + name + "?") +
      "\0" +
      suffix[0].replace(/\/$/u, "").replace(/\.git$/u, "")
    : key(origin + name);
  return {
    key: repository,
    account: ssh && login ? literal(login) : undefined,
    // GitHub serves the same repository path through its SCP and SSH URLs.
    homeRelative:
      ssh && provider !== "github" && !isGitHubCloudHost(hostname.toLowerCase())
        ? homeRelative
        : undefined,
  };
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
  const identity = (value: string, platform: Provider) =>
    remoteRepository(value, platform, provider === "inspector");
  const githubRepositories = new Set(
    sources.flatMap((source) => {
      if (source.platform !== "github") return [];
      const key = identity(source.url, "github")?.key;
      return key === undefined ? [] : [key];
    }),
  );
  for (const source of sources) {
    const githubKey = identity(source.url, "github")?.key;
    const sourceProvider =
      source.platform === "github" ||
      (githubKey !== undefined && githubRepositories.has(githubKey))
        ? "github"
        : provider;
    const targets = remotes.flatMap(
      (remote) => identity(remote, sourceProvider) ?? [],
    );
    if (!targets.length) continue;
    const target = identity(source.url, sourceProvider);
    if (
      !target ||
      !targets.some(
        ({ key, account, homeRelative }) =>
          key === target.key &&
          (homeRelative === undefined ||
            target.homeRelative === undefined ||
            homeRelative === target.homeRelative) &&
          ((homeRelative === false && target.homeRelative === false) ||
            account === undefined ||
            target.account === undefined ||
            account === target.account),
      )
    )
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
  return prepareLocalImport(
    input,
    snapshotImportOptions(options),
    dependencies,
  );
}

/** @internal Prepare evidence using settings captured by either local import entrypoint. */
export async function prepareLocalImport(
  input: ExternalFindings,
  options: NormalizedLocalImportOptions,
  dependencies: LocalExternalImportDependencies,
): Promise<PreparedLocalExternalImport> {
  requireIdentity(options.sourceKey, "Source key");
  const current = structuredClone(input);
  validateExternalReport(current.report);
  let dependabotSource: string | undefined;
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
    if (options.provider !== "github") continue;
    const native = dependabotRepository(finding);
    if (!native) continue;
    const claimed = finding.evidence.details?.repository?.url;
    if (
      claimed &&
      cloudRepositoryUrlKey(claimed) !== cloudRepositoryUrlKey(native)
    )
      throw new CodexSecurityError(
        "The normalized repository does not match the original Dependabot alert.",
      );
    if (dependabotSource && dependabotSource !== native)
      throw new CodexSecurityError(
        "Select Dependabot alerts from only one GitHub host and repository.",
      );
    dependabotSource = native;
  }
  const { repository, options: workbenchOptions } = await localContext(
    options.repository,
    dependencies,
  );
  const sources = new Map<string, ExternalSourceRepository>();
  for (const finding of current.findings) {
    const url = finding.evidence.details?.repository?.url;
    if (url) sources.set(url, { url });
  }
  const inspector = inspectorReportRepository(
    options.provider,
    current.findings,
    "local",
    options.inspectorProjectMap,
  );
  if (inspector) {
    const platform = inspector.platform ?? options.provider;
    const native = remoteRepository(inspector.url, platform, true);
    for (const url of sources.keys()) {
      if (!native || remoteRepository(url, platform, true)?.key !== native.key)
        throw new CodexSecurityError(
          `Imported repository ${JSON.stringify(url)} does not match the retained Inspector repository ${JSON.stringify(inspector.url)}.`,
        );
    }
  }
  for (const source of [
    ...(inspector ? [inspector] : []),
    ...(dependencies.sourceRepositories ?? []),
  ]) {
    // A reader's platform must not loosen an operator-supplied Inspector map.
    if (sources.get(source.url)?.platform !== "github")
      sources.set(
        source.url,
        options.inspectorProjectMap ? { url: source.url } : source,
      );
  }
  if (dependabotSource)
    sources.set(dependabotSource, {
      url: dependabotSource,
      platform: "github",
    });
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
      const summary = {
        repository,
        read: current.read,
        ...(current.report === undefined
          ? {}
          : { report: structuredClone(current.report) }),
        ready: current.findings.length,
        excluded: structuredClone(current.excluded),
      };
      if (hasNoExternalRecords(current)) {
        if (hasScannerDiagnostics(current))
          throw new NoPublishableFindingsError(structuredClone(current));
        return {
          ...summary,
          findings: [],
          counts: { created: 0, updated: 0, unchanged: 0 },
        };
      }
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
        ...summary,
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
