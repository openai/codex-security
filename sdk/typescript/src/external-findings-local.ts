import { isNumberObject } from "node:util/types";
import { CodexSecurityError } from "./errors.js";
import {
  forwardExternalImportSetting,
  requireExternalImports,
} from "./external-imports-feature.js";
import {
  snapshotImportOptions,
  snapshotSourceRepositories,
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
import { localFindingRepositories } from "./external-findings-read.js";
import {
  hasGitMetadata,
  localGitProtectionRoots,
  importGitProtectionRoots,
} from "./local-git-metadata.js";
import {
  blackDuckReportRepositories,
  projectedBlackDuckRepositoryUrl,
} from "./blackduck-findings.js";
import {
  azureReposHttpsUrl,
  isGitHubCloudHost,
  isGitHubSshOverHttps,
  isGitSsh,
  parseGitRemote,
} from "./git-remote.js";
import { veracodeReportRepositories } from "./veracode-findings.js";
import { inspectorReportRepository } from "./inspector-findings.js";
import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";
import { sonarRepositoryUrls } from "./sonar-findings.js";
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
  enclosingGitWorktreeRoot,
  gitOutput,
  normalizeRepository,
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
  /** Explicitly verified Sonar repository when a checkout uses an SSH host alias. */
  sourceRepositoryUrl?: string;
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
  /** Every declared source matched a configured Git remote of the checkout. */
  matchesRepositoryRemote: boolean;
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
interface RemoteRepositoryIdentity {
  key: string;
  account?: string;
  homeRelative?: boolean;
}

function sonarHostedGit(hostname: string) {
  return (
    isGitHubCloudHost(hostname) ||
    hostname === "gitlab.com" ||
    hostname === "bitbucket.org"
  );
}

function sonarHostedHostname(hostname: string) {
  const name = hostname.toLowerCase().replace(/\.$/u, "");
  return sonarHostedGit(name) ||
    ["ssh.github.com", "ssh.dev.azure.com", "dev.azure.com"].includes(name)
    ? name
    : undefined;
}

function remoteRepository(
  value: string,
  provider: Provider,
  bound: boolean,
  platform: Provider = provider,
  possibleSshHost?: string,
): RemoteRepositoryIdentity | undefined {
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
  const ssh = isGitSsh(url.protocol);
  const protocol = url.protocol === "http:" ? "http:" : "https:";
  const hosted = sonarHostedHostname(url.hostname);
  if (provider === "sonar" && hosted) url.hostname = hosted;
  const githubSshOverHttps = isGitHubSshOverHttps(url);
  let hostname = githubSshOverHttps ? "github.com" : url.hostname;
  // An unresolved SSH name can be a local Host alias. Only substitute the
  // supplied hostname when checking the path of an unverified manual mapping.
  if (possibleSshHost && ssh && (!hosted || hosted === "dev.azure.com"))
    hostname = sonarHostedHostname(possibleSshHost) ?? possibleSshHost;
  const port =
    githubSshOverHttps || url.port === gitTransportPorts[url.protocol]
      ? ""
      : url.port;
  // A GitHub source identifies a case-insensitive repository on custom Enterprise
  // hosts too; other providers can refer to VCS hosts with case-sensitive paths.
  const key = platform === "github" ? cloudRepositoryUrlKey : repositoryUrlKey;
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
  // Azure's generated SCP clone URL spells spaces as %20, even though Git sends SCP paths literally.
  const azure =
    provider === "sonar" && !(scpStyle && path.startsWith("/"))
      ? azureReposHttpsUrl(
          url,
          scpStyle ? name.replace(/%2520/gu, "%20") : name,
        )
      : undefined;
  const repository = suffix
    ? key(origin + name + "?") +
      "\0" +
      suffix[0].replace(/\/$/u, "").replace(/\.git$/u, "")
    : key(azure ?? origin + name);
  return {
    key: repository,
    account: ssh && login ? literal(login) : undefined,
    // GitHub serves the same repository path through its SCP and SSH URLs.
    homeRelative:
      ssh && platform !== "github" && !isGitHubCloudHost(hostname.toLowerCase())
        ? homeRelative
        : undefined,
  };
}

function matchingRemote(
  left: RemoteRepositoryIdentity,
  right: RemoteRepositoryIdentity,
) {
  return (
    left.key === right.key &&
    (left.homeRelative === undefined ||
      right.homeRelative === undefined ||
      left.homeRelative === right.homeRelative) &&
    ((left.homeRelative === false && right.homeRelative === false) ||
      left.account === undefined ||
      right.account === undefined ||
      left.account === right.account)
  );
}

/** A credential-free Sonar repository binding from a supported Git fetch transport. */
export function sonarRepositoryForRemote(origin: string): string | undefined {
  try {
    if (/[\s\\\p{Cc}?#]/u.test(origin)) return;
    const remote = parseGitRemote(origin);
    if (!remote) return;
    const { url } = remote;
    // Git dispatches remote helpers by the literal scheme, while URL lowercases it.
    if (!remote.scpStyle && !origin.startsWith(url.protocol + "//")) return;
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
      isGitSsh(url.protocol) &&
      url.username === "git" &&
      (!url.port || url.port === "22") &&
      sonarHostedGit(hostname)
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
    const candidateRemote = remoteRepository(origin, "sonar", true);
    const target = remoteRepository(source, "sonar", true);
    if (isGitSsh(url.protocol) && candidateRemote?.account !== "git") return;
    return candidateRemote && target && matchingRemote(candidateRemote, target)
      ? source
      : undefined;
  } catch {
    return undefined;
  }
}

/** Use the same executable and configuration boundaries for every Git query proving a binding. */
export function boundSonarWorktree(
  repository: string,
  protectedRoots: string | readonly string[],
  environment: NodeJS.ProcessEnv | undefined,
  signal?: AbortSignal,
) {
  return enclosingGitWorktreeRoot(repository, signal, {
    requireIfPresent: true,
    readGit: (directory, args) =>
      gitOutput(
        directory,
        args,
        signal,
        undefined,
        undefined,
        "utf8",
        protectedRoots,
        environment,
      ),
  });
}

function localRepositoryPlatform(
  provider: Provider,
  sources: readonly ExternalSourceRepository[],
  bound: boolean,
) {
  const githubKey = (url: string) =>
    remoteRepository(url, provider, bound, "github")?.key;
  const githubRepositories = new Set(
    sources.flatMap((source) => {
      if (source.platform !== "github") return [];
      const key = githubKey(source.url);
      return key === undefined ? [] : [key];
    }),
  );
  return (source: ExternalSourceRepository): Provider => {
    if (source.platform === "github") return "github";
    if (githubRepositories.size === 0) return provider;
    const key = githubKey(source.url);
    return key !== undefined && githubRepositories.has(key)
      ? "github"
      : provider;
  };
}

function sameScannerRepositories(
  remotes: Iterable<RemoteRepositoryIdentity>,
): boolean {
  let known: RemoteRepositoryIdentity | undefined;
  for (const remote of remotes) {
    if (known && !matchingRemote(known, remote)) return false;
    // HTTPS does not specify the login or path interpretation carried by SSH.
    known = {
      key: remote.key,
      account: remote.account ?? known?.account,
      homeRelative: remote.homeRelative ?? known?.homeRelative,
    };
  }
  return true;
}

/** @internal */
export interface ConfiguredFetchRemote {
  name: string;
  url: string;
}

/** @internal Effective fetch URLs from the selected, protected checkout. */
export async function configuredFetchRemotes(
  repository: string,
  provider: Provider,
  protectedRoots: WorkbenchCommandOptions["protectedRoot"],
  environment: WorkbenchCommandOptions["environment"],
  signal?: AbortSignal,
): Promise<ConfiguredFetchRemote[]> {
  if (!(await hasGitMetadata(repository, signal))) return [];
  const gitProtectedRoots = [
    ...(typeof protectedRoots === "string"
      ? [protectedRoots]
      : (protectedRoots ?? [])),
  ];
  // The Sonar caller includes the discovered Git roots for both checkouts.
  if (provider !== "sonar")
    gitProtectedRoots.push(
      await abortable(() => canonicalConfigPath(process.cwd()), signal),
    );
  if (
    provider === "sonar" &&
    !(await boundSonarWorktree(
      repository,
      gitProtectedRoots,
      environment,
      signal,
    ))
  )
    return [];
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
      return [];
    throw error;
  }
  const remotes: ConfiguredFetchRemote[] = [];
  for (const name of remoteNames.split(/\r?\n/u).filter(Boolean)) {
    if (provider === "sonar") {
      // Git fetches from only the first URL, after insteadOf rewrites.
      const url = await readGit(["remote", "get-url", "--", name]);
      if (/[\r\n]/u.test(url))
        throw new CodexSecurityError(
          "A configured Git remote URL contains a line break. Configure each fetch URL as a separate Git value.",
        );
      remotes.push({ name, url });
    } else {
      const urls = await readGit(["remote", "get-url", "--all", "--", name]);
      for (const url of urls.split(/\r?\n/u)) remotes.push({ name, url });
    }
  }
  return remotes;
}

async function requireMatchingRepository(
  repository: string,
  provider: Provider,
  sources: readonly ExternalSourceRepository[],
  strictSources: ReadonlyMap<string, Provider>,
  strictPlatformFor: (source: ExternalSourceRepository) => Provider,
  protectedRoots: WorkbenchCommandOptions["protectedRoot"],
  environment: WorkbenchCommandOptions["environment"],
  signal?: AbortSignal,
  possibleSshHost?: string,
  fetchRemotes?: readonly ConfiguredFetchRemote[],
): Promise<boolean> {
  if (sources.length === 0) return false;
  const remotes =
    fetchRemotes ??
    (await configuredFetchRemotes(
      repository,
      provider,
      protectedRoots,
      environment,
      signal,
    ));
  const boundProvider =
    provider === "sonar" ||
    provider === "inspector" ||
    provider === "blackduck" ||
    provider === "veracode";
  const loosePlatformFor = localRepositoryPlatform(provider, sources, false);
  const comparable: string[] = [];
  const unverified: string[] = [];
  for (const { url: remote } of remotes) {
    const verified =
      provider === "sonar" ? sonarRepositoryForRemote(remote) : remote;
    if (verified) comparable.push(verified);
    else if (!/[\s\\\p{Cc}?#]/u.test(remote)) unverified.push(remote);
  }
  let allSourcesMatched = true;
  for (const source of sources) {
    const bound = boundProvider || strictSources.has(source.url);
    const platform = bound
      ? (strictSources.get(source.url) ?? strictPlatformFor(source))
      : loosePlatformFor(source);
    const identity = (url: string) =>
      remoteRepository(url, provider, bound, platform);
    const targets = comparable.flatMap((remote) => identity(remote) ?? []);
    const target = identity(source.url);
    if (target && targets.some((remote) => matchingRemote(remote, target)))
      continue;
    allSourcesMatched = false;
    // A custom SSH upstream can agree with a manual mapping even when a
    // recognized HTTPS remote points at a fork. It cannot prove a Cloud binding.
    const configured = unverified.flatMap(
      (remote) =>
        remoteRepository(remote, provider, bound, platform, possibleSshHost) ??
        [],
    );
    if (target && configured.some((remote) => matchingRemote(remote, target)))
      continue;
    if (targets.length || configured.length)
      throw new CodexSecurityError(
        `Imported repository ${JSON.stringify(source.url)} does not match a configured remote of ${repository}. Select the matching local repository.`,
      );
  }
  return allSourcesMatched;
}

export function sonarCheckoutMatchesSource(
  repository: string,
  url: string,
  protectedRoots: readonly string[],
  environment: NodeJS.ProcessEnv,
  signal?: AbortSignal,
) {
  return requireMatchingRepository(
    repository,
    "sonar",
    [{ url }],
    new Map(),
    () => "sonar",
    [...protectedRoots],
    environment,
    signal,
  );
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
        () => importGitProtectionRoots(path, environment, dependencies.signal),
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
  readerSources = snapshotSourceRepositories(dependencies.sourceRepositories),
  parsedSources: readonly ExternalSourceRepository[] = [],
  fetchRemotes?: readonly ConfiguredFetchRemote[],
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
  const references = [...readerSources, ...parsedSources];
  const inspector = inspectorReportRepository(
    options.provider,
    current.findings,
    "local",
    options.inspectorProjectMap,
  );
  const projected =
    options.provider === "blackduck"
      ? []
      : current.findings.filter((finding) =>
          projectedBlackDuckRepositoryUrl(finding, "local"),
        );
  const mixed = projected.length > 0 && readerSources.length > 0;
  const nativeSources = new Map(
    (mixed ? current.findings : projected)
      .filter(
        ({ evidence }) =>
          options.provider !== "endor" ||
          isRecord(evidence.source_data?.["runContext"]),
      )
      .map(
        (finding) =>
          [
            finding,
            localFindingRepositories(options.provider, finding),
          ] as const,
      ),
  );
  const platformFor = localRepositoryPlatform(
    options.provider,
    options.inspectorProjectMap
      ? []
      : [
          ...references,
          ...Array.from(nativeSources.values()).flat(),
          ...(inspector ? [inspector] : []),
        ],
    true,
  );
  const identify = (url: string) =>
    remoteRepository(url, options.provider, true, platformFor({ url })) ?? {
      key: url,
    };
  // A hint from an independent reader applies across projected rows. A native
  // GitHub asset in one row only identifies the platform of that row's claims.
  const operatorPlatform = localRepositoryPlatform(
    options.provider,
    readerSources,
    true,
  );
  const sameRepositories = (urls: Iterable<string>) =>
    sameScannerRepositories(Array.from(urls, identify));
  const bound = blackDuckReportRepositories(
    options.provider,
    current.findings,
    "local",
    sameRepositories,
  );
  for (const source of veracodeReportRepositories(
    options.provider,
    current.findings,
    "local",
    sameRepositories,
  ).values()) {
    sources.set(source.url, source);
  }
  const strictSources = new Map<string, Provider>();
  const known = new Set<string>(parsedSources.map(({ url }) => url));
  for (const finding of current.findings) {
    const { evidence, source_finding_id: id } = finding;
    const url = evidence.details?.repository?.url;
    if (url) sources.set(url, { url });
    const retained = bound.get(id);
    const native = nativeSources.get(finding) ?? [];
    if (retained) {
      const claims = [
        retained.url,
        ...(url ? [url] : []),
        ...native.map((ref) => ref.url),
      ];
      const rowPlatform = (claim: string) =>
        options.provider !== "wiz"
          ? platformFor({ url: claim })
          : native.some((source) => source.platform === "github")
            ? "github"
            : operatorPlatform({ url: claim });
      if (
        !sameScannerRepositories(
          claims.map(
            (claim) =>
              remoteRepository(
                claim,
                options.provider,
                true,
                rowPlatform(claim),
              ) ?? {
                key: claim,
              },
          ),
        )
      )
        throw new CodexSecurityError(
          "The retained scanner repository does not match the original provider finding.",
        );
      for (const source of [retained, ...native])
        sources.set(source.url, source);
      for (const claim of claims) {
        const platform = rowPlatform(claim);
        if (!strictSources.has(claim) || platform !== "github")
          strictSources.set(claim, platform);
      }
    }
    for (const source of native) known.add(source.url);
  }
  if (mixed) {
    // A caller reference with no matching row spelling can still be a Git alias.
    const rows = [...sources.keys(), ...known].map(identify);
    const byKey = Map.groupBy(rows, (remote) => remote.key);
    const represented = new Set(rows.map((remote) => JSON.stringify(remote)));
    const aliases = readerSources
      .map(({ url }) => identify(url))
      .filter((remote) => !represented.has(JSON.stringify(remote)));
    for (const [key, group] of Map.groupBy(aliases, (remote) => remote.key)) {
      const candidates = byKey.get(key);
      if (!candidates || !sameScannerRepositories([...candidates, ...group]))
        throw new CodexSecurityError(
          "Reader repository does not match a source in the normalized findings.",
        );
    }
  }
  if (strictSources.size && options.provider !== "blackduck") {
    const keys = new Set(
      Array.from(strictSources.keys(), (url) => identify(url).key),
    );
    for (const source of references)
      if (!strictSources.has(source.url) && keys.has(identify(source.url).key))
        strictSources.set(source.url, platformFor(source));
  }
  if (inspector) {
    const platform = inspector.platform ?? options.provider;
    const native = remoteRepository(
      inspector.url,
      options.provider,
      true,
      platform,
    );
    for (const url of sources.keys()) {
      if (
        !native ||
        remoteRepository(url, options.provider, true, platform)?.key !==
          native.key
      )
        throw new CodexSecurityError(
          `Imported repository ${JSON.stringify(url)} does not match the retained Inspector repository ${JSON.stringify(inspector.url)}.`,
        );
    }
  }
  for (const source of [...(inspector ? [inspector] : []), ...references]) {
    // A reader's platform must not loosen an operator-supplied Inspector map.
    if (sources.get(source.url)?.platform !== "github")
      sources.set(
        source.url,
        options.inspectorProjectMap ? { url: source.url } : source,
      );
  }
  const sonarSources = sonarRepositoryUrls(
    options.provider,
    current.findings,
    current.report,
    "local",
  );
  const manualSource =
    options.provider === "sonar" && options.sourceRepositoryUrl
      ? declaredScannerRepositoryUrl(
          options.sourceRepositoryUrl,
          "Sonar",
          "local",
        )
      : undefined;
  if (manualSource) sonarSources.add(manualSource);
  for (const url of sonarSources)
    if (!sources.has(url)) sources.set(url, { url });
  if (sonarSources.size && !sameRepositories(sources.keys()))
    throw new CodexSecurityError(
      manualSource
        ? "The Sonar evidence does not match the declared source repository."
        : "The retained Sonar repository does not match the other source repository claims.",
    );
  if (
    options.provider === "blackduck" &&
    current.findings.length &&
    sources.size > 1 &&
    !sameScannerRepositories(Array.from(sources.keys(), identify))
  )
    throw new CodexSecurityError(
      "Black Duck occurrences must belong to the same project version and source repository.",
    );
  if (dependabotSource)
    sources.set(dependabotSource, {
      url: dependabotSource,
      platform: "github",
    });
  const selected = manualSource ? new URL(manualSource) : undefined;
  const matchesRepositoryRemote = await requireMatchingRepository(
    repository,
    options.provider,
    [...sources.values()],
    strictSources,
    platformFor,
    workbenchOptions.protectedRoot,
    workbenchOptions.environment,
    dependencies.signal,
    selected?.protocol === "https:" ? selected.hostname : undefined,
    fetchRemotes,
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
    matchesRepositoryRemote,
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
        ...(current.report === undefined
          ? {}
          : { report: structuredClone(current.report) }),
        ready: current.findings.length,
        excluded: structuredClone(current.excluded),
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
