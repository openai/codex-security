import { isUtf8 } from "node:buffer";
import { lstat, readFile, realpath, stat } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import { isNumberObject } from "node:util/types";
import { environmentEntry } from "./auth.js";
import { snykRepositoryScope } from "./snyk-findings.js";
import { semgrepSarifSourceRepositories } from "./semgrep-findings.js";
import {
  isSemgrepPlatformReport,
  semgrepPlatformFindingRepository,
} from "./semgrep-platform-findings.js";
import { CodexSecurityError } from "./errors.js";
import {
  hostedRepositoryUrl,
  validateHostedRepositoryUrl,
} from "./hosted-scanner-http.js";
import {
  forwardExternalImportSetting,
  requireExternalImports,
} from "./external-imports-feature.js";
import {
  checkHostedFindingProvider,
  snapshotExternalFindings,
  snapshotImportOptions,
  snapshotSourceRepositories,
  type ExternalFindings,
  type HostedExternalFindings,
  type NormalizedFindingsFor,
  type ExternalSourceRepository,
} from "./external-findings.js";
import {
  cloudRepositoryUrlKey,
  hostedRepositoryUrlKey,
  repositoryUrlKey,
  isVerifiedGitHubRepository,
  validateExternalReport,
} from "./external-import-contract.js";
import type {
  ExternalFindingEvidence,
  Provider,
} from "./external-import-models.js";
import {
  gitPathToHttpPath,
  gitTransportBytes,
  isGitHubCloudHost,
  isGitSshRemote,
  isLocalGitRemote,
  isWindowsGitDrive,
  normalizeHostedGitRepositoryUrl,
  parseGitRemote,
} from "./git-remote.js";
import { localFindingRepositories } from "./external-findings-read.js";
import {
  blackDuckReportRepositories,
  projectedBlackDuckRepositoryUrl,
} from "./blackduck-findings.js";
import { veracodeReportRepositories } from "./veracode-findings.js";
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

export interface LocalExternalImportPreview extends HostedExternalFindings {
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

// Imported scanner paths retain their source machine's drive, independent of this checkout's OS.
const windowsDrivePath = /^[a-z]:[\\/]/iu;

/** Compare transport forms without changing retained scanner evidence. */
interface RemoteRepositoryIdentity {
  key: string;
  account?: string;
  homeRelative?: boolean;
}

function remoteRepository(
  value: string,
  provider: Provider,
  bound: boolean,
  hostedKey?: (url: string) => string,
): RemoteRepositoryIdentity | undefined {
  // libcurl rejects multiple unescaped userinfo separators before making a request.
  if (/^(?:https?|ftps?):\/\/[^/?#@]*@[^/?#@]*@/iu.test(value))
    return undefined;
  const key =
    hostedKey ??
    (provider === "github" ? cloudRepositoryUrlKey : repositoryUrlKey);
  const transport = /^(?:ssh|git\+ssh|ssh\+git|git):\/\/([^/]*)(.*)$/isu.exec(
    value,
  );
  const authority = transport?.[1];
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
    return bound && (transport || /^https?:\/\//iu.test(value.trimStart()))
      ? { key: "\0" + value }
      : undefined;
  }
  if (!remote || !Object.hasOwn(gitTransportPorts, remote.url.protocol))
    return undefined;
  const { url, scpStyle } = remote;
  let path = remote.path;
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
  const origin = `${protocol}//${hostname}${port ? `:${port}` : ""}/`;
  const httpTransport = url.protocol === "http:" || url.protocol === "https:";
  const rawSuffix = /[?#].*$/su.exec(value)?.[0] ?? "";
  // Git appends its HTTP service path before libcurl strips fragment text.
  const requestSuffix = httpTransport
    ? rawSuffix.replace(/#.*$/su, "#").replace(/\/$/u, "")
    : "";
  const requestKey = (path: string) => {
    const repository = key(origin + path);
    return requestSuffix
      ? JSON.stringify([repository, requestSuffix])
      : repository;
  };
  if (!bound) {
    // SCP paths are literal. SSH URI paths include their query and fragment text.
    if (scpStyle) path = path.replaceAll("%", "%25");
    else if (ssh || url.protocol === "git:") path += rawSuffix;
    // Keep literal path delimiters in URL-escaped form, separate from HTTP selectors.
    return {
      key: requestKey(path.replace(/%3f|\?/giu, "%3F").replaceAll("#", "%23")),
    };
  }

  if (!ssh && url.protocol !== "git:") {
    if (httpTransport) {
      // libcurl and WHATWG differ on backslashes and encoded dot segments.
      const raw = /^https?:\/\/[^/\\?#\s]+(\/[^\\?#]*)?(?:[?#].*)?$/iu.exec(
        value,
      );
      if (!raw) return { key: "\0" + value };
      // The hosted HTTP key normalizes the raw Git path. URL.pathname escapes literal braces.
      if (hostedKey) path = (raw[1] ?? "").slice(1);
      else if (/\/(?:%2e|\.%2e|%2e\.|%2e%2e)(?:\/|$)/iu.test(raw[1] ?? ""))
        return { key: "\0" + value };
    }
    if (rawSuffix && !httpTransport) return { key: key(origin + path) + "\0" };
    return { key: requestKey(path) };
  }

  // Git passes the original path (including dot segments, '?' and '#') to upload-pack.
  if (!scpStyle && !transport) return { key: value };
  const gitPath = gitTransportBytes(transport?.[2] ?? path, scpStyle);
  const login = scpStyle
    ? /^([^@/:\s?#]+)@/u.exec(value)?.[1]
    : /^(.*)@/u.exec(authority ?? "")?.[1];
  const homeRelative =
    /^\/?~(?:\/|$)/u.test(gitPath) || (scpStyle && !/^[~/]/u.test(gitPath));
  const suffix = /[?#].*$/su.exec(gitPath);
  // Express upload-pack bytes as a URL path for comparison with the HTTP source.
  const name = gitPathToHttpPath(gitPath.slice(0, suffix?.index));
  const repository = suffix
    ? key(origin + name + "?") +
      "\0" +
      suffix[0].replace(/\/$/u, "").replace(/\.git$/u, "")
    : key(origin + name);
  return {
    key: repository,
    account: ssh && login ? gitTransportBytes(login, scpStyle) : undefined,
    // GitHub serves the same repository path through its SCP and SSH URLs.
    homeRelative:
      ssh && provider !== "github" && !isGitHubCloudHost(hostname.toLowerCase())
        ? homeRelative
        : undefined,
  };
}

function scannerRepository(
  value: string,
  provider: Provider,
): RemoteRepositoryIdentity {
  if (windowsDrivePath.test(value)) return { key: value };
  return remoteRepository(value, provider, true) ?? { key: value };
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

function localRepositoryPlatform(
  provider: Provider,
  sources: readonly ExternalSourceRepository[],
  bound: boolean,
) {
  const githubKey = (url: string) =>
    windowsDrivePath.test(url)
      ? undefined
      : remoteRepository(url, "github", bound)?.key;
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

type HostedRepository = ExternalSourceRepository & { gitlab?: boolean };

function hostedRepositoryMatches(
  source: HostedRepository,
  value: string,
  expectedKey?: string,
  gitlab = source.gitlab,
): boolean {
  if (!/^https?:\/\//iu.test(source.url)) return source.url === value;
  const github = source.platform === "github";
  const url = normalizeHostedGitRepositoryUrl(value, source.url, github);
  return (
    hostedRepositoryUrlKey(url, github, gitlab) ===
    (expectedKey ?? hostedRepositoryUrlKey(source.url, github, gitlab))
  );
}

async function requireMatchingRepository(
  repository: string,
  provider: Provider,
  sources: readonly ExternalSourceRepository[],
  hosted: HostedRepository | undefined,
  strictSources: ReadonlyMap<string, Provider>,
  strictPlatformFor: (source: ExternalSourceRepository) => Provider,
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
  const readGit = (args: readonly string[]) => {
    const overrides: NodeJS.ProcessEnv = { LC_ALL: "C" };
    // GIT_CONFIG redirects only git config; read the same configuration as git remote.
    if (args[0] === "config")
      for (const name of Object.keys(environment ?? process.env))
        if (
          (process.platform === "win32" ? name.toUpperCase() : name) ===
          "GIT_CONFIG"
        )
          overrides[name] = undefined;
    return abortable(async () => {
      try {
        const output = await gitOutput(
          repository,
          args,
          signal,
          overrides,
          undefined,
          "buffer",
          gitProtectedRoots,
          environment,
        );
        // Keep a byte per character until Git's record boundaries and config keys have been matched.
        return output.toString("latin1").replace(/\n$/u, "");
      } catch (error) {
        // The SDK exposes Git's original UTF-8 diagnostics on command errors.
        if (error instanceof Error) {
          if ("stderr" in error && Buffer.isBuffer(error.stderr))
            error.stderr = error.stderr.toString("utf8");
          if ("stdout" in error && Buffer.isBuffer(error.stdout))
            error.stdout = error.stdout.toString("utf8");
        }
        throw error;
      }
    }, signal);
  };
  const utf8 = (raw: string) => {
    const bytes = Buffer.from(raw, "latin1");
    return isUtf8(bytes) ? bytes.toString("utf8") : undefined;
  };
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
  if (!remoteNames) return;
  const remoteConfig = (
    await readGit([
      "config",
      "--null",
      "--get-regexp",
      "^(remote\\..*\\.(url|vcs)|url\\..*\\.insteadof)$",
    ]).catch((error: unknown) => {
      if (error instanceof Error && "code" in error && error.code === 1)
        return "";
      throw error;
    })
  ).split("\0");
  const multilinePrefixes = remoteConfig
    .filter((entry) => entry.startsWith("url."))
    .map((entry) => entry.slice(entry.indexOf("\n") + 1))
    .filter((prefix) => prefix.includes("\n"))
    .sort((a, b) => b.length - a.length);
  const remotes: { url: string; forcedHelper: boolean }[] = [];
  let hasUnverifiedRemote = false;
  for (const rawName of remoteNames.split("\n").filter(Boolean)) {
    const name = utf8(rawName);
    if (name === undefined) {
      hasUnverifiedRemote = true;
      continue;
    }
    const vcsKey = `remote.${rawName}.vcs\n`;
    const configuredHelper = remoteConfig
      .findLast((entry) => entry.startsWith(vcsKey))
      ?.slice(vcsKey.length);
    const output = await readGit(["remote", "get-url", "--all", "--", name]);
    const lines = output.split("\n");
    const urlKey = `remote.${rawName}.url\n`;
    const configured = remoteConfig
      .filter((entry) => entry.startsWith(urlKey))
      .map((entry) => entry.slice(urlKey.length));
    let urls = lines;
    // Each effective URL after a list reset contributes at least one line.
    if (
      lines.length > 1 &&
      configured.slice(-lines.length).some((url) => url.includes("\n"))
    ) {
      // A rewrite can consume line breaks in its longest matching insteadOf prefix.
      // Git config keys (including the replacement URL) cannot contain a newline.
      // Git emits either the full list or the suffix after the last empty URL.
      const afterReset = configured.lastIndexOf("") + 1;
      const records: string[] = [];
      let end = lines.length;
      for (let i = configured.length - 1; i >= 0 && end > 0; i--) {
        const original = configured[i]!;
        const prefix = multilinePrefixes.find((value) =>
          original.startsWith(value),
        );
        const start =
          end - original.slice(prefix?.length ?? 0).split("\n").length;
        if (start < 0 || (start === 0 && i !== 0 && i !== afterReset)) break;
        records.push(lines.slice(start, end).join("\n"));
        end = start;
      }
      if (end === 0) urls = records.reverse();
      else {
        hasUnverifiedRemote = true;
        urls = [await readGit(["remote", "get-url", "--", name])];
      }
    }
    for (const rawUrl of urls) {
      // Explicit helper:: takes precedence over remote.<name>.vcs.
      const explicit = /^([a-z0-9][a-z0-9+.-]*)::/iu.exec(rawUrl);
      const helper = explicit?.[1] ?? configuredHelper;
      const address = explicit ? rawUrl.slice(explicit[0].length) : rawUrl;
      if (helper === undefined && isLocalGitRemote(address)) continue;
      const url = utf8(address);
      if (url === undefined) {
        hasUnverifiedRemote = true;
        continue;
      }
      const transport = /^([a-z0-9][a-z0-9+.-]*:)\/\//iu.exec(url)?.[1] ?? "";
      const curl = /^(?:https?|ftps?):$/u.test(transport.toLowerCase());
      // A configured URL has a case-insensitive scheme. An explicit Git helper
      // has a case-sensitive name and only the standard curl names take URL arguments.
      const recognized = curl
        ? helper === undefined || /^(?:https?|ftps?)$/u.test(helper)
        : helper === undefined &&
          (!url.includes("://") ||
            Object.hasOwn(gitTransportPorts, transport) ||
            // Inspector can retain an unrecognized spelling as a literal repository key.
            (provider === "inspector" &&
              remoteRepository(url, provider, true)?.key === url));
      // libcurl rejects raw ASCII control characters and spaces that URL() may discard.
      if (!recognized || (curl && /[\x00-\x20\x7f]/u.test(url))) {
        hasUnverifiedRemote = true;
        continue;
      }
      if (isWindowsGitDrive(url) && !url.startsWith("-")) {
        // Git's Windows path validity rules decide between a drive and an SSH host.
        // Diagnostic mode opens no repository. gitOutput disables all transports before SSH setup.
        try {
          await readGit(["fetch-pack", "--diag-url", url]);
          continue;
        } catch (error) {
          if (!(
            error instanceof Error &&
            "code" in error &&
            error.code === 128 &&
            "stderr" in error &&
            typeof error.stderr === "string" &&
            error.stderr
              .split(/\r?\n/u)
              .filter((line) => line.startsWith("fatal: "))
              .join("\n") === "fatal: transport 'ssh' not allowed"
          ))
            throw error;
        }
      }
      remotes.push({ url, forcedHelper: helper !== undefined });
    }
  }
  if (!hasUnverifiedRemote && !remotes.length) return;
  const mismatch = (url: string) =>
    new CodexSecurityError(
      `Imported repository ${JSON.stringify(url)} does not match a configured remote of ${repository}. Select the matching local repository.`,
    );
  const drive = sources.find(({ url }) => windowsDrivePath.test(url));
  if (drive) throw mismatch(drive.url);
  if (hosted) {
    const platform = hosted.platform ?? provider;
    const key = (url: string) =>
      hostedRepositoryUrlKey(url, hosted.platform === "github", hosted.gitlab);
    const http = /^https?:\/\//iu;
    const httpKey = http.test(hosted.url)
      ? remoteRepository(hosted.url, platform, true, key)?.key
      : undefined;
    for (const { url: remote } of remotes) {
      const parsed = remoteRepository(remote, platform, true, key);
      if (!parsed) continue;
      // Git's HTTP credentials and default port don't change the checkout repository.
      if (
        httpKey && http.test(remote)
          ? parsed.key === httpKey
          : hostedRepositoryMatches(hosted, remote, httpKey)
      )
        return;
    }
    throw mismatch(hosted.url);
  }
  const ftpAddress = (value: string) => {
    const scheme = /^ftps?:\/\//iu.exec(value)?.[0];
    if (!scheme) return undefined;
    // FTP login and path bytes can select a different repository. Fold only the ASCII DNS hostname.
    const address = value
      .slice(scheme.length)
      .replace(
        /^([^/?#@]*@)?([\w.-]+)(?=[:/?#]|$)/u,
        (_, login: string = "", host: string) => login + host.toLowerCase(),
      );
    return scheme.toLowerCase() + address;
  };
  const boundProvider =
    provider === "inspector" ||
    provider === "blackduck" ||
    provider === "veracode";
  const loosePlatformFor = localRepositoryPlatform(provider, sources, false);
  for (const source of sources) {
    const bound = boundProvider || strictSources.has(source.url);
    const platform = bound
      ? (strictSources.get(source.url) ?? strictPlatformFor(source))
      : loosePlatformFor(source);
    const identity = (url: string) => remoteRepository(url, platform, bound);
    const targets = remotes.flatMap(({ url, forcedHelper }) => {
      // A curl helper uses the inner URL's transport. An FTP login or path can identify
      // a different repository from the same host's HTTPS endpoint.
      if (forcedHelper && ftpAddress(url) !== ftpAddress(source.url)) return [];
      return identity(url) ?? [];
    });
    const target = identity(source.url);
    if (!target || !targets.some((remote) => matchingRemote(remote, target)))
      throw mismatch(source.url);
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
export async function prepareNormalizedLocalImport<P extends Provider>(
  input: NormalizedFindingsFor<P>,
  options: NormalizedLocalImportOptions & { provider: P },
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
  input: HostedExternalFindings,
  options: NormalizedLocalImportOptions,
  dependencies: LocalExternalImportDependencies,
  readerSources = snapshotSourceRepositories(dependencies.sourceRepositories),
  parsedSources: readonly ExternalSourceRepository[] = [],
): Promise<PreparedLocalExternalImport> {
  requireIdentity(options.sourceKey, "Source key");
  const current = snapshotExternalFindings(input, options.provider);
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
    checkHostedFindingProvider(options.provider, finding.evidence.source_data);
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
  const reportUrl = current.sourceRepositoryUrl || undefined;
  if (reportUrl) sources.set(reportUrl, { url: reportUrl });
  const snyk =
    options.provider === "snyk" ? snykRepositoryScope(current) : undefined;
  const snykProject = snyk?.project;
  for (const url of [snykProject?.url, snykProject?.nativeUrl])
    if (url) sources.set(url, { url });
  let hostedUrl = reportUrl ?? snyk?.sourceUrl;
  const reportPlatform = current.sourceRepositoryPlatform;
  const singleProject = Boolean(
    hostedUrl ||
    reportPlatform ||
    (options.provider === "semgrep" &&
      current.findings.some(({ evidence }) =>
        isSemgrepPlatformReport(evidence.source_data),
      )),
  );
  let hostedPlatform = snykProject?.platform;
  if (snyk && !snykProject && !current.findings.length)
    hostedPlatform = reportPlatform;
  let hostedGitHub =
    reportPlatform !== "other" && hostedPlatform && hostedPlatform === "github";
  for (const { evidence } of current.findings) {
    const url = evidence.details?.repository?.url;
    if (url) sources.set(url, { url });
    const data = evidence.source_data;
    if (snyk && data) {
      for (const source of snyk.claims.get(data) ?? []) {
        sources.set(source.url, { url: source.url });
        if (source.nativeUrl)
          sources.set(source.nativeUrl, { url: source.nativeUrl });
        // A native plugin may report its local drive path. Check it against the checkout below.
        if (
          reportPlatform === "other" &&
          windowsDrivePath.test(source.url) &&
          isGitSshRemote(source.url)
        )
          hostedUrl ??= source.url;
        // Only retained or independent evidence can establish GitHub on a populated report.
        if (source.platform !== undefined)
          hostedGitHub = (hostedGitHub ?? true) && source.platform === "github";
      }
    }
    if (options.provider === "semgrep") {
      const native = semgrepPlatformFindingRepository(
        data,
        (url) =>
          reportPlatform !== "other" &&
          isVerifiedGitHubRepository(url, references),
      );
      if (native) {
        hostedUrl ??= native;
        sources.set(native, { url: native });
      } else if (singleProject) {
        for (const source of semgrepSarifSourceRepositories(data))
          sources.set(source.url, source);
      }
    }
  }
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
    scannerRepository(url, platformFor({ url }));
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
      const snykClaims =
        evidence.source_data && snyk?.claims.get(evidence.source_data);
      if (
        !sameScannerRepositories(
          claims.map((claim) => {
            // Snyk already verified its native URL against this row's declared repository.
            const resolved =
              snykClaims?.find(({ nativeUrl }) => nativeUrl === claim)?.url ??
              claim;
            return scannerRepository(resolved, rowPlatform(resolved));
          }),
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
    const native = remoteRepository(inspector.url, platform, true);
    for (const url of sources.keys()) {
      if (
        windowsDrivePath.test(url) ||
        !native ||
        remoteRepository(url, platform, true)?.key !== native.key
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
  let hosted: HostedRepository | undefined;
  const collectedSources = [...sources.values()];
  const projectedUrl =
    singleProject && !hostedUrl
      ? (
          collectedSources.find(({ url }) => /^https?:\/\//iu.test(url)) ??
          collectedSources[0]
        )?.url
      : undefined;
  const source = hostedUrl ?? projectedUrl;
  if (source) {
    const github =
      hostedGitHub ??
      collectedSources.some(({ platform }) => platform === "github");
    const url = projectedUrl
      ? normalizeHostedGitRepositoryUrl(projectedUrl, undefined, github)
      : source;
    // A case-sensitive report may retain only its private SSH selector.
    if (
      projectedUrl &&
      !(
        reportPlatform === "other" &&
        !windowsDrivePath.test(url) &&
        isGitSshRemote(url)
      )
    )
      hostedRepositoryUrl(url, "Projected source repository URL");
    hosted = {
      url,
      platform: github ? "github" : undefined,
      gitlab: snyk?.destinationSuffix,
    };
    // Validate the entire report even when the checkout has several remotes or none.
    for (const url of sources.keys()) {
      validateHostedRepositoryUrl(url);
      if (
        !hostedRepositoryMatches(
          hosted,
          url,
          undefined,
          snyk?.allowsSuffix(url),
        )
      )
        throw new CodexSecurityError(
          "The normalized repository does not match the hosted scanner project.",
        );
    }
  }
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
  await requireMatchingRepository(
    repository,
    options.provider,
    [...sources.values()],
    hosted,
    strictSources,
    platformFor,
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
