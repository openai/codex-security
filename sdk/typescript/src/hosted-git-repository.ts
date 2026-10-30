import { isIPv4 } from "node:net";
import {
  cloudRepositoryUrlKey,
  repositoryUrlKey,
} from "./external-import-contract.js";
import { isGitHubCloudHost } from "./git-remote.js";

// Git treats a colon followed by "//" as the start of a URL transport.
const scpRemote = /^(?:([^@/:\s?#]+)@)?(\[[^\]]+\]|[^@/:\s?#]+):(?!\/\/)(.+)$/u;

const sshRemote = /^(?:ssh|git\+ssh|ssh\+git):\/\/([^/]+?)(?:\/|%2[fF])/u;

/** A native file URL or an unambiguous local path. */
export function isLocalGitRemote(remote: string): boolean {
  if (remote.includes("://")) return remote.startsWith("file://");
  const colon = remote.indexOf(":");
  return colon < 0 || remote.slice(0, colon).includes("/");
}

export function isWindowsGitDrive(remote: string): boolean {
  // Git for Windows accepts one character or up to four consecutive non-ASCII bytes before a drive colon.
  return (
    process.platform === "win32" &&
    !remote.includes("://") &&
    /^(?:.|[\u0080-\u07ff]{2}):(?!:)/su.test(remote)
  );
}

function parseScpRemote(remote: string): RegExpExecArray | null {
  return !isLocalGitRemote(remote) &&
    !remote.includes("://") &&
    !/^[a-z\d][a-z\d+.-]*::/iu.test(remote)
    ? scpRemote.exec(remote)
    : null;
}

function sshAuthority(host: string): URL | null {
  if (/[\/\\?#@\s\x00-\x1f\x7f]/u.test(host)) return null;
  // Git passes a leading plus on decimal ports through to OpenSSH.
  const parse = (authority: string) =>
    URL.parse("ssh://" + authority.replace(/:\+(\d+)$/u, ":$1"));
  const parsed = parse(host);
  if (parsed) return parsed;
  // Git accepts brackets around DNS names, with an SSH port inside or after the brackets.
  const bracketed = /^\[([^\]]+)\](?::(\+?\d*))?$/u.exec(host);
  // An empty port outside the brackets is ignored, but an inner trailing colon is a hostname byte.
  if (!bracketed || bracketed[1]!.endsWith(":")) return null;
  const [, name, port] = bracketed;
  return parse(name + (port ? `:${port}` : ""));
}

/** Git decodes URI escapes once except for NUL, and sends SCP bytes literally. */
export function gitTransportBytes(raw: string, scpStyle: boolean): string {
  const bytes = Buffer.from(raw).toString("latin1");
  return scpStyle
    ? bytes
    : bytes.replace(/%(?!00)([\da-f]{2})/giu, (_, hex: string) =>
        String.fromCharCode(parseInt(hex, 16)),
      );
}

/** Decode only URI escapes whose ASCII bytes cannot introduce a delimiter. */
export function decodeUnreserved(value: string): string {
  return value.replace(/%([0-9a-f]{2})/giu, (escape, hex: string) => {
    const byte = String.fromCharCode(parseInt(hex, 16));
    return /^[a-z0-9._~-]$/iu.test(byte) ? byte : escape.toUpperCase();
  });
}

/** Represent upload-pack path bytes relative to an HTTP repository origin. */
export function gitPathToHttpPath(bytes: string): string {
  return bytes
    .replace(/^\//u, "")
    .replace(
      /[%\x00-\x20\x7f-\xff]/gu,
      (byte) =>
        "%" + byte.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0"),
    );
}

/** Ignore the optional DNS root dot for provider classification only. */
export function gitServiceHostname(hostname: string): string {
  return hostname.replace(/\.$/u, "");
}

export function isPublicGitHost(host: string): boolean {
  return (
    isGitHubCloudHost(host) || host === "gitlab.com" || host === "bitbucket.org"
  );
}

/** Public SSH-over-443 hosts share the HTTPS hostname after the first DNS label. */
function publicGitSsh443Host(hostname: string): string | undefined {
  switch (gitServiceHostname(hostname)) {
    case "ssh.github.com":
    case "altssh.gitlab.com":
    case "altssh.bitbucket.org":
      return hostname.slice(hostname.indexOf(".") + 1);
  }
}

function matchesHttpsHost(url: string | undefined, hostname: string): boolean {
  const source = url && URL.parse(url);
  return (
    !!source &&
    source.protocol === "https:" &&
    source.hostname.toLowerCase() === hostname
  );
}

/** Standard public SSH aliases, plus a GitHub host established by the caller. */
export function normalizeHostedGitRepositoryUrl(
  remote: string,
  source: string | undefined,
  github: boolean,
): string {
  // A projected single-project report may retain only its SSH spelling.
  return normalizeGitSshAlias(
    remote,
    (host) =>
      (github || isPublicGitHost(gitServiceHostname(host))) &&
      matchesHttpsHost(source ?? `https://${host}`, host),
  );
}

function normalizeGitSshAlias(
  repository: string,
  isAliasHost: (host: string) => boolean,
): string {
  const isGitSshUser = (username: string, hostname: string) =>
    (username === "git" && hostname === "github.com") ||
    (isAliasHost(hostname) &&
      (username === "git" ||
        username ===
          /^([^.]+)\.ghe\.com$/u.exec(gitServiceHostname(hostname))?.[1]));
  const hostedAlias = (
    url: URL,
    user: string,
    path: string,
    scpStyle: boolean,
  ) => {
    const hostname = url.hostname.toLowerCase();
    const standard =
      isGitSshUser(user, hostname) && (url.port === "" || url.port === "22");
    const alternate =
      user === "git" && url.port === "443" && publicGitSsh443Host(hostname);
    if (!standard && !alternate) return repository;
    const bytes = gitTransportBytes(path, scpStyle);
    if (/[?#\\]/u.test(bytes) || /(?:^|\/)\.{1,2}(?:\/|$)/u.test(bytes))
      return repository;
    return `https://${alternate || hostname}/${gitPathToHttpPath(bytes)}`;
  };
  const scp = parseScpRemote(repository);
  if (scp) {
    if (!scp[1]) return repository;
    const authority = sshAuthority(scp[2]!);
    return authority
      ? hostedAlias(authority, scp[1], scp[3]!, true)
      : repository;
  }
  // Git separates the decoded authority from the path at the first slash.
  const ssh = sshRemote.exec(repository);
  if (ssh && !/[\t\r\n]/u.test(repository)) {
    const authority = gitTransportBytes(ssh[1]!, false);
    const login = /^([^@:]+)@([^@]+)$/u.exec(authority);
    if (!login || /[/\\%?#\s]/u.test(authority)) return repository;
    const url = sshAuthority(login[2]!);
    if (url)
      return hostedAlias(
        url,
        login[1]!,
        "/" + repository.slice(ssh[0].length),
        false,
      );
  }
  return repository;
}

function hostedHttpAuthority(authority: string): string {
  if (/[%@\\\s]/u.test(authority)) return authority;
  const hostname = URL.parse(`https://${authority}/`)?.hostname;
  // Hostname serialization handles IP literals and IDNA. The connector distinguishes explicit ports.
  const port = /:\d*$/u.exec(authority)?.[0] ?? "";
  return hostname ? hostname + port : authority;
}

function hostedHttpPath(path: string): string {
  const segments: string[] = [];
  for (const segment of path.split("/")) {
    // Git's HTTP transport resolves literal dot segments before sending the path.
    if (segment === "..") {
      segments.pop();
    } else if (segment !== ".") {
      const spelling = segment.replace(/\P{ASCII}+/gu, (text) =>
        encodeURIComponent(text.toWellFormed()),
      );
      const decoded = decodeUnreserved(spelling);
      segments.push(
        decoded === "." || decoded === ".." ? segment.toUpperCase() : decoded,
      );
    }
  }
  if (/(?:^|\/)\.{1,2}$/u.test(path)) segments.push("");
  return segments.join("/");
}

/** Compare the HTTP request path a browser and Git would send for the same link. */
export function ambiguousHostedHttpPath(value: string): boolean {
  const path = /^https?:\/\/[^/?#]+\/([^?#]*)/iu.exec(value)?.[1];
  if (path === undefined) return false;
  const web = URL.parse(value)?.pathname.slice(1);
  return (
    web !== undefined &&
    path !== web &&
    hostedHttpPath(path) !== hostedHttpPath(web)
  );
}

/** Compare hosted HTTP repository spellings without changing the retained evidence. */
export function hostedRepositoryUrlKey(
  value: string,
  github = false,
  knownGitSuffix = false,
): string {
  const url = value.replace(
    /^(https?:\/\/)([^/?#]+)\/([^?#]*)/iu,
    (_, scheme: string, authority: string, path: string) =>
      scheme + hostedHttpAuthority(authority) + "/" + hostedHttpPath(path),
  );
  if (github) return cloudRepositoryUrlKey(url);
  const host = URL.parse(url)?.hostname ?? "";
  const service = /^https?:\/\//iu.test(url) ? gitServiceHostname(host) : host;
  if (service !== host && isGitHubCloudHost(service))
    return cloudRepositoryUrlKey(url);
  // An arbitrary Git server can serve different repositories at /repo and /repo.git.
  const key = repositoryUrlKey(url);
  return !knownGitSuffix && !isPublicGitHost(service) && /\.git\/?$/u.test(url)
    ? key + ".git"
    : key;
}

/** The Git HTTP Host and TLS server name can differ from the web URL's parsed IP literal. */
export function ambiguousGitIpHost(url: string): boolean {
  const host = URL.parse(url)?.hostname;
  if (!host || (!isIPv4(host) && !host.startsWith("["))) return false;
  const authority = /^https?:\/\/([^/?#]*)/iu.exec(url)?.[1] ?? "";
  const rawHost = authority
    .slice(authority.lastIndexOf("@") + 1)
    .replace(/:\d*$/u, "");
  return rawHost.toLowerCase() !== host;
}

/** Match a Git checkout to an independently selected hosted repository. */
export function hostedRepositoryMatches(
  source: { url: string; platform?: string; gitlab?: boolean },
  remote: string,
): boolean {
  if (!/^https?:\/\//iu.test(source.url)) return remote === source.url;
  const github = source.platform === "github";
  const url = normalizeHostedGitRepositoryUrl(remote, source.url, github);
  // Git passes raw URL paths to its HTTP transport. Do not turn backslashes,
  // controls or an encoded traversal into a match via web URL serialization.
  if (
    !/^https?:\/\//iu.test(url) ||
    /[\\\x00-\x20\x7f?#]/u.test(url) ||
    // libcurl accepts encoded userinfo but rejects multiple literal authority delimiters.
    /^https?:\/\/[^/?#]*@[^/?#]*@/iu.test(url) ||
    ambiguousGitIpHost(url) ||
    ambiguousHostedHttpPath(url)
  )
    return false;
  // The local checkout's credentials and default HTTP port don't change the server path.
  const key = (value: string) =>
    hostedRepositoryUrlKey(
      value.replace(
        /^(https?:\/\/)([^/?#\\]+)\//iu,
        (match, scheme: string, authority: string) => {
          const parsed = URL.parse(scheme + authority);
          return parsed ? scheme + parsed.host + "/" : match;
        },
      ),
      github,
      source.gitlab || source.platform === "gitlab",
    );
  return key(url) === key(source.url);
}
