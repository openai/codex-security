export interface GitRemote {
  url: URL;
  /** Repository path without a URL's leading slash; SCP paths remain literal. */
  path: string;
  scpStyle: boolean;
}

/** Parse transport syntax only; callers decide which hosts and credentials are allowed. */
export function parseGitRemote(remote: string): GitRemote | undefined {
  if (remote.includes("://")) {
    const url = new URL(remote);
    return {
      url,
      path: url.pathname.slice(1),
      scpStyle: false,
    };
  }
  const scp = /^((?:[^@/:\s?#]+@)?(?:\[[^\]]+\]|[^@/:\s?#]+)):(.+)$/u.exec(
    remote,
  );
  if (scp === null) return undefined;
  return {
    url: new URL(`ssh://${scp[1]}`),
    // An SCP path's ?, #, and dot segments are literal Git path characters.
    path: scp[2]!,
    scpStyle: true,
  };
}

export function isGitHubCloudHost(host: string): boolean {
  return host === "github.com" || host.endsWith(".ghe.com");
}

export function isGitHubSshOverHttps(url: URL): boolean {
  return (
    ["ssh:", "git+ssh:", "ssh+git:"].includes(url.protocol) &&
    url.hostname.toLowerCase() === "ssh.github.com" &&
    url.port === "443"
  );
}
