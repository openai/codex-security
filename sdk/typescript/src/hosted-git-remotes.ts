import { constants } from "node:fs";
import { access, lstat, readdir, stat } from "node:fs/promises";
import { delimiter, isAbsolute, join, resolve, sep } from "node:path";

import { isUtf8 } from "node:buffer";
import { environmentEntry } from "./auth.js";
import {
  isLocalGitRemote,
  isWindowsGitDrive,
} from "./hosted-git-repository.js";
import {
  abortable,
  gitOutput,
  nullIfMissingPath,
  trustedGitCommand,
} from "./targets.js";

async function recognizedCurlHelper(
  name: string,
  repository: string,
  trustedEnvironment: () => Promise<NodeJS.ProcessEnv>,
  readGit: (args: readonly string[]) => Promise<string | undefined>,
): Promise<boolean> {
  const lower = name.toLowerCase();
  if (!/^(?:https?|ftps?)$/u.test(lower)) return false;
  if (name === lower) return true;

  const environment = await trustedEnvironment();
  const execPath = await readGit(["--exec-path"]);
  if (!execPath) return false;
  // Git prepends its exec path at the invocation directory and again when dispatching from the worktree.
  const cwd = resolve(
    repository,
    (await readGit(["rev-parse", "--show-cdup"])) ?? "",
  );
  const locations = (base: string) =>
    (isAbsolute(execPath) ? execPath : base + sep + execPath).split(delimiter);
  const directories = [
    ...locations(cwd),
    ...(cwd === repository ? [] : locations(repository)),
    ...(environmentEntry(environment, "PATH") ?? "").split(delimiter),
  ];
  const find = async (helper: string) => {
    for (const dir of directories) {
      // Git for Windows tries .exe before the extensionless helper, within each directory.
      for (const suffix of process.platform === "win32" ? [".exe", ""] : [""]) {
        const filename = "git-remote-" + helper + suffix;
        // POSIX resolves symlinks before a following '..', as Git does during PATH lookup.
        const path =
          process.platform === "win32"
            ? resolve(cwd, dir, filename)
            : (dir.startsWith("/") ? dir : cwd + "/" + dir) + "/" + filename;
        try {
          await access(
            path,
            process.platform === "win32" ? constants.F_OK : constants.X_OK,
          );
          const file = await stat(path, { bigint: true });
          if (file.isFile()) return file;
          if (suffix) return;
        } catch (error) {
          const code = (error as NodeJS.ErrnoException).code;
          if (code !== "ENOENT" && code !== "ENOTDIR" && code !== "EACCES")
            return;
        }
      }
    }
  };
  // Different spellings can resolve to one file on a case-insensitive volume.
  const [selected, standard] = await Promise.all([find(name), find(lower)]);
  return (
    !!selected &&
    !!standard &&
    selected.ino !== 0n &&
    selected.dev === standard.dev &&
    selected.ino === standard.ino
  );
}

/** Read effective external Git URLs without invoking a transport. An empty result means none could be verified. */
export async function readHostedGitRemotes(
  repository: string,
  protectedRoots: string[],
  environment?: NodeJS.ProcessEnv,
  signal?: AbortSignal,
): Promise<string[] | undefined> {
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
          protectedRoots,
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
  const remoteConfig = (
    await readGit([
      "config",
      "--null",
      "--get-regexp",
      "^remote\\..*\\.vcs$",
    ]).catch((error: unknown) => {
      if (error instanceof Error && "code" in error && error.code === 1)
        return "";
      throw error;
    })
  ).split("\0");
  const remotes: string[] = [];
  let hasUnverifiedRemote = false;
  // The default fetch can resolve an unlisted legacy source even when other remotes are named.
  const resolved = new Set<string>();
  const missingUrls = new Set([
    "fatal: No remote configured to list refs from.",
    "fatal: remote (null) has no configured URL", // Git 2.43 when the default only names a helper.
  ]);
  const listed = new Set(remoteNames.split("\n").filter(Boolean));
  async function* candidates() {
    yield* listed;
    yield "";
    if (hasUnverifiedRemote || remotes.length) return;
    // Git's legacy metadata directories hold unlisted remote names. Let Git interpret each file.
    const common = utf8(
      await readGit([
        "rev-parse",
        "--path-format=absolute",
        "--git-common-dir",
      ]),
    );
    if (!common) return;
    for (const folder of ["remotes", "branches"]) {
      const dir = join(common, folder);
      if (!(await lstat(dir).catch(nullIfMissingPath))?.isDirectory()) continue;
      const entries = await abortable(
        () => readdir(dir, { withFileTypes: true }),
        signal,
      );
      for (const entry of entries) {
        const raw = Buffer.from(entry.name).toString("latin1");
        if ((entry.isFile() || entry.isSymbolicLink()) && !listed.has(raw))
          yield raw;
      }
    }
  }
  for await (const rawName of candidates()) {
    const name = utf8(rawName);
    if (name === undefined) {
      hasUnverifiedRemote = true;
      continue;
    }
    const vcsKey = `remote.${rawName}.vcs\n`;
    const configuredHelper = remoteConfig
      .findLast((entry) => entry.startsWith(vcsKey))
      ?.slice(vcsKey.length);
    if (configuredHelper !== undefined)
      missingUrls.add(`fatal: remote ${name} has no configured URL`);
    // Resolve the same first URL as a fetch, including rewrites on an implicit local remote name.
    // --get-url exits before Git connects to a transport.
    const legacy = name !== "" && !listed.has(rawName);
    const query = legacy
      ? ["remote", "get-url", "--", name]
      : ["ls-remote", "--get-url", ...(name ? ["--", name] : [])];
    const rawUrl = await readGit(query).catch((error: unknown) => {
      // Only Git can distinguish a historical remote from an unrelated file in the same directory.
      if (
        legacy &&
        error instanceof Error &&
        "code" in error &&
        error.code === 2
      )
        return undefined;
      if (
        error instanceof Error &&
        "code" in error &&
        error.code === 128 &&
        "stderr" in error &&
        typeof error.stderr === "string" &&
        error.stderr.split(/\r?\n/u).some((line) => missingUrls.has(line))
      )
        return undefined;
      throw error;
    });
    if (rawUrl === undefined) {
      if (name && !legacy) hasUnverifiedRemote = true;
      continue;
    }
    // Explicit helper:: takes precedence over remote.<name>.vcs.
    // A named remote's configured helper also governs an identical default fetch URL.
    if (!name && resolved.has(rawUrl)) continue;
    resolved.add(rawUrl);
    const explicit = /^([a-z0-9][a-z0-9+.-]*)::/iu.exec(rawUrl);
    const helper = explicit?.[1] ?? configuredHelper;
    const address = explicit ? rawUrl.slice(explicit[0].length) : rawUrl;
    if (helper === undefined && isLocalGitRemote(address)) continue;
    const url = utf8(address);
    if (url === undefined) {
      hasUnverifiedRemote = true;
      continue;
    }
    const transport = /^([a-z0-9][a-z0-9+.-]*):\/\//iu.exec(url)?.[1] ?? "";
    const curlHelper = /^(?:https?|ftps?)$/u;
    const curl = curlHelper.test(transport.toLowerCase());
    // Git uses the scheme spelling in the implicit git-remote-<scheme> executable name.
    const effectiveHelper = helper ?? transport;
    const recognized = curl
      ? await recognizedCurlHelper(
          effectiveHelper,
          repository,
          async () =>
            (
              await trustedGitCommand(
                repository,
                true,
                environment ?? process.env,
                protectedRoots,
                signal,
              )
            ).environment,
          async (args) => utf8(await readGit(args)),
        )
      : helper === undefined &&
        (!url.includes("://") ||
          /^(?:ssh|git\+ssh|ssh\+git|git)$/u.test(transport));
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
    remotes.push(url);
  }
  return hasUnverifiedRemote || remotes.length ? remotes : undefined;
}
