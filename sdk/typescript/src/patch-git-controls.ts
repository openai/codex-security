import { constants } from "node:fs";
import {
  access,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  readlink,
  realpath,
  rm,
  stat,
  symlink,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { setTimeout as delay } from "node:timers/promises";
import {
  basename,
  delimiter,
  dirname,
  isAbsolute,
  join,
  parse,
  relative,
  resolve,
  sep,
} from "node:path";
import { gitAlternatePathBytes, gitMarkerRoot } from "./targets.js";

// Git hook entrypoints: https://git-scm.com/docs/githooks
const GIT_HOOKS = [
  "applypatch-msg",
  "pre-applypatch",
  "post-applypatch",
  "pre-commit",
  "pre-merge-commit",
  "prepare-commit-msg",
  "commit-msg",
  "post-commit",
  "pre-rebase",
  "post-checkout",
  "post-merge",
  "pre-push",
  "pre-receive",
  "update",
  "proc-receive",
  "post-receive",
  "post-update",
  "reference-transaction",
  "push-to-checkout",
  "pre-auto-gc",
  "post-rewrite",
  "sendemail-validate",
  "fsmonitor-watchman",
  "p4-changelist",
  "p4-prepare-changelist",
  "p4-post-changelist",
  "p4-pre-submit",
  "post-index-change",
].flatMap((hook) =>
  process.platform === "win32" ? [hook, `${hook}.exe`] : [hook],
);

export interface PatchGitCommandOptions {
  readonly encoding?: "base64";
  readonly nestedProbe?: boolean;
  readonly indexFile?: string;
  readonly input?: string | Uint8Array;
  readonly environment?: NodeJS.ProcessEnv;
}

type RunGit = (
  root: string,
  directory: string,
  args: string[],
  options?: PatchGitCommandOptions,
) => Promise<string>;

type RunIndexGit = (
  args: string[],
  options?: PatchGitCommandOptions,
) => Promise<string>;

export async function withPatchGitIndex<T>(
  run: RunIndexGit,
  inspect: (run: RunIndexGit) => Promise<T>,
  files?: readonly string[],
  sourcePathspecs?: readonly string[],
): Promise<T> {
  const directory = await mkdtemp(
    join(await realpath(tmpdir()), "codex-security-patch-tree-"),
  );
  const indexFile = join(directory, "index");
  const indexed: RunIndexGit = (args, options) =>
    run(args, { ...options, indexFile });
  try {
    let hasHead = true;
    try {
      await indexed(["rev-parse", "--verify", "--quiet", "HEAD"]);
    } catch (error) {
      const failure = error as { code?: unknown; status?: unknown };
      if ((failure.code ?? failure.status) !== 1) throw error;
      // An unborn symbolic HEAD has no commit; malformed refs still fail.
      await indexed(["symbolic-ref", "--quiet", "HEAD"]);
      hasHead = false;
    }
    await indexed(["read-tree", ...(hasHead ? ["HEAD"] : ["--empty"])]);
    const entries = Buffer.from(
      await run(
        [
          ...(sourcePathspecs === undefined ? ["--literal-pathspecs"] : []),
          "ls-files",
          "--stage",
          "--full-name",
          "-z",
          ...(sourcePathspecs ?? (files === undefined ? [] : ["--", ...files])),
        ],
        {
          encoding: "base64",
        },
      ),
      "base64",
    ).toString("latin1");
    await indexed(
      ["-c", "core.ignorestat=false", "update-index", "-z", "--index-info"],
      {
        input: Buffer.from(
          entries.replaceAll(/(^|\0)([0-7]+ [a-f\d]+) [123]\t/gu, "$1$2 0\t"),
          "latin1",
        ),
      },
    );
    return await inspect(indexed);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

export interface PatchGitControls {
  readonly readOnlyPaths: readonly string[];
  readonly modelOnlyReadOnlyPaths: readonly string[];
  readonly externalCachePaths: readonly string[];
  readonly snapshotStoragePaths: readonly string[];
  readonly snapshotConfigPaths: readonly string[];
  hostFilterSettings(switchingBranch: boolean): Promise<readonly string[]>;
  validate(): Promise<void>;
}

// Windows provisions read ACLs in the background. Ask Git to read the same
// files explicitly before a snapshot can silently ignore an inaccessible config.
export async function ensureWindowsSnapshotConfigReadable(
  paths: readonly string[],
  probe: (
    args: string[],
    input: string,
    refreshReadGrants: boolean,
  ) => Promise<unknown>,
  signal?: AbortSignal,
): Promise<void> {
  const input =
    paths.map((path) => path.replaceAll("\\", "/")).join("\n") + "\n";
  const deadline = Date.now() + 30_000;
  let refreshReadGrants = false;
  for (;;) {
    signal?.throwIfAborted();
    try {
      await probe(
        ["hash-object", "--no-filters", "--stdin-paths"],
        input,
        refreshReadGrants,
      );
      return;
    } catch (error) {
      const stderr = (error as { stderr?: string } | null)?.stderr;
      if (
        typeof stderr !== "string" ||
        !/permission denied|access is denied/iu.test(stderr) ||
        Date.now() >= deadline
      )
        throw error;
      // A fresh sandbox launch can schedule an ACL refresh skipped by a busy helper.
      refreshReadGrants = true;
      await delay(250, undefined, { signal });
    }
  }
}

const missing = (error: unknown): undefined => {
  if (
    ["ENOENT", "ENOTDIR"].includes((error as NodeJS.ErrnoException).code ?? "")
  )
    return undefined;
  throw error;
};

function inside(root: string, path: string): boolean {
  const difference = relative(root, path);
  return (
    difference !== ".." &&
    !difference.startsWith(`..${sep}`) &&
    !isAbsolute(difference)
  );
}

function controlPathText(bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      bytes,
    );
  } catch (cause) {
    throw new Error(
      "Patch cannot safely use Git configuration or administration paths that are not valid UTF-8.",
      { cause },
    );
  }
}

const realControlPath = async (path: string) =>
  controlPathText(await realpath(path, { encoding: "buffer" }));

// Append before realpath so a link/.. path keeps the filesystem's meaning.
const relativeFile = (directory: string, path: string) =>
  isAbsolute(path) ? path : `${directory}${sep}${path}`;

async function readGitMarker(
  marker: string | Buffer,
): Promise<Buffer | true | undefined> {
  const metadata = await stat(marker).catch(missing);
  if (metadata === undefined) return undefined;
  if (metadata.isDirectory()) return true;
  if (!metadata.isFile()) return undefined;
  const contents = await readFile(marker);
  return contents.subarray(0, 8).equals(Buffer.from("gitdir: "))
    ? contents
    : undefined;
}

export async function selectedGitFileReference(
  marker: string,
  gitDirectory: string,
): Promise<string | undefined> {
  const contents = await readGitMarker(marker);
  if (contents === undefined || contents === true) return undefined;
  const reference = relativeFile(
    dirname(marker),
    controlPathText(contents)
      .slice(8)
      .replace(/[\r\n]+$/u, ""),
  );
  return (await realControlPath(reference).catch(missing)) === gitDirectory
    ? reference
    : undefined;
}

function hasNoWorktree(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  const failure = error as Error & {
    code?: unknown;
    status?: unknown;
    stderr?: unknown;
  };
  const diagnostic = Buffer.isBuffer(failure.stderr)
    ? failure.stderr.toString("utf8")
    : failure.stderr;
  return (
    (failure.code === 128 || failure.status === 128) &&
    typeof diagnostic === "string" &&
    /fatal: this operation must be run in a work tree\r?\n$/u.test(diagnostic)
  );
}

async function readCommonDirectory(
  gitDirectory: string,
  rememberReference?: (path: string) => Promise<void>,
): Promise<string | undefined> {
  const commonBytes = await readFile(join(gitDirectory, "commondir")).catch(
    missing,
  );
  const common =
    commonBytes === undefined ? undefined : controlPathText(commonBytes);
  if (common === undefined) return undefined;
  const commonReference = relativeFile(
    gitDirectory,
    common.replace(/[\r\n]+$/u, ""),
  );
  const resolvedCommon = await realControlPath(commonReference);
  await rememberReference?.(commonReference);
  return resolvedCommon;
}

async function markerDirectories(
  directory: string,
  isGitDirectory: (path: string, contents?: Buffer | true) => Promise<boolean>,
  commonDirectory?: string,
  rememberReference?: (path: string) => Promise<void>,
): Promise<string[] | undefined> {
  const marker = join(directory, ".git");
  const contents = await readGitMarker(marker);
  if (contents === undefined) return undefined;
  if (!(await isGitDirectory(marker, contents))) return undefined;
  const reference =
    contents === true
      ? marker
      : relativeFile(
          directory,
          controlPathText(contents)
            .slice(8)
            .replace(/[\r\n]+$/u, ""),
        );
  const gitDirectory = await realControlPath(reference).catch(missing);
  if (gitDirectory === undefined) return undefined;
  if (!(await stat(gitDirectory)).isDirectory()) return undefined;
  await rememberReference?.(reference);
  if (commonDirectory !== undefined) return [gitDirectory, commonDirectory];
  const common = await readCommonDirectory(gitDirectory, rememberReference);
  return common === undefined ? [gitDirectory] : [gitDirectory, common];
}

async function isRegisteredLinkedWorktree(
  checkout: string,
  directories: string[],
): Promise<boolean> {
  const [gitDirectory, common] = directories;
  if (
    !gitDirectory ||
    !common ||
    relative(join(common, "worktrees"), dirname(gitDirectory)) !== ""
  )
    return false;
  // Git records the reciprocal checkout path in the common repository's
  // worktree registration. A gitfile in the selected checkout cannot supply it.
  const backlink = join(gitDirectory, "gitdir");
  if (!(await lstat(backlink).catch(missing))?.isFile()) return false;
  const registered = relativeFile(
    gitDirectory,
    controlPathText(await readFile(backlink)).replace(/[\r\n]+$/u, ""),
  );
  const marker = await realControlPath(registered).catch(missing);
  return (
    marker !== undefined && relative(join(checkout, ".git"), marker) === ""
  );
}

// Git permits include files and hook directories that do not exist yet.
async function canonicalPath(path: string): Promise<string> {
  // Match realpath's Windows separators when a path no longer exists.
  if (sep === "\\") path = path.replaceAll("/", sep);
  // Some realpath implementations collapse file/.. even when lookup fails.
  const canonical = await stat(path)
    .then(() => realControlPath(path))
    .catch(missing);
  if (canonical !== undefined) return canonical;
  const parent = dirname(path);
  if (parent === path) return path;
  // A missing intermediate component must not collapse into an existing file.
  return `${await canonicalPath(parent)}${path.slice(parent.length)}`;
}

async function directoryLinkEntry(
  path: string,
  identity: { dev: bigint; ino: bigint },
): Promise<string> {
  const parent = await canonicalPath(dirname(path));
  const spelling = basename(path);
  const names = await readdir(parent).catch((error: unknown) => {
    // Traversal can be permitted without directory-list access.
    if (
      ["EACCES", "EPERM"].includes((error as NodeJS.ErrnoException).code ?? "")
    )
      return undefined;
    throw error;
  });
  // Exact names remain distinct in case-sensitive directories.
  if (names !== undefined && !names.includes(spelling)) {
    for (const name of names) {
      if (name.toLowerCase() !== spelling.toLowerCase()) continue;
      const candidate = join(parent, name);
      const metadata = await lstat(candidate, { bigint: true }).catch(missing);
      if (metadata?.dev === identity.dev && metadata.ino === identity.ino)
        return candidate;
    }
    let match: string | undefined;
    for (const name of names) {
      if (name.toLowerCase() === spelling.toLowerCase()) continue;
      const candidate = join(parent, name);
      const metadata = await lstat(candidate, { bigint: true }).catch(missing);
      if (metadata?.dev !== identity.dev || metadata.ino !== identity.ino)
        continue;
      if (match !== undefined) return join(parent, spelling);
      match = candidate;
    }
    if (match !== undefined) return match;
  }
  return join(parent, spelling);
}

function trimDirectorySeparators(path: string): string {
  const rootLength = parse(path).root.length;
  return (
    path.slice(0, rootLength) +
    path.slice(rootLength).replace(sep === "\\" ? /[\\/]+$/u : /\/+$/u, "")
  );
}

async function directoryLinks(path: string): Promise<string[]> {
  const links = new Set<string>();
  const inspected = new Set<string>();
  const inspect = async (path: string): Promise<void> => {
    path = trimDirectorySeparators(path);
    if (inspected.has(path)) return;
    inspected.add(path);
    // Reject filesystem loops before tracing individual links.
    await canonicalPath(path);
    for (
      let entry = path;
      dirname(entry) !== entry;
      entry = trimDirectorySeparators(dirname(entry))
    ) {
      const metadata = await lstat(entry, { bigint: true }).catch(missing);
      if (!metadata?.isSymbolicLink()) continue;
      links.add(await directoryLinkEntry(entry, metadata));
      // Link targets can contain additional directory links.
      await inspect(relativeFile(dirname(entry), await readlink(entry)));
    }
  };
  await inspect(path);
  return [...links];
}

async function readableGitParent(
  checkout: string,
  path: Buffer,
  directory: boolean,
  gitlink: boolean,
  selectsGitDirectory: (
    directory: Buffer,
    markerContents: Buffer | true,
  ) => Promise<boolean>,
): Promise<{ path: string; exact: boolean } | undefined> {
  const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  if (path.at(-1) === 47) path = path.subarray(0, -1);
  if (!directory) path = path.subarray(0, Math.max(0, path.lastIndexOf(47)));
  let exact = true;
  while (path.length > 0) {
    try {
      return { path: utf8.decode(path), exact };
    } catch {
      // Check the actual byte path; never inspect its replacement-decoded alias.
    }
    // Ordinary symlink replacements are data, including raw-byte ancestors.
    let skippedSymlink = false;
    for (let offset = 0; offset < path.length;) {
      const separator = path.indexOf(47, offset);
      const end = separator < 0 ? path.length : separator;
      const prefix = path.subarray(0, end);
      if (
        (!gitlink ||
          !exact ||
          end !== path.length ||
          process.platform !== "win32") &&
        (
          await lstat(
            Buffer.concat([Buffer.from(`${checkout}${sep}`), prefix]),
          ).catch(missing)
        )?.isSymbolicLink()
      ) {
        path = prefix.subarray(0, Math.max(0, prefix.lastIndexOf(47)));
        exact = false;
        skippedSymlink = true;
        break;
      }
      offset = end + 1;
    }
    if (skippedSymlink) continue;
    const rawCheckout = Buffer.concat([Buffer.from(`${checkout}${sep}`), path]);
    const marker = Buffer.concat([rawCheckout, Buffer.from(`${sep}.git`)]);
    const markerContents = await readGitMarker(marker);
    if (
      markerContents !== undefined &&
      (await selectsGitDirectory(rawCheckout, markerContents))
    )
      throw new Error(
        "Patch cannot safely use Git administration whose checkout path is not valid UTF-8.",
      );
    path = path.subarray(0, Math.max(0, path.lastIndexOf(47)));
    exact = false;
  }
  return undefined;
}

export async function capturePatchGitControls(
  directory: string,
  run: RunGit,
  usesWorktreeMarker: boolean,
  usesCommonDirectoryMarker = true,
  selectedGitDirectory?: string,
  configuration = {
    global: process.env["GIT_CONFIG_GLOBAL"],
    system: process.env["GIT_CONFIG_SYSTEM"],
    noSystem: process.env["GIT_CONFIG_NOSYSTEM"],
    xdgConfigHome: process.env["XDG_CONFIG_HOME"],
    objectDirectory: process.env["GIT_OBJECT_DIRECTORY"],
    alternateObjectDirectories: process.env["GIT_ALTERNATE_OBJECT_DIRECTORIES"],
  },
  automaticPublication = false,
): Promise<PatchGitControls | undefined> {
  const runBytes = async (
    root: string,
    checkout: string,
    args: string[],
    options?: PatchGitCommandOptions,
  ) =>
    Buffer.from(
      await run(root, checkout, args, { ...options, encoding: "base64" }),
      "base64",
    );
  const runControl = async (
    root: string,
    checkout: string,
    args: string[],
    options?: PatchGitCommandOptions,
  ) => controlPathText(await runBytes(root, checkout, args, options));
  // GIT_CONFIG selects a file only for git-config, not snapshot bookkeeping.
  const configurationEnvironment = { GIT_CONFIG: undefined };
  // Config records contain unrelated keys too. Split bytes before decoding paths.
  const runConfigFields = async (
    checkout: string,
    args: string[],
    input?: Uint8Array,
  ) =>
    (
      await runBytes(root, checkout, args, {
        input,
        environment: configurationEnvironment,
      })
    )
      .toString("latin1")
      .split("\0");
  const configPath = (field: string) =>
    controlPathText(Buffer.from(field, "latin1"));
  let root: string;
  try {
    const output = await runControl(directory, directory, [
      "rev-parse",
      "--show-toplevel",
    ]);
    if (output.length === 0) return undefined;
    root = await realControlPath(output.replace(/\n$/u, ""));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (
      message.includes("not a git repository") ||
      message.toLowerCase() === "git is not available on a trusted path."
    )
      return undefined;
    throw error;
  }
  const isGitDirectory = async (
    path: string,
    markerContents?: Buffer | true,
    nestedProbe = false,
  ): Promise<boolean> => {
    let administration: Buffer | undefined = Buffer.from(path);
    if (Buffer.isBuffer(markerContents)) {
      let target = markerContents.subarray(8);
      while (target.at(-1) === 10 || target.at(-1) === 13)
        target = target.subarray(0, -1);
      administration =
        target.length === 0
          ? undefined
          : isAbsolute(target.toString("latin1"))
            ? target
            : Buffer.concat([Buffer.from(`${dirname(path)}${sep}`), target]);
    }
    if (administration !== undefined) {
      for (const name of ["HEAD", "commondir"]) {
        const metadataPath = Buffer.concat([
          administration,
          Buffer.from(`${sep}${name}`),
        ]);
        const metadata = await stat(metadataPath).catch(missing);
        if (metadata && !metadata.isFile() && !metadata.isDirectory())
          throw new Error(
            `Patch cannot safely inspect non-regular Git metadata: ${metadataPath.toString("utf8")}`,
          );
      }
    }
    // Git's early gitfile reader finds relative targets using slash separators.
    const gitPath =
      process.platform === "win32" ? path.replaceAll("\\", "/") : path;
    try {
      // This early rev-parse mode only checks filesystem structure. It does not
      // select the candidate repository or load its configuration and hooks.
      await runBytes(root, root, ["rev-parse", "--resolve-git-dir", gitPath], {
        nestedProbe,
      });
      return true;
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      const failure = error as Error & {
        code?: unknown;
        status?: unknown;
        stderr?: unknown;
      };
      const diagnostic = Buffer.isBuffer(failure.stderr)
        ? failure.stderr.toString("utf8")
        : failure.stderr;
      const negatives = [
        `fatal: not a gitdir '${gitPath}'`,
        `fatal: gitfile does not point to a valid repository: ${gitPath}`,
        `fatal: no path in gitfile: ${gitPath}`,
      ];
      if (Buffer.isBuffer(markerContents)) {
        // This text is used only to recognize Git's diagnostic, never as a path
        // for filesystem access. Match the subprocess's UTF-8 error decoding.
        const configured = markerContents
          .subarray(8)
          .toString("utf8")
          .replace(/[\r\n]+$/u, "");
        const target = isAbsolute(configured)
          ? configured
          : `${gitPath.slice(0, gitPath.lastIndexOf("/") + 1)}${configured}`;
        negatives.push(`fatal: not a git repository: ${target}`);
      }
      if (
        (failure.code === 128 || failure.status === 128) &&
        typeof diagnostic === "string" &&
        negatives.some(
          (negative) =>
            diagnostic.endsWith(`${negative}\n`) ||
            diagnostic.endsWith(`${negative}\r\n`),
        )
      )
        return false;
      throw error;
    }
  };
  const rawCheckoutSelectsGit = async (
    checkout: Buffer,
    markerContents: Buffer | true,
  ): Promise<boolean> => {
    const temporary = await mkdtemp(
      join(tmpdir(), "codex-security-git-marker-"),
    );
    try {
      const alias = join(temporary, "checkout");
      // The symlink preserves byte names and relative gitfile resolution while
      // giving the native filesystem-only probe a representable argument.
      await symlink(checkout, alias);
      return await isGitDirectory(join(alias, ".git"), markerContents, true);
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  };
  const administrationRoots = new Map<string, { dev: bigint; ino: bigint }>();
  const administrationLinks = new Set<string>();
  const nestedDirectories = new Map<string, readonly string[]>();
  const rememberAdministrationReference = async (
    path: string,
  ): Promise<void> => {
    for (const link of await directoryLinks(path))
      administrationLinks.add(link);
  };
  const remember = async (path: string): Promise<void> => {
    const metadata = await stat(path, { bigint: true });
    administrationRoots.set(path, { dev: metadata.dev, ino: metadata.ino });
  };
  const controlPaths = new Map<
    string,
    {
      canonical: string;
      identity: { dev: bigint; ino: bigint } | undefined;
      directory: boolean | undefined;
      readOnly: boolean;
      allowDirectoryChanges: boolean;
      allowDirectoryCreation: boolean;
      contents: Buffer | null | undefined;
    }
  >();
  const snapshotStoragePaths = new Set<string>();
  const snapshotConfigPaths = new Set<string>();
  const modelOnlyReadOnlyPaths = new Set<string>();
  const externalCachePaths = new Set<string>();
  const inaccessibleIncludes = new Set<string>();
  const unreadableConfigurations = new Set<string>();
  const inaccessibleHooks = new Set<string>();
  const hookContents = new Map<
    string,
    Buffer | { size: bigint; mtimeNs: bigint; ctimeNs: bigint }
  >();
  const hookDirectories = new Set<string>();
  const hookIsAvailable = async (path: string): Promise<boolean> => {
    const executable = await access(path, constants.X_OK).then(
      () => true,
      () => false,
    );
    if (!executable) return false;
    const metadata = await stat(path).catch(missing);
    return metadata !== undefined && !metadata.isDirectory();
  };
  const rememberControl = async (
    path: string,
    protectDirectory = true,
    addReadPermission = true,
    allowDirectoryCreation = false,
  ): Promise<void> => {
    const canonical = await canonicalPath(path);
    const metadata = await stat(canonical, { bigint: true }).catch(missing);
    const directory = metadata?.isDirectory();
    const previous = controlPaths.get(path);
    controlPaths.set(path, {
      canonical,
      contents: previous?.contents,
      identity: metadata && { dev: metadata.dev, ino: metadata.ino },
      directory,
      readOnly:
        previous?.readOnly === true ||
        (addReadPermission && (protectDirectory || !directory)),
      allowDirectoryChanges:
        !protectDirectory && previous?.allowDirectoryChanges !== false,
      allowDirectoryCreation:
        (allowDirectoryCreation || !protectDirectory) &&
        (previous === undefined ||
          previous.allowDirectoryCreation ||
          previous.allowDirectoryChanges),
    });
  };
  const rememberConfiguration = async (
    path: string,
    protectDirectory = true,
    optional = false,
  ): Promise<void> => {
    await rememberControl(path, protectDirectory);
    const control = controlPaths.get(path)!;
    if (control.contents !== undefined) return;
    if (!(await stat(control.canonical).catch(missing))?.isFile()) return;
    try {
      control.contents = await readFile(control.canonical);
      unreadableConfigurations.delete(path);
    } catch (error) {
      if (
        optional &&
        ["EACCES", "EPERM"].includes(
          (error as NodeJS.ErrnoException).code ?? "",
        )
      ) {
        unreadableConfigurations.add(path);
        return;
      }
      throw error;
    }
  };
  const rememberSelectedConfiguration = async (
    path: string,
    optional = false,
  ): Promise<void> => {
    try {
      // Absent and empty regular inputs have no --show-origin records. Devices
      // such as /dev/null and unavailable optional inputs keep native behavior.
      const metadata = await stat(path).catch(missing);
      if (metadata === undefined) {
        await rememberControl(path, false);
        controlPaths.get(path)!.contents = null;
      } else if (metadata.isFile())
        await rememberConfiguration(path, true, optional);
    } catch (error) {
      if (
        optional &&
        ["EACCES", "EPERM"].includes(
          (error as NodeJS.ErrnoException).code ?? "",
        )
      )
        return;
      throw error;
    }
  };
  const expandConfigurationPath = async (path: string) => {
    try {
      return (
        await runControl(
          root,
          root,
          [
            "-c",
            `codexsecurity.patchcontrolpath=${path}`,
            "config",
            "--null",
            "--type=path",
            "--get",
            "codexsecurity.patchcontrolpath",
          ],
          { environment: configurationEnvironment },
        )
      ).replace(/\0$/u, "");
    } catch (error) {
      // Git omits the per-user defaults when it cannot expand HOME.
      if (
        error instanceof Error &&
        error.message.includes("failed to expand user dir")
      )
        return undefined;
      throw error;
    }
  };
  const globalConfigurationPaths: string[] = [];
  if (configuration.global !== undefined) {
    if (configuration.global !== "")
      globalConfigurationPaths.push(configuration.global);
  } else {
    for (const path of [
      configuration.xdgConfigHome
        ? `${configuration.xdgConfigHome}/git/config`
        : await expandConfigurationPath("~/.config/git/config"),
      await expandConfigurationPath("~/.gitconfig"),
    ])
      if (path !== undefined) globalConfigurationPaths.push(path);
  }
  if (configuration.system) {
    const disabled =
      configuration.noSystem === undefined
        ? "false"
        : (
            await runControl(
              root,
              root,
              [
                "-c",
                `codexsecurity.patchnosystem=${configuration.noSystem}`,
                "config",
                "--type=bool",
                "--get",
                "codexsecurity.patchnosystem",
              ],
              { environment: configurationEnvironment },
            )
          ).trim();
    if (disabled === "false")
      globalConfigurationPaths.push(configuration.system);
  }
  const insideSelectedRoots = (path: string): boolean =>
    inside(root, path) ||
    [...administrationRoots.keys()].some((administration) =>
      inside(administration, path),
    );
  // Global configuration can include a checkout-controlled file.
  const userSelectedConfig = async (
    scope: string | undefined,
    origin: string | undefined,
    checkout: string,
  ): Promise<boolean> =>
    (scope === "global" || scope === "system" || scope === "command") &&
    !(
      origin?.startsWith("file:") &&
      insideSelectedRoots(
        await canonicalPath(relativeFile(checkout, origin.slice(5))),
      )
    );
  const canPrepareStorage = async (path: string): Promise<boolean> => {
    for (const entry of await directoryLinks(path)) {
      if (administrationLinks.has(entry)) {
        await rememberControl(entry, true, false);
      } else if (insideSelectedRoots(dirname(entry))) {
        await rememberControl(entry, true, false);
        return false;
      }
    }
    return true;
  };
  const rememberHook = async (path: string): Promise<void> => {
    if (await hookIsAvailable(path)) {
      await rememberControl(path, false);
      const canonical = controlPaths.get(path)!.canonical;
      const metadata = await stat(canonical, { bigint: true });
      if (metadata.isFile()) {
        try {
          hookContents.set(path, await readFile(canonical));
        } catch (error) {
          if (
            !["EACCES", "EPERM"].includes(
              (error as NodeJS.ErrnoException).code ?? "",
            )
          )
            throw error;
          // Execute-only native hooks remain usable, but writable aliases must
          // not change them while the model controls the repository.
          hookContents.set(path, {
            size: metadata.size,
            mtimeNs: metadata.mtimeNs,
            ctimeNs: metadata.ctimeNs,
          });
        }
      }
    } else {
      // Git ignores inactive entries; reject their activation before bookkeeping.
      inaccessibleHooks.add(path);
    }
  };
  const activeHostFilters = new Set<string>();
  const branchFilterSettings = new Set<string>();
  let hasConditionalFilters = false;
  const filterCheckouts = new Set<string>();
  let checkoutCleanFilter = false;
  const activeCheckoutFilters = async (checkout: string): Promise<string[]> => {
    const entries = await runConfigFields(checkout, [
      "config",
      "--null",
      "--show-scope",
      "--show-origin",
      "--includes",
      "--get-regexp",
      "^filter\\..+\\.(clean|smudge|process)$",
    ]).catch((error: NodeJS.ErrnoException & { status?: number }) => {
      if (error.status === 1 || Number(error.code) === 1) return [];
      throw error;
    });
    const drivers = new Map<string, boolean>();
    for (let index = 0; index + 2 < entries.length; index += 3) {
      const setting = entries[index + 2]!;
      const separator = setting.indexOf("\n");
      const key = separator < 0 ? setting : setting.slice(0, separator);
      drivers.set(
        configPath(key),
        separator >= 0 &&
          separator + 1 < setting.length &&
          !(await userSelectedConfig(
            entries[index],
            configPath(entries[index + 1]!),
            checkout,
          )),
      );
    }
    return [...drivers]
      .filter(([, untrusted]) => untrusted)
      .map(([key]) => key);
  };
  const captureReferences = async (checkout: string): Promise<void> => {
    filterCheckouts.add(checkout);
    const origins = await runConfigFields(checkout, [
      "config",
      "--null",
      "--show-origin",
      "--includes",
      "--list",
      "--name-only",
    ]);
    let includes = false;
    const activeConfigurations = new Set<string>();
    for (let index = 0; index + 1 < origins.length; index += 2) {
      const origin = origins[index]!;
      if (origin.startsWith("file:")) {
        const path = relativeFile(checkout, configPath(origin.slice(5)));
        activeConfigurations.add(path);
      }
      if (/^(include|includeif\..*)\.path$/u.test(origins[index + 1]!))
        includes = true;
    }
    const captureHooks = async (configured?: string): Promise<void> => {
      let entry: string;
      try {
        entry = await runControl(root, checkout, [
          ...(configured === undefined
            ? []
            : ["-c", `core.hooksPath=${configured}`]),
          "rev-parse",
          "--git-path",
          "hooks/post-index-change",
        ]);
      } catch (error) {
        if (
          configured !== undefined &&
          error instanceof Error &&
          error.message.includes("failed to expand user dir")
        )
          return;
        throw error;
      }
      // A complete entry preserves Git's empty hooksPath semantics.
      const hooks = relativeFile(checkout, dirname(entry.replace(/\n$/u, "")));
      hookDirectories.add(hooks);
      // Bind absent entries too, while leaving ordinary directory contents editable.
      for (const hook of GIT_HOOKS)
        await rememberHook(relativeFile(hooks, hook));
    };
    const inspectedIncludes = new Set<string>();
    const captureInclude = async (
      relativeTo: string,
      value: string,
      optional: boolean,
      userSelected: boolean,
    ): Promise<void> => {
      let path = configPath(value);
      if (path.length === 0) return;
      try {
        // Expand each value with Git without expanding inactive values as a group.
        path = (
          await runControl(
            root,
            checkout,
            [
              "-c",
              `codexsecurity.patchcontrolpath=${path}`,
              "config",
              "--null",
              "--type=path",
              "--get",
              "codexsecurity.patchcontrolpath",
            ],
            { environment: configurationEnvironment },
          )
        ).replace(/\0$/u, "");
      } catch (error) {
        // Active includes already passed Git's normal --includes read above.
        if (
          optional &&
          error instanceof Error &&
          error.message.includes("failed to expand user dir")
        )
          return;
        throw error;
      }
      const includePath = relativeFile(relativeTo, path);
      try {
        if (
          !insideSelectedRoots(await canonicalPath(includePath)) &&
          (!userSelected ||
            (await directoryLinks(includePath)).some((link) =>
              insideSelectedRoots(dirname(link)),
            ))
        )
          throw new Error(
            `Checkout requested ${optional ? "a conditional" : "an active"} include outside the selected Git roots: ${includePath}`,
          );
        await rememberConfiguration(includePath, !optional, optional);
      } catch (error) {
        // Active includes already passed Git's normal --includes read above.
        if (
          optional &&
          ["EACCES", "ELOOP"].includes(
            (error as NodeJS.ErrnoException).code ?? "",
          )
        ) {
          inaccessibleIncludes.add(includePath);
          return;
        }
        throw error;
      }
      if (!optional) return;
      const control = controlPaths.get(includePath)!;
      if (!Buffer.isBuffer(control.contents)) return;
      const origin = dirname(includePath);
      const identity = `${control.canonical}\0${await canonicalPath(origin)}`;
      if (inspectedIncludes.has(identity)) return;
      inspectedIncludes.add(identity);
      let entries: string[];
      try {
        // Parse captured bytes without activating dormant includes or their errors.
        entries = await runConfigFields(
          checkout,
          ["config", "--file", "-", "--no-includes", "--null", "--list"],
          control.contents,
        );
      } catch (error) {
        if (error instanceof Error && error.message.includes("bad config line"))
          return;
        throw error;
      }
      for (const entry of entries) {
        const separator = entry.indexOf("\n");
        const key = entry.slice(0, separator);
        const value = entry.slice(separator + 1);
        if (
          automaticPublication &&
          value &&
          /^filter\..+\.(clean|smudge|process)$/u.test(key)
        ) {
          hasConditionalFilters = true;
          if (!userSelected || insideSelectedRoots(control.canonical))
            branchFilterSettings.add(configPath(key));
        }
        if (key === "core.hookspath") await captureHooks(configPath(value));
        else if (/^(include|includeif\..*)\.path$/u.test(key))
          await captureInclude(
            origin,
            value,
            true,
            userSelected && !insideSelectedRoots(control.canonical),
          );
      }
    };
    if (includes) {
      const paths = await runConfigFields(checkout, [
        "config",
        "--null",
        "--show-scope",
        "--show-origin",
        "--includes",
        "--get-regexp",
        "^(include|includeif\\..*)\\.path$",
      ]);
      for (let index = 0; index + 2 < paths.length; index += 3) {
        const scope = paths[index]!;
        const origin = paths[index + 1]!;
        const value = paths[index + 2]!;
        const separator = value.indexOf("\n");
        const key = value.slice(0, separator);
        const relativeTo = origin.startsWith("file:")
          ? dirname(relativeFile(checkout, configPath(origin.slice(5))))
          : checkout;
        await captureInclude(
          relativeTo,
          value.slice(separator + 1),
          key.startsWith("includeif."),
          await userSelectedConfig(scope, origin, checkout),
        );
      }
    }
    for (const path of activeConfigurations) await rememberConfiguration(path);
    if (
      automaticPublication &&
      origins.some(
        (key, index) =>
          index % 2 === 1 && /^filter\..+\.(clean|smudge|process)$/u.test(key),
      )
    ) {
      for (const key of await activeCheckoutFilters(checkout)) {
        activeHostFilters.add(key);
        if (!key.endsWith(".smudge")) checkoutCleanFilter = true;
      }
    }
    for (const path of globalConfigurationPaths) {
      const selected = relativeFile(checkout, path);
      await rememberSelectedConfiguration(selected, true);
      activeConfigurations.add(selected);
    }
    for (const path of activeConfigurations) {
      const control = controlPaths.get(path);
      if (control && Buffer.isBuffer(control.contents))
        snapshotConfigPaths.add(control.canonical);
    }
    const localConfig = (
      await runControl(root, checkout, [
        "rev-parse",
        "--path-format=absolute",
        "--git-path",
        "config",
      ])
    ).replace(/\n$/u, "");
    await rememberSelectedConfiguration(localConfig);
    let worktreeConfig = false;
    try {
      worktreeConfig =
        (
          await runControl(
            root,
            checkout,
            [
              "config",
              "--local",
              "--no-includes",
              "--type=bool",
              "--get",
              "extensions.worktreeConfig",
            ],
            { environment: configurationEnvironment },
          )
        ).trim() === "true";
    } catch (error) {
      const failure = error as { code?: unknown; status?: unknown };
      if ((failure.code ?? failure.status) !== 1) throw error;
    }
    if (worktreeConfig) {
      const path = (
        await runControl(root, checkout, [
          "rev-parse",
          "--path-format=absolute",
          "--git-path",
          "config.worktree",
        ])
      ).replace(/\n$/u, "");
      await rememberSelectedConfiguration(path);
    }
    await captureHooks();
  };
  const selectedPaths: string[] = [];
  for (const argument of ["--absolute-git-dir", "--git-common-dir"]) {
    const output = await runControl(root, root, [
      "rev-parse",
      "--path-format=absolute",
      argument,
    ]);
    selectedPaths.push(output.replace(/\n$/u, ""));
  }
  const selectedDirectories = await Promise.all(
    selectedPaths.map(realControlPath),
  );
  const gitDirectory = selectedDirectories[0]!;
  const commonDirectory = selectedDirectories[1]!;
  // A checkout's core.worktree can change Git's reported top-level directory.
  // Anchor implicit metadata to the checkout selected by the caller.
  const requestedDirectory = await realControlPath(directory);
  const gitDirectorySelected =
    !usesWorktreeMarker ||
    (!usesCommonDirectoryMarker &&
      relative(gitDirectory, commonDirectory) === "");
  const commonDirectorySelected =
    !usesCommonDirectoryMarker ||
    (!usesWorktreeMarker && inside(gitDirectory, commonDirectory));
  let markerRoot =
    (gitDirectorySelected || inside(requestedDirectory, gitDirectory)) &&
    (commonDirectorySelected || inside(requestedDirectory, commonDirectory))
      ? null
      : await gitMarkerRoot(requestedDirectory, undefined, "nearest");
  // Git skips an empty .git directory when searching upward from a component.
  while (markerRoot !== null && markerRoot !== root) {
    const marker = join(markerRoot, ".git");
    const contents = await readGitMarker(marker);
    if (
      contents !== undefined &&
      (await isGitDirectory(marker, contents, true))
    )
      break;
    const parent = dirname(markerRoot);
    markerRoot =
      parent === markerRoot
        ? null
        : await gitMarkerRoot(parent, undefined, "nearest");
  }
  const checkout = usesWorktreeMarker
    ? (markerRoot ?? requestedDirectory)
    : requestedDirectory;
  const trustedGitDirectory =
    gitDirectorySelected || inside(checkout, gitDirectory);
  const trustedCommonDirectory =
    commonDirectorySelected || inside(checkout, commonDirectory);
  const validateRegistration = async () => {
    if (
      (!trustedGitDirectory || !trustedCommonDirectory) &&
      (markerRoot === null ||
        !(await isRegisteredLinkedWorktree(markerRoot, selectedDirectories)) ||
        (await selectedGitFileReference(
          join(markerRoot, ".git"),
          gitDirectory,
        )) === undefined)
    ) {
      throw new Error(
        "External Git administration requires an explicitly selected Git directory or a registered worktree. Set GIT_DIR or GIT_COMMON_DIR to the intended directory.",
      );
    }
  };
  await validateRegistration();
  for (const [index, path] of selectedDirectories.entries()) {
    await remember(path);
    for (const link of await directoryLinks(selectedPaths[index]!))
      administrationLinks.add(link);
  }
  const selectedCommonDirectory = usesCommonDirectoryMarker
    ? undefined
    : selectedDirectories[1];
  for (const argument of [
    ...(usesWorktreeMarker ? [] : ["--git-dir"]),
    ...(usesCommonDirectoryMarker ? [] : ["--git-common-dir"]),
  ]) {
    const path = relativeFile(
      root,
      (await runControl(root, root, ["rev-parse", argument])).replace(
        /\n$/u,
        "",
      ),
    );
    await rememberControl(path);
    for (const link of await directoryLinks(path))
      administrationLinks.add(link);
  }
  const selectedMarker = usesWorktreeMarker
    ? await markerDirectories(
        root,
        isGitDirectory,
        selectedCommonDirectory,
        rememberAdministrationReference,
      )
    : undefined;
  if (!usesWorktreeMarker && selectedGitDirectory !== undefined) {
    const reference = await selectedGitFileReference(
      selectedGitDirectory,
      selectedDirectories[0]!,
    );
    if (reference !== undefined)
      await rememberAdministrationReference(reference);
  }
  if (!usesWorktreeMarker && usesCommonDirectoryMarker)
    await readCommonDirectory(
      selectedDirectories[0]!,
      rememberAdministrationReference,
    );
  if (selectedMarker !== undefined)
    for (const link of await directoryLinks(join(root, ".git")))
      administrationLinks.add(link);
  const discover = async (capture: boolean): Promise<void> => {
    const pendingStoragePaths: { path: string; userSelected: boolean }[] = [];
    const protectedRoots = capture
      ? []
      : (
          await Promise.all(
            [...administrationRoots].map(async ([path, identity]) => {
              const metadata = await stat(path, { bigint: true }).catch(
                missing,
              );
              return metadata?.dev === identity.dev &&
                metadata.ino === identity.ino
                ? path
                : undefined;
            }),
          )
        ).filter((path): path is string => path !== undefined);
    if (!capture) {
      for (const path of inaccessibleHooks) {
        if (await hookIsAvailable(path))
          throw new Error(
            `Git hook became accessible during the patch: ${path}`,
          );
      }
      for (const path of inaccessibleIncludes) {
        try {
          const canonical = await canonicalPath(path);
          const metadata = await stat(canonical).catch(missing);
          if (metadata === undefined || metadata.isDirectory()) continue;
        } catch (error) {
          if (
            ["EACCES", "ELOOP"].includes(
              (error as NodeJS.ErrnoException).code ?? "",
            )
          )
            continue;
          throw error;
        }
        throw new Error(
          `Git conditional include became accessible during the patch: ${path}`,
        );
      }
      for (const [path, expected] of controlPaths) {
        const canonical = await canonicalPath(path);
        const metadata = await stat(canonical, { bigint: true }).catch(missing);
        // An absent entry or directory cannot supply hook/configuration bytes.
        // Keep file activation and overlapping configuration roles bound.
        if (
          expected.allowDirectoryChanges &&
          (expected.identity === undefined || expected.directory === true) &&
          (metadata === undefined || metadata.isDirectory())
        )
          continue;
        if (
          canonical === expected.canonical &&
          expected.allowDirectoryCreation &&
          expected.identity === undefined &&
          metadata?.isDirectory()
        ) {
          expected.identity = { dev: metadata.dev, ino: metadata.ino };
          expected.directory = true;
          expected.allowDirectoryCreation = false;
        }
        if (
          canonical !== expected.canonical ||
          (![...administrationRoots.keys()].some((root) =>
            inside(root, expected.canonical),
          ) &&
            (metadata?.dev !== expected.identity?.dev ||
              metadata?.ino !== expected.identity?.ino ||
              metadata?.isDirectory() !== expected.directory))
        )
          throw new Error(
            `Git configuration or hooks changed location during the patch: ${path}`,
          );
        const hook = hookContents.get(path);
        if (
          hook !== undefined &&
          (!metadata?.isFile() ||
            !(await hookIsAvailable(path)) ||
            (Buffer.isBuffer(hook)
              ? !(await readFile(canonical)).equals(hook)
              : metadata.size !== hook.size ||
                metadata.mtimeNs !== hook.mtimeNs ||
                metadata.ctimeNs !== hook.ctimeNs))
        )
          throw new Error(`Git hook changed during the patch: ${path}`);
        if (unreadableConfigurations.has(path)) {
          try {
            await readFile(canonical);
          } catch (error) {
            if (
              ["EACCES", "EPERM"].includes(
                (error as NodeJS.ErrnoException).code ?? "",
              )
            )
              continue;
            throw error;
          }
          throw new Error(
            `Git configuration became readable during the patch: ${path}`,
          );
        }
        if (
          expected.contents === null
            ? metadata !== undefined && !metadata.isDirectory()
            : expected.contents !== undefined &&
              (!metadata?.isFile() ||
                !(await readFile(canonical)).equals(expected.contents))
        )
          throw new Error(
            `Git configuration changed during the patch: ${path}`,
          );
      }
      const marker =
        selectedMarker === undefined
          ? undefined
          : await markerDirectories(
              root,
              isGitDirectory,
              selectedCommonDirectory,
            );
      if (
        selectedDirectories.some((path) => !protectedRoots.includes(path)) ||
        (selectedMarker !== undefined &&
          (marker === undefined ||
            marker.length !== selectedMarker.length ||
            marker.some((path, index) => path !== selectedMarker[index])))
      ) {
        throw new Error(
          "Selected Git administration changed during the patch. Inspect the checkout before retrying.",
        );
      }
      await validateRegistration();
    }
    const visited = new Set<string>();
    const visit = async (checkout: string): Promise<void> => {
      const canonical = await realControlPath(checkout);
      if (!inside(root, canonical))
        throw new Error(
          "Nested Git checkout resolves outside the selected repository.",
        );
      if (visited.has(canonical)) return;
      let naturalWorktree = true;
      let commonDirectory = selectedDirectories[1]!;
      if (canonical !== root) {
        const directories = await markerDirectories(
          checkout,
          (path, contents) => isGitDirectory(path, contents, true),
          undefined,
          capture ? rememberAdministrationReference : undefined,
        );
        if (directories === undefined) return;
        commonDirectory = directories.at(-1)!;
        const previous = nestedDirectories.get(canonical);
        if (
          !capture &&
          previous !== undefined &&
          (directories.length !== previous.length ||
            directories.some((path, index) => path !== previous[index]))
        )
          throw new Error(
            `Nested Git administration changed during the patch: ${checkout}`,
          );
        if (
          !capture &&
          directories.some(
            (path) => !protectedRoots.some((root) => inside(root, path)),
          )
        )
          throw new Error(
            `Patch selected Git metadata outside the pre-patch administration directories: ${checkout}`,
          );
        if (
          directories.some(
            (path) =>
              !inside(root, path) &&
              !selectedDirectories.some((selected) => inside(selected, path)),
          ) &&
          !(await isRegisteredLinkedWorktree(canonical, directories))
        )
          throw new Error(
            `Nested Git administration is outside the selected repository and its registered worktrees: ${checkout}`,
          );
        if (capture) {
          nestedDirectories.set(canonical, directories);
          for (const path of directories) await remember(path);
          for (const link of await directoryLinks(join(checkout, ".git")))
            administrationLinks.add(link);
        }
        const config = join(directories.at(-1)!, "config");
        if ((await stat(config).catch(missing))?.isFIFO())
          throw new Error(
            `Patch cannot safely inspect non-regular Git metadata: ${config}`,
          );
        let worktree: string | undefined;
        try {
          worktree = await realControlPath(
            (
              await runControl(root, checkout, ["rev-parse", "--show-toplevel"])
            ).replace(/\n$/u, ""),
          );
        } catch (error) {
          if (!hasNoWorktree(error)) throw error;
          naturalWorktree = false;
        }
        if (worktree !== undefined && relative(canonical, worktree) !== "")
          throw new Error(
            "Git's worktree root does not match the selected checkout's .git marker. Select the intended checkout explicitly or fix its Git configuration.",
          );
      }
      if (canonical === root && configuration.objectDirectory !== undefined) {
        if (capture)
          await rememberControl(
            relativeFile(root, configuration.objectDirectory),
            true,
            false,
          );
      } else {
        const objects = await canonicalPath(join(commonDirectory, "objects"));
        if (
          !inside(commonDirectory, objects) &&
          !selectedDirectories.some((selected) => inside(selected, objects))
        )
          throw new Error(
            `Git object storage resolves outside the selected Git administration: ${checkout}`,
          );
      }
      if (capture) {
        await captureReferences(checkout);
        const [common, storage] = await Promise.all([
          runControl(root, checkout, [
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
          ]),
          // Git LFS reads the selected config with includes enabled.
          runControl(root, checkout, [
            "config",
            "--includes",
            "--null",
            "--show-scope",
            "--show-origin",
            "--default=lfs",
            "--get",
            "lfs.storage",
          ]).catch((error: unknown) => {
            const failure = error as Error & {
              code?: unknown;
              status?: unknown;
              signal?: unknown;
              killed?: boolean;
            };
            // Git LFS discards failed config reads, including partial output,
            // and uses the default cache after reporting its warning.
            if (
              error instanceof Error &&
              failure.name !== "AbortError" &&
              !failure.signal &&
              !failure.killed &&
              (failure.code === 128 || failure.status === 128)
            )
              return "";
            throw error;
          }),
        ]);
        const [scope, origin, value] = storage.split("\0");
        const configured = value || "lfs";
        const absolute =
          isAbsolute(configured) &&
          (process.platform !== "win32" || parse(configured).root.length > 1);
        const lfs = absolute
          ? configured
          : join(common.replace(/\n$/u, ""), configured);
        const userSelected = await userSelectedConfig(scope, origin, checkout);
        pendingStoragePaths.push({ path: lfs, userSelected });
      }
      let tracked: Buffer;
      let untracked: Buffer;
      let deleted: Buffer;
      try {
        [tracked, untracked, deleted] = await withPatchGitIndex(
          (args, options) =>
            run(
              root,
              checkout,
              [
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                ...args,
              ],
              options,
            ),
          async (indexed) => {
            const outputs = await Promise.all([
              indexed(
                ["ls-files", "--cached", "--stage", "--full-name", "-z"],
                {
                  encoding: "base64",
                },
              ),
              indexed(
                [
                  "ls-files",
                  "--others",
                  "--exclude-standard",
                  "--full-name",
                  "-z",
                ],
                {
                  encoding: "base64",
                },
              ),
              indexed(["ls-files", "--deleted", "--full-name", "-z"], {
                encoding: "base64",
              }),
            ]);
            return outputs.map((output) => Buffer.from(output, "base64")) as [
              Buffer,
              Buffer,
              Buffer,
            ];
          },
        );
      } catch (error) {
        if (!naturalWorktree && hasNoWorktree(error)) return;
        throw error;
      }
      visited.add(canonical);
      const candidates = new Map<
        string,
        { gitlink: boolean; selected: boolean }
      >();
      const add = async (
        path: string,
        directory: boolean,
        gitlink: boolean,
        inspectAncestors = false,
      ): Promise<void> => {
        const readable = await readableGitParent(
          checkout,
          Buffer.from(path, "latin1"),
          directory,
          gitlink,
          rawCheckoutSelectsGit,
        );
        if (readable === undefined) return;
        let candidate = resolve(checkout, readable.path);
        gitlink &&= readable.exact;
        while (candidate !== checkout && inside(checkout, candidate)) {
          const previous = candidates.get(candidate);
          candidates.set(candidate, {
            gitlink: (previous?.gitlink ?? false) || gitlink,
            selected:
              (previous?.selected ?? false) ||
              readable.exact ||
              inspectAncestors,
          });
          gitlink = false;
          readable.exact = false;
          candidate = dirname(candidate);
        }
      };
      for (const entry of tracked
        .toString("latin1")
        .split("\0")
        .filter(Boolean)) {
        // A tracked file can become a directory without appearing as deleted.
        await add(
          entry.slice(entry.indexOf("\t") + 1),
          true,
          entry.startsWith("160000 "),
        );
      }
      // Git can replace a directory's deleted tracked files with a gitlink.
      for (const path of deleted.toString("latin1").split("\0").filter(Boolean))
        await add(path, false, false, true);
      for (const path of untracked
        .toString("latin1")
        .split("\0")
        .filter(Boolean))
        if (path.endsWith("/")) await add(path, true, false);
      const symlinkedAncestors: string[] = [];
      for (const [candidate, { gitlink, selected }] of [...candidates].sort(
        ([a], [b]) => a.length - b.length,
      )) {
        if (symlinkedAncestors.some((ancestor) => inside(ancestor, candidate)))
          continue;
        // Git for Windows follows directory junctions as directories.
        if (
          (!gitlink || process.platform !== "win32") &&
          (await lstat(candidate).catch(missing))?.isSymbolicLink()
        ) {
          symlinkedAncestors.push(candidate);
          continue;
        }
        if (
          [...visited].some(
            (path) =>
              path !== canonical &&
              inside(canonical, path) &&
              inside(path, candidate),
          )
        )
          continue;
        if (
          selected &&
          (await lstat(join(candidate, ".git")).catch(missing)) !== undefined
        )
          await visit(candidate);
      }
    };
    await visit(root);
    if (capture && checkoutCleanFilter) {
      // Inspect the original checkout before status or add can invoke a filter.
      const passive = [
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.ignoreStat=false",
        "-c",
        "core.trustctime=true",
        "-c",
        "core.checkStat=default",
      ];
      for (const key of activeHostFilters)
        passive.push(
          "-c",
          `${key}=`,
          "-c",
          `${key.slice(0, key.lastIndexOf("."))}.required=false`,
        );
      for (const checkout of visited) {
        const local = await runBytes(root, checkout, [
          ...passive,
          "ls-files",
          "--others",
          "--directory",
          "--no-empty-directory",
          "-z",
        ]);
        const error =
          "Cannot automatically publish from a checkout with local-only files or tracked edits and a checkout-selected Git filter. Run patch without --create-pr and review the changes before publishing.";
        if (local.length) throw new Error(error);
        // Git normally skips these paths when it compares the worktree to the index.
        const entries = await runBytes(root, checkout, [
          ...passive,
          "ls-files",
          "-v",
          "-z",
        ]);
        if (/(?:^|\0)[a-zS] /u.test(entries.toString("latin1")))
          throw new Error(error);
        // The index may itself contain private edits. Check it separately even when
        // the worktree exactly matches those staged bytes. Visit gitlinks below
        // their own root rather than letting Git invoke a nested status command.
        for (const comparison of [["diff", "--cached"], ["diff-files"]]) {
          const changed = await runBytes(root, checkout, [
            ...passive,
            ...comparison,
            "--name-only",
            "-z",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            "--ignore-submodules=dirty",
            "--",
          ]);
          if (changed.length) throw new Error(error);
        }
      }
    }
    for (const { path, userSelected } of pendingStoragePaths) {
      try {
        const children = [join(path, "objects"), join(path, "tmp")];
        const canonical = await canonicalPath(path);
        const protectsAdministration = [...administrationRoots.keys()].some(
          (administration) => inside(canonical, administration),
        );
        let prepare =
          !protectsAdministration &&
          (userSelected || insideSelectedRoots(canonical));
        for (const candidate of [path, ...children])
          if (!(await canPrepareStorage(candidate))) prepare = false;
        if (!prepare) {
          // A non-directory ancestor makes both cache children unavailable.
          let ancestor = canonical;
          let metadata = await stat(ancestor).catch(missing);
          while (metadata === undefined && dirname(ancestor) !== ancestor) {
            ancestor = dirname(ancestor);
            metadata = await stat(ancestor).catch(missing);
          }
          if (!metadata?.isDirectory()) continue;
          // Keep model write restrictions and let snapshots inherit host access.
          for (const child of children) {
            await rememberControl(child, true, false, true);
            const target = controlPaths.get(child)!.canonical;
            if (insideSelectedRoots(target)) modelOnlyReadOnlyPaths.add(target);
            else externalCachePaths.add(target);
          }
          continue;
        }
        // Git LFS renames from tmp into objects. Separate writable bindings
        // create distinct mounts on Linux and make that rename fail with EXDEV.
        // Keep both directories on the same binding, preserving narrower Git
        // control exclusions already captured within the cache.
        for (const child of children) {
          await mkdir(child, { recursive: true });
          await rememberControl(child, true, false);
          const target = controlPaths.get(child)!.canonical;
          modelOnlyReadOnlyPaths.add(target);
          if (!inside(canonical, target)) {
            if (!userSelected || insideSelectedRoots(canonical))
              throw new Error(
                `Git LFS storage left the selected cache: ${child}`,
              );
            await rememberControl(child);
            snapshotStoragePaths.add(target);
          }
        }
        await rememberControl(path);
        snapshotStoragePaths.add(canonical);
      } catch (error) {
        // Unavailable optional storage gets no extra snapshot permission.
        // Git/LFS reports the failure if a snapshot actually uses it.
        if (
          !["EACCES", "EPERM", "EROFS", "ENOTDIR"].includes(
            (error as NodeJS.ErrnoException).code ?? "",
          )
        )
          throw error;
      }
    }
  };
  await discover(true);
  const snapshotControlPaths: string[] = [];
  for (const [path, control] of controlPaths) {
    if (!control.readOnly) continue;
    for (const link of await directoryLinks(path))
      if ([...snapshotStoragePaths].some((storage) => inside(storage, link)))
        snapshotControlPaths.push(link);
  }
  const snapshotControlLocation = async (path: string): Promise<string> => {
    let ancestor = path;
    for (;;) {
      try {
        const canonical = `${await canonicalPath(ancestor)}${path.slice(ancestor.length)}`;
        for (const link of await directoryLinks(ancestor))
          if (
            [...snapshotStoragePaths].some((storage) => inside(storage, link))
          )
            snapshotControlPaths.push(link);
        return canonical;
      } catch (error) {
        // Locate opaque control paths without resolving their entries. The
        // native sandbox must enforce the literal exclusions or reject them.
        if (
          !["EACCES", "ELOOP"].includes(
            (error as NodeJS.ErrnoException).code ?? "",
          )
        )
          throw error;
        const parent = dirname(ancestor);
        if (parent === ancestor) throw error;
        ancestor = parent;
      }
    }
  };
  for (const path of inaccessibleIncludes) {
    const canonical = await snapshotControlLocation(path);
    if ([...snapshotStoragePaths].some((storage) => inside(storage, canonical)))
      snapshotControlPaths.push(canonical);
  }
  for (const directory of hookDirectories) {
    const canonical = await snapshotControlLocation(directory);
    if ([...snapshotStoragePaths].some((storage) => inside(storage, canonical)))
      for (const hook of GIT_HOOKS)
        snapshotControlPaths.push(relativeFile(canonical, hook));
  }
  const alternateObjectDirectories: string[] = [];
  for (let bytes of gitAlternatePathBytes(
    Buffer.from(configuration.alternateObjectDirectories ?? ""),
    delimiter,
  )) {
    const nul = bytes.indexOf(0);
    if (nul !== -1) bytes = bytes.subarray(0, nul);
    if (bytes.length === 0) continue;
    let selected: string;
    try {
      selected = new TextDecoder("utf-8", {
        fatal: true,
        ignoreBOM: true,
      }).decode(bytes);
    } catch {
      // Permission paths require UTF-8; keep the original Git binding unchanged.
      continue;
    }
    let resolved: Buffer;
    try {
      resolved = await runBytes(
        root,
        root,
        ["rev-parse", "--path-format=absolute", "--git-path", "objects"],
        { environment: { GIT_OBJECT_DIRECTORY: selected } },
      );
    } catch (error) {
      const failure = error as Error & { code?: unknown; status?: unknown };
      // An unavailable primary object directory fails repository discovery;
      // the original alternate binding still lets Git report or ignore it.
      if (
        (failure.code ?? failure.status) === 128 &&
        failure.message.includes("fatal: not a git repository")
      )
        continue;
      throw error;
    }
    let path: string;
    try {
      path = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })
        .decode(resolved)
        .replace(/\n$/u, "");
    } catch {
      continue;
    }
    if ((await stat(path).catch(missing))?.isDirectory())
      alternateObjectDirectories.push(path);
  }
  return {
    readOnlyPaths: [
      ...new Set([
        ...alternateObjectDirectories,
        ...administrationRoots.keys(),
        ...snapshotControlPaths,
        ...[...controlPaths.values()]
          .filter(
            ({ canonical, identity, readOnly }) =>
              readOnly &&
              (identity !== undefined ||
                [...snapshotStoragePaths].some((storage) =>
                  inside(storage, canonical),
                )),
          )
          .map(({ canonical }) => canonical),
      ]),
    ],
    modelOnlyReadOnlyPaths: [...modelOnlyReadOnlyPaths],
    externalCachePaths: [...externalCachePaths],
    snapshotStoragePaths: [...snapshotStoragePaths],
    snapshotConfigPaths: [...snapshotConfigPaths],
    async hostFilterSettings(switchingBranch) {
      if (!hasConditionalFilters) return [...activeHostFilters];
      // Switching can activate a conditional config before Git calls post-checkout.
      if (switchingBranch)
        return [...new Set([...activeHostFilters, ...branchFilterSettings])];
      // Once HEAD is bound, use Git's actual config order so operator overrides survive.
      return [
        ...new Set(
          (
            await Promise.all([...filterCheckouts].map(activeCheckoutFilters))
          ).flat(),
        ),
      ];
    },
    validate: () => discover(false),
  };
}
