import { constants } from "node:fs";
import { lstat, open, readlink, realpath, stat } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import { buffer } from "node:stream/consumers";
import { environmentEntry } from "./auth.js";
import { abortReason } from "./errors.js";
import { nullIfUnavailableInputRoot } from "./prompt-files.js";
import { canonicalConfigPath } from "./runtime.js";
import { isWithin } from "./trusted-executable.js";
import {
  abortable,
  gitMarkerRoot,
  gitProtectionRoots,
  nullIfMissingPath,
} from "./targets.js";

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

async function readMetadataText(
  path: string,
  signal?: AbortSignal,
  format?: "gitfile" | "HEAD",
): Promise<string | undefined> {
  const selected = await abortable(
    () => stat(path).catch(nullIfMissingPath),
    signal,
  );
  if (!selected?.isFile()) return undefined;
  const file = await open(
    path,
    constants.O_RDONLY |
      (constants.O_NONBLOCK ?? 0) |
      (format === "HEAD" ? (constants.O_NOFOLLOW ?? 0) : 0),
  );
  try {
    const metadata = await abortable(() => file.stat(), signal);
    if (!metadata.isFile()) return undefined;
    if (format === undefined)
      return await file.readFile({ encoding: "utf8", signal });
    // Match Git's 1 MiB gitfile limit and its 255-byte HEAD prefix.
    if (format === "gitfile" && metadata.size > 1024 * 1024) return undefined;
    const length = format === "HEAD" ? 255 : metadata.size;
    if (!length) return "";
    const bytes = await buffer(
      file.createReadStream({ end: length - 1, signal }),
    );
    return bytes.toString("utf8");
  } finally {
    await file.close();
  }
}

async function metadataPointer(
  path: string,
  prefix: string,
  context: { directory: string; environment: NodeJS.ProcessEnv },
  signal?: AbortSignal,
  format?: "gitfile",
): Promise<{ path: string; canonical: string } | undefined> {
  const text = await readMetadataText(path, signal, format);
  if (text === undefined) return undefined;
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
  const canonical = await abortable(
    () => realpath(target).catch(nullIfMissingPath),
    signal,
  );
  return canonical === null ? undefined : { path: target, canonical };
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
    ? (await metadataPointer(commonMarker, "", context, signal))?.canonical
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

async function metadataDirectory(
  entry: string,
  directory: boolean,
  signal?: AbortSignal,
) {
  if (directory) return realpath(entry);
  const context = { directory: dirname(entry), environment: process.env };
  return (await metadataPointer(entry, "gitdir: ", context, signal, "gitfile"))
    ?.canonical;
}

async function gitSourceStorage(
  entry: string,
  directory: boolean,
  signal?: AbortSignal,
): Promise<string[]> {
  const target = await metadataDirectory(entry, directory, signal);
  if (target === undefined) return [];
  const head = join(target, "HEAD");
  const metadata = await lstat(head).catch(nullIfMissingPath);
  if (metadata?.isSymbolicLink()) {
    if (!(await readlink(head)).startsWith("refs/")) return [];
  } else {
    const text = await readMetadataText(head, signal, "HEAD");
    if (!text || !/^(?:ref:[ \t\r\n]*refs\/|[0-9a-fA-F]{40})/u.test(text))
      return [];
  }
  const context = { directory: dirname(entry), environment: process.env };
  return associatedMetadataRoots(target, context, signal, context.directory);
}

/** Match the local upload-pack source and its document boundaries before workers fetch it. */
export async function localGitSourceRoots(
  repository: string,
  signal?: AbortSignal,
): Promise<string[]> {
  const suffixed = repository + ".git";
  for (const entry of [
    join(repository, ".git"),
    repository,
    join(suffixed, ".git"),
    suffixed,
  ]) {
    signal?.throwIfAborted();
    const metadata = await stat(entry).catch(nullIfUnavailableInputRoot);
    if (!metadata || (!metadata.isDirectory() && !metadata.isFile())) continue;
    const storage = await gitSourceStorage(
      entry,
      metadata.isDirectory(),
      signal,
    ).catch(nullIfUnavailableInputRoot);
    const target = storage?.[0];
    if (storage && target)
      return worktreeDocumentRoots(entry, target, storage, signal);
    // A regular file (including a bundle) ends Git's search and owns no directories.
    if (metadata.isFile()) return [];
  }
  return [];
}

async function worktreeDocumentRoots(
  entry: string,
  target: string,
  storage: readonly string[],
  signal?: AbortSignal,
) {
  const common = storage[1];
  const candidates = new Set<string>();
  const physical = await realpath(entry);
  for (const parent of new Set([
    dirname(entry),
    dirname(physical),
    dirname(target),
  ])) {
    const checkout = await gitMarkerRoot(parent, signal, "nearest").catch(
      nullIfUnavailableInputRoot,
    );
    if (checkout !== null) candidates.add(checkout);
  }
  // A worktree registered in the common directory records its own .git marker.
  if (
    common &&
    dirname(target) ===
      (await realpath(join(common, "worktrees")).catch(
        nullIfUnavailableInputRoot,
      ))
  ) {
    const backlink = await metadataPointer(
      join(target, "gitdir"),
      "",
      { directory: target, environment: process.env },
      signal,
    ).catch(nullIfUnavailableInputRoot);
    if (backlink) {
      const parent = await realpath(dirname(backlink.path)).catch(
        nullIfUnavailableInputRoot,
      );
      if (
        parent &&
        backlink.canonical ===
          (await realpath(join(parent, ".git")).catch(
            nullIfUnavailableInputRoot,
          ))
      )
        candidates.add(parent);
    }
  }
  const owners: string[] = [];
  for (const candidate of candidates) {
    const marker = join(candidate, ".git");
    const metadata = await stat(marker).catch(nullIfUnavailableInputRoot);
    if (
      metadata &&
      (await metadataDirectory(marker, metadata.isDirectory(), signal).catch(
        nullIfUnavailableInputRoot,
      )) === target
    )
      owners.push(candidate);
  }
  const roots = [...new Set([...owners, ...storage])];
  // A worktree retains its own link boundary even when it lives inside Git storage.
  return roots.filter(
    (root) =>
      owners.includes(root) ||
      !roots.some((other) => other !== root && isWithin(other, root)),
  );
}

export async function localGitProtectionRoots(
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
          : (await metadataPointer(marker, "gitdir: ", context, signal))
              ?.canonical;
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

/** Discover Git metadata for the selection, then for the current working directory. */
export async function commandGitProtectionRoots(
  repository: string,
  environment: NodeJS.ProcessEnv,
  signal?: AbortSignal,
  cwd = process.cwd(),
): Promise<string[]> {
  const roots = await localGitProtectionRoots(repository, environment, signal);
  if (signal?.aborted) throw abortReason(signal);
  if (cwd !== repository)
    roots.push(...(await localGitProtectionRoots(cwd, environment, signal)));
  return roots;
}

export async function hasGitMetadata(
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
