import { statSync } from "node:fs";
import { lstat, readFile, realpath, stat } from "node:fs/promises";
import { dirname, isAbsolute, join, parse, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { DeepScanNonRetryableError } from "./errors.js";

export const CODEX_SANDBOX_STATE_META_CAPABILITY = "codex/sandbox-state-meta";

export type DeepWorkerParentSandbox = {
  /** Validated path and glob keys preserved in every worker profile. */
  readonly filesystemDenies: readonly string[];
  readonly globScanMaxDepth?: number;
  /** Concrete parent rules used only to authorize a narrow scratch grant. */
  readonly filesystemWriteRules?: readonly ScratchPathRule[];
  /** Unrestricted filesystems permit writes across volumes. */
  readonly filesystemRootWritable?: boolean;
  /** A :root grant is bound to the originating sandbox cwd's volume. */
  readonly filesystemRootWritePath?: string;
};

type ScratchPathRule = { readonly path: string; readonly access: "read" | "write" };

export type DeepWorkerScratchAccess = {
  readonly writePath: string;
  readonly readOnlyPaths: readonly string[];
};

/** Resolve the effective host policy, never a model-supplied scan argument. */
export function resolveDeepWorkerParentSandbox(extra: unknown): DeepWorkerParentSandbox {
  const state = trustedSandboxState(extra);
  const sandboxCwd = validateSandboxCwd(state.sandboxCwd);

  const profile = record(state.permissionProfile);
  if (!profile || profile.type !== "managed") {
    throw unsupportedParentSandbox(
      "the parent must provide a managed filesystem permission profile"
    );
  }

  if (profile.network !== "enabled" && profile.network !== "restricted") {
    throw unsupportedParentSandbox("the parent network permission is missing or invalid");
  }

  const filesystem = record(profile.file_system);
  if (!filesystem) {
    throw unsupportedParentSandbox("the parent filesystem permission is missing or invalid");
  }

  if (filesystem.type === "unrestricted") {
    return { filesystemDenies: [], filesystemRootWritable: true };
  }

  if (filesystem.type !== "restricted" || !Array.isArray(filesystem.entries)) {
    throw unsupportedParentSandbox("the parent filesystem permission cannot be verified");
  }

  const globScanMaxDepth = resolveGlobScanMaxDepth(filesystem);

  let hasRootRead = false;
  let filesystemRootWritePath: string | undefined;
  let unresolvedReadRule = false;
  const filesystemWriteRules: ScratchPathRule[] = [];
  const filesystemDenies: string[] = [];
  for (const value of filesystem.entries) {
    const entry = record(value);
    if (!entry || !isKnownFilesystemAccess(entry.access)) {
      throw unsupportedParentSandbox(
        "a parent filesystem permission has an invalid access mode"
      );
    }

    const path = record(entry.path);
    if (!path) {
      throw unsupportedParentSandbox("a parent filesystem permission has an invalid path");
    }

    const isDeny = entry.access === "deny" || entry.access === "none";
    if (isDeny) {
      validateDenyMissingPathBehavior(entry);
    }

    if (path.type === "special" || path.type === "generated_default_special") {
      const special = record(path.value);
      if (!special || !isValidSpecialPath(special)) {
        throw unsupportedParentSandbox(
          "an unknown parent filesystem permission cannot be preserved"
        );
      }
      if (isDeny) {
        throw unsupportedParentSandbox(
          "parent filesystem denials on special paths cannot be preserved"
        );
      }
      if (special.kind === "root") {
        hasRootRead = true;
        if (entry.access === "write" && sandboxCwd !== undefined) {
          filesystemRootWritePath = parse(sandboxCwd).root;
          filesystemWriteRules.push({ path: filesystemRootWritePath, access: "write" });
        }
      } else if (special.kind === "slash_tmp") {
        if (process.platform !== "win32") {
          try {
            if (statSync("/tmp").isDirectory()) {
              filesystemWriteRules.push({ path: "/tmp", access: entry.access as "read" | "write" });
            }
          } catch {
            // Native :slash_tmp grants nothing when /tmp is unavailable.
          }
        }
      } else if (special.kind !== "minimal" && entry.access === "read") {
        // Current hosts materialize project roots. Metadata does not bind
        // TMPDIR, so neither symbol can safely narrow a concrete write here.
        unresolvedReadRule = true;
      }
    } else if (path.type === "path" || path.type === "generated_default_path") {
      if (!isNonEmptyString(path.path)) {
        throw unsupportedParentSandbox("a parent filesystem permission has an invalid path");
      }
      if (isDeny) {
        if (!isAbsolute(path.path)) {
          throw unsupportedParentSandbox(
            "a parent filesystem denial path cannot be preserved"
          );
        }
        if (hasGlobMetacharacters(path.path)) {
          throw unsupportedParentSandbox(
            "a parent filesystem denial path with glob characters cannot be preserved"
          );
        }
        filesystemDenies.push(path.path);
      } else if (isAbsolute(path.path)) {
        filesystemWriteRules.push({ path: path.path, access: entry.access as "read" | "write" });
      } else if (entry.access === "read") {
        unresolvedReadRule = true;
      }
    } else if (path.type === "glob_pattern") {
      if (!isNonEmptyString(path.pattern)) {
        throw unsupportedParentSandbox("a parent filesystem permission has an invalid glob");
      }
      if (!isDeny) {
        throw unsupportedParentSandbox(
          "parent filesystem glob grants cannot be preserved"
        );
      }
      if (!isAbsolute(path.pattern)) {
        if (path.pattern.startsWith("codex-project-roots://")) {
          throw unsupportedParentSandbox(
            "the host supplied symbolic project-roots denial metadata that cannot be preserved"
          );
        }
        throw unsupportedParentSandbox(
          "a parent filesystem denial glob cannot be preserved"
        );
      }
      filesystemDenies.push(path.pattern);
    } else {
      throw unsupportedParentSandbox(
        "an unknown parent filesystem permission cannot be preserved"
      );
    }
  }

  if (!hasRootRead) {
    throw unsupportedParentSandbox(
      "the parent restricts readable paths beyond the supported read-only worker sandbox"
    );
  }

  return {
    filesystemDenies,
    ...(globScanMaxDepth !== undefined ? { globScanMaxDepth } : {}),
    ...(!unresolvedReadRule && filesystemRootWritePath !== undefined ? { filesystemRootWritePath } : {}),
    ...(!unresolvedReadRule && filesystemWriteRules.some((rule) => rule.access === "write")
      ? { filesystemWriteRules }
      : {})
  };
}

/**
 * Clip known parent write authority to one scratch directory. Deny globs stay
 * in the worker profile for native Codex matching; this is not a glob engine.
 */
export async function resolveDeepWorkerScratchAccess(
  sandbox: DeepWorkerParentSandbox,
  scratchPath: string,
  targetPath: string
): Promise<DeepWorkerScratchAccess | undefined> {
  if (!sandbox.filesystemRootWritable && !sandbox.filesystemWriteRules?.some((rule) => rule.access === "write")) return;
  if (!isAbsolute(scratchPath) || !isAbsolute(targetPath)) return;
  const [scratch, target] = await Promise.all([
    canonicalPath(scratchPath),
    canonicalPath(targetPath)
  ]);
  if (!scratch || !target || hasGlobMetacharacters(scratch)
    || containsPath(scratch, target) || containsPath(target, scratch)) return;

  const rules: Array<ScratchPathRule & { readonly originalPath: string }> = [];
  for (const rule of sandbox.filesystemWriteRules ?? []) {
    const canonical = await canonicalPath(rule.path);
    // An unresolved read restriction cannot be discarded to grant writes.
    if (!canonical) {
      if (rule.access === "read") return;
      continue;
    }
    rules.push({ ...rule, path: canonical, originalPath: resolve(rule.path) });
  }
  if (sandbox.filesystemRootWritable) {
    rules.push({ path: parse(scratch).root, originalPath: parse(scratch).root, access: "write" });
  }

  const effectiveAccess = (path: string, spelling: "path" | "originalPath" = "path"): "read" | "write" | undefined => {
    let selected: ScratchPathRule | undefined;
    for (const value of rules) {
      const rule = { path: value[spelling], access: value.access };
      if (!containsPath(rule.path, path)) continue;
      if (!selected || rule.path.length > selected.path.length
        || (rule.path === selected.path && rule.access === "write")) selected = rule;
    }
    return selected?.access;
  };
  if (effectiveAccess(scratch) !== "write" || effectiveAccess(resolve(scratchPath), "originalPath") === "read") return;

  for (const denied of sandbox.filesystemDenies) {
    if (hasGlobMetacharacters(denied)) continue;
    const canonical = await canonicalPath(denied);
    if (!canonical || containsPath(canonical, scratch) || containsPath(resolve(denied), resolve(scratchPath))) return;
  }

  // Canonicalize the writable root, but preserve a carveout's remaining path
  // components so a symlink inode inside scratch remains protected too.
  const carveoutPaths = (original: string, canonical: string): string[] => [
    original,
    canonical,
    ...rules.filter((rule) => rule.access === "write" && containsPath(rule.originalPath, original))
      .map((rule) => join(rule.path, relative(rule.originalPath, original)))
  ];
  const readOnlyPaths = rules
    .filter((rule) => rule.access === "read" && rule.path !== scratch
      && containsPath(scratch, rule.path) && effectiveAccess(rule.path) === "read")
    .map((rule) => rule.path);
  for (const rule of rules) {
    if (rule.access === "read" && effectiveAccess(rule.originalPath, "originalPath") === "read") {
      for (const path of carveoutPaths(rule.originalPath, rule.path)) {
        if (containsPath(scratch, path)) readOnlyPaths.push(path);
      }
    }
  }

  // Native full-disk write profiles do not apply default metadata carveouts.
  const fullDiskWrite = (sandbox.filesystemRootWritable || (sandbox.filesystemRootWritePath !== undefined
    && relative(sandbox.filesystemRootWritePath, parse(scratch).root) === ""))
    && sandbox.filesystemDenies.length === 0
    && !rules.some((rule) => rule.access === "read" && effectiveAccess(rule.path) === "read");
  if (!fullDiskWrite) {
    // Keep both spellings: a protected .codex symlink must not become writable
    // by requesting its canonical destination as the scratch directory.
    for (const rule of rules.filter((entry) => entry.access === "write")) {
      const metadataPaths = [".git", ".agents", ".codex"].map((name) => join(rule.originalPath, name));
      const gitdir = await gitDirectoryFromPointer(join(rule.originalPath, ".git"));
      if (gitdir) metadataPaths.push(gitdir);
      for (const original of metadataPaths) {
        const canonical = await canonicalPath(original);
        if (!canonical) continue;
        const explicitlyWritable = rules.some((entry) => entry.access === "write"
          && containsPath(original, entry.originalPath) && containsPath(entry.path, scratch));
        if (!explicitlyWritable && (containsPath(canonical, scratch)
          || containsPath(original, resolve(scratchPath)))) return;
        if (effectiveAccess(canonical) !== "write" || !rules.some((entry) => entry.access === "write"
          && entry.originalPath === original)) {
          for (const path of carveoutPaths(original, canonical)) {
            if (containsPath(scratch, path)) readOnlyPaths.push(path);
          }
        }
      }
    }
  }
  return { writePath: scratch, readOnlyPaths: [...new Set(readOnlyPaths)] };
}

function containsPath(parent: string, child: string): boolean {
  const suffix = relative(parent, child);
  return suffix === "" || (!isAbsolute(suffix) && suffix !== ".." && !suffix.startsWith(`..${sep}`));
}

/** Match native Codex's existing Git worktree/submodule metadata carveout. */
async function gitDirectoryFromPointer(dotGit: string): Promise<string | undefined> {
  try {
    if (!(await stat(dotGit)).isFile()) return;
    const contents = (await readFile(dotGit, "utf8")).trim();
    const separator = contents.indexOf(":");
    if (separator < 0 || contents.slice(0, separator).trim() !== "gitdir") return;
    const pointer = contents.slice(separator + 1).trim();
    if (!pointer) return;
    const directory = resolve(dirname(dotGit), pointer);
    await stat(directory);
    return directory;
  } catch {
    return;
  }
}

/** Resolve missing descendants without following a dangling symlink as a directory. */
async function canonicalPath(path: string): Promise<string | undefined> {
  const requested = resolve(path);
  let existing = requested;
  for (;;) {
    try {
      const canonical = await realpath(existing);
      if (existing !== requested && !(await lstat(canonical)).isDirectory()) return;
      return join(canonical, relative(existing, requested));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") return;
      try {
        await lstat(existing);
        return;
      } catch (missing) {
        if ((missing as NodeJS.ErrnoException).code !== "ENOENT") return;
      }
      const parent = dirname(existing);
      if (parent === existing) return;
      existing = parent;
    }
  }
}

function trustedSandboxState(extra: unknown): Record<string, unknown> {
  const request = record(extra);
  const direct = record(request?._meta)?.[CODEX_SANDBOX_STATE_META_CAPABILITY];
  const requestInfo = record(request?.requestInfo);
  const forwarded = record(requestInfo?._meta)?.[CODEX_SANDBOX_STATE_META_CAPABILITY];

  if (direct !== undefined && forwarded !== undefined && !isDeepStrictEqual(direct, forwarded)) {
    throw unsupportedParentSandbox("the parent supplied conflicting sandbox metadata");
  }

  const state = record(direct ?? forwarded);
  if (!state) {
    throw unsupportedParentSandbox(
      "the host did not provide trusted parent sandbox metadata"
    );
  }
  return state;
}

function validateSandboxCwd(value: unknown): string | undefined {
  if (value === undefined) return;
  if (typeof value !== "string" || value.trim().length === 0) {
    throw unsupportedParentSandbox("the parent sandbox working directory is invalid");
  }
  if (value.startsWith("file:")) {
    try {
      const path = fileURLToPath(value);
      if (isAbsolute(path)) return path;
    } catch {
      throw unsupportedParentSandbox("the parent sandbox working directory is invalid");
    }
  }
  if (!isAbsolute(value)) {
    throw unsupportedParentSandbox("the parent sandbox working directory is invalid");
  }
  return value;
}

function resolveGlobScanMaxDepth(filesystem: Record<string, unknown>): number | undefined {
  const snakeCase = filesystem.glob_scan_max_depth;
  const camelCase = filesystem.globScanMaxDepth;
  if (
    snakeCase != null
    && camelCase != null
    && !isDeepStrictEqual(snakeCase, camelCase)
  ) {
    throw unsupportedParentSandbox("the parent filesystem glob depth is conflicting");
  }

  const value = snakeCase ?? camelCase;
  if (value == null) return undefined;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    throw unsupportedParentSandbox("the parent filesystem glob depth is invalid");
  }
  return value;
}

function validateDenyMissingPathBehavior(entry: Record<string, unknown>): void {
  const snakeCase = entry.missing_path_behavior;
  const camelCase = entry.missingPathBehavior;
  if (
    snakeCase != null
    && camelCase != null
    && !isDeepStrictEqual(snakeCase, camelCase)
  ) {
    throw unsupportedParentSandbox(
      "a parent filesystem denial has conflicting missing_path_behavior"
    );
  }
  if (snakeCase != null || camelCase != null) {
    throw unsupportedParentSandbox(
      "a parent filesystem denial with missing_path_behavior cannot be preserved"
    );
  }
}

function isKnownFilesystemAccess(value: unknown): value is "read" | "write" | "deny" | "none" {
  return value === "read"
    || value === "write"
    || value === "deny"
    || value === "none";
}

function isValidSpecialPath(value: Record<string, unknown>): boolean {
  if (value.kind === "project_roots") {
    return value.subpath === undefined
      || value.subpath === null
      || isNonEmptyString(value.subpath);
  }
  if (
    value.kind === "root"
    || value.kind === "minimal"
    || value.kind === "tmpdir"
    || value.kind === "slash_tmp"
  ) {
    return value.subpath === undefined || value.subpath === null;
  }
  return false;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function hasGlobMetacharacters(value: string): boolean {
  return value.includes("*") || value.includes("?") || value.includes("[");
}

function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function unsupportedParentSandbox(reason: string): DeepScanNonRetryableError {
  return new DeepScanNonRetryableError(
    `Deep Scan cannot safely start a worker: ${reason}.`
  );
}
