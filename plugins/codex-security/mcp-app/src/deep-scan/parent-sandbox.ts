import { isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { DeepScanNonRetryableError } from "./errors.js";

export const CODEX_SANDBOX_STATE_META_CAPABILITY = "codex/sandbox-state-meta";

export type DeepWorkerParentSandbox = {
  /**
   * Validated path and glob keys copied into the worker's stricter root-read
   * profile. Grants are intentionally not transported because Deep Scan
   * workers never inherit parent write access.
   */
  readonly filesystemDenies: readonly string[];
  readonly globScanMaxDepth?: number;
};

/** Resolve the effective host policy, never a model-supplied scan argument. */
export function resolveDeepWorkerParentSandbox(extra: unknown): DeepWorkerParentSandbox {
  const state = trustedSandboxState(extra);
  validateSandboxCwd(state.sandboxCwd);

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
    return { filesystemDenies: [] };
  }

  if (filesystem.type !== "restricted" || !Array.isArray(filesystem.entries)) {
    throw unsupportedParentSandbox("the parent filesystem permission cannot be verified");
  }

  const globScanMaxDepth = resolveGlobScanMaxDepth(filesystem);

  let hasRootRead = false;
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
      if (special.kind === "root") hasRootRead = true;
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
    ...(globScanMaxDepth !== undefined ? { globScanMaxDepth } : {})
  };
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

function validateSandboxCwd(value: unknown): void {
  if (value === undefined) return;
  if (typeof value !== "string" || value.trim().length === 0) {
    throw unsupportedParentSandbox("the parent sandbox working directory is invalid");
  }
  if (value.startsWith("file:")) {
    try {
      if (isAbsolute(fileURLToPath(value))) return;
    } catch {
      throw unsupportedParentSandbox("the parent sandbox working directory is invalid");
    }
  }
  if (!isAbsolute(value)) {
    throw unsupportedParentSandbox("the parent sandbox working directory is invalid");
  }
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
    `Deep Scan cannot safely start a read-only worker: ${reason}.`
  );
}
