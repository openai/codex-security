import { asRecord as record, isNonEmptyString } from "../record.js";
import { isAbsolute, relative, toNamespacedPath } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { DeepScanNonRetryableError } from "./errors.js";

export const CODEX_SANDBOX_STATE_META_CAPABILITY = "codex/sandbox-state-meta";

export type DeepWorkerParentSandbox = {
  /**
   * Validated glob keys copied into the worker's stricter root-read
   * profile. Workers never inherit parent write access.
   */
  readonly filesystemDenies: readonly string[];
  /** Preserve literal paths separately from glob patterns. */
  readonly literalFilesystemDenies?: readonly string[];
  /** Windows needs the parent's named read root for the selected plugin. */
  readonly pluginReadRoot?: string;
  /** Preserve the selected source's named read root for Windows ACL setup. */
  readonly sourceReadRoot?: string;
  readonly globScanMaxDepth?: number;
};

/** Resolve the effective host policy, never a model-supplied scan argument. */
export function resolveDeepWorkerParentSandbox(
  extra: unknown,
  pluginRoot = process.platform === "win32"
    ? process.env.CODEX_SECURITY_PLUGIN_ROOT
    : undefined,
  sourceRoot = process.platform === "win32"
    ? process.env.CODEX_SECURITY_REPOSITORY
    : undefined,
): DeepWorkerParentSandbox {
  const state = trustedSandboxState(extra);

  const profile = record(state.permissionProfile);
  if (!profile || profile.type !== "managed") {
    throw unsupportedParentSandbox(
      "the parent must provide a managed filesystem permission profile",
    );
  }

  const filesystem = record(profile.file_system);
  if (!filesystem) {
    throw unsupportedParentSandbox(
      "the parent filesystem permission is missing or invalid",
    );
  }

  if (filesystem.type === "unrestricted") {
    return { filesystemDenies: [] };
  }

  if (filesystem.type !== "restricted" || !Array.isArray(filesystem.entries)) {
    throw unsupportedParentSandbox(
      "the parent filesystem permission cannot be verified",
    );
  }

  const globScanMaxDepth = resolveGlobScanMaxDepth(filesystem);

  let hasRootRead = false;
  const filesystemDenies: string[] = [];
  const literalFilesystemDenies: string[] = [];
  let pluginReadRoot: string | undefined;
  let sourceReadRoot: string | undefined;
  for (const value of filesystem.entries) {
    const entry = record(value);
    if (!entry || !isKnownFilesystemAccess(entry.access)) {
      throw unsupportedParentSandbox(
        "a parent filesystem permission has an invalid access mode",
      );
    }

    const path = record(entry.path);
    if (!path) {
      throw unsupportedParentSandbox(
        "a parent filesystem permission has an invalid path",
      );
    }

    const isDeny = entry.access === "deny" || entry.access === "none";
    if (isDeny) {
      validateDenyMissingPathBehavior(entry);
    }

    if (path.type === "special" || path.type === "generated_default_special") {
      const special = record(path.value);
      if (!special || !isValidSpecialPath(special)) {
        throw unsupportedParentSandbox(
          "an unknown parent filesystem permission cannot be preserved",
        );
      }
      if (isDeny) {
        throw unsupportedParentSandbox(
          "parent filesystem denials on special paths cannot be preserved",
        );
      }
      if (special.kind === "root") hasRootRead = true;
    } else if (path.type === "path" || path.type === "generated_default_path") {
      if (!isNonEmptyString(path.path)) {
        throw unsupportedParentSandbox(
          "a parent filesystem permission has an invalid path",
        );
      }
      if (isDeny) {
        if (!isAbsolute(path.path)) {
          throw unsupportedParentSandbox(
            "a parent filesystem denial path cannot be preserved",
          );
        }
        literalFilesystemDenies.push(path.path);
      } else if (entry.access === "read" && isAbsolute(path.path)) {
        if (
          pluginRoot !== undefined &&
          relative(
            toNamespacedPath(path.path),
            toNamespacedPath(pluginRoot),
          ) === ""
        )
          pluginReadRoot = path.path;
        if (
          sourceRoot !== undefined &&
          relative(
            toNamespacedPath(path.path),
            toNamespacedPath(sourceRoot),
          ) === ""
        )
          sourceReadRoot = path.path;
      }
    } else if (path.type === "glob_pattern") {
      if (!isNonEmptyString(path.pattern)) {
        throw unsupportedParentSandbox(
          "a parent filesystem permission has an invalid glob",
        );
      }
      if (!isDeny) {
        throw unsupportedParentSandbox(
          "parent filesystem glob grants cannot be preserved",
        );
      }
      if (!isAbsolute(path.pattern)) {
        if (path.pattern.startsWith("codex-project-roots://")) {
          throw unsupportedParentSandbox(
            "the host supplied symbolic project-roots denial metadata that cannot be preserved",
          );
        }
        throw unsupportedParentSandbox(
          "a parent filesystem denial glob cannot be preserved",
        );
      }
      filesystemDenies.push(path.pattern);
    } else {
      throw unsupportedParentSandbox(
        "an unknown parent filesystem permission cannot be preserved",
      );
    }
  }

  if (!hasRootRead) {
    throw unsupportedParentSandbox(
      "the parent restricts readable paths beyond the supported read-only worker sandbox",
    );
  }

  return {
    filesystemDenies,
    ...(pluginReadRoot === undefined ? {} : { pluginReadRoot }),
    ...(sourceReadRoot === undefined ? {} : { sourceReadRoot }),
    ...(literalFilesystemDenies.length ? { literalFilesystemDenies } : {}),
    ...(globScanMaxDepth !== undefined ? { globScanMaxDepth } : {}),
  };
}

function trustedSandboxState(extra: unknown): Record<string, unknown> {
  const request = record(extra);
  const direct = record(request?._meta)?.[CODEX_SANDBOX_STATE_META_CAPABILITY];
  const requestInfo = record(request?.requestInfo);
  const forwarded = record(requestInfo?._meta)?.[
    CODEX_SANDBOX_STATE_META_CAPABILITY
  ];

  if (
    direct !== undefined &&
    forwarded !== undefined &&
    !isDeepStrictEqual(direct, forwarded)
  ) {
    throw unsupportedParentSandbox(
      "the parent supplied conflicting sandbox metadata",
    );
  }

  const state = record(direct ?? forwarded);
  if (!state) {
    throw unsupportedParentSandbox(
      "the host did not provide trusted parent sandbox metadata",
    );
  }
  return state;
}

function resolveGlobScanMaxDepth(
  filesystem: Record<string, unknown>,
): number | undefined {
  const snakeCase = filesystem.glob_scan_max_depth;
  const camelCase = filesystem.globScanMaxDepth;
  if (
    snakeCase != null &&
    camelCase != null &&
    !isDeepStrictEqual(snakeCase, camelCase)
  ) {
    throw unsupportedParentSandbox(
      "the parent filesystem glob depth is conflicting",
    );
  }

  const value = snakeCase ?? camelCase;
  if (value == null) return undefined;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    throw unsupportedParentSandbox(
      "the parent filesystem glob depth is invalid",
    );
  }
  return value;
}

function validateDenyMissingPathBehavior(entry: Record<string, unknown>): void {
  const snakeCase = entry.missing_path_behavior;
  const camelCase = entry.missingPathBehavior;
  if (
    snakeCase != null &&
    camelCase != null &&
    !isDeepStrictEqual(snakeCase, camelCase)
  ) {
    throw unsupportedParentSandbox(
      "a parent filesystem denial has conflicting missing_path_behavior",
    );
  }
  if (snakeCase != null || camelCase != null) {
    throw unsupportedParentSandbox(
      "a parent filesystem denial with missing_path_behavior cannot be preserved",
    );
  }
}

function isKnownFilesystemAccess(
  value: unknown,
): value is "read" | "write" | "deny" | "none" {
  return (
    value === "read" ||
    value === "write" ||
    value === "deny" ||
    value === "none"
  );
}

function isValidSpecialPath(value: Record<string, unknown>): boolean {
  if (value.kind === "project_roots") {
    return (
      value.subpath === undefined ||
      value.subpath === null ||
      isNonEmptyString(value.subpath)
    );
  }
  if (
    value.kind === "root" ||
    value.kind === "minimal" ||
    value.kind === "tmpdir" ||
    value.kind === "slash_tmp"
  ) {
    return value.subpath === undefined || value.subpath === null;
  }
  return false;
}

function unsupportedParentSandbox(reason: string): DeepScanNonRetryableError {
  return new DeepScanNonRetryableError(
    `Deep Scan cannot safely start a read-only worker: ${reason}.`,
  );
}
