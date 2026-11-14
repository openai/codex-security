import {
  configuredExecutableValue,
  executablePathForSpawn,
  isExplicitPathWithTrailingWhitespace,
  isExecutableFile,
} from "./executable-path.js";
import { retryWindowsRename } from "./retry-windows-rename.js";
export { executablePathForSpawn } from "./executable-path.js";
import { bundledPluginRoot, hasPluginManifest } from "./bundled-plugin.js";
export {
  bundledPluginCandidates,
  bundledPluginRoot,
} from "./bundled-plugin.js";
import {
  PLUGIN_PYTHON_PROBE,
  PLUGIN_PYTHON_PROBE_TIMEOUT_MS,
  PLUGIN_PYTHON_READY,
} from "./plugin-python-probe.js";
import { resolveBundledCodexExecutable } from "./codex-sdk-environment.js";
import { abortable, gitProtectionRoots, resolveTargetPath } from "./targets.js";
import type { AbsolutePath } from "./config-path.js";
import { isNonEmptyString, notify } from "./value.js";
import {
  execFile as execFileCallback,
  spawn,
  type ChildProcessWithoutNullStreams,
  type SpawnOptionsWithoutStdio,
} from "node:child_process";
import { createHash, randomUUID, type Hash } from "node:crypto";
import { shortArchivePrefix } from "./scan-archive-path.js";
import {
  chmodSync,
  close as closeCallback,
  constants,
  createWriteStream,
  fstat as fstatCallback,
  open as openCallback,
  read as readCallback,
  type BigIntStats,
  type Stats,
} from "node:fs";
import {
  access,
  chmod,
  cp,
  copyFile,
  link,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  readlink,
  realpath,
  rename,
  rm,
  rmdir,
  stat,
  utimes,
  writeFile,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { createRequire } from "node:module";
import {
  basename,
  dirname,
  extname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
  win32,
} from "node:path";
import { promisify } from "node:util";
import type { Duplex } from "node:stream";
import { pipeline } from "node:stream/promises";
import { crc32 } from "node:zlib";
import { setTimeout as delay } from "node:timers/promises";
import { fromFdPromise, type ZipFile } from "yauzl";
import { parse } from "smol-toml";
import {
  CodexSecurityError,
  InvalidTargetError,
  OutputDirectoryError,
  OutputDirectoryNotEmptyError,
  OutputInsideProtectedRootError,
  PluginBootstrapError,
  LocalPluginBootstrapError,
  PluginPythonUnavailableError,
  type ProtectedScanPathKind,
  SandboxUnavailableError,
  errorMessage,
  abortReason,
} from "./errors.js";
import {
  writeCodexConfig,
  writePrivateConfig,
  type JsonObject,
} from "./config.js";
import { isRecord } from "./record.js";
import {
  campaignExecutable,
  inspectTrustedExecutable,
  isWithin,
  resolveTrustedExecutable,
  type InspectedExecutable,
} from "./trusted-executable.js";
import {
  isWindowsUnsafePathComponent,
  sqliteFilename,
  windowsUnsafePathComponent,
} from "./windows-path.js";

const execFile = promisify(execFileCallback);

export type StartCodex = (
  command: string,
  args: readonly string[],
  options: SpawnOptionsWithoutStdio & { stdio: ["pipe", "pipe", "pipe"] },
) => ChildProcessWithoutNullStreams;

export const MARKETPLACE_NAME = "codex-security-sdk";
export const PLUGIN_NAME = "codex-security";
const MARKETPLACE_MANIFEST = `${JSON.stringify(
  {
    name: MARKETPLACE_NAME,
    interface: { displayName: "Codex Security SDK" },
    plugins: [
      {
        name: PLUGIN_NAME,
        source: { source: "local", path: `./plugins/${PLUGIN_NAME}` },
        policy: { installation: "AVAILABLE", authentication: "ON_INSTALL" },
        category: "Security",
      },
    ],
  },
  null,
  2,
)}\n`;

const MAX_ZIP_ENTRIES = 4_096;
const MAX_ZIP_CENTRAL_DIRECTORY = 16 * 1024 * 1024;
const MAX_ZIP_ENTRY_SIZE = 128 * 1024 * 1024;
const MAX_ZIP_EXPANDED_SIZE = 512 * 1024 * 1024;
const MODEL_UNSAFE_PATH = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u;
const CREDENTIAL_LOCK_NAME = ".codex-security-scan.lock";
const CREDENTIAL_LOCK_DATABASE = ".codex-security-scan.sqlite3";
const CREDENTIAL_LOGOUT_MARKER = ".codex-security-logged-out";
const KEYRING_LOGIN = ".codex-security-keyring-login";
const CREDENTIAL_LOCK_HEARTBEAT_MILLISECONDS = 5_000;
const CREDENTIAL_LOCK_POLL_MILLISECONDS = 25;
const INCOMPLETE_CREDENTIAL_LOCK_MILLISECONDS = 30_000;
const MAX_PROCESS_ID = 2_147_483_647;
const SANDBOX_PROBE_TIMEOUT_MILLISECONDS = 10_000;
const PLUGIN_HELPER_SECRET_ENVIRONMENT_VARIABLES = new Set([
  "OPENAI_API_KEY",
  "CODEX_API_KEY",
  "OPENROUTER_API_KEY",
  "FIREWORKS_API_KEY",
  "CHEAPER_INFERENCE_API_KEY",
  "HF_TOKEN",
]);
const PREPARE_SCAN_ARTIFACT_RESTORER_PROGRAM = `
from pathlib import Path
from runpy import run_path
import json
import sys

module = run_path(sys.argv[1])
canonical_path, root_identity = module["scan_root_identity"](Path(sys.argv[2]))
print(json.dumps({
    "canonicalPath": str(canonical_path),
    "dev": str(root_identity[0]),
    "ino": str(root_identity[1]),
}, ensure_ascii=False))
`.trim();
const RESTORE_SCAN_ARTIFACT_PROGRAM = `
from pathlib import Path
from runpy import run_path
import sys

module = run_path(sys.argv[1])
try:
    module["write_scan_local_bytes"](
        Path(sys.argv[2]),
        sys.argv[3],
        sys.stdin.buffer.read(),
        expected_root_identity=(int(sys.argv[4]), int(sys.argv[5])),
    )
except (module["ContractError"], OSError) as error:
    raise SystemExit(str(error))
`.trim();
const WINDOWS_CREDENTIAL_ACL_COMPLETE_PREFIX = "CODEX_SECURITY_ACL_COMPLETE:";
const WINDOWS_CREDENTIAL_DESCENDANTS_CHANGED_EXIT_CODE = 2;

export interface PluginInstall {
  pluginRoot: string;
  marketplaceRoot: string;
  installedRoot: string;
  marketplaceName: typeof MARKETPLACE_NAME;
  name: typeof PLUGIN_NAME;
  version: string;
}

export interface CodexCommand {
  command: string;
  args?: readonly string[];
}

interface CodexCommandResult {
  success: boolean;
  exitCode: number | null;
  stdout: string;
  stderr: string;
}

export type ProcessEnvironment = Record<string, string | undefined>;

export interface PluginPythonOptions {
  configuredPath?: string;
  environment?: ProcessEnvironment;
  homeDirectory?: string;
  managedRuntimeRoots?: readonly string[];
  protectedRoot?: string | readonly string[];
  /** @internal Additional roots excluded only from ambient interpreter discovery. */
  discoveryProtectedRoots?: readonly string[];
  /** @internal Ambient PATH lookup requires a known boundary for saved Git targets. */
  allowPathLookup?: boolean;
  currentDirectory?: string;
  signal?: AbortSignal;
}

export interface WorkbenchCommandOptions {
  python: string;
  pluginRoot: string;
  instructionRoot?: string;
  environment: ProcessEnvironment;
  stateDirectory?: string;
  protectedRoot?: string | readonly string[];
  currentDirectory?: string;
  signal?: AbortSignal;
  failureMessage?: string;
}

export interface ScanArtifactRestorer {
  restore(relativePath: string, contents: Uint8Array): Promise<void>;
}

function environmentValue(
  environment: ProcessEnvironment,
  requested: string,
  preserveWhitespace = false,
): string | undefined {
  const exact = environment[requested];
  const value = exact?.trim()
    ? exact
    : Object.entries(environment).find(
        ([name, value]) => name.toUpperCase() === requested && value?.trim(),
      )?.[1];
  return preserveWhitespace ? value : value?.trim();
}

export function codexSecurityStateDirectory(
  environment: ProcessEnvironment = process.env,
): string {
  const configured = environmentValue(
    environment,
    "CODEX_SECURITY_STATE_DIR",
    process.platform !== "win32",
  );
  const path =
    configured !== undefined
      ? resolve(expandHome(configured, environment))
      : resolve(
          expandHome(
            environmentValue(environment, "CODEX_HOME", true) ??
              join(homedir(), ".codex"),
            environment,
          ),
          "state",
          "plugins",
          "codex-security",
        );
  requireModelSafeOutputDir(path);
  return path;
}

export function codexSecurityCredentialHome(
  environment: ProcessEnvironment = process.env,
): string {
  return join(codexSecurityStateDirectory(environment), "codex-home");
}

export async function prepareCodexSecurityCredentialHome(
  environment: ProcessEnvironment = process.env,
  validateLocation?: (path: string) => void,
): Promise<string> {
  const path = codexSecurityCredentialHome(environment);
  try {
    try {
      await mkdir(path, { recursive: true, mode: 0o700 });
    } catch (error) {
      if (nodeErrorCode(error) === "EEXIST") {
        if ((await lstat(path).catch(() => null))?.isDirectory() === false) {
          throw new OutputDirectoryError(
            `Codex Security credential home is not a directory: ${path}`,
            { cause: error },
          );
        }
      }
      throw error;
    }
    if ((process.umask() & 0o700) !== 0) await chmod(path, 0o700);
    const metadata = await lstat(path, { bigint: true });
    if (!metadata.isDirectory()) {
      throw new OutputDirectoryError(
        `Codex Security credential home is not a directory: ${path}`,
      );
    }
    const canonical = await realpath(path);
    requireModelSafeOutputDir(canonical);
    validateLocation?.(canonical);
    await requireSecureCredentialHome(canonical, {
      metadata,
    });
    return canonical;
  } catch (error) {
    if (error instanceof OutputDirectoryError) throw error;
    const code = nodeErrorCode(error);
    const recovery =
      code === "EACCES" || code === "EPERM" || code === "EROFS"
        ? "\nCheck permissions or set CODEX_SECURITY_STATE_DIR to a private, writable directory outside the repository."
        : "";
    throw new OutputDirectoryError(
      `Unable to prepare the Codex Security credential home: ${path}\n${errorMessage(error)}${recovery}`,
      { cause: error },
    );
  }
}

/**
 * Re-verify the credential home before every use.
 *
 * Durable cross-process `(st_dev, st_ino)` pins are deferred: there is no
 * workbench row for credential homes, and path+mode+trusted-ancestry checks on
 * each use already close the cross-user rename/replace class. Lock acquisition
 * still pins identity for the duration of a single lock session.
 */
export async function requireSecureCredentialHome(
  path: string,
  options: Parameters<typeof requirePrivateDirectory>[3] & {
    metadata?: BigIntStats;
    expectedDevice?: bigint;
    expectedInode?: bigint;
    validateWindowsAcl?: boolean;
  } = {},
): Promise<BigIntStats> {
  const platform = options.platform ?? process.platform;
  let metadata = options.metadata;
  if (metadata === undefined) {
    try {
      metadata = await lstat(path, { bigint: true });
    } catch (error) {
      throw new OutputDirectoryError(
        `Unable to inspect the Codex Security credential home: ${path}`,
        { cause: error },
      );
    }
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new OutputDirectoryError(
      `Codex Security credential home is not a directory: ${path}`,
    );
  }
  const canonical = await realpath(path);
  requireModelSafeOutputDir(canonical);
  const canonicalMetadata = await lstat(canonical, { bigint: true });
  if (
    canonicalMetadata.dev !== metadata.dev ||
    canonicalMetadata.ino !== metadata.ino
  ) {
    throw new OutputDirectoryError(
      `Codex Security credential home was replaced: ${canonical}`,
    );
  }
  metadata = canonicalMetadata;
  if (!metadata.isDirectory()) {
    throw new OutputDirectoryError(
      `Codex Security credential home is not a directory: ${path}`,
    );
  }
  if (
    options.expectedDevice !== undefined &&
    options.expectedInode !== undefined &&
    (metadata.dev !== options.expectedDevice ||
      metadata.ino !== options.expectedInode)
  ) {
    throw new OutputDirectoryError(
      `Codex Security credential home was replaced: ${canonical}`,
    );
  }
  if (platform !== "win32" || options.validateWindowsAcl !== false) {
    await requirePrivateCredentialHome(
      { mode: Number(metadata.mode), uid: Number(metadata.uid) },
      canonical,
      {
        platform,
        secureWindowsHome: options.secureWindowsHome,
      },
    );
  }
  if (platform !== "win32") {
    await requireSecureOutputAncestry(canonical);
  }
  return metadata;
}

export async function requirePrivateCredentialHome(
  metadata: Pick<Stats, "mode" | "uid">,
  path: string,
  options: Parameters<typeof requirePrivateDirectory>[3] = {},
): Promise<void> {
  await requirePrivateDirectory(metadata, path, "credential home", options);
}

export async function preparePolicyOutputDirectory(
  path: string,
  options: Parameters<typeof requirePrivateDirectory>[3] = {},
): Promise<void> {
  const metadata = await lstat(path);
  if ((options.platform ?? process.platform) !== "win32") {
    requireOutputDirectoryOwnership(metadata, path);
    return;
  }
  await requirePrivateDirectory(
    metadata,
    path,
    "policy output directory",
    options,
  );
}

export async function requirePrivateDirectory(
  metadata: Pick<Stats, "mode" | "uid">,
  path: string,
  description: string,
  options: {
    platform?: NodeJS.Platform;
    secureWindowsHome?: (path: string) => Promise<void>;
  } = {},
): Promise<void> {
  if ((options.platform ?? process.platform) !== "win32") {
    requirePrivateOutputDirectory(metadata, path);
    return;
  }

  try {
    await (options.secureWindowsHome ?? secureWindowsCredentialHome)(path);
  } catch (error) {
    const detail = windowsCredentialAclFailure(error);
    throw new OutputDirectoryError(
      `Unable to create a private Windows ${description}: ${path}${detail}`,
      { cause: error },
    );
  }
}

function windowsCredentialAclFailure(error: unknown): string {
  const stderr =
    typeof error === "object" && error !== null && "stderr" in error
      ? error.stderr
      : undefined;
  const detail =
    typeof stderr === "string" && stderr.trim() !== ""
      ? stderr
      : errorMessage(error);
  const normalized = errorMessage(detail).replace(/\s+/gu, " ").trim();
  return normalized === "" ? "" : `. ${normalized}`;
}

const WINDOWS_SYSTEM_SID = "S-1-5-18";
const WINDOWS_ADMINISTRATORS_SID = "S-1-5-32-544";
const WINDOWS_TRUSTED_INSTALLER_SID =
  "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const WINDOWS_LOCAL_SERVICE_SID = "S-1-5-19";
const WINDOWS_NETWORK_SERVICE_SID = "S-1-5-20";
const WINDOWS_EVERYONE_SID = "S-1-1-0";
const WINDOWS_AUTHENTICATED_USERS_SID = "S-1-5-11";
const WINDOWS_USERS_SID = "S-1-5-32-545";
const WINDOWS_CREATOR_OWNER_SID = "S-1-3-0";
const WINDOWS_CREATOR_GROUP_SID = "S-1-3-1";
const WINDOWS_OWNER_RIGHTS_SID = "S-1-3-4";
const WINDOWS_ALL_APPLICATION_PACKAGES_SID = "S-1-15-2-1";
const WINDOWS_PRINCIPAL_ALIASES: Readonly<Record<string, string>> = {
  SY: WINDOWS_SYSTEM_SID,
  BA: WINDOWS_ADMINISTRATORS_SID,
  LS: WINDOWS_LOCAL_SERVICE_SID,
  NS: WINDOWS_NETWORK_SERVICE_SID,
  WD: WINDOWS_EVERYONE_SID,
  AU: WINDOWS_AUTHENTICATED_USERS_SID,
  BU: WINDOWS_USERS_SID,
  CO: WINDOWS_CREATOR_OWNER_SID,
  CG: WINDOWS_CREATOR_GROUP_SID,
  OW: WINDOWS_OWNER_RIGHTS_SID,
  AC: WINDOWS_ALL_APPLICATION_PACKAGES_SID,
  AN: "S-1-5-7",
  IU: "S-1-5-4",
  NU: "S-1-5-2",
  SU: "S-1-5-6",
  RC: "S-1-5-12",
  ED: "S-1-5-9",
  BG: "S-1-5-32-546",
  PU: "S-1-5-32-547",
  AO: "S-1-5-32-548",
  SO: "S-1-5-32-549",
  PO: "S-1-5-32-550",
  BO: "S-1-5-32-551",
  RE: "S-1-5-32-552",
  RU: "S-1-5-32-554",
  RD: "S-1-5-32-555",
  NO: "S-1-5-32-556",
  MU: "S-1-5-32-558",
  LU: "S-1-5-32-559",
  IS: "S-1-5-32-568",
  CY: "S-1-5-32-569",
  ER: "S-1-5-32-573",
  CD: "S-1-5-32-574",
  RA: "S-1-5-32-575",
  ES: "S-1-5-32-576",
  HA: "S-1-5-32-578",
  AA: "S-1-5-32-579",
};
const WINDOWS_ACCOUNT_SID = /^S-1-5-21-(?:\d+-){3}\d+$/u;
const WINDOWS_SID = /^S-1-(?:\d+-)*\d+$/u;
const WINDOWS_GUID =
  /^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/iu;
const WINDOWS_SDDL_SID = "(?:S-1-(?:\\d+-)*\\d+|[A-Z]{2})";
const WINDOWS_SECURITY_DESCRIPTOR = new RegExp(
  `^O:(${WINDOWS_SDDL_SID})(?:G:${WINDOWS_SDDL_SID})?D:([A-Z_]*)(.*)$`,
  "u",
);

export interface WindowsCredentialAcl {
  owner: string;
  protected: boolean;
  grantsCurrentUserAccess: boolean;
  untrustedPrincipals: string[];
  deniedPrincipals: string[];
}

class UntrustedWindowsCredentialOwnerError extends Error {
  public constructor(owner: string) {
    super(`Windows credential ACL owner is not a trusted principal: ${owner}`);
  }
}

class RepairableWindowsCredentialAclError extends Error {
  public constructor(cause: unknown) {
    super("Windows credential ACL requires repair", { cause });
  }
}

class RepairableWindowsCredentialOwnerError extends Error {
  public constructor(cause: UntrustedWindowsCredentialOwnerError) {
    super(cause.message, { cause });
  }
}

class WindowsCredentialDescendantsChangedError extends Error {}

/** Inspect a Windows DACL without translating locale-specific account names. */
export function inspectWindowsCredentialAcl(
  descriptor: string,
  currentUserSid: string,
  options: {
    resolvedAliases?: Readonly<Record<string, string>>;
    currentGroupSids?: ReadonlySet<string>;
    scope?: "directory" | "file" | "ancestor";
  } = {},
): WindowsCredentialAcl {
  if (!WINDOWS_SID.test(currentUserSid)) {
    throw new Error("Unable to identify the current Windows user SID");
  }
  const match = WINDOWS_SECURITY_DESCRIPTOR.exec(descriptor.trim());
  if (match === null) {
    throw new Error("Windows credential ACL has no owner or DACL");
  }

  const principalAliases: Readonly<Record<string, string>> = {
    ...WINDOWS_PRINCIPAL_ALIASES,
    ...options.resolvedAliases,
  };
  const trustedPrincipals = new Set([
    currentUserSid,
    WINDOWS_SYSTEM_SID,
    WINDOWS_ADMINISTRATORS_SID,
    principalAliases["LA"] ?? "LA",
  ]);
  if (options.scope === "ancestor") {
    trustedPrincipals.add(WINDOWS_TRUSTED_INSTALLER_SID);
  }
  const normalizePrincipal = (principal: string): string =>
    principalAliases[principal] ?? principal;
  const trustedPrincipal = (principal: string): boolean =>
    trustedPrincipals.has(principal);
  const owner = normalizePrincipal(match[1]!);
  if (!trustedPrincipal(owner)) {
    throw new UntrustedWindowsCredentialOwnerError(owner);
  }
  const flags = match[2]!;
  if (flags.includes("NO_ACCESS_CONTROL")) {
    throw new Error("Windows credential ACL grants unrestricted access");
  }

  let remaining = match[3]!;
  let grantsCurrentDirectoryAccess = false;
  let grantsCurrentFileAccess = false;
  let grantsCurrentContainerAccess = false;
  let hasAccessRules = false;
  const untrustedPrincipals = new Set<string>();
  const deniedPrincipals = new Set<string>();
  while (remaining.startsWith("(")) {
    const { rule, rest } = windowsSecurityDescriptorRule(remaining);
    const fields = rule.split(";");
    const callback = ["XA", "XD", "ZA"].includes(fields[0]!);
    if ((callback && fields.length < 7) || (!callback && fields.length !== 6)) {
      throw new Error("Windows credential ACL has a malformed access rule");
    }
    const [
      type,
      inheritance,
      rights,
      objectGuid,
      inheritObjectGuid,
      rawPrincipal,
    ] = fields;
    if (!["A", "OA", "D", "OD", "XA", "XD", "ZA"].includes(type!)) {
      throw new Error("Windows credential ACL has an unsupported access rule");
    }
    if (rawPrincipal === "" || rights === "") {
      throw new Error("Windows credential ACL has an incomplete access rule");
    }
    const objectRule = type === "OA" || type === "OD" || type === "ZA";
    for (const guid of [objectGuid!, inheritObjectGuid!]) {
      if (guid !== "" && (!objectRule || !WINDOWS_GUID.test(guid))) {
        throw new Error("Windows credential ACL has a malformed object rule");
      }
    }
    const inheritanceFlags = windowsAceFlags(inheritance!);
    hasAccessRules = true;
    const principal = normalizePrincipal(rawPrincipal!);
    if (type === "A" || type === "OA" || type === "XA" || type === "ZA") {
      if (!trustedPrincipal(principal)) {
        if (
          options.scope !== "ancestor" ||
          // OWNER RIGHTS applies to the owner already verified above. Every
          // descendant is inspected with its own security descriptor.
          (principal !== WINDOWS_OWNER_RIGHTS_SID &&
            windowsAceAllowsAncestorReplacement(rights!, inheritanceFlags))
        ) {
          untrustedPrincipals.add(principal);
        }
      } else if (
        !callback &&
        objectGuid === "" &&
        inheritObjectGuid === "" &&
        principal === currentUserSid &&
        windowsAceGrantsFullControl(rights!)
      ) {
        if (!inheritanceFlags.has("IO")) {
          grantsCurrentDirectoryAccess = true;
        }
        if (inheritanceFlags.has("OI") && !inheritanceFlags.has("NP")) {
          grantsCurrentFileAccess = true;
        }
        if (inheritanceFlags.has("CI") && !inheritanceFlags.has("NP")) {
          grantsCurrentContainerAccess = true;
        }
      }
    } else if (
      principal === currentUserSid ||
      !WINDOWS_ACCOUNT_SID.test(principal) ||
      (options.currentGroupSids?.has(principal) ?? true)
    ) {
      deniedPrincipals.add(principal);
    }
    remaining = rest;
  }
  if (!hasAccessRules || (remaining !== "" && !remaining.startsWith("S:"))) {
    throw new Error("Windows credential ACL has an invalid access-rule list");
  }

  return {
    owner,
    protected: flags.includes("P"),
    grantsCurrentUserAccess:
      grantsCurrentDirectoryAccess &&
      (options.scope === "file" ||
        (grantsCurrentFileAccess && grantsCurrentContainerAccess)) &&
      deniedPrincipals.size === 0,
    untrustedPrincipals: [...untrustedPrincipals],
    deniedPrincipals: [...deniedPrincipals],
  };
}

function windowsSecurityDescriptorRule(value: string) {
  let depth = 0;
  let quoted = false;
  let escaped = false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]!;
    if (quoted) {
      if (!escaped && character === '"') quoted = false;
      escaped = character === "\\" && !escaped;
      continue;
    }
    if (character === '"') {
      quoted = true;
    } else if (character === "(") {
      depth += 1;
    } else if (character === ")") {
      depth -= 1;
      if (depth === 0) {
        return { rule: value.slice(1, index), rest: value.slice(index + 1) };
      }
    }
  }
  throw new Error("Windows credential ACL has a malformed rule");
}

function windowsAceFlags(value: string): ReadonlySet<string> {
  if (value.length % 2 !== 0) {
    throw new Error("Windows credential ACL has malformed inheritance flags");
  }
  const flags = new Set<string>();
  for (let offset = 0; offset < value.length; offset += 2) {
    const flag = value.slice(offset, offset + 2);
    if (!["OI", "CI", "NP", "IO", "ID"].includes(flag)) {
      throw new Error(
        "Windows credential ACL has unsupported inheritance flags",
      );
    }
    flags.add(flag);
  }
  return flags;
}

function windowsAceGrantsFullControl(rights: string): boolean {
  if (rights === "FA" || rights === "GA") return true;
  if (!/^0x[\da-f]+$/iu.test(rights)) return false;
  const mask = BigInt(rights);
  return (mask & 0x1f01ffn) === 0x1f01ffn || (mask & 0x10000000n) !== 0n;
}

function windowsAceAllowsAncestorReplacement(
  rights: string,
  inheritanceFlags: ReadonlySet<string>,
): boolean {
  if (inheritanceFlags.has("IO")) return false;
  if (/^0x[\da-f]+$/iu.test(rights)) {
    return (BigInt(rights) & 0x100d0040n) !== 0n;
  }
  // Rights tokens stay aligned to pairs of UTF-16 code units.
  for (const [right] of rights.matchAll(/[\s\S]{2}/g)) {
    if (["FA", "GA", "FW", "GW", "SD", "WD", "WO", "DC", "DT"].includes(right))
      return true;
  }
  return false;
}

export async function streamWindowsCredentialAclDescriptors(
  command: string,
  args: readonly string[],
  inspectDescriptor: (descriptor: string) => Promise<void>,
  options: { environment?: NodeJS.ProcessEnv } = {},
): Promise<void> {
  const child = spawn(command, [...args], {
    env: options.environment,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });

  let descendantsChanged = false;
  const completion = new Promise<void>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (code === 0) {
        resolve();
        return;
      }
      if (code === WINDOWS_CREDENTIAL_DESCENDANTS_CHANGED_EXIT_CODE) {
        descendantsChanged = true;
        resolve();
        return;
      }
      const reason = signal === null ? `exit code ${code}` : `signal ${signal}`;
      reject(
        Object.assign(
          new Error(`Windows credential ACL inspection failed with ${reason}`),
          { code, signal, stderr },
        ),
      );
    });
  });

  try {
    await Promise.all([
      completion,
      (async () => {
        // Consume chunks directly: readline can resume its queued-line
        // iterator after EOF and throw instead of draining the last lines.
        child.stdout.setEncoding("utf8");
        let pending = "";
        for await (const chunk of child.stdout) {
          const lines = (pending + chunk).split(/[\r\n]/u);
          pending = lines.pop()!;
          for (const descriptor of lines) {
            if (descriptor === "") continue;
            await inspectDescriptor(descriptor);
          }
        }
        if (pending !== "") {
          await inspectDescriptor(pending);
        }
      })(),
    ]);
  } catch (error) {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    throw error;
  }

  if (descendantsChanged) {
    // Finish descriptor callbacks before allowing another snapshot attempt.
    throw new WindowsCredentialDescendantsChangedError(
      "Windows credential descendants changed during ACL inspection",
    );
  }
}

// win32.parse stops at the UNC marker for extended-length share paths.
const WINDOWS_CREDENTIAL_UNC_ROOT =
  /^[\\/]{2}[?.][\\/]UNC[\\/][^\\/]+[\\/][^\\/]+[\\/]?/iu;

function windowsCredentialRootLength(path: string): number {
  const root =
    WINDOWS_CREDENTIAL_UNC_ROOT.exec(path)?.[0] ?? win32.parse(path).root;
  if (win32.isAbsolute(path) && win32.relative(root, path) === "") {
    throw new Error(
      "A private Windows directory must be below a volume or share root",
    );
  }
  return root.length;
}

export function windowsCredentialAncestorAclScript(path: string): string {
  const rootLength = windowsCredentialRootLength(path);
  return [
    "$path = $env:CODEX_SECURITY_CREDENTIAL_ACL_PATH",
    // Stop at the drive or UNC share root, then inspect the outermost ancestor first.
    `$ancestors = @(while ($path.Length -gt ${rootLength}) { $parent = Microsoft.PowerShell.Management\\Split-Path -Path $path -Parent; if (-not $parent -or $parent -eq $path) { break }; $parent; $path = $parent })`,
    "for ($i = $ancestors.Count - 1; $i -ge 0; $i--) { Write-CredentialAcl $ancestors[$i] }",
  ].join("\n");
}

export async function inspectWindowsCredentialAclSnapshot(
  path: string,
  currentUserSid: string,
  options: {
    command: string;
    args: readonly string[];
    environment?: NodeJS.ProcessEnv;
    resolvedAliases?: Readonly<Record<string, string>>;
    resolveDescriptorAliases?: (descriptor: string) => Promise<void>;
    currentGroupSids?: ReadonlySet<string>;
  },
): Promise<{
  home: WindowsCredentialAcl;
  descendantsArePrivate: boolean;
}> {
  const rootLength = windowsCredentialRootLength(path);
  const ancestors: string[] = [];
  let ancestor = win32.dirname(path);
  while (true) {
    ancestors.push(ancestor);
    const parent = win32.dirname(ancestor);
    if (ancestor.length <= rootLength || ancestor === parent) break;
    ancestor = parent;
  }
  ancestors.reverse();

  for (let attempt = 0; attempt < 3; attempt += 1) {
    let home: WindowsCredentialAcl | undefined;
    let descendantsArePrivate = true;
    let inspected = 0;
    let completed = false;
    try {
      await streamWindowsCredentialAclDescriptors(
        options.command,
        options.args,
        async (descriptor) => {
          if (completed) {
            throw new Error(
              "Windows credential ACL inspection continued after completion",
            );
          }
          if (descriptor.startsWith(WINDOWS_CREDENTIAL_ACL_COMPLETE_PREFIX)) {
            if (
              descriptor !==
              `${WINDOWS_CREDENTIAL_ACL_COMPLETE_PREFIX}${inspected}`
            ) {
              throw new Error(
                "Windows credential descendants could not be verified",
              );
            }
            completed = true;
            return;
          }
          const index = inspected;
          inspected += 1;
          await options.resolveDescriptorAliases?.(descriptor);

          if (index < ancestors.length) {
            const ancestorPath = ancestors[index]!;
            try {
              const ancestor = inspectWindowsCredentialAcl(
                descriptor,
                currentUserSid,
                {
                  currentGroupSids: options.currentGroupSids,
                  resolvedAliases: options.resolvedAliases,
                  scope: "ancestor",
                },
              );
              if (ancestor.untrustedPrincipals.length !== 0) {
                throw new Error(
                  "Windows credential-home ancestor allows another identity to replace the directory",
                );
              }
            } catch (error) {
              let guidance =
                "Choose a location outside this ancestor with trusted ownership and permissions.";
              if (index === 0) {
                guidance = WINDOWS_CREDENTIAL_UNC_ROOT.test(
                  win32.toNamespacedPath(ancestorPath),
                )
                  ? "This share root is unsupported. Choose a location outside this share with trusted ownership and permissions."
                  : "This volume root is unsupported. Choose a location on a volume with trusted ancestry; another directory on the same volume will not resolve this.";
              }
              throw new Error(
                `Windows private-directory ancestor could not be trusted: ${ancestorPath}. ${errorMessage(error)}. ${guidance}`,
                { cause: error },
              );
            }
            return;
          }

          if (index === ancestors.length) {
            try {
              home = inspectWindowsCredentialAcl(descriptor, currentUserSid, {
                currentGroupSids: options.currentGroupSids,
                resolvedAliases: options.resolvedAliases,
              });
            } catch (error) {
              if (error instanceof UntrustedWindowsCredentialOwnerError) {
                throw new RepairableWindowsCredentialOwnerError(error);
              }
              throw new RepairableWindowsCredentialAclError(error);
            }
            return;
          }

          const descendant = inspectWindowsCredentialAcl(
            descriptor,
            currentUserSid,
            {
              currentGroupSids: options.currentGroupSids,
              resolvedAliases: options.resolvedAliases,
              scope: "file",
            },
          );
          if (
            !descendant.grantsCurrentUserAccess ||
            descendant.untrustedPrincipals.length !== 0
          ) {
            descendantsArePrivate = false;
          }
        },
        { environment: options.environment },
      );
    } catch (error) {
      if (error instanceof WindowsCredentialDescendantsChangedError) continue;
      throw error;
    }
    if (inspected <= ancestors.length) {
      throw new Error("Windows credential-home ancestry could not be verified");
    }
    if (!completed) {
      throw new Error("Windows credential descendants could not be verified");
    }
    if (home === undefined) {
      throw new Error("Windows credential ACL could not be verified");
    }
    return { home, descendantsArePrivate };
  }
  throw new Error("Windows credential descendants could not be verified");
}

/** A file server may add its own groups to the client's token. */
export async function isLocalWindowsCredentialVolume(
  path: string,
  readDriveType: (drive: string) => Promise<string>,
): Promise<boolean> {
  const drive = /^\\\\[?.]\\([A-Z]:)\\/iu.exec(
    win32.toNamespacedPath(path),
  )?.[1];
  if (!drive) return false;
  // Win32_LogicalDisk reports removable, local disk, and RAM disk as 2, 3, 6.
  return ["2", "3", "6"].includes((await readDriveType(drive)).trim());
}

/** Keep every token group, including groups used only for deny ACEs. */
export function parseWindowsTokenGroupSids(output: string): Set<string> {
  const groups = new Set<string>();
  for (const row of output.trim().split(/\r?\n/u)) {
    const sid =
      /^"(?:[^"]|"")*","(?:[^"]|"")*","(S-1-(?:\d+-)*\d+)","(?:[^"]|"")*"$/u.exec(
        row,
      )?.[1];
    if (!sid) throw new Error("Unable to identify Windows token group SIDs");
    groups.add(sid);
  }
  return groups;
}

async function secureWindowsCredentialHome(path: string): Promise<void> {
  const ancestorAclScript = windowsCredentialAncestorAclScript(path);
  const treePath = win32.toNamespacedPath(path);
  const systemRoot = process.env["SystemRoot"] ?? "C:\\Windows";
  const systemDirectory = join(systemRoot, "System32");
  const powershellDirectory = join(
    systemDirectory,
    "WindowsPowerShell",
    "v1.0",
  );
  const powershell = join(powershellDirectory, "powershell.exe");
  const powershellArgs = [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-Command",
  ];
  const inheritedEnvironment = Object.fromEntries(
    Object.entries(process.env).filter(
      ([name]) => name.toUpperCase() !== "PSMODULEPATH",
    ),
  );
  const processOptions = {
    env: {
      ...inheritedEnvironment,
      CODEX_SECURITY_CREDENTIAL_ACL_PATH: path,
      CODEX_SECURITY_CREDENTIAL_TREE_PATH: treePath,
      PSModulePath: join(powershellDirectory, "Modules"),
    },
    encoding: "utf8" as const,
    windowsHide: true,
    maxBuffer: 1024 * 1024,
  };
  const identity = await execFile(
    join(systemDirectory, "whoami.exe"),
    ["/user", "/fo", "csv", "/nh"],
    processOptions,
  );
  const sid = /^"(?:[^"]|"")*","(S-1-(?:\d+-)*\d+)"$/u.exec(
    identity.stdout.trim(),
  )?.[1];
  if (sid === undefined) {
    throw new Error("Unable to identify the current Windows user SID");
  }

  // Signed built-in cmdlets remain available under ConstrainedLanguage;
  // arbitrary .NET constructors, static methods, and SID translation do not.
  // Enumerate and count ACLs in the same process: parallel startup can create
  // or remove private cache and lock files while this traversal is running.
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "$script:descriptorCount = 0",
    "function Write-CredentialAcl($path) {",
    "  $descriptors = @(Microsoft.PowerShell.Security\\Get-Acl -LiteralPath $path | Microsoft.PowerShell.Utility\\Select-Object -ExpandProperty Sddl)",
    "  if ($descriptors.Count -ne @($path).Count) { throw 'Windows credential ACL could not be verified' }",
    "  foreach ($descriptor in $descriptors) { if (-not $descriptor) { throw 'Windows credential ACL could not be verified' }; $script:descriptorCount += 1; $descriptor }",
    "}",
    "function Read-CredentialDescendants($path) {",
    "  try { $entries = @(Microsoft.PowerShell.Management\\Get-ChildItem -LiteralPath $path -Force) } catch {",
    // A child can disappear while an existing directory is being enumerated.
    // Retry that incomplete listing before accepting a vanished descendant.
    `    if ($_.FullyQualifiedErrorId -eq 'System.IO.FileNotFoundException,Microsoft.PowerShell.Commands.GetChildItemCommand') { exit ${WINDOWS_CREDENTIAL_DESCENDANTS_CHANGED_EXIT_CODE} }`,
    "    if ($path -ne $env:CODEX_SECURITY_CREDENTIAL_TREE_PATH -and $_.CategoryInfo.Category -eq 'ObjectNotFound') { return }",
    "    throw",
    "  }",
    "  $children = @(foreach ($entry in $entries) {",
    "    if (($entry.Attributes -band 1024) -and ($entry.LinkType -in @('SymbolicLink', 'Junction'))) { throw 'Windows credential home contains a symbolic link or junction' }",
    "    if ($entry.PSObject.TypeNames -notcontains 'System.IO.DirectoryInfo' -and $entry.PSObject.TypeNames -notcontains 'System.IO.FileInfo') { throw 'Windows credential home contains an unsafe entry' }",
    // Keep the extended-length path when Windows PowerShell returns child names.
    '    "$path\\$($entry.Name)"',
    "  })",
    "  if ($children.Count -eq 0) { return }",
    "  try { Write-CredentialAcl $children } catch {",
    // A vanished path is the only reason to retry the batch one child at a time.
    "    if ($_.FullyQualifiedErrorId -notlike 'GetAcl_PathNotFound,*') { throw }",
    "    for ($i = 0; $i -lt $children.Count; $i++) {",
    "      try { Write-CredentialAcl $children[$i] } catch {",
    "        if ($_.FullyQualifiedErrorId -notlike 'GetAcl_PathNotFound,*') { throw }",
    "        $children[$i] = $null",
    "      }",
    "    }",
    "  }",
    "  for ($i = 0; $i -lt $children.Count; $i++) {",
    "    if ($children[$i] -and $entries[$i].PSIsContainer) { Read-CredentialDescendants $children[$i] }",
    "  }",
    "}",
    ancestorAclScript,
    "Write-CredentialAcl $env:CODEX_SECURITY_CREDENTIAL_ACL_PATH",
    "try { Read-CredentialDescendants $env:CODEX_SECURITY_CREDENTIAL_TREE_PATH } catch {",
    // Either a batch or a single-child Get-Acl may report an incomplete listing.
    `  if ($_.FullyQualifiedErrorId -in @('System.IO.FileNotFoundException,Microsoft.PowerShell.Commands.GetAclCommand', 'GetAcl_PathNotFound_Exception,Microsoft.PowerShell.Commands.GetAclCommand')) { exit ${WINDOWS_CREDENTIAL_DESCENDANTS_CHANGED_EXIT_CODE} }`,
    "  throw",
    "}",
    `"${WINDOWS_CREDENTIAL_ACL_COMPLETE_PREFIX}$script:descriptorCount"`,
  ].join("\n");
  const resolvePrincipalScript = [
    "$ErrorActionPreference = 'Stop'",
    "$descriptor = 'O:' + $env:CODEX_SECURITY_CREDENTIAL_PRINCIPAL + 'G:SYD:(A;;GA;;;SY)'",
    "Microsoft.PowerShell.Utility\\ConvertFrom-SddlString -Sddl $descriptor | Microsoft.PowerShell.Utility\\Select-Object -ExpandProperty RawDescriptor | Microsoft.PowerShell.Utility\\Select-Object -ExpandProperty Owner | Microsoft.PowerShell.Utility\\Select-Object -ExpandProperty Value",
  ].join("; ");
  const resolvedAliases: Record<string, string> = {};
  function requireNumericSid(value: string): string {
    if (!WINDOWS_SID.test(value))
      throw new Error(
        "Windows credential ACL contains an unresolvable identity",
      );
    return value;
  }
  const resolvePrincipal = async (principal: string): Promise<void> => {
    if (
      !/^[A-Z]{2}$/u.test(principal) ||
      WINDOWS_PRINCIPAL_ALIASES[principal] !== undefined ||
      resolvedAliases[principal] !== undefined
    ) {
      return;
    }
    const resolved = await execFile(
      powershell,
      [...powershellArgs, resolvePrincipalScript],
      {
        ...processOptions,
        env: {
          ...processOptions.env,
          CODEX_SECURITY_CREDENTIAL_PRINCIPAL: principal,
        },
      },
    );
    resolvedAliases[principal] = requireNumericSid(resolved.stdout.trim());
  };
  const loadLocalGroupSids = async (): Promise<Set<string> | null> => {
    const local = await isLocalWindowsCredentialVolume(
      treePath,
      async (drive) => {
        const volume = await execFile(
          powershell,
          [
            ...powershellArgs,
            `$ErrorActionPreference = 'Stop'; (CimCmdlets\\Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID = '${drive}'").DriveType`,
          ],
          processOptions,
        );
        return volume.stdout;
      },
    );
    if (!local) return null;
    const groups = await execFile(
      join(systemDirectory, "whoami.exe"),
      ["/groups", "/fo", "csv", "/nh"],
      processOptions,
    );
    return parseWindowsTokenGroupSids(groups.stdout);
  };
  let currentGroupSids: Set<string> | null | undefined;
  const resolveDescriptorAliases = async (
    descriptor: string,
  ): Promise<void> => {
    const header = WINDOWS_SECURITY_DESCRIPTOR.exec(descriptor.trim());
    if (header === null) return;
    await resolvePrincipal(header[1]!);
    let remaining = header[3]!;
    while (remaining.startsWith("(")) {
      const { rule, rest } = windowsSecurityDescriptorRule(remaining);
      const fields = rule.split(";");
      const principal = fields[5];
      if (principal !== undefined) {
        await resolvePrincipal(principal);
        const trustee = resolvedAliases[principal] ?? principal;
        if (
          currentGroupSids === undefined &&
          ["D", "OD", "XD"].includes(fields[0]!) &&
          trustee !== sid &&
          WINDOWS_ACCOUNT_SID.test(trustee)
        ) {
          currentGroupSids = await loadLocalGroupSids();
        }
      }
      remaining = rest;
    }
  };
  let descendantsArePrivate = true;
  const readAcl = async (): Promise<WindowsCredentialAcl> => {
    const snapshot = await inspectWindowsCredentialAclSnapshot(path, sid, {
      command: powershell,
      args: [...powershellArgs, script],
      environment: processOptions.env,
      get currentGroupSids() {
        return currentGroupSids ?? undefined;
      },
      resolvedAliases,
      resolveDescriptorAliases,
    });
    descendantsArePrivate = snapshot.descendantsArePrivate;
    return snapshot.home;
  };

  const icacls = (target: string, ...args: string[]) =>
    execFile(
      join(systemDirectory, "icacls.exe"),
      [target, ...args],
      processOptions,
    );
  const installTrustedAcl = () =>
    icacls(
      path,
      "/inheritance:r",
      "/grant:r",
      `*${sid}:(OI)(CI)F`,
      `*${WINDOWS_SYSTEM_SID}:(OI)(CI)F`,
      `*${WINDOWS_ADMINISTRATORS_SID}:(OI)(CI)F`,
    );
  let existing: WindowsCredentialAcl | undefined;
  for (let attempt = 0; existing === undefined && attempt < 3; attempt += 1) {
    try {
      existing = await readAcl();
    } catch (error) {
      if (error instanceof RepairableWindowsCredentialOwnerError) {
        await icacls(path, "/setowner", `*${sid}`);
      } else if (error instanceof RepairableWindowsCredentialAclError) {
        await installTrustedAcl();
      } else {
        throw error;
      }
    }
  }
  if (existing === undefined) {
    throw new Error("Windows credential ACL could not be repaired");
  }
  if (
    existing.grantsCurrentUserAccess &&
    existing.untrustedPrincipals.length === 0 &&
    !existing.protected
  ) {
    await icacls(path, "/inheritance:d");
    existing = await readAcl();
  }

  let verified = existing;
  if (
    !verified.protected ||
    !verified.grantsCurrentUserAccess ||
    verified.untrustedPrincipals.length !== 0
  ) {
    await installTrustedAcl();
    verified = await readAcl();
    for (const [remove, principals] of [
      ["/remove:g", verified.untrustedPrincipals],
      ["/remove:d", verified.deniedPrincipals],
    ] as const) {
      for (const principal of principals)
        await icacls(path, remove, `*${requireNumericSid(principal)}`);
    }
    if (
      verified.untrustedPrincipals.length !== 0 ||
      verified.deniedPrincipals.length !== 0
    ) {
      verified = await readAcl();
    }
  }
  if (!verified.protected) {
    throw new Error("Windows credential ACL still inherits access rules");
  }
  if (!verified.grantsCurrentUserAccess) {
    throw new Error(
      "Windows credential ACL does not grant the current user access",
    );
  }
  if (verified.untrustedPrincipals.length !== 0) {
    throw new Error("Windows credential ACL grants access to another identity");
  }
  if (!descendantsArePrivate) {
    await icacls(join(treePath, "*"), "/reset", "/t", "/q");
    await readAcl();
    if (!descendantsArePrivate) {
      throw new Error("Windows credential descendants remain accessible");
    }
  }
}

export interface RuntimeDatabase {
  exec(sql: string): unknown;
  prepare(sql: string): {
    all(...parameters: (string | number)[]): unknown[];
    finalize?(): void;
  };
  close(): void;
}

export function sqliteDatabaseOpener(
  access: "read-existing" | "read-write" = "read-write",
) {
  const require = createRequire(import.meta.url);
  const bun = process.versions["bun"] !== undefined;
  const Database = (
    bun ? require("bun:sqlite").Database : require("node:sqlite").DatabaseSync
  ) as new (filename: string, options?: object) => RuntimeDatabase;

  return (path: string): RuntimeDatabase => {
    const filename = sqliteFilename(path);
    if (access === "read-write") return new Database(filename);
    // Apple's SQLite requires write access to initialize missing WAL sidecars.
    // The history reader sets PRAGMA query_only on this existing-file connection.
    return new Database(
      filename,
      bun
        ? {
            readonly: process.platform !== "darwin",
            readwrite: process.platform === "darwin",
            create: false,
          }
        : { readOnly: true },
    );
  };
}

function sqliteBusy(error: unknown): boolean {
  return (
    isRecord(error) &&
    (error["errcode"] === 5 || error["code"] === "SQLITE_BUSY")
  );
}

export async function acquireScanExecutionLock(
  stateDirectory: string,
  scanDirectory: string,
): Promise<() => void> {
  const directory = join(stateDirectory, "scan-locks");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await requirePrivateDirectory(await stat(directory), directory, "scan locks");
  const identity = createHash("sha256").update(scanDirectory).digest("hex");
  const path = join(directory, `${identity}.sqlite3`);
  const database = sqliteDatabaseOpener()(path);
  try {
    if (process.platform !== "win32") await chmod(path, 0o600);
    database.exec("PRAGMA busy_timeout = 0");
    database.exec("BEGIN EXCLUSIVE");
  } catch (error) {
    database.close();
    if (sqliteBusy(error)) {
      throw new CodexSecurityError(
        "This scan is already running in another CLI or SDK call.",
      );
    }
    throw error;
  }
  return () => database.close();
}

export async function withCredentialHomeLock<T>(
  codexHome: string,
  operation: () => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  const release = await acquireCodexSecurityCredentialHomeLock(
    codexHome,
    signal,
  );
  try {
    return await operation();
  } finally {
    await release();
  }
}

export async function acquireCodexSecurityCredentialHomeLock(
  codexHome: string,
  signal?: AbortSignal,
  securityOptions: Parameters<typeof requirePrivateDirectory>[3] = {},
): Promise<() => Promise<void>> {
  throwIfSignalAborted(signal);
  const homeMetadata = await requireSecureCredentialHome(
    codexHome,
    securityOptions,
  );
  const expectedDevice = homeMetadata.dev;
  const expectedInode = homeMetadata.ino;
  const lock = join(codexHome, CREDENTIAL_LOCK_NAME);
  const ownerPath = join(lock, "owner.json");
  const token = randomUUID();
  const databasePath = join(codexHome, CREDENTIAL_LOCK_DATABASE);
  const existingDatabaseMetadata = await lstat(databasePath).catch(
    nullIfMissingFileError,
  );
  if (existingDatabaseMetadata !== null) {
    requireCredentialLockDatabaseFile(existingDatabaseMetadata, databasePath);
  }
  const openDatabase = sqliteDatabaseOpener();
  // Let SQLite create a missing guard so no separate descriptor can close after
  // another connection acquires its process-owned POSIX lock. Keep the guard
  // across releases so every contender locks the same inode.
  const database = openDatabase(databasePath);
  let databaseLocked = false;

  try {
    // SQLite creates new databases with the process umask. Tighten or repair
    // the guard synchronously before yielding so concurrent first-time callers
    // cannot reject its transient mode. The credential home is already private,
    // and the pre-open check above rejects linked existing files.
    if (process.platform !== "win32") chmodSync(databasePath, 0o600);
    const databaseMetadata = await lstat(databasePath);
    requireCredentialLockDatabaseFile(databaseMetadata, databasePath);
    if (
      existingDatabaseMetadata !== null &&
      (databaseMetadata.dev !== existingDatabaseMetadata.dev ||
        databaseMetadata.ino !== existingDatabaseMetadata.ino)
    ) {
      throw new OutputDirectoryError(
        `Codex Security credential-home lock changed while opening it: ${databasePath}`,
      );
    }
    requirePrivateCredentialFile(databaseMetadata, databasePath);

    database.exec("PRAGMA busy_timeout = 0");
    while (true) {
      throwIfSignalAborted(signal);
      await requireSecureCredentialHome(codexHome, {
        ...securityOptions,
        expectedDevice,
        expectedInode,
        validateWindowsAcl: false,
      });
      if (!databaseLocked) {
        try {
          database.exec("BEGIN EXCLUSIVE");
        } catch (error) {
          if (!sqliteBusy(error)) {
            throw error;
          }
          await delay(CREDENTIAL_LOCK_POLL_MILLISECONDS, undefined, { signal });
          continue;
        }
        const currentDatabase = await lstat(databasePath);
        if (
          currentDatabase.dev !== databaseMetadata.dev ||
          currentDatabase.ino !== databaseMetadata.ino
        ) {
          throw new OutputDirectoryError(
            `Codex Security credential-home lock changed while acquiring it: ${databasePath}`,
          );
        }
        databaseLocked = true;
      }
      if ((await lstat(lock).catch(nullIfMissingFileError)) !== null) {
        if (await recoverStaleCredentialHomeLock(lock)) continue;
        await delay(CREDENTIAL_LOCK_POLL_MILLISECONDS, undefined, { signal });
        continue;
      }
      await requireSecureCredentialHome(codexHome, {
        ...securityOptions,
        expectedDevice,
        expectedInode,
      });
      try {
        await mkdir(lock, { mode: 0o700 });
      } catch (error) {
        if (nodeErrorCode(error) !== "EEXIST") throw error;
        if (await recoverStaleCredentialHomeLock(lock)) continue;
        await delay(CREDENTIAL_LOCK_POLL_MILLISECONDS, undefined, { signal });
        continue;
      }

      try {
        await writeFile(
          ownerPath,
          `${JSON.stringify({ pid: process.pid, token, protocol: "sqlite" })}\n`,
          { encoding: "utf8", flag: "wx", mode: 0o600 },
        );
      } catch (error) {
        await rm(lock, { recursive: true, force: true }).catch(() => undefined);
        throw error;
      }

      // Released clients use the directory heartbeat instead of the SQLite lock.
      const heartbeat = setInterval(async () => {
        try {
          const now = new Date();
          await utimes(lock, now, now);
        } catch {}
      }, CREDENTIAL_LOCK_HEARTBEAT_MILLISECONDS);
      heartbeat.unref();

      let released = false;
      return async () => {
        if (released) return;
        released = true;
        try {
          await requireSecureCredentialHome(codexHome, {
            ...securityOptions,
            expectedDevice,
            expectedInode,
          });
          const owner = JSON.parse(await readFile(ownerPath, "utf8")) as {
            token?: unknown;
          };
          if (owner.token !== token) {
            throw new PluginBootstrapError(
              "The Codex Security credential-home lock is no longer owned by this scan.",
            );
          }
          await rm(lock, { recursive: true, force: true });
        } finally {
          clearInterval(heartbeat);
          database.close();
        }
      };
    }
  } catch (error) {
    database.close();
    throw error;
  }
}

function requireCredentialLockDatabaseFile(
  metadata: Stats,
  path: string,
): void {
  if (!metadata.isFile() || metadata.nlink !== 1) {
    throw new OutputDirectoryError(
      `Codex Security credential-home lock must be a regular file, not a symlink or hard link: ${path}`,
    );
  }
}

async function recoverStaleCredentialHomeLock(lock: string): Promise<boolean> {
  const metadata = await lstat(lock).catch(nullIfMissingFileError);
  if (metadata === null) return true;
  if (!metadata.isDirectory()) {
    throw new OutputDirectoryError(
      `Codex Security credential-home lock is not a directory: ${lock}`,
    );
  }

  let owner: unknown;
  try {
    owner = JSON.parse(await readFile(join(lock, "owner.json"), "utf8"));
  } catch (error) {
    if (nodeErrorCode(error) !== "ENOENT" && !(error instanceof SyntaxError)) {
      throw error;
    }
  }

  // We hold the SQLite transaction, so a record from that protocol is orphaned.
  // Older clients only record a PID: a live one must be respected at any age.
  if (!isRecord(owner) || owner["protocol"] !== "sqlite") {
    // Only positive signed-32-bit PIDs identify an owner. Other values can name
    // process groups or fail argument validation, so use the stale-age check.
    const ownerPid = isRecord(owner) ? owner["pid"] : undefined;
    if (
      typeof ownerPid === "number" &&
      Number.isInteger(ownerPid) &&
      ownerPid > 0 &&
      ownerPid <= MAX_PROCESS_ID
    ) {
      try {
        process.kill(ownerPid, 0);
        return false;
      } catch (error) {
        if (nodeErrorCode(error) === "EPERM") return false;
        if (nodeErrorCode(error) !== "ESRCH") throw error;
      }
    } else if (
      Date.now() - metadata.mtimeMs <
      INCOMPLETE_CREDENTIAL_LOCK_MILLISECONDS
    ) {
      return false;
    }
  }

  const quarantine = `${lock}.stale-${randomUUID()}`;
  try {
    await rename(lock, quarantine);
  } catch (error) {
    if (nodeErrorCode(error) === "ENOENT") return true;
    throw error;
  }
  await rm(quarantine, { recursive: true, force: true });
  return true;
}

function sameInode(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

/** Distinguish two hard links from two paths to the same directory entry. */
async function hasSeparateAmbientLink(
  localPath: string,
  ambientHome: string,
): Promise<boolean> {
  try {
    const local = await lstat(localPath, { bigint: true });
    if (!local.isFile() || local.nlink < 2n || local.ino === 0n) return false;
    const ambient = await lstat(join(ambientHome, "auth.json"), {
      bigint: true,
    });
    if (!ambient.isFile() || !sameInode(local, ambient)) return false;
    const [localDir, ambientDir] = await Promise.all([
      stat(dirname(localPath), { bigint: true }),
      stat(ambientHome, { bigint: true }),
    ]);
    return (
      localDir.ino !== 0n &&
      ambientDir.ino !== 0n &&
      !sameInode(localDir, ambientDir)
    );
  } catch {
    // Without a verified second link, leave logout to the configured native store.
    return false;
  }
}

/** Native Codex defaults to file storage when the managed home has no setting. */
async function credentialStore(home: string): Promise<unknown> {
  const contents = await readFile(join(home, "config.toml"), "utf8").catch(
    nullIfMissingFileError,
  );
  return contents === null
    ? "file"
    : (parse(contents, { integersAsBigInt: "asNeeded" })[
        "cli_auth_credentials_store"
      ] ?? "file");
}

async function hasCredentialFile(home: string): Promise<boolean> {
  const file = await lstat(join(home, "auth.json")).catch(
    nullIfMissingFileError,
  );
  return file?.isFile() === true;
}

function savedKeyringHistory(home: string) {
  return readFile(join(home, KEYRING_LOGIN), "utf8").catch(
    nullIfMissingFileError,
  );
}

function canUseKeyring(store: unknown): boolean {
  return store === "auto" || store === "keyring";
}

function keyringHistory(
  saved: string | null,
  store: unknown,
  hasFile: boolean,
) {
  if (saved === "keyring" || saved === "pending") return "keyring";
  // On upgrade, a prior keyring login may exist. Auto can also move a file
  // credential into the keyring on refresh, removing auth.json.
  if (
    (saved === null && canUseKeyring(store)) ||
    (saved === "file" && store === "auto" && !hasFile)
  )
    return "keyring";
  return hasFile ? "file" : "none";
}

async function rememberStoredFile(home: string) {
  if ((await savedKeyringHistory(home)) === "none") {
    await writePrivateConfig(join(home, KEYRING_LOGIN), "file");
  }
}

/** Arm logout before a native login can persist a keyring grant and be interrupted. */
export async function beginCredentialLogin(home: string): Promise<void> {
  const store = await credentialStore(home);
  if (!canUseKeyring(store)) return;
  const marker = join(home, KEYRING_LOGIN);
  const saved = await savedKeyringHistory(home);
  const present = await hasCredentialFile(home);
  const previous = keyringHistory(saved, store, present);
  // Only this login's successful file fallback can discharge a new pending marker.
  const next = previous === "keyring" ? "keyring" : "pending";
  if (next !== saved) await writePrivateConfig(marker, next);
}

/** Is the managed file the active login, or a known-empty file destination for an ambient import? */
export async function credentialHomeUsesFileStorage(
  home: string,
  options: { allowAmbientImport?: boolean } = {},
): Promise<boolean> {
  const store = await credentialStore(home);
  if (store !== "auto") return store === "file";
  const saved = await savedKeyringHistory(home);
  const hasFile = await hasCredentialFile(home);
  return hasFile
    ? saved === "file"
    : options.allowAmbientImport === true && saved === "none";
}

/** Preserve credential provenance before a scan or sign-in replaces the shared config. */
export async function writeCredentialHomeConfig(
  home: string,
  config: JsonObject,
): Promise<void> {
  const old = await credentialStore(home);
  if (
    canUseKeyring(old) ||
    canUseKeyring(config["cli_auth_credentials_store"])
  ) {
    const marker = join(home, KEYRING_LOGIN);
    const saved = await savedKeyringHistory(home);
    const hasFile = await hasCredentialFile(home);
    const observed = keyringHistory(saved, old, hasFile);
    if (observed !== saved) await writePrivateConfig(marker, observed);
  }
  await writeCodexConfig(join(home, "config.toml"), config);
}

/** Run under the credential-home lock so status cannot reimport the sign-in during logout. */
export async function logoutCredentialHome<T extends number | void>(
  home: string,
  ambientHome: string,
  nativeLogout: (store?: string) => Promise<T>,
  onLoggedOut?: () => void,
): Promise<T> {
  const localPath = join(home, "auth.json");
  const shared = await hasSeparateAmbientLink(localPath, ambientHome);
  let recorded = false;
  const recordLogout = async () => {
    if (recorded) return;
    await setCodexSecurityCredentialLogout(home, true);
    if (shared) await rm(localPath);
    onLoggedOut?.();
    recorded = true;
  };

  // Detach before native logout can revoke a shared token, even if native cleanup fails.
  if (shared) await recordLogout();
  const marker = join(home, KEYRING_LOGIN);
  const previous = await savedKeyringHistory(home);
  const active = await credentialStore(home);
  const hasFile = await hasCredentialFile(home);
  const keyring =
    keyringHistory(previous, active, hasFile || shared) === "keyring";
  if (keyring && hasFile) {
    // Native keyring logout also unlinks the file, but only revokes the token it loads.
    const status = await nativeLogout(active === "file" ? undefined : "file");
    if (status !== undefined && status !== 0) return status;
    // A retry must not re-import ambient credentials after the file was revoked.
    await recordLogout();
  }
  let override: string | undefined;
  if (keyring && !canUseKeyring(active)) override = "keyring";
  else if (!keyring && active !== "file" && (hasFile || canUseKeyring(active)))
    override = "file";
  const status = await nativeLogout(override);
  if (status === undefined || status === 0) {
    await recordLogout();
    if (canUseKeyring(active)) await writePrivateConfig(marker, "none");
    else await rm(marker, { force: true });
  }
  return status;
}

export async function setCodexSecurityCredentialLogout(
  codexHome: string,
  loggedOut: boolean,
): Promise<void> {
  await requireSecureCredentialHome(codexHome);
  const marker = join(codexHome, CREDENTIAL_LOGOUT_MARKER);
  if (!loggedOut) {
    // Native auto removes auth.json on keyring success and leaves it on file fallback.
    const store = await credentialStore(codexHome);
    const history = join(codexHome, KEYRING_LOGIN);
    if (
      store === "keyring" ||
      (store === "auto" && !(await hasCredentialFile(codexHome)))
    ) {
      await writePrivateConfig(history, "keyring");
    } else if (
      store === "auto" &&
      (await savedKeyringHistory(codexHome)) === "pending"
    ) {
      await writePrivateConfig(history, "file");
    }
    await rm(marker, { force: true });
    return;
  }

  await writePrivateConfig(marker, "logged out\n");
}

export async function codexSecurityCredentialAllowsAmbientImport(
  codexHome: string,
): Promise<boolean> {
  await requireSecureCredentialHome(codexHome);
  try {
    if (!(await lstat(join(codexHome, CREDENTIAL_LOGOUT_MARKER))).isFile()) {
      throw new OutputDirectoryError(
        `Codex Security logout marker is not a regular file: ${codexHome}`,
      );
    }
    return false;
  } catch (error) {
    if (nodeErrorCode(error) === "ENOENT") return true;
    throw error;
  }
}

export async function codexSecurityHasStoredFileCredentials(
  codexHome: string,
): Promise<boolean> {
  await requireSecureCredentialHome(codexHome);
  const path = join(codexHome, "auth.json");
  let metadata: Stats;
  try {
    metadata = await lstat(path);
  } catch (error) {
    if (nodeErrorCode(error) === "ENOENT") return false;
    throw error;
  }
  if (!metadata.isFile()) {
    throw new OutputDirectoryError(
      `Codex Security stored authentication is not a regular file: ${path}`,
    );
  }
  requirePrivateCredentialFile(metadata, path);
  return true;
}

export function requirePrivateCredentialFile(
  metadata: Pick<Stats, "mode" | "uid">,
  path: string,
  effectiveUid = process.geteuid?.(),
): void {
  if (process.platform === "win32") return;
  if ((metadata.mode & 0o077) !== 0) {
    throw new OutputDirectoryError(
      `Codex Security stored authentication must not be accessible to other users: ${path}`,
    );
  }
  if (effectiveUid !== undefined && metadata.uid !== effectiveUid) {
    throw new OutputDirectoryError(
      `Codex Security stored authentication must be owned by the current user: ${path}`,
    );
  }
}

export async function preserveCodexSecurityPluginRegistration(
  codexHome: string,
  config: JsonObject,
): Promise<JsonObject> {
  let existing: unknown;
  try {
    existing = parse(await readFile(join(codexHome, "config.toml"), "utf8"));
  } catch (error) {
    if (nodeErrorCode(error) === "ENOENT") return config;
    throw new PluginBootstrapError(
      "Unable to read the existing Codex Security plugin registration.",
      { cause: error },
    );
  }

  const marketplaces = isRecord(existing)
    ? existing["marketplaces"]
    : undefined;
  const plugins = isRecord(existing) ? existing["plugins"] : undefined;
  const marketplace = isRecord(marketplaces)
    ? marketplaces[MARKETPLACE_NAME]
    : undefined;
  const plugin = isRecord(plugins)
    ? plugins[`${PLUGIN_NAME}@${MARKETPLACE_NAME}`]
    : undefined;
  const source = isRecord(marketplace) ? marketplace["source"] : undefined;
  if (
    !isRecord(marketplace) ||
    marketplace["source_type"] !== "local" ||
    typeof source !== "string" ||
    !(await sameFile(source, join(codexHome, "sdk-marketplace"))) ||
    !isRecord(plugin) ||
    plugin["enabled"] !== true
  ) {
    return config;
  }

  return {
    ...config,
    marketplaces: {
      [MARKETPLACE_NAME]: { source_type: "local", source },
    },
    plugins: {
      [`${PLUGIN_NAME}@${MARKETPLACE_NAME}`]: { enabled: true },
    },
  };
}

export function requireOutputOutsideRepository(
  repository: string,
  outputDirectory: string,
  pathKind: ProtectedScanPathKind = "output",
): void {
  if (
    isWithin(repository, outputDirectory) ||
    ((pathKind === "output" || pathKind === "state") &&
      isWithin(outputDirectory, repository))
  ) {
    throw new OutputInsideProtectedRootError(
      outputDirectory,
      repository,
      pathKind,
    );
  }
}

export function requireOutputOutsideRepositories(
  repositories: readonly string[],
  outputDirectory: string,
  pathKind: ProtectedScanPathKind = "output",
): void {
  for (const repository of repositories)
    requireOutputOutsideRepository(repository, outputDirectory, pathKind);
}

/** Check where the scan will create state and default artifacts without creating them. */
export async function checkScanStorage(
  stateDirectory: string,
  defaultOutputRepository?: string,
): Promise<void> {
  try {
    let root = await canonicalConfigPath(stateDirectory);
    await requireWritableDirectoryOrParent(root);
    if (defaultOutputRepository === undefined) return;

    for (const name of ["scans", safePrefix(defaultOutputRepository)]) {
      root = join(root, name);
      const metadata = await lstat(root).catch(nullIfMissingFileError);
      if (metadata !== null && !metadata.isDirectory()) {
        throw new OutputDirectoryError(
          `Persistent scan output must use real directories: ${root}`,
        );
      }
    }
    await requireWritableDirectoryOrParent(root);
    // New per-scan directories are created beneath this root.
    await requireSecureOutputAncestry(
      join(root, `codex-security-${randomUUID()}`),
    );
  } catch (error) {
    throw new OutputDirectoryError(
      `Cannot use scan state directory ${stateDirectory}. Check CODEX_SECURITY_STATE_DIR: ${errorMessage(error)}`,
      { cause: error },
    );
  }
}

async function requireWritableDirectoryOrParent(path: string): Promise<void> {
  const metadata = await lstat(path).catch(nullIfMissingFileError);
  if (metadata === null) {
    const parent = dirname(path);
    if (parent === path)
      throw new OutputDirectoryError(`Directory does not exist: ${path}`);
    return requireWritableDirectoryOrParent(parent);
  }
  if (!metadata.isDirectory())
    throw new OutputDirectoryError(`Expected a directory: ${path}`);
  await access(path, constants.W_OK | constants.X_OK);
}

export async function preparePersistentOutputRoot(
  stateDirectory: string,
  category: "scans" | "policies" | "validations" | "imports",
  repositoryName: string,
): Promise<string> {
  requireModelSafeOutputDir(stateDirectory);
  await mkdir(stateDirectory, { recursive: true, mode: 0o700 });
  let root = await realpath(stateDirectory);
  for (const directory of [category, safePrefix(repositoryName)]) {
    root = join(root, directory);
    await mkdir(root, { recursive: true, mode: 0o700 });
    if (!(await lstat(root)).isDirectory()) {
      throw new OutputDirectoryError(
        `Persistent ${category === "scans" ? "scan" : category === "policies" ? "policy" : category === "imports" ? "import" : "validation"} output must use real directories: ${root}`,
      );
    }
  }
  return root;
}

const WORKBENCH_ARGUMENTS_PROGRAM = String.raw`
import json, sys
sys.argv[2:] = json.loads(sys.stdin.buffer.readline())
`;
const WORKBENCH_SCRIPT_PROGRAM = String.raw`
import runpy, sys
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
`;

const WORKBENCH_REGISTRATION_PROGRAM = String.raw`
import os, runpy, sys
sys.argv = sys.argv[1:]
def before_output_change():
    with os.fdopen(3, "r+b", buffering=0) as control:
        control.write(b"?")
        if control.read(1) != b"!":
            raise SystemExit("Scan registration canceled before changing the output.")
sys._codex_security_before_output_change = before_output_change
if "--archive-existing" in sys.argv[1:] and "--archived-scan-dir" not in sys.argv[1:]:
    # Released workbenches accept this callback before moving an existing output.
    runpy.run_path(sys.argv[0])["main"](before_archive=before_output_change)
else:
    # A selected plugin keeps its script entrypoint, argv, stdin and stdout.
    runpy.run_path(sys.argv[0], run_name="__main__")
`;

export async function runWorkbench(
  options: Omit<WorkbenchCommandOptions, "python"> & { python?: string },
  args: readonly string[],
  input?: string,
): Promise<JsonObject> {
  const script = join(options.pluginRoot, "scripts", "workbench_db.py");
  const signal = options.signal;
  // Explicitly selected external plugins retain their own workbench protocol.
  const nativeLocalDedupe =
    args[0] === "local-dedupe" &&
    (await sameFile(options.pluginRoot, await bundledPluginRoot()));
  const run = async (
    arguments_: readonly string[],
    input?: string,
    registrationHandshake = false,
  ): Promise<string> => {
    const native =
      nativeLocalDedupe ||
      [
        "database-info",
        "store-findings",
        "list-stored-findings",
        "store-external-findings",
        "read-external-findings",
        "list-external-imports",
        "record-external-finding-publications",
        "list-external-finding-publications",
        "find-potential-duplicates",
        "store-dedupe-groups",
        "list-dedupe-groups",
        "dashboard",
        "severity-classification",
        "read-severity-classification",
      ].includes(arguments_[0] ?? "");
    const node =
      native && process.versions["bun"]
        ? await resolveTrustedExecutable("node", options.environment, [
            process.cwd(),
            options.currentDirectory ?? process.cwd(),
            ...(typeof options.protectedRoot === "string"
              ? [options.protectedRoot]
              : (options.protectedRoot ?? [])),
          ])
        : undefined;
    if (node === null) {
      throw new Error("Node.js is not available on a trusted PATH.");
    }
    const command = native
      ? (node?.executable ?? process.execPath)
      : (options.python ??= await resolvePluginPython({
          environment: options.environment,
          protectedRoot: options.protectedRoot,
          currentDirectory: options.currentDirectory,
          signal: options.signal,
        }));
    const stateDirectory = native
      ? (options.stateDirectory ??
        codexSecurityStateDirectory(options.environment))
      : undefined;
    // Validate one JSON document before framing its unchanged source as payload.
    if (nativeLocalDedupe && input !== undefined) JSON.parse(input);
    const result = await runCodexCommand(
      { command },
      native
        ? [join(options.pluginRoot, "mcp", "helpers.mjs"), ...arguments_]
        : [
            "-I",
            "-X",
            "utf8",
            "-B",
            "-c",
            WORKBENCH_ARGUMENTS_PROGRAM +
              (registrationHandshake
                ? WORKBENCH_REGISTRATION_PROGRAM
                : WORKBENCH_SCRIPT_PROGRAM),
            script,
          ],
      pluginHelperEnvironment({
        ...(node?.environment ?? options.environment),
        // Python's compressed-rollout reader needs the selected Node even when
        // this SDK was launched by absolute path without Node on PATH.
        ...(!native &&
        !process.versions["bun"] &&
        environmentValue(options.environment, "CODEX_MCP_NODE_PATH") ===
          undefined
          ? { CODEX_MCP_NODE_PATH: process.execPath }
          : {}),
        _CODEX_SECURITY_INSTRUCTION_ROOT:
          arguments_[0] === "register-cli-scan"
            ? (options.instructionRoot ?? options.pluginRoot)
            : undefined,
      }),
      // The SDK owns configuration normalization; the helper receives its resolved location.
      nativeLocalDedupe
        ? `{"stateDirectory":${JSON.stringify(stateDirectory)},"payload":${input ?? "null"}}`
        : native
          ? JSON.stringify(
              arguments_[0] === "database-info"
                ? stateDirectory
                : {
                    stateDirectory,
                    payload:
                      input === undefined ? undefined : JSON.parse(input),
                  },
            )
          : input,
      signal,
      {
        registrationHandshake,
        // Frame Python arguments on stdin to preserve NUL and long diagnostics.
        stdinPrefix: native
          ? undefined
          : `${JSON.stringify(arguments_.map((argument) => argument.toWellFormed()))}\n`,
      },
    );
    if (!result.success) {
      throw new Error(
        result.stderr.trim() ||
          result.stdout.trim() ||
          `Workbench exited with status ${result.exitCode}.`,
      );
    }
    return result.stdout;
  };
  let stdout: string;
  try {
    const registrationHandshake =
      signal !== undefined &&
      args[0] === "register-cli-scan" &&
      (process.platform === "win32" ||
        (args.includes("--archive-existing") &&
          !args.includes("--archived-scan-dir")));
    try {
      stdout = await run(args, input, registrationHandshake);
    } catch (error) {
      const focusedIndex = args.indexOf("--after-scan-id");
      if (
        args[0] !== "list-unmatched-scan-pairs" ||
        focusedIndex === -1 ||
        !/unrecognized arguments: --after-scan-id(?:\s+\S+)?$/u.test(
          processErrorDetail(error),
        )
      )
        throw error;
      options.signal?.throwIfAborted();
      const legacyArgs = [...args];
      legacyArgs.splice(focusedIndex, 2);
      stdout = await run(legacyArgs, input, registrationHandshake);
    }
  } catch (error) {
    if (options.signal?.aborted) throw error;
    const detail = processErrorDetail(error);
    const failure =
      options.failureMessage ?? "Could not run the Codex Security workbench";
    throw new CodexSecurityError(`${failure}: ${detail}`, { cause: error });
  }
  let result: unknown;
  try {
    result = JSON.parse(stdout);
  } catch (error) {
    throw new CodexSecurityError(
      "The Codex Security workbench returned invalid JSON.",
      { cause: error },
    );
  }
  if (!isRecord(result)) {
    throw new CodexSecurityError(
      "The Codex Security workbench returned an invalid response.",
    );
  }
  return result as JsonObject;
}

export async function resolveScanOutputPath(
  outputDirectory: string,
  validateTraversalLink?: (path: string) => void,
): Promise<string> {
  try {
    const requested = resolveInputPath(outputDirectory);
    const path = await resolveParentTraversal(requested, {
      allowMissing: true,
    });
    requireModelSafeOutputDir(path);
    if (validateTraversalLink && path !== resolve(requested)) {
      await validateDirectoryLinks(requested, validateTraversalLink);
    }
    return path;
  } catch (error) {
    throw outputInspectionError(outputDirectory, error);
  }
}

export async function validateOutputDir(
  outputDirectory?: string,
  archiveExisting = false,
  validateTraversalLink?: (path: string) => void,
): Promise<string | null> {
  if (outputDirectory === undefined) {
    return null;
  }
  try {
    const path = await resolveScanOutputPath(
      outputDirectory,
      validateTraversalLink,
    );
    const metadata = await lstat(path).catch(nullIfMissingFileError);
    if (metadata !== null) {
      if (!metadata.isDirectory()) {
        throw new OutputDirectoryError(
          `Scan output is not a directory: ${path}`,
        );
      }
      if (!archiveExisting && (await readdir(path)).length !== 0) {
        throw new OutputDirectoryNotEmptyError(path);
      }
      requireOutputDirectoryOwnership(metadata, path);
      const writableLeaf =
        !archiveExisting ||
        (process.platform === "win32" && (await readdir(path)).length === 0);
      const canonical = await checkedOutputPath(path, writableLeaf).catch(
        rethrowOutputPathValidationError,
      );
      requireModelSafeOutputDir(canonical);
      return canonical;
    }

    let parent = dirname(path);
    while (true) {
      try {
        if ((await stat(parent)).isDirectory()) {
          const canonical = resolve(
            await realpath(parent),
            relative(parent, path),
          );
          requireModelSafeOutputDir(canonical);
          await requireSecureOutputAncestry(canonical).catch(
            rethrowOutputPathValidationError,
          );
          return canonical;
        }
        break;
      } catch (error) {
        if (nodeErrorCode(error) !== "ENOENT") throw error;
        const next = dirname(parent);
        if (next === parent) break;
        parent = next;
      }
    }
    throw new OutputDirectoryError(
      `Unable to create scan output directory: ${path}`,
    );
  } catch (error) {
    throw outputInspectionError(outputDirectory, error);
  }
}

function outputInspectionError(
  outputDirectory: string,
  cause: unknown,
): OutputDirectoryError {
  return cause instanceof OutputDirectoryError
    ? cause
    : new OutputDirectoryError(
        `Unable to inspect scan output directory: ${outputDirectory}`,
        { cause },
      );
}

/** Check each traversed directory link at its physical location, including linked targets. */
export async function validateDirectoryLinks(
  requested: string,
  validateLocation: (path: string) => void,
): Promise<void> {
  const directories = [dirname(requested)];
  const visited = new Set<string>();
  while (directories.length > 0) {
    let directory = directories.pop()!;
    while (dirname(directory) !== directory && !visited.has(directory)) {
      visited.add(directory);
      if (
        (await lstat(directory).catch(nullIfMissingFileError))?.isSymbolicLink()
      ) {
        const parent = await realpath(
          await resolveParentTraversal(dirname(directory)),
        );
        validateLocation(join(parent, basename(directory)));
        directories.push(resolveTargetPath(await readlink(directory), parent));
      }
      directory = dirname(directory);
    }
  }
}

function rethrowOutputPathValidationError(error: unknown): never {
  if (
    process.platform !== "win32" ||
    nodeErrorCode(error) !== "ERR_DLOPEN_FAILED"
  )
    throw error;
  const blocked =
    error instanceof Error &&
    /^(?:LoadLibrary failed: )?An Application Control policy has blocked this file\.(?:\s|$)/u.test(
      error.message,
    );
  throw new OutputDirectoryError(
    blocked
      ? "Windows Application Control blocked the bundled Codex Security filesystem module (windows.node). Check the CodeIntegrity Operational log in Event Viewer."
      : "Could not load the bundled Codex Security filesystem module (windows.node) on Windows.",
    { cause: error },
  );
}

export async function prepareScanArtifactRestorer(
  options: WorkbenchCommandOptions,
  scanDirectory: string,
): Promise<ScanArtifactRestorer> {
  let helperPath: string;
  let canonicalPath: string;
  let dev: string;
  let ino: string;
  try {
    // Recovery uses the SDK-owned writer, even if the scan selected a custom plugin.
    helperPath = join(
      await bundledPluginRoot(),
      "scripts",
      "finalize_scan_contract.py",
    );
    const result = await runCodexCommand(
      { command: options.python },
      [
        "-I",
        "-X",
        "utf8",
        "-B",
        "-c",
        PREPARE_SCAN_ARTIFACT_RESTORER_PROGRAM,
        helperPath,
        scanDirectory,
      ],
      pluginHelperEnvironment(options.environment),
      undefined,
      options.signal,
    );
    if (!result.success) {
      throw new Error(
        result.stderr.trim() ||
          result.stdout.trim() ||
          `Artifact restoration setup exited with status ${result.exitCode}.`,
      );
    }
    const prepared: unknown = JSON.parse(result.stdout);
    if (
      !isRecord(prepared) ||
      !isNonEmptyString(prepared["canonicalPath"]) ||
      typeof prepared["dev"] !== "string" ||
      !/^(?:0|[1-9]\d*)$/u.test(prepared["dev"]) ||
      typeof prepared["ino"] !== "string" ||
      !/^(?:0|[1-9]\d*)$/u.test(prepared["ino"])
    ) {
      throw new Error("Artifact restoration setup returned invalid output.");
    }
    canonicalPath = prepared["canonicalPath"];
    dev = prepared["dev"];
    ino = prepared["ino"];
  } catch (error) {
    if (options.signal?.aborted) throw error;
    throw new OutputDirectoryError(
      "Could not securely prepare completed scan artifact restoration.",
      { cause: error },
    );
  }

  return {
    async restore(relativePath, contents) {
      try {
        const result = await runCodexCommand(
          { command: options.python },
          [
            "-I",
            "-X",
            "utf8",
            "-B",
            "-c",
            RESTORE_SCAN_ARTIFACT_PROGRAM,
            helperPath,
            canonicalPath,
            relativePath,
            dev,
            ino,
          ],
          pluginHelperEnvironment(options.environment),
          contents,
        );
        if (!result.success) {
          throw new Error(
            result.stderr.trim() ||
              result.stdout.trim() ||
              `Artifact restoration exited with status ${result.exitCode}.`,
          );
        }
      } catch (error) {
        throw new OutputDirectoryError(
          "Could not safely restore a completed scan artifact.",
          { cause: error },
        );
      }
    },
  };
}

export async function planOutputArchive(
  outputDirectory: string | null,
): Promise<string | null> {
  if (outputDirectory === null) return null;
  const entries = await readdir(outputDirectory).catch(nullIfMissingFileError);
  if (entries === null || entries.length === 0) return null;
  const id = randomUUID().slice(0, 8);
  const archive = `${outputDirectory}${outputArchiveSuffix(id)}`;
  if (process.platform === "win32" || !(await archiveNameTooLong(archive)))
    return archive;
  // The workbench reserves a sibling with an eight-character random suffix.
  const sibling = `${outputDirectory}.previous-${id}`;
  if (!(await archiveNameTooLong(sibling))) return sibling;
  return join(
    dirname(outputDirectory),
    shortArchivePrefix(basename(outputDirectory)) + id,
  );
}

async function archiveNameTooLong(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return false;
  } catch (error) {
    return nodeErrorCode(error) === "ENAMETOOLONG";
  }
}

function outputArchiveSuffix(id = randomUUID().slice(0, 8)): string {
  return `.previous-${new Date()
    .toISOString()
    .replaceAll(/[-:]/g, "")
    .replace(/\.\d{3}Z$/, "")}-${id}`;
}

export function requireModelSafeOutputDir(path: string): void {
  if (MODEL_UNSAFE_PATH.test(path)) {
    throw new OutputDirectoryError(
      "Scan output directory must not contain control or line-separator characters.",
    );
  }
  const ambiguous =
    process.platform === "win32" ? windowsUnsafePathComponent(path) : undefined;
  if (ambiguous !== undefined) {
    throw new OutputDirectoryError(
      `Codex Security paths must not contain Windows-ambiguous components: ${ambiguous}`,
    );
  }
}

export async function canonicalizeModelSafePath(
  input: string,
): Promise<string> {
  const path = resolve(expandHome(input));
  requireModelSafeOutputDir(path);
  const canonical = await canonicalConfigPath(path);
  requireModelSafeOutputDir(canonical);
  return canonical;
}

export async function canonicalConfigPath(
  path: string,
  { verifyIdentity = false }: { verifyIdentity?: boolean } = {},
): Promise<string> {
  let existing = resolve(path);
  const missing: string[] = [];
  while (true) {
    try {
      const canonical = await realpath(existing);
      if (verifyIdentity && !(await sameFile(existing, canonical)))
        throw new InvalidTargetError(`Repository path changed: ${existing}`);
      return join(canonical, ...missing);
    } catch (error) {
      const parent = dirname(existing);
      if (
        (error as NodeJS.ErrnoException).code !== "ENOENT" ||
        parent === existing
      )
        throw error;
      missing.unshift(basename(existing));
      existing = parent;
    }
  }
}

export async function prepareOutputDir(
  outputDirectory: string | undefined,
  repositoryName: string,
  temporaryRoot: string = tmpdir(),
  validateLocation?: (path: string) => void,
  archiveExisting = false,
  onOutputArchived?: (archiveDir: string) => void,
): Promise<string> {
  return prepareOutputDirectory(
    outputDirectory,
    repositoryName,
    temporaryRoot,
    validateLocation,
    archiveExisting ? "archive" : "reject",
    onOutputArchived,
  );
}

/** Leave archival to the scan registration transaction. */
export async function prepareScanRegistrationOutput(
  outputDirectory: string | undefined,
  repositoryName: string,
  temporaryRoot: string = tmpdir(),
  validateLocation?: (path: string) => void,
  archiveExisting = false,
): Promise<string> {
  return prepareOutputDirectory(
    outputDirectory,
    repositoryName,
    temporaryRoot,
    validateLocation,
    archiveExisting ? "preserve" : "reject",
  );
}

async function prepareOutputDirectory(
  outputDirectory: string | undefined,
  repositoryName: string,
  temporaryRoot: string,
  validateLocation: ((path: string) => void) | undefined,
  existingOutput: "reject" | "archive" | "preserve",
  onOutputArchived?: (archiveDir: string) => void,
): Promise<string> {
  const path = await validateOutputDir(
    outputDirectory,
    existingOutput !== "reject",
    validateLocation,
  );
  if (path === null) {
    requireModelSafeOutputDir(temporaryRoot);
    const canonicalRoot = await realpath(temporaryRoot);
    requireModelSafeOutputDir(canonicalRoot);
    validateLocation?.(canonicalRoot);
    const prefix = `codex-security-${safePrefix(repositoryName)}`;
    let created: string;
    if (process.platform === "win32") {
      const suffix = `-${randomUUID()}`;
      // Reserve room within NTFS's 255-unit component limit for later archival.
      // The SDK suffix is longer than the workbench's .previous-<tempname> suffix.
      const prefixLength = 255 - suffix.length - outputArchiveSuffix().length;
      created = join(
        canonicalRoot,
        `${prefix.slice(0, prefixLength)}${suffix}`,
      );
      await createWindowsOutputDirectory(created, false);
    } else {
      try {
        created = await mkdtemp(join(canonicalRoot, `${prefix}-`));
      } catch (error) {
        if (nodeErrorCode(error) !== "ENAMETOOLONG") throw error;
        // The repository name itself can fill a filesystem component.
        created = await mkdtemp(join(canonicalRoot, "codex-security-"));
      }
    }
    try {
      if ((process.umask() & 0o700) !== 0) await chmod(created, 0o700);
      return await validatePreparedOutputDir(created, validateLocation);
    } catch (error) {
      await rmdir(created).catch(() => undefined);
      throw error;
    }
  }
  validateLocation?.(path);
  let createdRoot: string | undefined;
  try {
    let existing = await lstat(path).catch(nullIfMissingFileError);
    if (existing !== null && existingOutput === "archive") {
      const archiveDir = await planOutputArchive(path);
      if (archiveDir !== null) {
        await rename(path, archiveDir);
        notify(() => onOutputArchived?.(archiveDir));
        existing = null;
      }
    }
    if (existing === null) {
      createdRoot =
        process.platform === "win32"
          ? await createWindowsOutputDirectory(path, true)
          : await mkdir(path, { recursive: true, mode: 0o700 });
      if ((process.umask() & 0o700) !== 0) await chmod(path, 0o700);
    }
    // Registration retains a populated scan for archival. An empty Windows
    // directory must still satisfy the checks for a writable scan output.
    const preserveContents =
      existingOutput === "preserve" &&
      (process.platform !== "win32" || (await readdir(path)).length !== 0);
    return await validatePreparedOutputDir(
      path,
      validateLocation,
      preserveContents,
    );
  } catch (error) {
    if (createdRoot !== undefined) {
      await removeEmptyDirectories(path, createdRoot);
    }
    if (error instanceof OutputDirectoryError) throw error;
    throw new OutputDirectoryError(
      `Unable to create scan output directory: ${path}`,
      {
        cause: error,
      },
    );
  }
}

async function windowsOutputBinding() {
  return createRequire(import.meta.url)(
    join(
      await bundledPluginRoot(),
      "mcp",
      "native",
      `win32-${process.arch}`,
      "windows.node",
    ),
  ) as {
    createPrivateWindowsDirectory(path: Buffer, checkOutput: boolean): number;
    validateWindowsOutputPath(
      path: Buffer,
      writableLeaf?: boolean,
      retainedDirectory?: string,
    ): number;
  };
}

export async function requireWindowsOutputPath(
  path: string,
  writableLeaf?: boolean,
  retainedDirectory?: string,
): Promise<void> {
  const native = await windowsOutputBinding();
  const error = native.validateWindowsOutputPath(
    Buffer.from(win32.toNamespacedPath(path), "utf16le"),
    writableLeaf,
    retainedDirectory,
  );
  if (error !== 0)
    throw new OutputDirectoryError(
      `Scan output directory or its parent could not be trusted (Windows error ${error}): ${path}`,
    );
}

export async function createWindowsOutputDirectory(
  path: string,
  recursive: boolean,
): Promise<string | undefined> {
  const native = await windowsOutputBinding();
  const create = async (target: string): Promise<string | undefined> => {
    const createOne = () =>
      native.createPrivateWindowsDirectory(
        Buffer.from(win32.toNamespacedPath(target), "utf16le"),
        true,
      );
    let error = createOne();
    let firstCreated: string | undefined;
    if (
      recursive &&
      (error === 2 || error === 3) &&
      dirname(target) !== target
    ) {
      firstCreated = await create(dirname(target));
      error = createOne();
    }
    if (error === 0) return firstCreated ?? target;
    if (recursive && error === 183 && (await stat(target)).isDirectory()) {
      await requireWindowsOutputPath(target, target === path);
      return firstCreated;
    }
    throw new OutputDirectoryError(
      `Unable to create private Windows output directory (Windows error ${error}): ${target}`,
    );
  };
  return create(path);
}

export async function validatePreparedOutputDir(
  path: string,
  validateLocation?: (path: string) => void,
  allowNonempty = false,
): Promise<string> {
  const metadata = await lstat(path);
  if (!metadata.isDirectory()) {
    throw new OutputDirectoryError(`Scan output is not a directory: ${path}`);
  }
  const canonical = await checkedOutputPath(path, !allowNonempty);
  requireModelSafeOutputDir(canonical);
  validateLocation?.(canonical);
  if (!allowNonempty && (await readdir(canonical)).length !== 0) {
    throw new OutputDirectoryError(
      `Scan output directory must be empty: ${path}`,
    );
  }
  requireOutputDirectoryOwnership(metadata, path);
  return canonical;
}

async function checkedOutputPath(
  path: string,
  writableLeaf: boolean,
): Promise<string> {
  if (process.platform === "win32") {
    // Keep the selected leaf for the no-follow check, including across an
    // in-place directory change between lstat and canonicalization.
    const directory = dirname(path);
    const parent = await realpath(directory);
    const selected = join(parent, relative(directory, path));
    await requireWindowsOutputPath(selected, writableLeaf);
    const canonical = await realpath(selected);
    if (canonical === selected) return selected;
    // Accept a canonical leaf spelling (case or short name) within the checked parent.
    if (dirname(canonical) === parent) {
      const [leaf, resolved] = await Promise.all([
        lstat(selected, { bigint: true }),
        lstat(canonical, { bigint: true }),
      ]);
      if (leaf.isDirectory() && leaf.ino !== 0n && sameInode(leaf, resolved)) {
        return canonical;
      }
    }
    throw new OutputDirectoryError(
      `Scan output directory changed during preparation: ${path}`,
    );
  }
  await requireSecureOutputAncestry(path);
  const canonical = await realpath(path);
  if (canonical !== path) await requireSecureOutputAncestry(canonical);
  return canonical;
}

export function requirePrivateOutputDirectory(
  metadata: Pick<Stats, "mode" | "uid">,
  path: string,
  effectiveUid = process.geteuid?.(),
): void {
  if (process.platform === "win32") return;
  if ((metadata.mode & 0o077) !== 0) {
    throw new OutputDirectoryError(
      `Scan output directory must not be accessible to other users (chmod 700): ${path}`,
    );
  }
  requireOutputDirectoryOwnership(metadata, path, effectiveUid);
}

export function requireOutputDirectoryOwnership(
  metadata: Pick<Stats, "uid">,
  path: string,
  effectiveUid = process.geteuid?.(),
): void {
  if (process.platform === "win32") return;
  if (effectiveUid !== undefined && metadata.uid !== effectiveUid) {
    throw new OutputDirectoryError(
      `Scan output directory must be owned by the current user: ${path}`,
    );
  }
}

/** Reject shared parents whose owner can rename or replace scan output. */
export async function requireSecureOutputAncestry(
  path: string,
  effectiveUid = process.geteuid?.(),
): Promise<void> {
  if (process.platform === "win32") return requireWindowsOutputPath(path);
  let current = dirname(resolve(path));
  while (true) {
    try {
      current = await realpath(current);
      break;
    } catch (error) {
      if (nodeErrorCode(error) !== "ENOENT") {
        throw new OutputDirectoryError(
          `Unable to inspect scan output parent directory: ${current}`,
          { cause: error },
        );
      }
      const parent = dirname(current);
      if (parent === current) {
        throw new OutputDirectoryError(
          `Unable to inspect scan output parent directory: ${current}`,
          { cause: error },
        );
      }
      current = parent;
    }
  }
  while (true) {
    let metadata: Stats;
    try {
      metadata = await lstat(current);
    } catch (error) {
      throw new OutputDirectoryError(
        `Unable to inspect scan output parent directory: ${current}`,
        { cause: error },
      );
    }
    if (!metadata.isDirectory()) {
      throw new OutputDirectoryError(
        `Scan output parent must be a non-symlink directory: ${current}`,
      );
    }
    requireTrustedOutputAncestor(metadata, current, effectiveUid);
    const parent = dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

export function requireTrustedOutputAncestor(
  metadata: Pick<Stats, "mode" | "uid">,
  path: string,
  effectiveUid = process.geteuid?.(),
): void {
  if (
    effectiveUid !== undefined &&
    metadata.uid !== 0 &&
    metadata.uid !== effectiveUid
  ) {
    throw new OutputDirectoryError(
      `Scan output parent must have a trusted owner: ${path}`,
    );
  }
  if ((metadata.mode & 0o022) === 0) return;
  if ((metadata.mode & 0o1000) === 0) {
    throw new OutputDirectoryError(
      `Scan output parent must not be group- or world-writable without the sticky bit: ${path}`,
    );
  }
}

async function removeEmptyDirectories(
  path: string,
  root: string,
): Promise<void> {
  let current = path;
  while (true) {
    try {
      await rmdir(current);
    } catch {
      return;
    }
    if (current === root) return;
    current = dirname(current);
  }
}

export async function createIsolatedHome(
  temporaryRoot: string = tmpdir(),
  validateLocation?: (path: string) => void,
): Promise<string> {
  const path = await mkdtemp(
    join(temporaryRoot, "openai-codex-security-home-"),
  );
  try {
    if ((process.umask() & 0o700) !== 0) await chmod(path, 0o700);
    return await validatePreparedOutputDir(path, validateLocation);
  } catch (error) {
    await rmdir(path).catch(() => undefined);
    throw error;
  }
}

export async function importAmbientAuth(
  ambientHome: string,
  isolatedHome: string,
): Promise<boolean> {
  const source = join(expandHome(ambientHome), "auth.json");
  let metadata;
  try {
    metadata = await stat(source);
  } catch (error) {
    if (nodeErrorCode(error) === "ENOENT") return false;
    throw new PluginBootstrapError(
      `Unable to inspect ambient Codex authentication: ${source}`,
      {
        cause: error,
      },
    );
  }
  if (!metadata.isFile()) {
    return false;
  }
  await mkdir(isolatedHome, { recursive: true, mode: 0o700 });
  if (process.platform !== "win32" && (process.umask() & 0o700) !== 0) {
    await chmod(isolatedHome, 0o700);
  }
  if (await codexSecurityHasStoredFileCredentials(isolatedHome)) return true;
  const destination = join(isolatedHome, "auth.json");
  const temporary = join(isolatedHome, `.auth-${randomUUID()}.tmp`);
  try {
    await copyFile(source, temporary, constants.COPYFILE_EXCL);
    await chmod(temporary, 0o600);
    try {
      try {
        await link(temporary, destination);
      } catch (error) {
        if (
          !["EPERM", "ENOTSUP", "EOPNOTSUPP", "EXDEV", "EMLINK"].includes(
            nodeErrorCode(error) ?? "",
          )
        ) {
          throw error;
        }
        await copyFile(temporary, destination, constants.COPYFILE_EXCL);
      }
    } catch (error) {
      if (
        nodeErrorCode(error) === "EEXIST" &&
        (await codexSecurityHasStoredFileCredentials(isolatedHome))
      ) {
        return true;
      }
      throw error;
    }
    await chmod(destination, 0o600);
    await rememberStoredFile(isolatedHome);
    return true;
  } catch (error) {
    throw new PluginBootstrapError(
      "Unable to copy ambient Codex authentication.",
      {
        cause: error,
      },
    );
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}

export async function extractPluginZip(
  archive: string,
  destination: string,
  signal?: AbortSignal,
): Promise<string> {
  return extractValidatedPluginZip(archive, destination, signal);
}

async function extractValidatedPluginZip(
  archive: string,
  destination: string,
  signal?: AbortSignal,
  digest?: Hash,
): Promise<string> {
  const archivePath = resolve(expandHome(archive));
  const parent = dirname(destination);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  // Windows mkdtemp otherwise fails at 248 UTF-16 units, including its suffix.
  const stagingParent =
    process.platform === "win32"
      ? win32.toNamespacedPath(await realpath(parent))
      : parent;
  const staging = await realpath(
    await mkdtemp(join(stagingParent, ".codex-security-plugin-")),
  );
  let publishingOnWindows = false;
  try {
    throwIfSignalAborted(signal);
    let expandedSize = 0;
    const paths = new Set<string>();
    const checksums: Array<{ path: string; checksum: number }> = [];
    const zip = await openPluginZip(archivePath, signal);
    try {
      for await (const entry of zip.eachEntry()) {
        throwIfSignalAborted(signal);
        if (zip.entryCount > MAX_ZIP_ENTRIES) {
          throw new PluginBootstrapError(
            `Plugin ZIP contains too many entries: ${zip.entryCount}.`,
          );
        }
        if (entry.fileName.startsWith("__MACOSX/")) continue;
        const path = safeArchivePath(entry.fileName);
        const collisionKey = path.toLowerCase();
        if (paths.has(collisionKey)) {
          throw new PluginBootstrapError(
            `Plugin ZIP contains a duplicate path: ${entry.fileName}`,
          );
        }
        paths.add(collisionKey);
        if (((entry.externalFileAttributes >>> 16) & 0o170000) === 0o120000) {
          throw new PluginBootstrapError(
            `Plugin ZIP contains an unsafe path: ${entry.fileName}`,
          );
        }
        if (entry.uncompressedSize > MAX_ZIP_ENTRY_SIZE) {
          throw new PluginBootstrapError(
            `Plugin ZIP entry exceeds the safety limit: ${entry.fileName}`,
          );
        }
        expandedSize += entry.uncompressedSize;
        if (expandedSize > MAX_ZIP_EXPANDED_SIZE) {
          throw new PluginBootstrapError(
            "Plugin ZIP expanded size exceeds the safety limit.",
          );
        }
        const mode = (entry.externalFileAttributes >>> 16) & 0o170000;
        const directory =
          entry.fileName.endsWith("/") ||
          mode === 0o040000 ||
          (entry.versionMadeBy >>> 8 === 0 &&
            entry.externalFileAttributes === 16);
        const output = join(staging, ...path.split("/"));
        const entryMode = (entry.externalFileAttributes >>> 16) & 0xffff;
        const permissions = (entryMode || (directory ? 0o700 : 0o600)) & 0o777;
        digest?.update(JSON.stringify([path, directory, permissions]));
        await mkdir(directory ? output : dirname(output), {
          recursive: true,
          ...(directory ? { mode: permissions } : {}),
        });
        if (directory) continue;
        const stream = await zip.openReadStreamPromise(entry);
        await pipeline(
          stream,
          createWriteStream(output, { mode: permissions, flags: "wx" }),
          { signal },
        );
        checksums.push({ path, checksum: entry.crc32 >>> 0 });
      }
    } finally {
      zip.close();
    }
    for (const { path, checksum } of checksums) {
      throwIfSignalAborted(signal);
      const bytes = await readFile(join(staging, ...path.split("/")));
      if (crc32(bytes) !== checksum) {
        throw new PluginBootstrapError(
          `Plugin ZIP entry failed CRC-32 validation: ${path}`,
        );
      }
      digest?.update(createHash("sha256").update(bytes).digest());
    }
    const pluginRoot = await discoverPluginRoot(staging);
    throwIfSignalAborted(signal);
    const relativeRoot = relative(staging, pluginRoot);
    if (process.platform === "win32") {
      publishingOnWindows = true;
      await retryWindowsRename(
        async () => {
          throwIfSignalAborted(signal);
          if (await lstat(destination).catch(nullIfMissingFileError))
            throw new Error(`Destination already exists: ${destination}`);
          await rename(staging, destination);
        },
        undefined,
        signal,
      );
      publishingOnWindows = false;
    } else {
      await rename(staging, destination);
    }
    return await validatePluginRoot(join(destination, relativeRoot));
  } catch (error) {
    let cleanupDiagnostic = "";
    await rm(staging, { recursive: true, force: true }).catch(
      (cleanupError) => {
        cleanupDiagnostic = `\nCould not remove staging directory ${staging}: ${errorMessage(cleanupError)}`;
      },
    );
    throwIfSignalAborted(signal);
    if (publishingOnWindows)
      throw new PluginBootstrapError(
        `Could not publish extracted plugin ZIP: ${errorMessage(error)}${cleanupDiagnostic}`,
        { cause: error },
      );
    if (error instanceof PluginBootstrapError) throw error;
    throw new PluginBootstrapError(`Invalid plugin ZIP: ${archivePath}`, {
      cause: error,
    });
  }
}

async function openPluginZip(
  path: string,
  signal?: AbortSignal,
): Promise<ZipFile> {
  const fd = await promisify(openCallback)(
    path,
    constants.O_RDONLY |
      (process.platform === "win32" ? 0 : constants.O_NONBLOCK),
  );
  try {
    const metadata = await promisify(fstatCallback)(fd);
    if (!metadata.isFile() || metadata.size < 22) {
      throw new Error("missing end of central directory");
    }
    const tailSize = Math.min(metadata.size, 65_557);
    const tail = await readExactly(
      fd,
      tailSize,
      metadata.size - tailSize,
      signal,
    );
    let end = tail.byteLength - 22;
    while (
      end >= 0 &&
      (tail.readUInt32LE(end) !== 0x06054b50 ||
        end + 22 + tail.readUInt16LE(end + 20) !== tail.byteLength)
    ) {
      end -= 1;
    }
    if (end < 0) throw new Error("missing end of central directory");
    const entries = tail.readUInt16LE(end + 10);
    const centralSize = tail.readUInt32LE(end + 12);
    const centralOffset = tail.readUInt32LE(end + 16);
    if (
      entries === 0xffff ||
      centralSize === 0xffffffff ||
      centralOffset === 0xffffffff
    ) {
      throw new Error("unsupported ZIP64 archive");
    }
    if (entries > MAX_ZIP_ENTRIES) {
      throw new PluginBootstrapError(
        `Plugin ZIP contains too many entries: ${entries}.`,
      );
    }
    if (centralSize > MAX_ZIP_CENTRAL_DIRECTORY) {
      throw new PluginBootstrapError(
        "Plugin ZIP central directory exceeds the safety limit.",
      );
    }
    const endOffset = metadata.size - tailSize + end;
    if (centralOffset + centralSize > endOffset) {
      throw new Error("invalid central directory bounds");
    }
    const central = await readExactly(fd, centralSize, centralOffset, signal);
    let offset = 0;
    for (let index = 0; index < entries; index += 1) {
      if (
        offset + 46 > central.byteLength ||
        central.readUInt32LE(offset) !== 0x02014b50
      ) {
        throw new Error("invalid central directory");
      }
      const nameLength = central.readUInt16LE(offset + 28);
      const extraLength = central.readUInt16LE(offset + 30);
      const commentLength = central.readUInt16LE(offset + 32);
      const nameStart = offset + 46;
      const nameEnd = nameStart + nameLength;
      if (nameEnd > central.byteLength) {
        throw new Error("invalid central directory name");
      }
      if (central.subarray(nameStart, nameEnd).includes(0x5c)) {
        throw new PluginBootstrapError(
          "Plugin ZIP contains a backslash-qualified path.",
        );
      }
      offset = nameEnd + extraLength + commentLength;
    }
    if (offset !== central.byteLength) {
      throw new Error("invalid central directory size");
    }
    // Yauzl owns the descriptor only after construction succeeds.
    return await fromFdPromise(fd, {
      autoClose: true,
      strictFileNames: true,
    });
  } catch (error) {
    await promisify(closeCallback)(fd);
    throw error;
  }
}

export async function resolvePluginPath(
  pluginPath: string | undefined,
  workspace: string,
  signal?: AbortSignal,
): Promise<string> {
  return (await resolvePluginSource(pluginPath, workspace, signal)).root;
}

/** @internal */
export interface PluginZipSource {
  path: string;
  digest: string;
}

/** @internal */
export async function resolvePluginSource(
  pluginPath: string | undefined,
  workspace: string,
  signal?: AbortSignal,
  pinZip = false,
): Promise<{ root: string; zip?: PluginZipSource }> {
  try {
    if (pluginPath === undefined) {
      return { root: await bundledPluginRoot() };
    }

    const path = resolve(expandHome(pluginPath));
    const metadata = await lstat(path).catch(() => null);
    if (metadata?.isFile() && extname(path).toLowerCase() === ".zip") {
      const digest = pinZip ? createHash("sha256") : undefined;
      const archive = digest ? await realpath(path) : path;
      const root = await extractValidatedPluginZip(
        archive,
        join(workspace, "extracted-plugin"),
        signal,
        digest,
      );
      return {
        root,
        ...(digest && { zip: { path: archive, digest: digest.digest("hex") } }),
      };
    }
    if (metadata?.isDirectory()) {
      throwIfSignalAborted(signal);
      return { root: await validatePluginRoot(path) };
    }
    throw new PluginBootstrapError(
      `Plugin path must be a directory or ZIP: ${path}`,
    );
  } catch (error) {
    if (signal?.aborted || error instanceof LocalPluginBootstrapError)
      throw error;
    throw new LocalPluginBootstrapError(errorMessage(error), { cause: error });
  }
}

/** @internal */
export async function prepareWindowsScanPluginZip(
  source: PluginZipSource,
  scanDirectory: string,
  protectedDirectories: readonly string[],
  validateLocation: (path: string) => void,
  signal?: AbortSignal,
): Promise<{ workspace: string; root: string } | undefined> {
  throwIfSignalAborted(signal);
  const protectedPath = (path: string) =>
    protectedDirectories.some((directory) => isWithin(directory, path));
  if (protectedPath(source.path)) return;
  const metadata = await lstat(source.path).catch(nullIfMissingFileError);
  if (metadata === null) return;
  const changed = "The selected plugin ZIP changed after runtime preparation.";
  if (!metadata.isFile()) throw new LocalPluginBootstrapError(changed);
  const canonicalSource = await realpath(source.path).catch(
    nullIfMissingFileError,
  );
  if (canonicalSource === null) return;
  if (protectedPath(canonicalSource))
    throw new LocalPluginBootstrapError(changed);
  let workspace: string | undefined;
  const parents = [...new Set([dirname(scanDirectory), tmpdir()])].filter(
    (parent) => !protectedPath(parent) && !isWithin(scanDirectory, parent),
  );
  // PowerShell may fail to launch the selected plugin's .cmd at a long path.
  // Prefer the shorter canonical parent, retaining the output parent on ties.
  const candidates = await abortable(
    () => Promise.allSettled(parents.map((path) => realpath(path))),
    signal,
  );
  const length = (candidate: PromiseSettledResult<string>) =>
    candidate.status === "fulfilled" ? candidate.value.length : Infinity;
  for (const candidate of candidates.sort((a, b) => length(a) - length(b))) {
    throwIfSignalAborted(signal);
    try {
      if (candidate.status === "rejected") throw candidate.reason;
      const canonical = candidate.value;
      if (protectedPath(canonical) || isWithin(scanDirectory, canonical))
        continue;
      // Host-side plugin helpers may execute from this copy. A sibling keeps it
      // outside the writable scan, and the native creator verifies its parents.
      workspace = await prepareOutputDir(
        undefined,
        "plugin-input",
        canonical,
        validateLocation,
      );
      break;
    } catch (error) {
      if (
        !(error instanceof OutputDirectoryError) &&
        !["EACCES", "EPERM", "ENOENT"].includes(nodeErrorCode(error) ?? "")
      )
        throw error;
    }
  }
  // Keep existing plugin handling where neither scan input location is usable.
  if (workspace === undefined) return;
  try {
    throwIfSignalAborted(signal);
    const digest = createHash("sha256");
    const root = await extractValidatedPluginZip(
      source.path,
      join(workspace, "plugin"),
      signal,
      digest,
    );
    throwIfSignalAborted(signal);
    if (digest.digest("hex") !== source.digest) {
      throw new LocalPluginBootstrapError(changed);
    }
    return { workspace, root };
  } catch (error) {
    try {
      await cleanupSdkDirectory(workspace);
    } catch (cleanupError) {
      throwIfSignalAborted(signal);
      throw new LocalPluginBootstrapError(
        `${errorMessage(error)}\nCould not remove scan input directory ${workspace}: ${errorMessage(cleanupError)}`,
        { cause: error },
      );
    }
    throwIfSignalAborted(signal);
    const cause =
      error instanceof PluginBootstrapError ? error.cause : undefined;
    if (
      isRecord(cause) &&
      cause["code"] === "ENOENT" &&
      cause["syscall"] === "open" &&
      cause["path"] === source.path
    )
      return;
    throw error;
  }
}

export async function createMarketplace(
  codexHome: string,
  pluginRoot: string,
  signal?: AbortSignal,
): Promise<string> {
  try {
    throwIfSignalAborted(signal);
    const root = await realpath(pluginRoot);
    const marketplace = join(codexHome, "sdk-marketplace");
    const pluginDestination = join(marketplace, "plugins", PLUGIN_NAME);
    await copyPluginTree(root, pluginDestination, signal);
    const projection = await pluginRuntimeProjection(pluginDestination, signal);
    for (const [path, file] of projection?.files ?? []) {
      const destination = join(pluginDestination, path);
      await mkdir(dirname(destination), { recursive: true });
      await writeFile(destination, file.contents, { mode: file.mode, signal });
      if (file.mode !== undefined) await chmod(destination, file.mode);
    }
    await writeMarketplaceManifest(marketplace, signal);
    return marketplace;
  } catch (error) {
    if (signal?.aborted || error instanceof LocalPluginBootstrapError)
      throw error;
    throw new LocalPluginBootstrapError(errorMessage(error), { cause: error });
  }
}

async function writeMarketplaceManifest(
  marketplace: string,
  signal?: AbortSignal,
): Promise<void> {
  throwIfSignalAborted(signal);
  const manifestPath = join(
    marketplace,
    ".agents",
    "plugins",
    "marketplace.json",
  );
  await mkdir(dirname(manifestPath), { recursive: true, mode: 0o700 });
  const temporary = `${manifestPath}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, MARKETPLACE_MANIFEST, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
      signal,
    });
    throwIfSignalAborted(signal);
    try {
      await rename(temporary, manifestPath);
    } catch (error) {
      // Concurrent replacement can fail on Windows after another repair wins.
      const published = await readFile(manifestPath, "utf8").catch(() => null);
      if (published !== MARKETPLACE_MANIFEST) throw error;
    }
    throwIfSignalAborted(signal);
  } finally {
    await rm(temporary, { force: true });
  }
}

type PluginRuntimeProjection = {
  root: string;
  files: Map<string, { contents: Buffer; mode?: number }>;
};

// Private handoff to the staged SDK launcher and shell-invoked helpers.
export const SDK_NODE_SEARCH_PATH = "_CODEX_SECURITY_SDK_NODE_SEARCH_PATH";

export async function sdkNodeSearchPath(
  roots: readonly string[],
): Promise<string> {
  let fallback = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin";
  const current = dirname(process.execPath);
  if (
    process.release.name === "node" &&
    !process.versions["bun"] &&
    !process.versions["electron"] &&
    basename(process.execPath) === "node" &&
    !current.includes(":")
  )
    fallback += `:${current}`;
  const inspected = await inspectTrustedExecutable(
    "node",
    { PATH: fallback },
    roots,
  );
  return inspected.environment["PATH"] ?? "";
}

async function pluginRuntimeProjection(
  root: string,
  signal?: AbortSignal,
): Promise<PluginRuntimeProjection | undefined> {
  const path = join(root, ".mcp.json");
  // Keep the source link checks ahead of any configuration read.
  if (!(await lstat(path).catch(nullIfMissingFileError))?.isFile()) return;
  const configuration: unknown = JSON.parse(
    await readFile(path, { encoding: "utf8", signal }),
  );
  const servers = isRecord(configuration)
    ? configuration["mcpServers"]
    : undefined;
  const server = isRecord(servers) ? servers[PLUGIN_NAME] : undefined;
  if (
    !isRecord(server) ||
    (server["command"] !== "./scripts/launch_codex_security_mcp" &&
      server["command"] !== "./scripts/launch_codex_security_mcp.cmd")
  ) {
    return;
  }
  const environment = server["env_vars"];
  if (environment !== undefined && !Array.isArray(environment)) return;
  server["env_vars"] = [
    ...(environment ?? []),
    ...["CODEX_SECURITY_PLUGIN_ROOT", "CODEX_SECURITY_REPOSITORY"].filter(
      (name) => !environment?.includes(name),
    ),
  ];
  const files: PluginRuntimeProjection["files"] = new Map();
  server["command"] =
    server["command"] === "./scripts/launch_codex_security_mcp.cmd"
      ? "./scripts/launch_codex_security_mcp_sdk.cmd"
      : "./scripts/launch_codex_security_mcp_sdk";
  files.set("scripts/launch_codex_security_mcp_sdk", {
    contents: Buffer.from(
      "#!/bin/sh\n" +
        'if [ -n "${CODEX_SECURITY_PLUGIN_ROOT:-}" ]; then\n' +
        '  exec "$CODEX_SECURITY_PLUGIN_ROOT/scripts/launch_codex_security_mcp" "$@"\n' +
        "fi\n" +
        'exec "$(command -p dirname "$0")/launch_codex_security_mcp" "$@"\n',
    ),
    mode: 0o755,
  });
  files.set("scripts/launch_codex_security_mcp_sdk.cmd", {
    contents: Buffer.from(
      "@echo off\r\nsetlocal DisableDelayedExpansion\r\n" +
        "if not defined CODEX_SECURITY_PLUGIN_ROOT goto codex_security_sdk_original\r\n" +
        '"%CODEX_SECURITY_PLUGIN_ROOT%\\scripts\\launch_codex_security_mcp.cmd" %*\r\n' +
        "exit /b\r\n:codex_security_sdk_original\r\n" +
        '"%~dp0launch_codex_security_mcp.cmd" %*\r\n',
    ),
    mode: 0o755,
  });
  files.set(".mcp.json", {
    contents: Buffer.from(`${JSON.stringify(configuration, null, 2)}\n`),
  });
  return { root, files };
}

export function resolveCodexCommand(
  environment: ProcessEnvironment = process.env,
): CodexCommand {
  const configured = configuredExecutableValue(
    environmentValue(environment, "CODEX_CLI_PATH", true),
    process.platform,
    (value) => isExecutableFile(expandHomeForLookup(value, environment)),
  );
  const expanded =
    configured === undefined
      ? undefined
      : expandHomeForLookup(configured, environment);
  if (
    expanded &&
    (process.platform !== "win32" || /\.(?:exe|com)$/iu.test(expanded))
  ) {
    return {
      command:
        process.platform === "win32"
          ? resolve(expanded)
          : isAbsolute(expanded)
            ? expanded
            : `${process.cwd()}${sep}${expanded}`,
    };
  }

  return { command: resolveBundledCodexExecutable() };
}

export async function codexExecutableReadPaths(
  command: string,
): Promise<string[]> {
  const executable = await realpath(command);
  const packageJson = resolve(dirname(executable), "..", "package.json");
  try {
    const metadata = JSON.parse(await readFile(packageJson, "utf8"));
    if (
      metadata?.name !== "@openai/codex" ||
      typeof metadata.bin?.codex !== "string"
    )
      return [executable];
    const launcher = await realpath(
      resolve(dirname(packageJson), metadata.bin.codex),
    );
    if (launcher !== executable) return [executable];
  } catch {
    // A custom executable need not belong to a readable, valid npm package.
    return [executable];
  }

  // npm's entrypoint launches a native binary, which Linux re-executes in the sandbox.
  return [
    executable,
    await realpath(resolveBundledCodexExecutable(packageJson)),
  ];
}

export async function bootstrapPlugin(
  codexHome: string,
  pluginRoot: string,
  options: {
    codexCommand?: CodexCommand;
    runCodex?: (
      command: CodexCommand,
      args: readonly string[],
      environment: ProcessEnvironment,
      signal?: AbortSignal,
    ) => Promise<string>;
    environment?: ProcessEnvironment;
    signal?: AbortSignal;
  } = {},
): Promise<PluginInstall> {
  const root = await realpath(pluginRoot);
  const { name, version } = await pluginMetadata(root);
  const projection = await pluginRuntimeProjection(root, options.signal).catch(
    (error: unknown) => {
      if (options.signal?.aborted) throw error;
      throw new LocalPluginBootstrapError(errorMessage(error), {
        cause: error,
      });
    },
  );
  const marketplace = join(codexHome, "sdk-marketplace");
  throwIfSignalAborted(options.signal);
  const command =
    options.codexCommand ?? resolveCodexCommand(options.environment);
  const environment = {
    ...(options.environment ?? process.env),
    CODEX_HOME: codexHome,
  };
  const run = options.runCodex ?? runPluginCommand;
  const existing = await lstat(marketplace).catch(nullIfMissingFileError);
  if (existing !== null && !existing.isDirectory()) {
    throw new LocalPluginBootstrapError(
      `Codex Security plugin marketplace path must be a directory: ${marketplace}`,
    );
  }

  const staged =
    existing === null
      ? null
      : await pluginMetadata(join(marketplace, "plugins", PLUGIN_NAME)).catch(
          () => null,
        );
  const stagedRoot = join(marketplace, "plugins", PLUGIN_NAME);
  const matchesSelected = (
    destination: string,
    allowExtraFiles = false,
    generatedDirectory?: string,
  ) =>
    pluginContentsMatch(
      root,
      destination,
      options.signal,
      allowExtraFiles,
      projection,
      generatedDirectory,
    );
  const stagedMatches =
    staged?.version === version && (await matchesSelected(stagedRoot));
  const matchesNativeInstall = async (
    installedRoot: string,
    allowRuntimeFiles = false,
  ) =>
    (await matchesSelected(stagedRoot)) &&
    // Ordinary reuse permits runtime files when all selected bytes are present.
    // The native receipt still verifies the complete generated command output.
    ((allowRuntimeFiles && (await matchesSelected(installedRoot, true))) ||
      (await matchesSelected(
        installedRoot,
        false,
        migratedCommands(installedRoot),
      )));
  const nativeMigration = (installedRoot: string, allowRuntimeFiles = false) =>
    verifiedCommandMigration(
      installedRoot,
      (path) => matchesNativeInstall(path, allowRuntimeFiles),
      options.signal,
    );
  const matchesReceipt = async (installedRoot: string, migration: unknown) => {
    if (
      typeof migration === "string" &&
      options.runCodex === undefined &&
      (await isBundledPluginInstaller(command))
    ) {
      return (await nativeMigration(installedRoot, true)) === migration;
    }
    return matchesSelected(installedRoot, true);
  };

  if (!stagedMatches) {
    if (existing !== null) {
      if (isWithin(await realpath(marketplace), root)) {
        throw new PluginBootstrapError(
          `Cannot refresh the SDK plugin marketplace because it contains the selected plugin source: ${marketplace}. Copy the selected plugin outside this directory and retry.`,
        );
      }
      await rm(marketplace, { recursive: true, force: true });
    }
    await createMarketplace(codexHome, root, options.signal);
  } else if (
    (await readFile(
      join(marketplace, ".agents", "plugins", "marketplace.json"),
      "utf8",
    ).catch(nullIfMissingFileError)) !== MARKETPLACE_MANIFEST
  ) {
    await writeMarketplaceManifest(marketplace, options.signal);
  }

  const config = await readFile(join(codexHome, "config.toml"), "utf8").catch(
    (error: unknown) => {
      if (nodeErrorCode(error) === "ENOENT") return "";
      throw error;
    },
  );
  const configuration = parse(config);
  const marketplaces = configuration["marketplaces"];
  const registration = isRecord(marketplaces)
    ? marketplaces[MARKETPLACE_NAME]
    : undefined;

  const registered =
    isRecord(registration) &&
    registration["source_type"] === "local" &&
    typeof registration["source"] === "string" &&
    (await sameFile(registration["source"], marketplace));

  if (!registered) {
    await run(
      command,
      ["plugin", "marketplace", "add", marketplace],
      environment,
      options.signal,
    );
  }

  const installRecord = join(marketplace, "installed-plugin.json");
  const previous: unknown = await readFile(installRecord, "utf8")
    .then((value) => JSON.parse(value) as unknown)
    .catch((error: unknown) => {
      const code = nodeErrorCode(error);
      if (code === "ENOENT" || error instanceof SyntaxError) {
        return null;
      }
      if (
        process.platform === "win32" &&
        error instanceof Error &&
        (code === "EACCES" || code === "EPERM")
      ) {
        // Keep the original system error, including its path, code and syscall.
        error.message +=
          " If the SDK created this plugin installation receipt but cannot reopen it, " +
          "check its read permissions and the permissions new files inherit from the sdk-marketplace directory.";
      }
      throw error;
    });

  const plugins = configuration["plugins"];
  const plugin = isRecord(plugins)
    ? plugins[`${PLUGIN_NAME}@${MARKETPLACE_NAME}`]
    : undefined;

  // Codex replaces the shared install even at the same version. Reuse it so
  // workers from an earlier scan can keep using their plugin files.
  if (
    stagedMatches &&
    registered &&
    isRecord(plugin) &&
    plugin["enabled"] === true &&
    isRecord(previous) &&
    typeof previous["installedPath"] === "string" &&
    previous["version"] === version &&
    (await matchesReceipt(
      previous["installedPath"],
      previous["nativeCommandMigration"],
    ))
  ) {
    return {
      pluginRoot: root,
      marketplaceRoot: marketplace,
      installedRoot: previous["installedPath"],
      marketplaceName: MARKETPLACE_NAME,
      name,
      version,
    };
  }

  const addPlugin = () =>
    run(
      command,
      ["plugin", "add", "--json", `${PLUGIN_NAME}@${MARKETPLACE_NAME}`],
      environment,
      options.signal,
    );
  let output: string;
  let retried = false;
  try {
    output = await addPlugin();
  } catch (first) {
    if (!isRolledBackPluginActivation(first)) throw first;
    throwIfSignalAborted(options.signal);
    if (!(await isBundledPluginInstaller(command))) throw first;
    // The bundled CLI restored the old cache. A short-lived Windows reader
    // of the new tree can release it before a fresh installation attempt.
    try {
      await delay(100, undefined, { signal: options.signal });
      throwIfSignalAborted(options.signal);
      if (!(await matchesSelected(stagedRoot))) {
        throw new LocalPluginBootstrapError(
          "The selected plugin or its marketplace changed before the native installation could be retried.",
          { cause: first },
        );
      }
      throwIfSignalAborted(options.signal);
      output = await addPlugin();
      retried = true;
    } catch (second) {
      throwIfSignalAborted(options.signal);
      throw isRolledBackPluginActivation(second) ? first : second;
    }
  }

  let installed: unknown;
  try {
    installed = JSON.parse(output);
  } catch (error) {
    throw new PluginBootstrapError(
      "Codex plugin install did not return a valid JSON result.",
      { cause: error },
    );
  }

  if (
    !isRecord(installed) ||
    typeof installed["installedPath"] !== "string" ||
    installed["version"] !== version
  ) {
    throw new PluginBootstrapError(
      "Codex plugin install did not return the selected plugin path and version.",
    );
  }

  // The bundled installer removes stale command skills before regenerating them.
  const bundledInstaller =
    retried ||
    (options.runCodex === undefined &&
      (await isBundledPluginInstaller(command)));
  const hasSourceMigration =
    bundledInstaller &&
    (
      await lstat(migratedCommands(root)).catch(nullIfMissingFileError)
    )?.isDirectory() === true;
  const nativeCommandMigration = hasSourceMigration
    ? await nativeMigration(installed["installedPath"])
    : undefined;
  if (
    retried &&
    !(hasSourceMigration
      ? nativeCommandMigration !== undefined
      : await matchesNativeInstall(installed["installedPath"]))
  ) {
    throw new PluginBootstrapError(
      "The retried Codex plugin install did not install the selected plugin contents.",
    );
  }

  await writeFile(
    installRecord,
    JSON.stringify({
      installedPath: installed["installedPath"],
      version,
      ...(nativeCommandMigration ? { nativeCommandMigration } : {}),
    }),
    { mode: 0o600, signal: options.signal },
  );

  return {
    pluginRoot: root,
    marketplaceRoot: marketplace,
    installedRoot: installed["installedPath"],
    marketplaceName: MARKETPLACE_NAME,
    name,
    version,
  };
}

async function isBundledPluginInstaller(
  command: CodexCommand,
): Promise<boolean> {
  try {
    return await sameFile(command.command, resolveBundledCodexExecutable());
  } catch {
    return false;
  }
}

function migratedCommands(plugin: string): string {
  return join(plugin, ".codex-plugin", "migrated-command-skills");
}

// Bind a receipt to the generated files observed in this installation.
// Entry names come from its directories, never from the saved digest.
async function verifiedCommandMigration(
  installedRoot: string,
  matchesSelected: (installedRoot: string) => Promise<boolean>,
  signal?: AbortSignal,
): Promise<string | undefined> {
  const digest = createHash("sha256");
  const record = (...fields: (string | number)[]) =>
    digest.update(JSON.stringify(fields)).update("\n");
  async function visit(path: string, name: string): Promise<boolean> {
    throwIfSignalAborted(signal);
    const metadata = await lstat(path, { bigint: true });
    if (
      metadata.isSymbolicLink() ||
      relative(path, await realpath(path)) !== ""
    )
      return false;
    if (metadata.isDirectory()) {
      record("directory", name);
      for (const entry of (await readdir(path)).sort()) {
        const child = join(path, entry);
        if (!(await visit(child, name ? `${name}/${entry}` : entry)))
          return false;
      }
      return sameInode(metadata, await lstat(path, { bigint: true }));
    }
    if (!metadata.isFile()) return false;
    const file = await open(
      path,
      constants.O_RDONLY |
        (constants.O_NOFOLLOW ?? 0) |
        (constants.O_NONBLOCK ?? 0),
    );
    try {
      const opened = await file.stat({ bigint: true });
      if (!opened.isFile()) return false;
      if (!sameInode(metadata, opened)) {
        if (process.platform !== "win32") return false;
        // Some Windows Node versions report a different device on an open handle.
        const { sameCheckedFileDevice } = await import("./contract.js");
        if (!(await sameCheckedFileDevice(file, { path, metadata }, opened)))
          return false;
      }
      const contents = createHash("sha256")
        .update(await file.readFile({ signal }))
        .digest("hex");
      record("file", name, Number(opened.mode & 0o111n), contents);
    } finally {
      await file.close();
    }
    return true;
  }
  throwIfSignalAborted(signal);
  const installation = await lstat(installedRoot, { bigint: true }).catch(
    nullIfMissingFileError,
  );
  if (
    !installation?.isDirectory() ||
    installation.ino === 0n ||
    !(await matchesSelected(installedRoot))
  )
    return;
  try {
    const directory = migratedCommands(await realpath(installedRoot));
    const parent = dirname(directory);
    if (
      !(await lstat(parent)).isDirectory() ||
      relative(parent, await realpath(parent)) !== ""
    )
      return;
    const root = await lstat(directory, { bigint: true }).catch(
      nullIfMissingFileError,
    );
    if (root && (!root.isDirectory() || !(await visit(directory, "")))) return;
    // Native activation replaces the installed directory even at the same version.
    if (!sameInode(installation, await lstat(installedRoot, { bigint: true })))
      return;
    throwIfSignalAborted(signal);
    return root ? `sha256:${digest.digest("hex")}` : "absent";
  } catch (error) {
    throwIfSignalAborted(signal);
    if (
      !["ENOENT", "ENOTDIR", "ELOOP", "EISDIR", "EACCES", "EPERM"].includes(
        nodeErrorCode(error) ?? "",
      )
    )
      throw error;
  }
}

async function pluginContentsMatch(
  source: string,
  destination: string,
  signal?: AbortSignal,
  allowExtraFiles = false,
  projection?: PluginRuntimeProjection,
  generatedDirectory?: string,
): Promise<boolean> {
  throwIfSignalAborted(signal);

  const sourceMetadata = await lstat(source);
  const destinationMetadata = await lstat(destination).catch(
    (error: unknown) => {
      if (["ENOENT", "ENOTDIR"].includes(nodeErrorCode(error) ?? "")) {
        return null;
      }
      throw error;
    },
  );

  if (destinationMetadata === null) return false;

  if (sourceMetadata.isFile() && destinationMetadata.isFile()) {
    const projected = projection?.files.get(
      relative(projection.root, source).split(sep).join("/"),
    );
    if (
      (projected === undefined &&
        sourceMetadata.size !== destinationMetadata.size) ||
      ((projected?.mode === undefined || process.platform !== "win32") &&
        ((projected?.mode ?? sourceMetadata.mode) & 0o111) !==
          (destinationMetadata.mode & 0o111))
    ) {
      return false;
    }
    const [sourceBytes, destinationBytes] = await Promise.all([
      readFile(source, { signal }),
      readFile(destination, { signal }),
    ]);
    return (projected?.contents ?? sourceBytes).equals(destinationBytes);
  }

  if (!sourceMetadata.isDirectory() || !destinationMetadata.isDirectory()) {
    return false;
  }

  let entries = await readdir(source);
  let nativeOutputs = 0;
  if (generatedDirectory) {
    const parent = dirname(generatedDirectory);
    if (
      parent === destination ||
      (relative(parent, destination) === "" &&
        (await sameFile(parent, destination)))
    ) {
      // The installer removes old command output before regenerating it. Resolve
      // its source spelling on volumes that preserve case but ignore it on lookup.
      const path = join(source, basename(generatedDirectory));
      const original = await lstat(path).catch(nullIfMissingFileError);
      if (original?.isSymbolicLink()) return false;
      if (original) {
        const name = basename(await realpath(path));
        entries = entries.filter((entry) => entry !== name);
      }
      const installed = await lstat(generatedDirectory).catch(
        nullIfMissingFileError,
      );
      if (installed) {
        if (!installed.isDirectory()) return false;
        nativeOutputs = 1;
      }
    }
  }
  const projectedDirectory =
    projection === undefined
      ? undefined
      : relative(projection.root, source).split(sep).join("/") || ".";
  const generated = [...(projection?.files ?? [])].filter(
    ([path]) =>
      dirname(path) === projectedDirectory && !entries.includes(basename(path)),
  );
  if (
    !allowExtraFiles &&
    entries.length + generated.length + nativeOutputs !==
      (await readdir(destination)).length
  )
    return false;
  for (const [path, file] of generated) {
    const generatedPath = join(destination, basename(path));
    const metadata = await lstat(generatedPath).catch(nullIfMissingFileError);
    if (
      !metadata?.isFile() ||
      (process.platform !== "win32" &&
        (metadata.mode & 0o111) !== ((file.mode ?? 0o644) & 0o111)) ||
      !file.contents.equals(await readFile(generatedPath, { signal }))
    ) {
      return false;
    }
  }

  for (const entry of entries) {
    if (
      !(await pluginContentsMatch(
        join(source, entry),
        join(destination, entry),
        signal,
        allowExtraFiles,
        projection,
        generatedDirectory,
      ))
    ) {
      return false;
    }
  }

  return true;
}

export async function pluginMetadata(
  root: string,
): Promise<{ name: typeof PLUGIN_NAME; version: string }> {
  const manifestPath = join(root, ".codex-plugin", "plugin.json");
  let manifest: unknown;
  try {
    if (!(await lstat(manifestPath)).isFile()) {
      throw new Error("plugin manifest is not a regular file");
    }
    manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  } catch (error) {
    throw new LocalPluginBootstrapError(
      `Invalid Codex plugin directory: ${root}`,
      {
        cause: error,
      },
    );
  }
  if (!isRecord(manifest) || manifest["name"] !== PLUGIN_NAME) {
    throw new LocalPluginBootstrapError(
      "Plugin manifest must have name 'codex-security'.",
    );
  }
  const version = manifest["version"];
  if (typeof version !== "string" || version.trim().length === 0) {
    throw new LocalPluginBootstrapError(
      "Plugin manifest must have a non-empty version.",
    );
  }
  return { name: PLUGIN_NAME, version };
}

export async function resolvePluginPython(
  options: PluginPythonOptions = {},
): Promise<string> {
  const environment = options.environment ?? process.env;
  const cwd = process.cwd();
  const requestedRoots = options.protectedRoot ?? cwd;
  const protectedRoot =
    typeof requestedRoots === "string" ? [requestedRoots] : [...requestedRoots];
  const callerDirectories = new Set([cwd, options.currentDirectory ?? cwd]);
  // Preserve target and enclosing-checkout protection for every interpreter.
  for (const directory of new Set([...callerDirectories, ...protectedRoot])) {
    for (const checkout of await gitProtectionRoots(directory, options.signal))
      if (!protectedRoot.includes(checkout)) protectedRoot.push(checkout);
  }
  // Named interpreters are ambient PATH discovery, even when PYTHON names one.
  // Explicit trusted paths and managed runtimes retain their existing precedence.
  const discoveryRoots = [
    ...protectedRoot,
    ...(options.discoveryProtectedRoots ?? []),
  ];
  for (const directory of callerDirectories) {
    const physical =
      directory === cwd
        ? cwd
        : await realpath(directory).catch(() => undefined);
    // A filesystem-root launch directory also contains the operator's installed tools.
    // Explicit scan roots and enclosing checkouts are already in protectedRoot.
    if (
      protectedRoot.length === 0 ||
      physical === undefined ||
      dirname(physical) !== physical
    )
      discoveryRoots.push(directory);
  }
  const missingBoundaryMessage =
    "Could not establish the saved checkout boundary for Python discovery. Set PYTHON to an absolute trusted interpreter.";
  if (options.configuredPath !== undefined) {
    if (
      !isPythonPathCandidate(options.configuredPath) &&
      options.allowPathLookup === false
    )
      throw new PluginPythonUnavailableError(missingBoundaryMessage);
    return await requirePython(
      options.configuredPath,
      "configured plugin Python",
      environment,
      isPythonPathCandidate(options.configuredPath)
        ? protectedRoot
        : discoveryRoots,
      options.signal,
    );
  }
  const inherited = environmentValue(environment, "PYTHON", true);
  if (inherited) {
    if (!isPythonPathCandidate(inherited) && options.allowPathLookup === false)
      throw new PluginPythonUnavailableError(missingBoundaryMessage);
    const roots = isPythonPathCandidate(inherited)
      ? protectedRoot
      : discoveryRoots;
    // Check an explicit literal path with the same repository protections as the launch.
    const candidate =
      isExplicitPathWithTrailingWhitespace(inherited, process.platform) &&
      (await resolveTrustedExecutable(
        expandHomeForLookup(inherited, environment),
        environment,
        roots,
      ))
        ? inherited
        : inherited.trim();
    return await requirePython(
      candidate,
      "PYTHON",
      environment,
      roots,
      options.signal,
    );
  }

  let managedRoots = options.managedRuntimeRoots;
  if (managedRoots === undefined) {
    try {
      const cache =
        environmentValue(environment, "XDG_CACHE_HOME", true) ||
        join(options.homeDirectory ?? homedir(), ".cache");
      managedRoots = [join(cache, "codex-runtimes", "codex-primary-runtime")];
    } catch (error) {
      // A numeric Linux UID can lack a home for the optional managed cache.
      if (
        process.platform !== "linux" ||
        (error as { info?: NodeJS.ErrnoException }).info?.code !== "ENOENT"
      )
        throw error;
      managedRoots = [];
    }
  }
  const relativeCandidates =
    process.platform === "win32"
      ? [
          join("dependencies", "python", "python.exe"),
          join("dependencies", "python", "python", "python.exe"),
          join("dependencies", "python", "bin", "python.exe"),
        ]
      : [
          join("dependencies", "python", "bin", "python3"),
          join("dependencies", "python", "bin", "python"),
        ];
  for (const root of managedRoots) {
    for (const relativeCandidate of relativeCandidates) {
      const candidate = join(root, relativeCandidate);
      const resolved = await usablePython(
        candidate,
        environment,
        protectedRoot,
        options.signal,
      );
      if (resolved !== null) return resolved;
    }
  }

  if (options.allowPathLookup === false)
    throw new PluginPythonUnavailableError(missingBoundaryMessage);
  for (const candidate of process.platform === "win32"
    ? ["python", "python3", "py"]
    : ["python3", "python"]) {
    const resolved = await usablePython(
      candidate,
      environment,
      discoveryRoots,
      options.signal,
    );
    if (resolved !== null) return resolved;
  }
  throw new PluginPythonUnavailableError(
    "The bundled Codex Security plugin requires Python 3.10 or later (Python 3.10 also requires tomli), but no usable interpreter was found. " +
      "Set pythonPath, --python, or PYTHON, install the Codex managed runtime, or add python3/python (py on Windows) to PATH.",
  );
}

export function pluginExecutionEnvironment(
  python: string,
  environment: ProcessEnvironment = process.env,
): ProcessEnvironment {
  return {
    ...pythonUtf8Environment(environment),
    PYTHON: python,
    CODEX_SECURITY_PYTHON_COMMAND: python,
    CODEX_CLI_PATH: resolveCodexCommand(environment).command,
  };
}

export function environmentWithGit(
  environment: ProcessEnvironment,
  git?: InspectedExecutable,
): ProcessEnvironment {
  if (git === undefined) return environment;
  const result = { ...environment };
  for (const name of Object.keys(result)) {
    const normalized = name.toUpperCase();
    if (normalized === "CODEX_SECURITY_GIT" || normalized === "PATH") {
      delete result[name];
    }
  }
  result["CODEX_SECURITY_GIT"] = git.executable ?? "";
  result["PATH"] = git.environment["PATH"] ?? "";
  return result;
}

export function pythonUtf8Environment(
  environment: ProcessEnvironment,
): ProcessEnvironment {
  const normalized = { ...environment };
  for (const name of Object.keys(normalized)) {
    if (name.toUpperCase() === "PYTHONUTF8") delete normalized[name];
  }
  normalized["PYTHONUTF8"] = "1";
  return normalized;
}

function pluginHelperEnvironment(
  environment: ProcessEnvironment,
): ProcessEnvironment {
  return pythonUtf8Environment(
    Object.fromEntries(
      Object.entries(environment).filter(
        ([name]) =>
          !PLUGIN_HELPER_SECRET_ENVIRONMENT_VARIABLES.has(name.toUpperCase()),
      ),
    ),
  );
}

export async function cleanupSdkDirectory(path: string): Promise<void> {
  await rm(path, { recursive: true, force: true });
}

// A child can finish or reject a request before the parent finishes writing it.
export function isDisconnectedChildStdin(
  error: NodeJS.ErrnoException,
): boolean {
  return [
    "EPIPE",
    "ECONNRESET",
    "ENOTCONN",
    "EOF",
    "ERR_STREAM_DESTROYED",
  ].includes(error.code ?? "");
}

export async function runCodexCommand(
  command: CodexCommand,
  args: readonly string[] | ((executable: string) => readonly string[]),
  environment: ProcessEnvironment,
  input?: string | Uint8Array,
  launchSignal?: AbortSignal | (() => AbortSignal),
  {
    registrationHandshake = false,
    stdinPrefix,
    cwd,
  }: {
    registrationHandshake?: boolean;
    stdinPrefix?: string;
    cwd?: string;
  } = {},
): Promise<CodexCommandResult> {
  const campaign = campaignExecutable(command.command, environment);
  const selected = campaign && (await campaign);
  const executable = selected?.executable ?? command.command;
  const commandArgs = typeof args === "function" ? args(executable) : args;
  const signal =
    typeof launchSignal === "function" ? launchSignal() : launchSignal;
  const cancellation = registrationHandshake
    ? new AbortController()
    : undefined;
  const abort = () => cancellation?.abort(signal?.reason);
  const commandSignal = cancellation?.signal ?? signal;
  const child = spawn(
    executablePathForSpawn(executable),
    [...(command.args ?? []), ...commandArgs],
    {
      cwd,
      env: selected?.environment ?? environment,
      stdio: registrationHandshake
        ? ["pipe", "pipe", "pipe", "pipe"]
        : ["pipe", "pipe", "pipe"],
      windowsHide: true,
      signal: commandSignal,
    },
  );
  let stdout = "";
  let stderr = "";
  let processError: Error | undefined;
  const control = child.stdio[3] as Duplex | undefined;
  control?.once("data", () => {
    // The helper cannot change the output until the host allows the transaction.
    signal?.removeEventListener("abort", abort);
    if (signal?.aborted) abort();
    else control.end("!");
  });
  control?.on("error", (error: NodeJS.ErrnoException) => {
    if (!isDisconnectedChildStdin(error)) processError = error;
  });
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });
  const completion = new Promise<CodexCommandResult>((resolve, reject) => {
    child.once("error", (error) => {
      processError = error;
    });
    child.stdin.on("error", (error: NodeJS.ErrnoException) => {
      if (!isDisconnectedChildStdin(error)) processError = error;
    });
    child.once("close", (exitCode) =>
      processError === undefined
        ? resolve({ success: exitCode === 0, exitCode, stdout, stderr })
        : reject(processError),
    );
  });
  let forceTermination: ReturnType<typeof setTimeout> | undefined;
  const settleCanceledChild = () => {
    if (!commandSignal?.aborted) return;
    if (child.exitCode === null && child.signalCode === null) {
      // spawn already sent SIGTERM. Give the command time to exit cleanly.
      forceTermination ??= setTimeout(() => child.kill("SIGKILL"), 1_000);
      return;
    }
    child.stdin.destroy();
    child.stdout.destroy();
    child.stderr.destroy();
    control?.destroy();
  };
  commandSignal?.addEventListener("abort", settleCanceledChild, { once: true });
  child.once("exit", settleCanceledChild);
  if (commandSignal?.aborted) settleCanceledChild();
  if (registrationHandshake) {
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
  }
  try {
    if (stdinPrefix !== undefined) child.stdin.write(stdinPrefix);
    child.stdin.end(input);
    return await completion;
  } finally {
    if (registrationHandshake) signal?.removeEventListener("abort", abort);
    control?.destroy();
    clearTimeout(forceTermination);
    commandSignal?.removeEventListener("abort", settleCanceledChild);
    child.removeListener("exit", settleCanceledChild);
  }
}

export async function probeCodexSandbox(
  command: CodexCommand,
  environment: ProcessEnvironment,
  signal?: AbortSignal,
): Promise<void> {
  // This preflight covers the Unix sandbox backends.
  if (process.platform === "win32") return;
  // Reuse the resolved Codex executable instead of looking up a probe on PATH.
  const args = (executable: string) => [
    "sandbox",
    "--",
    executable,
    "--version",
  ];
  signal?.throwIfAborted();
  let timeout: AbortSignal | undefined;
  let detail: string;
  try {
    const result = await runCodexCommand(
      command,
      args,
      environment,
      undefined,
      () => {
        // Campaign tool selection happens before the sandbox process starts.
        signal?.throwIfAborted();
        timeout = AbortSignal.timeout(SANDBOX_PROBE_TIMEOUT_MILLISECONDS);
        return signal === undefined
          ? timeout
          : AbortSignal.any([signal, timeout]);
      },
    );
    if (result.success) return;
    detail =
      result.stderr.trim() ||
      result.stdout.trim() ||
      `Codex exited with status ${result.exitCode}.`;
  } catch (error) {
    signal?.throwIfAborted();
    if (timeout?.aborted)
      throw new SandboxUnavailableError(
        `Codex sandbox probe timed out after ${SANDBOX_PROBE_TIMEOUT_MILLISECONDS / 1000} seconds.`,
        { cause: error },
      );
    detail = processErrorDetail(error);
  }
  const guidance =
    process.platform === "linux"
      ? "\nOn Linux this usually means unprivileged user namespaces are restricted (kernel.apparmor_restrict_unprivileged_userns=1 on Ubuntu 24.04 and later), which Bubblewrap needs; inside the container image, use the AppArmor profile and Compose override from the SDK README."
      : "";
  throw new SandboxUnavailableError(
    `Codex could not run a command in its sandbox: ${detail}\nTo reproduce, run '${command.command} ${args(command.command).join(" ")}'.${guidance}`,
  );
}

class RolledBackPluginActivationError extends Error {}

function isRolledBackPluginActivation(error: unknown): boolean {
  return (
    error instanceof PluginBootstrapError &&
    error.cause instanceof RolledBackPluginActivationError
  );
}

async function runPluginCommand(
  command: CodexCommand,
  args: readonly string[],
  environment: ProcessEnvironment,
  signal?: AbortSignal,
): Promise<string> {
  try {
    const run = (argv: readonly string[], cwd?: string) =>
      runCodexCommand(command, argv, environment, undefined, signal, { cwd });
    let result = await run(args);
    const source = args[1] === "marketplace" ? args[3] : undefined;
    if (
      result.exitCode === 1 &&
      source?.includes("#") &&
      result.stderr
        .split(/\r?\n/u)
        .includes("Error: --ref is only supported for git marketplace sources")
    ) {
      // Native Codex parsed a literal hash in the local path as a Git ref.
      result = await run(["plugin", "marketplace", "add", "."], source);
    }
    const { success, exitCode, stdout, stderr } = result;
    if (!success) {
      const detail =
        stderr.trim() ||
        stdout.trim() ||
        `Codex exited with status ${exitCode}.`;
      // This native headline is emitted only after the previous entry was
      // restored. The Windows message itself may be localized.
      if (
        process.platform === "win32" &&
        args[0] === "plugin" &&
        args[1] === "add" &&
        exitCode === 1 &&
        /^Error: failed to activate updated plugin cache entry: [^\r\n]+ \(os error 5\)(?:\r?\n|$)/u.test(
          stderr,
        ) &&
        !stderr.includes("failed to restore previous cache entry")
      )
        throw new RolledBackPluginActivationError(detail);
      throw new Error(detail);
    }
    return stdout;
  } catch (error) {
    const detail = processErrorDetail(error);
    throw new PluginBootstrapError(`Codex plugin bootstrap failed: ${detail}`, {
      cause: error,
    });
  }
}

async function discoverPluginRoot(root: string): Promise<string> {
  if (await hasPluginManifest(root)) return await validatePluginRoot(root);
  const children = (await readdir(root, { withFileTypes: true })).filter(
    (entry) => entry.isDirectory(),
  );
  if (children.length === 1) {
    const candidate = join(root, children[0]!.name);
    if (await hasPluginManifest(candidate))
      return await validatePluginRoot(candidate);
  }
  throw new PluginBootstrapError(
    "Plugin ZIP must contain Codex Security at its root or in one top-level directory.",
  );
}

async function validatePluginRoot(root: string): Promise<string> {
  await pluginMetadata(root);
  return await realpath(root);
}

export async function copyPluginTree(
  source: string,
  destination: string,
  signal?: AbortSignal,
): Promise<void> {
  await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
  try {
    await cp(source, destination, {
      recursive: true,
      force: false,
      filter: async (path) => {
        throwIfSignalAborted(signal);
        const metadata = await lstat(path);
        if (
          (!metadata.isDirectory() && !metadata.isFile()) ||
          (await realpath(path)) !== path
        ) {
          throw new PluginBootstrapError(
            `Plugin contains an unsafe source path: ${path}`,
          );
        }
        throwIfSignalAborted(signal);
        return true;
      },
    });
  } catch (error) {
    await rm(destination, { recursive: true, force: true });
    throw error;
  }
}

async function readExactly(
  fd: number,
  length: number,
  position: number,
  signal?: AbortSignal,
): Promise<Buffer> {
  const buffer = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    throwIfSignalAborted(signal);
    const { bytesRead } = await promisify(readCallback)(
      fd,
      buffer,
      offset,
      length - offset,
      position + offset,
    );
    if (bytesRead === 0) throw new Error("unexpected end of plugin file");
    offset += bytesRead;
  }
  return buffer;
}

function safeArchivePath(value: string): string {
  const parts = value.split("/");
  const normalized = parts
    .filter((part) => part !== "" && part !== ".")
    .join("/");
  if (
    value.length === 0 ||
    value.startsWith("/") ||
    value.startsWith("//") ||
    /^[A-Za-z]:/.test(value) ||
    parts.includes("..") ||
    value.includes("\\") ||
    value.includes("\0") ||
    parts.some(isWindowsUnsafePathComponent) ||
    normalized.length === 0
  ) {
    throw new PluginBootstrapError(
      `Plugin ZIP contains an unsafe path: ${value}`,
    );
  }
  return normalized;
}

async function requirePython(
  candidate: string,
  source: string,
  environment: ProcessEnvironment,
  protectedRoot: string | readonly string[],
  signal?: AbortSignal,
): Promise<string> {
  const resolved = await usablePython(
    candidate,
    environment,
    protectedRoot,
    signal,
  );
  if (resolved !== null) return resolved;
  throw new PluginPythonUnavailableError(
    `The ${source} interpreter is unavailable or unusable: ${candidate}. ` +
      "The bundled Codex Security plugin requires Python 3.10 or later for scan execution; Python 3.10 also requires tomli.",
  );
}

async function usablePython(
  candidate: string,
  environment: ProcessEnvironment = process.env,
  protectedRoot: string | readonly string[] = process.cwd(),
  signal?: AbortSignal,
): Promise<string | null> {
  const command = await resolveTrustedExecutable(
    isPythonPathCandidate(candidate)
      ? expandHomeForLookup(candidate, environment)
      : candidate,
    environment,
    protectedRoot,
  );
  if (command === null) return null;
  try {
    const { stdout } = await execFile(
      command.executable,
      ["-I", "-c", PLUGIN_PYTHON_PROBE],
      {
        env: command.environment,
        encoding: "utf8",
        timeout: PLUGIN_PYTHON_PROBE_TIMEOUT_MS,
        windowsHide: true,
        signal,
      },
    );
    return stdout.trim() === PLUGIN_PYTHON_READY ? command.executable : null;
  } catch (error) {
    if (signal?.aborted) throw error;
    return null;
  }
}

export function isPythonPathCandidate(candidate: string): boolean {
  return candidate.includes("/") || candidate.includes("\\");
}

/** @internal Compare filesystem identity without depending on path spelling. */
export function sameFile(left: string, right: string): Promise<boolean> {
  // NTFS file IDs can exceed JavaScript's safe integer range.
  return Promise.all([
    stat(left, { bigint: true }),
    stat(right, { bigint: true }),
  ]).then(
    ([leftMetadata, rightMetadata]) => sameInode(leftMetadata, rightMetadata),
    () => false,
  );
}

export function resolveInputPath(
  value: string,
  directory = process.cwd(),
  environment: ProcessEnvironment = process.env,
): AbsolutePath {
  if (value === "~") value = expandHome("~", environment);
  else if (value.startsWith("~/") || value.startsWith("~\\")) {
    const home = expandHome("~", environment);
    const suffix = value.startsWith("~\\")
      ? value.slice(2).split("\\").filter(Boolean).join(sep)
      : value.slice(2);
    value = home === "" ? suffix : `${home}${sep}${suffix}`;
  }
  return resolveTargetPath(value, directory) as AbsolutePath;
}

/** Resolve through the last parent traversal while retaining aliases in the remaining path. */
export async function resolveParentTraversal(
  path: string,
  { allowMissing = false }: { allowMissing?: boolean } = {},
): Promise<string> {
  const parts = path.split(sep);
  const parent = parts.lastIndexOf("..");
  if (parent === -1) return path;
  const prefix = parts.slice(0, parent + 1).join(sep);
  // A new output directory can be spelled missing/../scan before its parent exists.
  if (
    allowMissing &&
    (await stat(prefix).catch(nullIfMissingFileError)) === null
  ) {
    return resolve(path);
  }
  // Resolve each directory before moving to its parent. Some runtimes collapse
  // a literal ".." inside realpath before consulting the filesystem.
  const before =
    parts.slice(0, parent).join(sep) || (isAbsolute(path) ? sep : ".");
  const physical = dirname(
    await realpath(await resolveParentTraversal(before)),
  );
  if (!(await sameFile(prefix, physical)))
    throw new InvalidTargetError(`Repository path changed: ${prefix}`);
  return join(physical, ...parts.slice(parent + 1));
}

export function expandHomeForLookup(
  value: string,
  environment: ProcessEnvironment = process.env,
): string {
  const path = value.startsWith("~\\") ? value.replaceAll("\\", "/") : value;
  // Expand only the home prefix; joining the suffix would collapse symlink/.. paths.
  return path.startsWith("~/")
    ? `${expandHome("~", environment)}${sep}${path.slice(2)}`
    : expandHome(path, environment);
}

export function expandHome(
  value: string,
  environment: ProcessEnvironment = process.env,
): string {
  const home = () =>
    (process.platform === "win32"
      ? (environmentValue(environment, "USERPROFILE") ??
        environmentValue(environment, "HOME"))
      : (environmentValue(environment, "HOME") ??
        environmentValue(environment, "USERPROFILE"))) ?? homedir();
  if (value === "~") return home();
  if (value.startsWith("~/")) return join(home(), value.slice(2));
  if (value.startsWith("~\\")) {
    return join(home(), ...value.slice(2).split("\\"));
  }
  return value;
}

function safePrefix(value: string): string {
  return basename(value).replace(/[^A-Za-z0-9._-]/g, "-") || "repository";
}

function processErrorDetail(error: unknown): string {
  if (isRecord(error)) {
    for (const key of ["stderr", "stdout", "message"] as const) {
      const value = error[key];
      if (typeof value === "string" && value.trim()) return value.trim();
      if (value instanceof Uint8Array) {
        const decoded = new TextDecoder().decode(value).trim();
        if (decoded) return decoded;
      }
    }
  }
  return String(error) || "unknown error";
}

function nodeErrorCode(error: unknown): string | undefined {
  return isRecord(error) && typeof error["code"] === "string"
    ? error["code"]
    : undefined;
}

function throwIfSignalAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw abortReason(signal);
}

function nullIfMissingFileError(error: unknown): null {
  if (nodeErrorCode(error) === "ENOENT") return null;
  throw error;
}

/** @internal */
export function workbenchEnvironment(environment: ProcessEnvironment) {
  return {
    ...environment,
    CODEX_SECURITY_STATE_DIR: codexSecurityStateDirectory(environment),
  };
}

/** @internal */
export const resolveWorkbenchRuntime = (options: PluginPythonOptions) =>
  Promise.all([resolvePluginPython(options), bundledPluginRoot()]);
