import { execFile as execFileCallback, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  chmodSync,
  constants,
  existsSync,
  readdirSync,
  type BigIntStats,
  type Stats,
} from "node:fs";
import {
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
} from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { crc32 } from "node:zlib";
import { setTimeout as delay } from "node:timers/promises";
import extractZip from "extract-zip";
import { parse } from "smol-toml";
import {
  CodexSecurityError,
  OutputDirectoryError,
  OutputDirectoryNotEmptyError,
  OutputInsideProtectedRootError,
  PluginBootstrapError,
  PluginPythonUnavailableError,
  type ProtectedScanPathKind,
  errorMessage,
} from "./errors.js";
import type { JsonObject } from "./config.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";
import {
  isWindowsUnsafePathComponent,
  windowsUnsafePathComponent,
} from "./windows-path.js";

const execFile = promisify(execFileCallback);

export const MARKETPLACE_NAME = "codex-security-sdk";
export const PLUGIN_NAME = "codex-security";

const MAX_ZIP_ENTRIES = 4_096;
const MAX_ZIP_CENTRAL_DIRECTORY = 16 * 1024 * 1024;
const MAX_ZIP_ENTRY_SIZE = 128 * 1024 * 1024;
const MAX_ZIP_EXPANDED_SIZE = 512 * 1024 * 1024;
const MODEL_UNSAFE_PATH = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u;
const CREDENTIAL_LOCK_NAME = ".codex-security-scan.lock";
const CREDENTIAL_LOCK_DATABASE = ".codex-security-scan.sqlite3";
const CREDENTIAL_LOGOUT_MARKER = ".codex-security-logged-out";
const CREDENTIAL_LOCK_HEARTBEAT_MILLISECONDS = 5_000;
const CREDENTIAL_LOCK_POLL_MILLISECONDS = 25;
const INCOMPLETE_CREDENTIAL_LOCK_MILLISECONDS = 30_000;
const MAX_PROCESS_ID = 2_147_483_647;
const MAX_WINDOWS_CREDENTIAL_ACL_STDERR = 64 * 1024;
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
  protectedRoot?: string;
  signal?: AbortSignal;
}

export interface WorkbenchCommandOptions {
  python: string;
  pluginRoot: string;
  environment: ProcessEnvironment;
  signal?: AbortSignal;
  failureMessage?: string;
}

function environmentValue(
  environment: ProcessEnvironment,
  requested: string,
): string | undefined {
  const exact = environment[requested]?.trim();
  if (exact) return exact;
  return Object.entries(environment)
    .find(
      ([name, value]) => name.toUpperCase() === requested && value?.trim(),
    )?.[1]
    ?.trim();
}

export function codexSecurityStateDirectory(
  environment: ProcessEnvironment = process.env,
): string {
  const configured = environmentValue(environment, "CODEX_SECURITY_STATE_DIR");
  const path =
    configured !== undefined
      ? resolve(expandHome(configured, environment))
      : resolve(
          expandHome(
            environmentValue(environment, "CODEX_HOME") ??
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
        const existing = await lstat(path).catch(() => null);
        if (
          existing !== null &&
          (!existing.isDirectory() || existing.isSymbolicLink())
        ) {
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
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
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
    throw new OutputDirectoryError(
      `Unable to prepare the Codex Security credential home: ${path}`,
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
  options: {
    platform?: NodeJS.Platform;
    secureWindowsHome?: (path: string) => Promise<void>;
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
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
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
      `Unable to create a private Windows credential home: ${path}${detail}`,
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
      : error instanceof Error
        ? error.message
        : String(error);
  const normalized = errorMessage(detail)
    .replace(/\s+/gu, " ")
    .trim()
    .slice(0, 512);
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
          windowsAceAllowsAncestorReplacement(rights!, inheritanceFlags)
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
    } else {
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

function windowsSecurityDescriptorRule(value: string): {
  rule: string;
  rest: string;
} {
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
  for (let index = 0; index < rights.length; index += 2) {
    if (
      ["FA", "GA", "FW", "GW", "SD", "WD", "WO", "DC", "DT"].includes(
        rights.slice(index, index + 2),
      )
    ) {
      return true;
    }
  }
  return false;
}

export async function streamWindowsCredentialAclDescriptors(
  command: string,
  args: readonly string[],
  inspectDescriptor: (descriptor: string) => Promise<void>,
  options: { environment?: NodeJS.ProcessEnv } = {},
): Promise<number> {
  const child = spawn(command, [...args], {
    env: options.environment,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => {
    const remaining = MAX_WINDOWS_CREDENTIAL_ACL_STDERR - stderr.length;
    if (remaining > 0) stderr += chunk.slice(0, remaining);
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

  let descriptors = 0;
  try {
    await Promise.all([
      completion,
      (async () => {
        const lines = createInterface({
          input: child.stdout,
          crlfDelay: Infinity,
        });
        for await (const descriptor of lines) {
          if (descriptor === "") continue;
          await inspectDescriptor(descriptor);
          descriptors += 1;
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
  return descriptors;
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
  },
): Promise<{
  home: WindowsCredentialAcl;
  descendantsArePrivate: boolean;
}> {
  let ancestors = 0;
  for (let ancestor = dirname(path); ; ancestor = dirname(ancestor)) {
    ancestors += 1;
    if (ancestor === dirname(ancestor)) break;
  }

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

          if (index < ancestors) {
            const ancestor = inspectWindowsCredentialAcl(
              descriptor,
              currentUserSid,
              {
                resolvedAliases: options.resolvedAliases,
                scope: "ancestor",
              },
            );
            if (ancestor.untrustedPrincipals.length !== 0) {
              throw new Error(
                "Windows credential-home ancestor allows another identity to replace the directory",
              );
            }
            return;
          }

          if (index === ancestors) {
            try {
              home = inspectWindowsCredentialAcl(descriptor, currentUserSid, {
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
    if (inspected <= ancestors) {
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

async function secureWindowsCredentialHome(path: string): Promise<void> {
  const systemRoot = process.env["SystemRoot"] ?? "C:\\Windows";
  const systemDirectory = join(systemRoot, "System32");
  const powershell = join(
    systemDirectory,
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe",
  );
  const inheritedEnvironment = Object.fromEntries(
    Object.entries(process.env).filter(
      ([name]) => name.toUpperCase() !== "PSMODULEPATH",
    ),
  );
  const processOptions = {
    env: {
      ...inheritedEnvironment,
      CODEX_SECURITY_CREDENTIAL_ACL_PATH: path,
      PSModulePath: join(
        systemDirectory,
        "WindowsPowerShell",
        "v1.0",
        "Modules",
      ),
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
    "function Write-CredentialAcl($path) { $descriptor = Microsoft.PowerShell.Security\\Get-Acl -LiteralPath $path | Microsoft.PowerShell.Utility\\Select-Object -ExpandProperty Sddl; if (-not $descriptor) { throw 'Windows credential ACL could not be verified' }; $script:descriptorCount += 1; $descriptor }",
    "function Read-CredentialDescendants($path) {",
    "  try { $entries = @(Microsoft.PowerShell.Management\\Get-ChildItem -LiteralPath $path -Force) } catch {",
    // A child can disappear while an existing directory is being enumerated.
    // Retry that incomplete listing before accepting a vanished descendant.
    `    if ($_.FullyQualifiedErrorId -eq 'System.IO.FileNotFoundException,Microsoft.PowerShell.Commands.GetChildItemCommand') { exit ${WINDOWS_CREDENTIAL_DESCENDANTS_CHANGED_EXIT_CODE} }`,
    "    if ($path -ne $env:CODEX_SECURITY_CREDENTIAL_ACL_PATH -and $_.CategoryInfo.Category -eq 'ObjectNotFound') { return }",
    "    throw",
    "  }",
    "  foreach ($entry in $entries) {",
    "    if (($entry.Attributes -band 1024) -and ($entry.LinkType -in @('SymbolicLink', 'Junction'))) { throw 'Windows credential home contains a symbolic link or junction' }",
    "    if ($entry.PSObject.TypeNames -notcontains 'System.IO.DirectoryInfo' -and $entry.PSObject.TypeNames -notcontains 'System.IO.FileInfo') { throw 'Windows credential home contains an unsafe entry' }",
    "    try { Write-CredentialAcl $entry.FullName } catch { if ($_.FullyQualifiedErrorId -like 'GetAcl_PathNotFound,*') { continue }; throw }",
    "    if ($entry.PSIsContainer) { Read-CredentialDescendants $entry.FullName }",
    "  }",
    "}",
    "$path = $env:CODEX_SECURITY_CREDENTIAL_ACL_PATH",
    "while ($true) { $parent = Microsoft.PowerShell.Management\\Split-Path -Path $path -Parent; if (-not $parent -or $parent -eq $path) { break }; Write-CredentialAcl $parent; $path = $parent }",
    "Write-CredentialAcl $env:CODEX_SECURITY_CREDENTIAL_ACL_PATH",
    "Read-CredentialDescendants $env:CODEX_SECURITY_CREDENTIAL_ACL_PATH",
    `"${WINDOWS_CREDENTIAL_ACL_COMPLETE_PREFIX}$script:descriptorCount"`,
  ].join("\n");
  const resolvePrincipalScript = [
    "$ErrorActionPreference = 'Stop'",
    "$descriptor = 'O:' + $env:CODEX_SECURITY_CREDENTIAL_PRINCIPAL + 'G:SYD:(A;;GA;;;SY)'",
    "Microsoft.PowerShell.Utility\\ConvertFrom-SddlString -Sddl $descriptor | Microsoft.PowerShell.Utility\\Select-Object -ExpandProperty RawDescriptor | Microsoft.PowerShell.Utility\\Select-Object -ExpandProperty Owner | Microsoft.PowerShell.Utility\\Select-Object -ExpandProperty Value",
  ].join("; ");
  const resolvedAliases: Record<string, string> = {};
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
      [
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        resolvePrincipalScript,
      ],
      {
        ...processOptions,
        env: {
          ...processOptions.env,
          CODEX_SECURITY_CREDENTIAL_PRINCIPAL: principal,
        },
      },
    );
    const numeric = resolved.stdout.trim();
    if (!WINDOWS_SID.test(numeric)) {
      throw new Error(
        "Windows credential ACL contains an unresolvable identity",
      );
    }
    resolvedAliases[principal] = numeric;
  };
  const resolveDescriptorAliases = async (
    descriptor: string,
  ): Promise<void> => {
    const header = WINDOWS_SECURITY_DESCRIPTOR.exec(descriptor.trim());
    if (header === null) return;
    await resolvePrincipal(header[1]!);
    let remaining = header[3]!;
    while (remaining.startsWith("(")) {
      const { rule, rest } = windowsSecurityDescriptorRule(remaining);
      const principal = rule.split(";")[5];
      if (principal !== undefined) await resolvePrincipal(principal);
      remaining = rest;
    }
  };
  let descendantsArePrivate = true;
  const readAcl = async (): Promise<WindowsCredentialAcl> => {
    const snapshot = await inspectWindowsCredentialAclSnapshot(path, sid, {
      command: powershell,
      args: ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
      environment: processOptions.env,
      resolvedAliases,
      resolveDescriptorAliases,
    });
    descendantsArePrivate = snapshot.descendantsArePrivate;
    return snapshot.home;
  };

  const icacls = join(systemDirectory, "icacls.exe");
  const installTrustedAcl = async (target = path): Promise<void> => {
    await execFile(
      icacls,
      [
        target,
        "/inheritance:r",
        "/grant:r",
        `*${sid}:(OI)(CI)F`,
        `*${WINDOWS_SYSTEM_SID}:(OI)(CI)F`,
        `*${WINDOWS_ADMINISTRATORS_SID}:(OI)(CI)F`,
      ],
      processOptions,
    );
  };
  let existing: WindowsCredentialAcl | undefined;
  for (let attempt = 0; existing === undefined && attempt < 3; attempt += 1) {
    try {
      existing = await readAcl();
    } catch (error) {
      if (error instanceof RepairableWindowsCredentialOwnerError) {
        await execFile(icacls, [path, "/setowner", `*${sid}`], processOptions);
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
    await execFile(icacls, [path, "/inheritance:d"], processOptions);
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
    for (const principal of verified.untrustedPrincipals) {
      if (!WINDOWS_SID.test(principal)) {
        throw new Error(
          "Windows credential ACL contains an unresolvable identity",
        );
      }
      await execFile(
        icacls,
        [path, "/remove:g", `*${principal}`],
        processOptions,
      );
    }
    for (const principal of verified.deniedPrincipals) {
      if (!WINDOWS_SID.test(principal)) {
        throw new Error(
          "Windows credential ACL contains an unresolvable identity",
        );
      }
      await execFile(
        icacls,
        [path, "/remove:d", `*${principal}`],
        processOptions,
      );
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
    await execFile(
      icacls,
      [join(path, "*"), "/reset", "/t", "/q"],
      processOptions,
    );
    await readAcl();
    if (!descendantsArePrivate) {
      throw new Error("Windows credential descendants remain accessible");
    }
  }
}

export async function acquireCodexSecurityCredentialHomeLock(
  codexHome: string,
  signal?: AbortSignal,
  securityOptions: {
    platform?: NodeJS.Platform;
    secureWindowsHome?: (path: string) => Promise<void>;
  } = {},
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
    (error: unknown) => {
      if (nodeErrorCode(error) === "ENOENT") return null;
      throw error;
    },
  );
  if (existingDatabaseMetadata !== null) {
    requireCredentialLockDatabaseFile(existingDatabaseMetadata, databasePath);
  }
  const require = createRequire(import.meta.url);
  // Both supported runtimes bundle SQLite. Keep the transaction in the process
  // doing the protected work, so pausing it cannot expire its lock.
  const Database = process.versions["bun"]
    ? (require("bun:sqlite") as { Database: CredentialLockDatabaseConstructor })
        .Database
    : (
        require("node:sqlite") as {
          DatabaseSync: CredentialLockDatabaseConstructor;
        }
      ).DatabaseSync;
  // Let SQLite create a missing guard so no separate descriptor can close after
  // another connection acquires its process-owned POSIX lock. Keep the guard
  // across releases so every contender locks the same inode.
  const database = new Database(databasePath);
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
          if (
            !isRecord(error) ||
            (error["errcode"] !== 5 && error["code"] !== "SQLITE_BUSY")
          ) {
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
      const existingLock = await lstat(lock).catch((error: unknown) => {
        if (nodeErrorCode(error) === "ENOENT") return null;
        throw error;
      });
      if (existingLock !== null) {
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

interface CredentialLockDatabaseConstructor {
  new (path: string): {
    exec(sql: string): unknown;
    close(): void;
  };
}

async function recoverStaleCredentialHomeLock(lock: string): Promise<boolean> {
  const metadata = await lstat(lock).catch((error: unknown) => {
    if (nodeErrorCode(error) === "ENOENT") return null;
    throw error;
  });
  if (metadata === null) return true;
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
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

export async function setCodexSecurityCredentialLogout(
  codexHome: string,
  loggedOut: boolean,
): Promise<void> {
  await requireSecureCredentialHome(codexHome);
  const marker = join(codexHome, CREDENTIAL_LOGOUT_MARKER);
  if (!loggedOut) {
    await rm(marker, { force: true });
    return;
  }

  const temporary = join(
    codexHome,
    `.codex-security-logout-${randomUUID()}.tmp`,
  );
  try {
    const handle = await open(temporary, "wx", 0o600);
    try {
      await handle.chmod(0o600);
      await handle.writeFile("logged out\n", "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, marker);
  } finally {
    await rm(temporary, { force: true });
  }
}

export async function codexSecurityCredentialAllowsAmbientImport(
  codexHome: string,
): Promise<boolean> {
  await requireSecureCredentialHome(codexHome);
  try {
    const marker = await lstat(join(codexHome, CREDENTIAL_LOGOUT_MARKER));
    if (!marker.isFile() || marker.isSymbolicLink()) {
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
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
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
  const outputRelative = relative(repository, outputDirectory);
  const repositoryRelative = relative(outputDirectory, repository);
  if (
    outputRelative === "" ||
    (outputRelative !== ".." &&
      !outputRelative.startsWith(`..${sep}`) &&
      !isAbsolute(outputRelative)) ||
    (pathKind === "output" &&
      repositoryRelative !== ".." &&
      !repositoryRelative.startsWith(`..${sep}`) &&
      !isAbsolute(repositoryRelative))
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

export async function preparePersistentOutputRoot(
  stateDirectory: string,
  category: "scans" | "policies" | "validations",
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
        `Persistent ${category === "scans" ? "scan" : category === "policies" ? "policy" : "validation"} output must use real directories: ${root}`,
      );
    }
  }
  return root;
}

export async function runWorkbench(
  options: WorkbenchCommandOptions,
  args: readonly string[],
  input?: string,
): Promise<JsonObject> {
  let stdout: string;
  try {
    const environment = Object.fromEntries(
      Object.entries(options.environment).filter(
        ([name]) =>
          name.toUpperCase() !== "OPENAI_API_KEY" &&
          name.toUpperCase() !== "CODEX_API_KEY" &&
          name.toUpperCase() !== "OPENROUTER_API_KEY" &&
          name.toUpperCase() !== "FIREWORKS_API_KEY",
      ),
    );
    const result = await runCodexCommand(
      { command: options.python },
      [
        "-I",
        "-X",
        "utf8",
        "-B",
        join(options.pluginRoot, "scripts", "workbench_db.py"),
        ...args,
      ],
      pythonUtf8Environment(environment),
      input,
      options.signal,
    );
    if (!result.success) {
      throw new Error(
        result.stderr.trim() ||
          result.stdout.trim() ||
          `Workbench exited with status ${result.exitCode}.`,
      );
    }
    stdout = result.stdout;
  } catch (error) {
    if (options.signal?.aborted) throw error;
    const detail = processErrorDetail(error);
    const databaseFailure =
      /\b(?:unable to open database file|attempt to write a readonly database|readonly database|disk i\/o error)\b/iu.test(
        detail,
      );
    const failure =
      options.failureMessage ?? "Could not run the Codex Security workbench";
    throw new CodexSecurityError(
      databaseFailure
        ? `${failure}: cannot open the workbench database at ${join(
            codexSecurityStateDirectory(options.environment),
            "workbench.sqlite3",
          )}. Ensure the state directory and SQLite journal files are writable, or set CODEX_SECURITY_STATE_DIR to a writable directory outside the scanned repository.`
        : `${failure}: ${detail}`,
      { cause: error },
    );
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

export function bundledPluginCandidates(moduleDirectory: string): string[] {
  const packageCandidates = [
    resolve(moduleDirectory, "_bundled_plugin"),
    resolve(moduleDirectory, "../_bundled_plugin"),
  ];
  return basename(moduleDirectory) === "src"
    ? [
        resolve(moduleDirectory, "../../../plugins/codex-security"),
        ...packageCandidates,
      ]
    : packageCandidates;
}

export async function bundledPluginRoot(): Promise<string> {
  const moduleDirectory = dirname(fileURLToPath(import.meta.url));
  for (const candidate of bundledPluginCandidates(moduleDirectory)) {
    if (await hasPluginManifest(candidate)) {
      return await realpath(candidate);
    }
  }
  throw new PluginBootstrapError(
    "The bundled Codex Security plugin is missing.",
  );
}

export async function validateOutputDir(
  outputDirectory?: string,
  archiveExisting = false,
): Promise<string | null> {
  if (outputDirectory === undefined) {
    return null;
  }
  requireModelSafeOutputDir(outputDirectory);
  const path = resolve(expandHome(outputDirectory));
  try {
    const metadata = await lstat(path).catch((error: unknown) => {
      if (nodeErrorCode(error) === "ENOENT") return null;
      throw error;
    });
    if (metadata !== null) {
      if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
        throw new OutputDirectoryError(
          `Scan output is not a directory: ${path}`,
        );
      }
      if (!archiveExisting && (await readdir(path)).length !== 0) {
        throw new OutputDirectoryNotEmptyError(path);
      }
      requirePrivateOutputDirectory(metadata, path);
      await requireSecureOutputAncestry(path);
      const canonical = await realpath(path);
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
          await requireSecureOutputAncestry(canonical);
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
    if (error instanceof OutputDirectoryError) throw error;
    throw new OutputDirectoryError(
      `Unable to inspect scan output directory: ${outputDirectory}`,
      { cause: error },
    );
  }
}

export async function planOutputArchive(
  outputDirectory: string | null,
): Promise<string | null> {
  if (outputDirectory === null) return null;
  const entries = await readdir(outputDirectory).catch((error: unknown) => {
    if (nodeErrorCode(error) === "ENOENT") return null;
    throw error;
  });
  if (entries === null || entries.length === 0) return null;
  const timestamp = new Date()
    .toISOString()
    .replaceAll(/[-:]/g, "")
    .replace(/\.\d{3}Z$/, "");
  return `${outputDirectory}.previous-${timestamp}-${randomUUID().slice(0, 8)}`;
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
  for (let ancestor = path; ; ancestor = dirname(ancestor)) {
    try {
      const canonicalAncestor = resolve(ancestor, await realpath(ancestor));
      const canonical = resolve(canonicalAncestor, relative(ancestor, path));
      requireModelSafeOutputDir(canonical);
      return canonical;
    } catch (error) {
      if (nodeErrorCode(error) !== "ENOENT") throw error;
      if (dirname(ancestor) === ancestor) throw error;
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
  if (outputDirectory === undefined) {
    requireModelSafeOutputDir(temporaryRoot);
    requireModelSafeOutputDir(await realpath(temporaryRoot));
  }
  const path = await validateOutputDir(outputDirectory, archiveExisting);
  validateLocation?.(path ?? (await realpath(temporaryRoot)));
  if (path === null) {
    const created = await mkdtemp(
      join(temporaryRoot, `codex-security-${safePrefix(repositoryName)}-`),
    );
    if ((process.umask() & 0o700) !== 0) await chmod(created, 0o700);
    try {
      return await validatePreparedOutputDir(created, validateLocation);
    } catch (error) {
      await rmdir(created).catch(() => undefined);
      throw error;
    }
  }
  let createdRoot: string | undefined;
  try {
    let existing = await lstat(path).catch((error: unknown) => {
      if (nodeErrorCode(error) === "ENOENT") return null;
      throw error;
    });
    if (existing !== null && archiveExisting) {
      const archiveDir = await planOutputArchive(path);
      if (archiveDir !== null) {
        await rename(path, archiveDir);
        onOutputArchived?.(archiveDir);
        existing = null;
      }
    }
    if (existing === null) {
      createdRoot = await mkdir(path, { recursive: true, mode: 0o700 });
      if ((process.umask() & 0o700) !== 0) await chmod(path, 0o700);
    }
    return await validatePreparedOutputDir(path, validateLocation);
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

export async function validatePreparedOutputDir(
  path: string,
  validateLocation?: (path: string) => void,
): Promise<string> {
  const metadata = await lstat(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new OutputDirectoryError(`Scan output is not a directory: ${path}`);
  }
  const canonical = await realpath(path);
  requireModelSafeOutputDir(canonical);
  validateLocation?.(canonical);
  const entries = await readdir(canonical);
  if (entries.length !== 0) {
    throw new OutputDirectoryError(
      `Scan output directory must be empty: ${path}`,
    );
  }
  requirePrivateOutputDirectory(metadata, path);
  await requireSecureOutputAncestry(canonical);
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
  if (effectiveUid !== undefined && metadata.uid !== effectiveUid) {
    throw new OutputDirectoryError(
      `Scan output directory must be owned by the current user: ${path}`,
    );
  }
}

/** Reject shared parents whose owner can rename or replace private scan output. */
export async function requireSecureOutputAncestry(
  path: string,
  effectiveUid = process.geteuid?.(),
): Promise<void> {
  if (process.platform === "win32") return;
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
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
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
  const archivePath = resolve(expandHome(archive));
  await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
  const staging = await realpath(
    await mkdtemp(join(dirname(destination), ".codex-security-plugin-")),
  );
  try {
    throwIfSignalAborted(signal);
    await rejectBackslashZipNames(archivePath, signal);
    let expandedSize = 0;
    const paths = new Set<string>();
    const checksums: Array<{ path: string; checksum: number }> = [];
    await extractZip(archivePath, {
      dir: staging,
      defaultDirMode: 0o700,
      defaultFileMode: 0o600,
      onEntry(entry, archive) {
        throwIfSignalAborted(signal);
        if (archive.entryCount > MAX_ZIP_ENTRIES) {
          throw new PluginBootstrapError(
            `Plugin ZIP contains too many entries: ${archive.entryCount}.`,
          );
        }
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
        if (!directory) {
          checksums.push({ path, checksum: entry.crc32 >>> 0 });
        }
      },
    });
    for (const { path, checksum } of checksums) {
      throwIfSignalAborted(signal);
      const bytes = await readFile(join(staging, ...path.split("/")));
      if (crc32(bytes) !== checksum) {
        throw new PluginBootstrapError(
          `Plugin ZIP entry failed CRC-32 validation: ${path}`,
        );
      }
    }
    const pluginRoot = await discoverPluginRoot(staging);
    throwIfSignalAborted(signal);
    const relativeRoot = relative(staging, pluginRoot);
    await rename(staging, destination);
    return await validatePluginRoot(join(destination, relativeRoot));
  } catch (error) {
    await rm(staging, { recursive: true, force: true }).catch(() => undefined);
    throwIfSignalAborted(signal);
    if (error instanceof PluginBootstrapError) throw error;
    throw new PluginBootstrapError(`Invalid plugin ZIP: ${archivePath}`, {
      cause: error,
    });
  }
}

async function rejectBackslashZipNames(
  path: string,
  signal?: AbortSignal,
): Promise<void> {
  const handle = await open(path, "r");
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size < 22) {
      throw new Error("missing end of central directory");
    }
    const tailSize = Math.min(metadata.size, 65_557);
    const tail = await readExactly(
      handle,
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
    const central = await readExactly(
      handle,
      centralSize,
      centralOffset,
      signal,
    );
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
  } finally {
    await handle.close();
  }
}

export async function resolvePluginPath(
  pluginPath: string | undefined,
  workspace: string,
  signal?: AbortSignal,
): Promise<string> {
  if (pluginPath === undefined) {
    return await bundledPluginRoot();
  }

  const path = resolve(expandHome(pluginPath));
  const metadata = await lstat(path).catch(() => null);
  if (metadata?.isFile() && extname(path).toLowerCase() === ".zip") {
    return await extractPluginZip(
      path,
      join(workspace, "extracted-plugin"),
      signal,
    );
  }
  if (metadata?.isDirectory() && !metadata.isSymbolicLink()) {
    throwIfSignalAborted(signal);
    return await validatePluginRoot(path);
  }
  throw new PluginBootstrapError(
    `Plugin path must be a directory or ZIP: ${path}`,
  );
}

export async function createMarketplace(
  codexHome: string,
  pluginRoot: string,
  signal?: AbortSignal,
): Promise<string> {
  throwIfSignalAborted(signal);
  const root = await realpath(pluginRoot);
  const marketplace = join(codexHome, "sdk-marketplace");
  const pluginDestination = join(marketplace, "plugins", PLUGIN_NAME);
  await copyPluginTree(root, pluginDestination, signal);
  throwIfSignalAborted(signal);
  const manifest = {
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
  };
  const manifestPath = join(
    marketplace,
    ".agents",
    "plugins",
    "marketplace.json",
  );
  await mkdir(dirname(manifestPath), { recursive: true, mode: 0o700 });
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
    signal,
  });
  throwIfSignalAborted(signal);
  return marketplace;
}

export function resolveCodexCommand(
  environment: ProcessEnvironment = process.env,
): CodexCommand {
  const configured = environmentValue(environment, "CODEX_CLI_PATH");
  const expanded =
    configured === undefined ? undefined : expandHome(configured, environment);
  if (
    expanded &&
    (process.platform !== "win32" || /\.(?:exe|com)$/iu.test(expanded))
  ) {
    return { command: resolve(expanded) };
  }

  const platform = process.platform === "android" ? "linux" : process.platform;
  const packageName = `@openai/codex-${platform}-${process.arch}`;
  let packageJson: string;
  try {
    const require = createRequire(import.meta.url);
    const codexPackageJson = require.resolve("@openai/codex/package.json");
    packageJson = createRequire(codexPackageJson).resolve(
      `${packageName}/package.json`,
    );
  } catch (error) {
    throw new PluginBootstrapError(
      `The bundled Codex executable could not be resolved from ${packageName}. Reinstall @openai/codex with optional dependencies enabled, or set CODEX_CLI_PATH to an installed Codex executable.`,
      { cause: error },
    );
  }
  const vendor = join(dirname(packageJson), "vendor");
  const target = readdirSync(vendor, { withFileTypes: true }).find((entry) =>
    entry.isDirectory(),
  );
  const command = join(
    vendor,
    target?.name ?? "",
    "bin",
    process.platform === "win32" ? "codex.exe" : "codex",
  );
  if (target === undefined || !existsSync(command)) {
    throw new PluginBootstrapError(
      `The ${packageName} package does not contain the Codex executable. Reinstall @openai/codex with optional dependencies enabled, or set CODEX_CLI_PATH to an installed Codex executable.`,
    );
  }
  return { command };
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
  const marketplace = join(codexHome, "sdk-marketplace");
  throwIfSignalAborted(options.signal);
  const command =
    options.codexCommand ?? resolveCodexCommand(options.environment);
  const environment = {
    ...(options.environment ?? process.env),
    CODEX_HOME: codexHome,
  };
  const run = options.runCodex ?? runPluginCommand;
  const existing = await lstat(marketplace).catch((error: unknown) => {
    if (nodeErrorCode(error) === "ENOENT") return null;
    throw error;
  });
  if (existing !== null && !existing.isDirectory()) {
    throw new PluginBootstrapError(
      `Codex Security plugin marketplace path must be a directory: ${marketplace}`,
    );
  }

  const staged =
    existing === null
      ? null
      : await pluginMetadata(join(marketplace, "plugins", PLUGIN_NAME)).catch(
          () => null,
        );
  if (staged?.version !== version) {
    if (existing !== null) {
      await rm(marketplace, { recursive: true, force: true });
    }
    await createMarketplace(codexHome, root, options.signal);
  }
  const config = await readFile(join(codexHome, "config.toml"), "utf8").catch(
    (error: unknown) => {
      if (nodeErrorCode(error) === "ENOENT") return "";
      throw error;
    },
  );
  const marketplaces = parse(config)["marketplaces"];
  const registration = isRecord(marketplaces)
    ? marketplaces[MARKETPLACE_NAME]
    : undefined;
  if (
    !isRecord(registration) ||
    registration["source_type"] !== "local" ||
    typeof registration["source"] !== "string" ||
    !(await sameFile(registration["source"], marketplace))
  ) {
    await run(
      command,
      ["plugin", "marketplace", "add", marketplace],
      environment,
      options.signal,
    );
  }
  const output = await run(
    command,
    ["plugin", "add", "--json", `${PLUGIN_NAME}@${MARKETPLACE_NAME}`],
    environment,
    options.signal,
  );
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
  return {
    pluginRoot: root,
    marketplaceRoot: marketplace,
    installedRoot: installed["installedPath"],
    marketplaceName: MARKETPLACE_NAME,
    name,
    version,
  };
}

export async function pluginMetadata(
  root: string,
): Promise<{ name: typeof PLUGIN_NAME; version: string }> {
  const manifestPath = join(root, ".codex-plugin", "plugin.json");
  let manifest: unknown;
  try {
    const metadata = await lstat(manifestPath);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error("plugin manifest is not a regular file");
    }
    manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  } catch (error) {
    throw new PluginBootstrapError(`Invalid Codex plugin directory: ${root}`, {
      cause: error,
    });
  }
  if (!isRecord(manifest) || manifest["name"] !== PLUGIN_NAME) {
    throw new PluginBootstrapError(
      "Plugin manifest must have name 'codex-security'.",
    );
  }
  const version = manifest["version"];
  if (typeof version !== "string" || version.trim().length === 0) {
    throw new PluginBootstrapError(
      "Plugin manifest must have a non-empty version.",
    );
  }
  return { name: PLUGIN_NAME, version };
}

export async function resolvePluginPython(
  options: PluginPythonOptions = {},
): Promise<string> {
  const environment = options.environment ?? process.env;
  const protectedRoot = options.protectedRoot ?? process.cwd();
  if (options.configuredPath !== undefined) {
    return await requirePython(
      options.configuredPath,
      "configured plugin Python",
      environment,
      protectedRoot,
      options.signal,
    );
  }
  const inherited = environmentValue(environment, "PYTHON");
  if (inherited) {
    return await requirePython(
      inherited,
      "PYTHON",
      environment,
      protectedRoot,
      options.signal,
    );
  }

  const home = options.homeDirectory ?? homedir();
  const managedRoots = options.managedRuntimeRoots ?? [
    join(home, ".cache", "codex-runtimes", "codex-primary-runtime"),
  ];
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

  for (const candidate of process.platform === "win32"
    ? ["python", "python3", "py"]
    : ["python3", "python"]) {
    const resolved = await usablePython(
      candidate,
      environment,
      protectedRoot,
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
    CODEX_CLI_PATH: resolveCodexCommand(environment).command,
  };
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

export async function cleanupSdkDirectory(path: string): Promise<void> {
  await rm(path, { recursive: true, force: true });
}

export async function runCodexCommand(
  command: CodexCommand,
  args: readonly string[],
  environment: ProcessEnvironment,
  input?: string,
  signal?: AbortSignal,
): Promise<CodexCommandResult> {
  const child = spawn(command.command, [...args], {
    env: environment,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
    signal,
  });
  let stdout = "";
  let stderr = "";
  let processError: Error | undefined;
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
      if (
        !["EPIPE", "ECONNRESET", "EOF", "ERR_STREAM_DESTROYED"].includes(
          error.code ?? "",
        )
      )
        processError = error;
    });
    child.once("close", (exitCode) =>
      processError === undefined
        ? resolve({ success: exitCode === 0, exitCode, stdout, stderr })
        : reject(processError),
    );
  });
  child.stdin.end(input);
  return await completion;
}

async function runPluginCommand(
  command: CodexCommand,
  args: readonly string[],
  environment: ProcessEnvironment,
  signal?: AbortSignal,
): Promise<string> {
  try {
    const { success, exitCode, stdout, stderr } = await runCodexCommand(
      command,
      args,
      environment,
      undefined,
      signal,
    );
    if (!success) {
      throw new Error(
        stderr.trim() ||
          stdout.trim() ||
          `Codex exited with status ${exitCode}.`,
      );
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

async function copyPluginTree(
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
  handle: Awaited<ReturnType<typeof open>>,
  length: number,
  position: number,
  signal?: AbortSignal,
): Promise<Buffer> {
  const buffer = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    throwIfSignalAborted(signal);
    const { bytesRead } = await handle.read(
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
  protectedRoot: string,
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
  protectedRoot: string = process.cwd(),
  signal?: AbortSignal,
): Promise<string | null> {
  const command = await resolveTrustedExecutable(
    isPythonPathCandidate(candidate)
      ? expandHome(candidate, environment)
      : candidate,
    environment,
    protectedRoot,
  );
  if (command === null) return null;
  try {
    const { stdout } = await execFile(
      command.executable,
      [
        "-I",
        "-c",
        "import importlib.util,sys\nif sys.version_info < (3, 10): raise SystemExit(1)\nif sys.version_info < (3, 11) and importlib.util.find_spec('tomli') is None: raise SystemExit(1)\nprint('codex-security-python-ok')",
      ],
      {
        env: command.environment,
        encoding: "utf8",
        timeout: 5_000,
        windowsHide: true,
        signal,
      },
    );
    return stdout.trim() === "codex-security-python-ok"
      ? command.executable
      : null;
  } catch (error) {
    if (signal?.aborted) throw error;
    return null;
  }
}

export function isPythonPathCandidate(candidate: string): boolean {
  return (
    candidate.includes("/") ||
    candidate.includes("\\") ||
    candidate.startsWith(".")
  );
}

async function hasPluginManifest(root: string): Promise<boolean> {
  return await isRegularFile(join(root, ".codex-plugin", "plugin.json"));
}

async function isRegularFile(path: string): Promise<boolean> {
  try {
    const metadata = await lstat(path);
    return metadata.isFile() && !metadata.isSymbolicLink();
  } catch {
    return false;
  }
}

async function sameFile(left: string, right: string): Promise<boolean> {
  try {
    // NTFS file IDs can exceed JavaScript's safe integer range.
    const [leftMetadata, rightMetadata] = await Promise.all([
      stat(left, { bigint: true }),
      stat(right, { bigint: true }),
    ]);
    return (
      leftMetadata.dev === rightMetadata.dev &&
      leftMetadata.ino === rightMetadata.ino
    );
  } catch {
    return false;
  }
}

export function expandHome(
  value: string,
  environment: ProcessEnvironment = process.env,
): string {
  const home =
    (process.platform === "win32"
      ? environmentValue(environment, "USERPROFILE") ??
        environmentValue(environment, "HOME")
      : environmentValue(environment, "HOME") ??
        environmentValue(environment, "USERPROFILE")) ?? homedir();
  if (value === "~") return home;
  if (value.startsWith("~/")) return join(home, value.slice(2));
  if (value.startsWith("~\\")) {
    return join(home, ...value.slice(2).split("\\"));
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nodeErrorCode(error: unknown): string | undefined {
  return isRecord(error) && typeof error["code"] === "string"
    ? error["code"]
    : undefined;
}

function abortReason(signal: AbortSignal): unknown {
  return (
    signal.reason ??
    new DOMException("The operation was aborted.", "AbortError")
  );
}

function throwIfSignalAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw abortReason(signal);
}
