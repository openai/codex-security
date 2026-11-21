import { execFile as execFileCallback, spawn } from "node:child_process";
import { join, win32 } from "node:path";
import { promisify } from "node:util";

import { OutputDirectoryError } from "./config-errors.js";

const execFile = promisify(execFileCallback);
const WINDOWS_CREDENTIAL_ACL_COMPLETE_PREFIX = "CODEX_SECURITY_ACL_COMPLETE:";
const WINDOWS_CREDENTIAL_DESCENDANTS_CHANGED_EXIT_CODE = 2;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export async function requirePrivateWindowsDirectory(
  path: string,
  description: string,
  secureHome: (path: string) => Promise<void> = secureWindowsCredentialHome,
): Promise<void> {
  try {
    await secureHome(path);
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
