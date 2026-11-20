import { spawnSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { join, sep } from "node:path";
import type { PatchPublicationHooks } from "./patch-git-controls.js";

export const proxyUserinfo = /^(?:[a-z][\w+.-]*:\/{1,3})?[^/@?#\s]+@/iu;

export const gitPasswordSetting =
  /^(?:imap\.pass|sendemail(?:\..*)?\.smtppass|gitcvs(?:\..*)?\.dbpass)$/isu;

export const httpCredentialFile =
  /^http(?:\..*)?\.(?:cookiefile|(?:proxy)?ssl(?:key|cert))$/iu;

export const credentialFileVariable =
  /^(?:GOOGLE_APPLICATION_CREDENTIALS|PG(?:PASSFILE|SERVICEFILE|SSLCERT|SSLKEY)|TERRAFORM_CONFIG|TF_CLI_CONFIG_FILE)$/iu;

// Also embedded in the standalone Git and hook runners.
export function removePatchCredentials(
  environment: NodeJS.ProcessEnv,
  credentialNames: readonly string[],
  stripAwsCredentials?: boolean,
  proxyCredentials = proxyUserinfo,
  fileVariable = credentialFileVariable,
): void {
  for (const [name, value] of Object.entries(environment)) {
    if (
      fileVariable.test(name) ||
      /^TF_TOKEN_/iu.test(name) ||
      /^(?:DATABASE_URL|DOCKER_CONFIG|GH_CONFIG_DIR|GLAB_CONFIG_DIR|KUBECONFIG|NPM_CONFIG_USERCONFIG|OPENAI_FEDERATION_RULE_ID|PGPASSWORD)$|(?:^|_)(?:TOKEN|PASSWORD|SECRET|CREDENTIALS?|AUTHORIZATION|(?:API|ACCESS|SECRET|PRIVATE)_KEY|AUTH_SOCK|DOCKER_AUTH_CONFIG)(?:_FILE)?$/iu.test(
        name,
      ) ||
      credentialNames.includes(name.toUpperCase()) ||
      (stripAwsCredentials && /^AWS_/i.test(name)) ||
      (/^(?:https?|all)_proxy$/i.test(name) &&
        value !== undefined &&
        proxyCredentials.test(value))
    )
      delete environment[name];
  }
}

// HTTP credentials can be a username alone. SSH usernames select the remote
// account and remain available to validators unless a password is present.
export function withoutUrlCredentials(value: string): string {
  return value.replace(
    /((?:https?|ftps?|ssh(?:\+git)?|git(?:\+ssh)?|socks(?:4a?|5h?)?):\/\/)([^/?#\s]+@)/gi,
    (authority, scheme, userinfo) =>
      /^(?:https?|ftps?):/i.test(scheme) || userinfo.includes(":")
        ? scheme
        : authority,
  );
}

export interface WindowsGitConfig {
  prefix: string;
  binding: string;
  coordinator: string;
  bindings?: Record<string, string>;
  config: import("./patch-git-controls.js").PatchSnapshotConfig;
}

export function gitConfigPipePrefix(id: string): string {
  return "//./pipe/codex-security-git-" + id + "-";
}

// Executed by the coordinator and embedded in the standalone hook dispatcher.
export function filterCommandConfig(
  environment: NodeJS.ProcessEnv,
  git: string,
  marker?: string,
  windowsConfig?: WindowsGitConfig,
  parseGit = spawnSync,
  stripUrlCredentials = withoutUrlCredentials,
  proxyCredentials = proxyUserinfo,
  credentialFile = httpCredentialFile,
  passwordSetting = gitPasswordSetting,
): void {
  function include(key: string, value: string) {
    if (
      !windowsConfig ||
      !/^include(?:if\..*)?\.path$/i.test(key) ||
      !Object.hasOwn(windowsConfig.config.commands, value)
    )
      return value;
    return windowsConfig.prefix + windowsConfig.config.commands[value];
  }
  function credentialSetting(key: string, value: string): boolean {
    if (/^(?:http|remote)(?:\..*)?\.proxy$/i.test(key))
      return proxyCredentials.test(value) || stripUrlCredentials(key) !== key;
    return (
      stripUrlCredentials(key) !== key ||
      stripUrlCredentials(value) !== value ||
      (value !== "" && passwordSetting.test(key)) ||
      credentialFile.test(key) ||
      /^credential\.|^http(?:\..*)?\.(?:extraheader|sslcertpasswordprotected)$|^core\.(?:askpass|sshcommand)$/i.test(
        key,
      )
    );
  }
  // Keep indexed entries separate: together they can exceed the OS limit
  // for a single environment string. Let Git report malformed input itself.
  for (const name of Object.keys(environment)) {
    if (
      name !== name.toUpperCase() &&
      /^GIT_CONFIG_(?:COUNT|PARAMETERS|(?:KEY|VALUE)_\d+)$/i.test(name)
    ) {
      const value = environment[name];
      delete environment[name];
      if (process.platform === "win32") environment[name.toUpperCase()] = value;
    }
  }
  const rawCount = environment["GIT_CONFIG_COUNT"] ?? "";
  const count = Number(rawCount);
  let invalid =
    count < 0 ||
    (rawCount !== "" && !/^[ \t\r\n\f\v]*[+-]?\d+$/.test(rawCount));
  const tuples: [string, string][] = [];
  for (let index = 0; !invalid && index < count; index++) {
    const key = environment["GIT_CONFIG_KEY_" + index];
    const value = environment["GIT_CONFIG_VALUE_" + index];
    if (key === undefined || value === undefined || !key) invalid = true;
    else if (!credentialSetting(key, value)) {
      const staged = include(key, value);
      if (staged !== value && windowsConfig)
        (windowsConfig.bindings ??= {})["GIT_CONFIG_VALUE_" + tuples.length] =
          staged;
      tuples.push([key, value]);
    }
  }
  if (!invalid) {
    if (tuples.length < count) {
      environment["GIT_CONFIG_COUNT"] = String(tuples.length);
      for (const [index, [key, value]] of tuples.entries()) {
        environment["GIT_CONFIG_KEY_" + index] = key;
        environment["GIT_CONFIG_VALUE_" + index] = value;
      }
    }
    for (const name of Object.keys(environment)) {
      const tuple = /^GIT_CONFIG_(?:KEY|VALUE)_(\d+)$/.exec(name);
      if (
        tuple &&
        (Number(tuple[1]) >= tuples.length ||
          String(Number(tuple[1])) !== tuple[1])
      )
        delete environment[name];
    }
    if (!marker && !environment["GIT_CONFIG_PARAMETERS"]) return;
  }
  const empty = process.platform === "win32" ? "NUL" : "/dev/null";
  const parserEnvironment = { ...environment };
  for (const name of Object.keys(parserEnvironment))
    if (
      /^GIT_(CONFIG(?:_GLOBAL|_NOSYSTEM)?|DIR|COMMON_DIR|WORK_TREE)$/i.test(
        name,
      )
    )
      delete parserEnvironment[name];
  // Read Git's command scope without opening the checkout, following includes,
  // or passing any config values on the command line.
  parserEnvironment["GIT_DIR"] = empty;
  parserEnvironment["GIT_CONFIG_NOSYSTEM"] = "1";
  parserEnvironment["GIT_CONFIG_GLOBAL"] = empty;
  if (!invalid) parserEnvironment["GIT_CONFIG_COUNT"] = "0";
  const parsed = parseGit(
    git,
    ["config", "--no-includes", "--null", "--list", "--show-scope"],
    {
      env: parserEnvironment,
      encoding: "utf8",
      windowsHide: true,
      maxBuffer: Infinity,
    },
  );
  if (parsed.error) throw parsed.error;
  if (parsed.status !== 0)
    throw Object.assign(
      new Error(
        parsed.stderr.trimEnd() ||
          "Could not read Git command-scope configuration.",
      ),
      { code: parsed.status, stderr: parsed.stderr },
    );
  const records = parsed.stdout.split("\0");
  const parameters = [];
  const stagedParameters = [];
  let staged = false;
  let changed = false;
  let bridge = false,
    removed = false;
  const quote = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";
  for (let i = 0; i + 1 < records.length; i += 2) {
    if (records[i] !== "command") continue;
    const entry = records[i + 1]!;
    const split = entry.indexOf("\n");
    const key = split === -1 ? entry : entry.slice(0, split);
    const value = split === -1 ? "" : entry.slice(split + 1);
    if (key === marker) {
      changed = true;
      bridge = value === "begin";
      removed ||= value === "end";
      continue;
    }
    if (bridge || credentialSetting(key, value)) {
      changed = true;
      continue;
    }
    const parameter = (value: string) =>
      key.includes("=")
        ? quote(key) + "=" + (split === -1 ? "" : quote(value))
        : quote(split === -1 ? key : key + "=" + value);
    parameters.push(parameter(value));
    if (windowsConfig) {
      const rewritten = include(key, value);
      staged ||= rewritten !== value;
      stagedParameters.push(parameter(rewritten));
    }
  }
  if (marker && (!removed || bridge))
    throw new Error("Could not restore the publication hook configuration.");
  if (staged && windowsConfig)
    (windowsConfig.bindings ??= {})["GIT_CONFIG_PARAMETERS"] =
      stagedParameters.join(" ");
  if (changed) environment["GIT_CONFIG_PARAMETERS"] = parameters.join(" ");
}

// Git starts this trusted dispatcher with the native hook's cwd, argv, index
// and stdin. Only Git's original hook runs with the patch permissions.
const dispatcher = String.raw`
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const [event, ...args] = process.argv.slice(2);
const withoutUrlCredentials = ${withoutUrlCredentials};
const filterCommandConfig = ${filterCommandConfig};
if (event === "pre-push") {
  for (let i = 0; i < args.length; i++) args[i] = withoutUrlCredentials(args[i]);
}
const plan = JSON.parse(
  fs.readFileSync(path.join(__dirname, "plan.json"), "utf8"),
);
const environment = { ...process.env };
const removeCredentials = ${removePatchCredentials};
removeCredentials(environment, plan.credentialNames, plan.stripAwsCredentials, ${proxyUserinfo}, ${credentialFileVariable});
environment.CODEX_HOME = plan.home;

const windowsConfig = plan.windowsConfig;
if (windowsConfig)
  windowsConfig.prefix = (${gitConfigPipePrefix})(require("node:crypto").randomUUID());
filterCommandConfig(environment, plan.git, plan.marker, windowsConfig, spawnSync, withoutUrlCredentials, ${proxyUserinfo}, ${httpCredentialFile}, ${gitPasswordSetting});
const bindings = Object.entries(environment).filter(([name]) =>
  /^(?:GIT_(?:DIR|WORK_TREE|COMMON_DIR|OBJECT_DIRECTORY|ALTERNATE_OBJECT_DIRECTORIES|INDEX_FILE|PREFIX|EDITOR|ATTR_SOURCE|ATTR_NOSYSTEM|CONFIG(?:_GLOBAL|_SYSTEM|_NOSYSTEM|_PARAMETERS|_COUNT|_(?:KEY|VALUE)_\d+)?)|HOME|USERPROFILE|HOMEDRIVE|HOMEPATH|XDG_CONFIG_HOME)$/i.test(
    name,
  ),
);
const header = Buffer.from(
  JSON.stringify({
    bindings,
    windowsConfig,
    credentialNames: plan.credentialNames,
    stripAwsCredentials: plan.stripAwsCredentials,
  }),
);
const inputEvent = [
  "pre-push",
  "reference-transaction",
  "post-rewrite",
].includes(event);
const messageEvent = event === "prepare-commit-msg" || event === "commit-msg";

function matchesMessagePath(file, leaf, opened) {
  if (!leaf.isFile() || leaf.nlink !== 1n || leaf.ino !== opened.ino)
    return false;
  if (leaf.dev === opened.dev) return true;
  // Older Windows libuv reports zero for a path's volume but returns the
  // volume serial on file handles. Compare both identifiers on that runtime.
  if (process.platform !== "win32" || leaf.dev !== 0n) return false;
  const fd = fs.openSync(file, fs.constants.O_RDONLY);
  try {
    const named = fs.fstatSync(fd, { bigint: true });
    return (
      named.dev === opened.dev && named.ino === opened.ino && named.nlink === 1n
    );
  } finally {
    fs.closeSync(fd);
  }
}
function openMessage(file, flags) {
  const leaf = fs.lstatSync(file, { bigint: true });
  if (!leaf.isFile() || leaf.nlink !== 1n)
    throw new Error(
      "The commit-message hook requires a regular, unlinked COMMIT_EDITMSG.",
    );
  const fd = fs.openSync(
    file,
    flags | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0),
  );
  const stat = fs.fstatSync(fd, { bigint: true });
  if (!stat.isFile() || stat.nlink !== 1n || !matchesMessagePath(file, leaf, stat)) {
    fs.closeSync(fd);
    throw new Error("The commit-message file changed while opening it.");
  }
  return { fd, stat };
}
function unchanged(file, opened) {
  const current = fs.fstatSync(opened.fd, { bigint: true });
  return (
    current.nlink === 1n &&
    matchesMessagePath(file, fs.lstatSync(file, { bigint: true }), current) &&
    current.size === opened.stat.size &&
    // Native Windows sandbox ACL provisioning changes NTFS ChangeTime without
    // changing the original bytes or LastWriteTime.
    (process.platform === "win32" || current.ctimeNs === opened.stat.ctimeNs) &&
    current.mtimeNs === opened.stat.mtimeNs
  );
}
function readMessage(opened) {
  const bytes = Buffer.alloc(Number(opened.stat.size));
  for (let offset = 0; offset < bytes.length;) {
    const count = fs.readSync(
      opened.fd,
      bytes,
      offset,
      bytes.length - offset,
      offset,
    );
    if (!count)
      throw new Error("The commit-message file changed while reading it.");
    offset += count;
  }
  return bytes;
}
function readEditedMessage(file) {
  const edited = openMessage(file, fs.constants.O_RDONLY);
  try {
    const bytes = readMessage(edited);
    if (!unchanged(file, edited))
      throw new Error(
        "The hook's private commit-message file changed while reading it.",
      );
    return bytes;
  } finally {
    fs.closeSync(edited.fd);
  }
}
// Git sends a message hook's stdout and stderr to its diagnostic stream.
// Reserve stdout inside this sandbox for the validated message alone.
function runWindowsMessageHook() {
  const file = process.argv[1];
  stageMessage();
  const [binding, runner, ...args] = process.argv.slice(1);
  const result = require("node:child_process").spawnSync(
    process.execPath, ["-e", runner, "--", ...args], { stdio: [0, 2, 2] },
  );
  if (result.error) throw result.error;
  const fs = require("node:fs");
  if (result.status === 0 || fs.lstatSync(file, { throwIfNoEntry: false })) {
    const bytes = require(binding).readWindowsHookMessage(
      Buffer.from(require("node:path").toNamespacedPath(file), "utf16le"),
    );
    const size = Buffer.alloc(8);
    size.writeBigUInt64BE(BigInt(bytes.length));
    for (const part of [size, bytes])
      for (let offset = 0; offset < part.length;)
        offset += fs.writeSync(1, part, offset, part.length - offset);
  }
  process.exitCode = result.status ?? 1;
}
// Create the message under the hook's write grant. On Windows a file
// created by the host before the sandbox starts can retain a read-only ACL.
function stageMessage() {
  const fs = require("node:fs");
  const path = require("node:path");
  const [destination, length] = process.argv.splice(1, 2);
  const bytes = Buffer.alloc(Number(length));
  for (let offset = 0; offset < bytes.length;) {
    const count = fs.readSync(0, bytes, offset, bytes.length - offset, null);
    if (count === 0) throw new Error("Incomplete commit-message frame.");
    offset += count;
  }
  const fresh = path.join(
    path.dirname(destination),
    require("node:crypto").randomUUID(),
  );
  fs.writeFileSync(fresh, bytes, { flag: "wx", mode: 0o600 });
  fs.renameSync(fresh, destination);
}
let original, originalBytes, privateMessage;
let input;
try {
  if (messageEvent) {
    if (
      !plan.message ||
      !plan.messageDirectories[event] ||
      !args[0] ||
      fs.realpathSync.native(args[0]) !== fs.realpathSync.native(plan.message)
    )
      throw new Error("The hook did not receive Git's commit-message file.");
    // Editors may atomically replace this file. Keep their write grant out of
    // Git's admin directory and hold the original descriptor until Git resumes.
    original = openMessage(plan.message, fs.constants.O_RDWR);
    originalBytes = readMessage(original);
    privateMessage = path.join(
      plan.messageDirectories[event],
      path.basename(plan.message),
    );
    // Git for Windows passes slash-separated paths to both native and shell hooks.
    args[0] = privateMessage.split(path.sep).join("/");
  }
  if (inputEvent) {
    input = path.join(
      plan.data,
      require("node:crypto").randomUUID() + ".stdin",
    );
    const fd = fs.openSync(input, "wx", 0o600);
    try {
      const chunk = Buffer.alloc(65536);
      let size;
      while ((size = fs.readSync(0, chunk, 0, chunk.length, null)) > 0)
        for (let offset = 0; offset < size;)
          offset += fs.writeSync(fd, chunk, offset, size - offset);
    } finally {
      fs.closeSync(fd);
    }
  }
  // Git introduced hook run in 2.36 and --to-stdin in 2.40. Earlier Git
  // has one classic executable per event. Invoke it inside the same sandbox.
  const version = spawnSync(plan.git, ["--version"], {
    cwd: __dirname,
    env: environment,
    windowsHide: true,
    encoding: "utf8",
  });
  const release = /^git version (\d+)\.(\d+)/.exec(version.stdout ?? "");
  if (version.status !== 0 || !release)
    throw new Error("Could not determine Git's hook dispatch support.");
  let hook;
  if (
    Number(release[1]) > 2 ||
    (Number(release[1]) === 2 && Number(release[2]) >= 40)
  ) {
    hook = [
      "hook",
      "run",
      "--ignore-missing",
      ...(input ? ["--to-stdin=" + input] : []),
      event,
      "--",
      ...args,
    ];
  } else {
    const alias = plan.marker.replace(".", "-");
    const script = [
      '!f () { cd -- "$2" || exit;',
      'export GIT_CONFIG_PARAMETERS="$5";',
      'h=$("$1" rev-parse --path-format=absolute --git-path "hooks/$3") || exit;',
      "input=$4; shift 5;",
      ...(process.platform === "win32"
        ? ['if test ! -x "$h" && test -x "$h.exe"; then h=$h.exe; fi;']
        : []),
      'test -x "$h" || exit 0;',
      'exec "$h" "$@" < "$input"; }; f',
    ].join(" ");
    const slash = (value) => value.split(path.sep).join("/");
    hook = [
      "-c",
      "alias." + alias + "=" + script,
      alias,
      slash(plan.git),
      slash(process.cwd()),
      event,
      input ? slash(input) : "/dev/null",
      environment.GIT_CONFIG_PARAMETERS,
      ...args,
    ];
  }
  const windowsMessage = original && plan.windowsMessageBinding;
  const runner = windowsMessage
    ? [
        stageMessage, "(" + runWindowsMessageHook + ")();",
      ].join("\n")
    : original ? "(" + stageMessage + ")();\n" + plan.runner : plan.runner;
  const permissionProfile = messageEvent ? plan.profile + "_" + event : plan.profile;
  const result = spawnSync(
    plan.codex,
    [
      ...plan.codexArgs,
      "sandbox",
      "--cd",
      plan.directory,
      "--profile",
      plan.profile,
      "--permission-profile",
      permissionProfile,
      "--include-managed-config",
      "--",
      plan.runtime,
      "-e",
      runner,
      "--",
      ...(original ? [privateMessage, String(originalBytes.length)] : []),
      ...(windowsMessage ? [plan.windowsMessageBinding, plan.runner] : []),
      String(header.length),
      plan.git,
      "-C",
      process.cwd(),
      ...hook,
    ],
    {
      env: environment,
      input: original ? Buffer.concat([originalBytes, header]) : header,
      stdio: ["pipe", windowsMessage ? "pipe" : "inherit", "inherit"],
      maxBuffer: Infinity,
      windowsHide: true,
    },
  );
  if (result.error) throw result.error;
  // Git keeps a validator's message edits even when it vetoes the commit.
  let bytes;
  if (windowsMessage) {
    if (result.stdout.length || result.status === 0) {
      if (
        result.stdout.length < 8 ||
        result.stdout.readBigUInt64BE() !== BigInt(result.stdout.length - 8)
      ) throw new Error("Incomplete edited commit-message frame.");
      bytes = result.stdout.subarray(8);
    }
  } else if (
    original &&
    (result.status === 0 || fs.lstatSync(privateMessage, { throwIfNoEntry: false }))
  ) {
    bytes = readEditedMessage(privateMessage);
  }
  if (bytes !== undefined) {
    if (
      !readMessage(original).equals(originalBytes) ||
      !unchanged(plan.message, original)
    )
      throw new Error(
        "The original Git commit-message file changed while the hook was running.",
      );
    for (let offset = 0; offset < bytes.length;)
      offset += fs.writeSync(
        original.fd,
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
    fs.ftruncateSync(original.fd, bytes.length);
  }
  process.exitCode = result.status ?? 1;
} finally {
  if (original) fs.closeSync(original.fd);
  if (input) fs.rmSync(input, { force: true });
}
`;

export async function writePublicationHooks(
  directory: string,
  hooks: PatchPublicationHooks,
  plan: {
    runtime: string;
    codex: string;
    codexArgs: readonly string[];
    marker: string;
    git: string;
    directory: string;
    home: string;
    profile: string;
    data: string;
    message?: string;
    messageDirectories: Record<string, string>;
    windowsMessageBinding?: string;
    windowsConfig?: WindowsGitConfig;
    runner: string;
    credentialNames: string[];
    stripAwsCredentials: boolean;
  },
): Promise<string[]> {
  const { marker } = plan;
  const runner = join(directory, "run.cjs");
  const shell = (value: string) =>
    "'" + value.split(sep).join("/").replaceAll("'", "'\"'\"'") + "'";
  await writeFile(runner, dispatcher, { flag: "wx", mode: 0o600 });
  await writeFile(join(directory, "plan.json"), JSON.stringify(plan), {
    flag: "wx",
    mode: 0o600,
  });
  await Promise.all(
    [...hooks.events].map((event) =>
      writeFile(
        join(directory, event),
        "#!/bin/sh\nunset NODE_OPTIONS NODE_PATH\nexec " +
          shell(plan.runtime) +
          " " +
          shell(runner) +
          " " +
          shell(event) +
          ' "$@"\n',
        { flag: "wx", mode: 0o700 },
      ),
    ),
  );
  return [
    "-c",
    marker + "=begin",
    "-c",
    "core.hooksPath=" + directory,
    ...[...hooks.configured].flatMap((name) => [
      "-c",
      "hook." + name + ".enabled=false",
    ]),
    "-c",
    marker + "=end",
  ];
}
