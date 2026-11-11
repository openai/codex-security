import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join, sep } from "node:path";
import type { PatchPublicationHooks } from "./patch-git-controls.js";

// Git starts this trusted dispatcher with the native hook's cwd, argv, index
// and stdin. Only Git's original hook runs with the patch permissions.
const dispatcher = String.raw`
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const [event, ...args] = process.argv.slice(2);
const plan = JSON.parse(
  fs.readFileSync(path.join(__dirname, "plan.json"), "utf8"),
);
const environment = { ...process.env };
const credentials = new RegExp(plan.credentialPattern, "i");
for (const name of Object.keys(environment)) {
  if (
    credentials.test(name) ||
    (/^(?:https?|all)_proxy$/i.test(name) &&
      /^(?:[a-z][\w+.-]*:\/\/)?[^/@\s]+@/i.test(environment[name])) ||
    plan.credentialNames.includes(name.toUpperCase()) ||
    (plan.stripAwsCredentials && /^AWS_/i.test(name))
  )
    delete environment[name];
}
environment.CODEX_HOME = plan.home;

// Let Git parse its own command scope, including inherited git -c quoting.
// Read only that scope without loading a checkout or an operator config file.
const parserEnvironment = { ...environment };
for (const name of ["GIT_CONFIG", "GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE"])
  delete parserEnvironment[name];
parserEnvironment.GIT_CONFIG_NOSYSTEM = "1";
parserEnvironment.GIT_CONFIG_GLOBAL =
  process.platform === "win32" ? "NUL" : "/dev/null";
parserEnvironment.GIT_CEILING_DIRECTORIES = path.dirname(__dirname);
const parsed = spawnSync(
  plan.git,
  ["config", "--no-includes", "--null", "--list", "--show-scope"],
  {
    cwd: __dirname,
    env: parserEnvironment,
    encoding: "utf8",
    windowsHide: true,
    maxBuffer: Infinity,
  },
);
if (parsed.error) throw parsed.error;
if (parsed.status !== 0)
  throw new Error("Could not read the publication hook's Git configuration.");
const records = parsed.stdout.split("\0");
for (const name of Object.keys(environment))
  if (/^GIT_CONFIG_(?:PARAMETERS|COUNT|(?:KEY|VALUE)_\d+)$/i.test(name))
    delete environment[name];
let bridge = false,
  removed = false;
const parameters = [];
const quote = (value) => "'" + value.replaceAll("'", "'\\''") + "'";
for (let i = 0; i + 1 < records.length; i += 2) {
  if (records[i] !== "command") continue;
  const entry = records[i + 1];
  const split = entry.indexOf("\n");
  const key = split === -1 ? entry : entry.slice(0, split);
  const value = split === -1 ? "" : entry.slice(split + 1);
  if (key === plan.marker) {
    bridge = value === "begin";
    removed ||= value === "end";
    continue;
  }
  // Host transports retain their authentication. Do not rebind credentials
  // passed through Git command scope in a checkout-supplied child program.
  if (
    bridge ||
    /^credential\.|^http(?:\..*)?\.(?:extraheader|proxy|cookiefile|sslkey|sslcertpasswordprotected)$|^core\.(?:askpass|sshcommand)$/i.test(
      key,
    )
  )
    continue;
  parameters.push(split === -1 ? quote(key) : quote(key) + "=" + quote(value));
}
if (!removed || bridge)
  throw new Error("Could not restore the publication hook configuration.");
environment.GIT_CONFIG_PARAMETERS = parameters.join(" ");
const bindings = Object.entries(environment).filter(([name]) =>
  /^(?:GIT_(?:DIR|WORK_TREE|COMMON_DIR|OBJECT_DIRECTORY|ALTERNATE_OBJECT_DIRECTORIES|INDEX_FILE|PREFIX|EDITOR|ATTR_SOURCE|ATTR_NOSYSTEM|CONFIG(?:_GLOBAL|_SYSTEM|_NOSYSTEM|_PARAMETERS)?)|HOME|USERPROFILE|HOMEDRIVE|HOMEPATH|XDG_CONFIG_HOME)$/i.test(
    name,
  ),
);
bindings.push(
  ["GIT_CONFIG_COUNT", null],
  ...plan.credentialNames.map((name) => [name, null]),
);
const header = Buffer.from(
  JSON.stringify({
    bindings,
    stripAwsCredentials: plan.stripAwsCredentials,
    stripHookProxyCredentials: true,
  }),
);
const inputEvent = [
  "pre-push",
  "reference-transaction",
  "post-rewrite",
].includes(event);
const messageEvent = event === "prepare-commit-msg" || event === "commit-msg";

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
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
  if (!sameFile(leaf, stat) || !stat.isFile() || stat.nlink !== 1n) {
    fs.closeSync(fd);
    throw new Error("The commit-message file changed while opening it.");
  }
  return { fd, stat };
}
function unchanged(file, opened) {
  const current = fs.fstatSync(opened.fd, { bigint: true });
  return (
    current.nlink === 1n &&
    sameFile(current, fs.lstatSync(file, { bigint: true })) &&
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
let original, originalBytes, privateMessage;
let input;
try {
  if (messageEvent) {
    if (
      !plan.message ||
      !plan.messageDirectory ||
      !args[0] ||
      fs.realpathSync.native(args[0]) !== fs.realpathSync.native(plan.message)
    )
      throw new Error("The hook did not receive Git's commit-message file.");
    // Editors may atomically replace this file. Keep their write grant out of
    // Git's admin directory and hold the original descriptor until Git resumes.
    original = openMessage(plan.message, fs.constants.O_RDWR);
    originalBytes = readMessage(original);
    privateMessage = path.join(
      plan.messageDirectory,
      path.basename(plan.message),
    );
    const fresh = path.join(
      plan.messageDirectory,
      require("node:crypto").randomUUID(),
    );
    fs.writeFileSync(fresh, originalBytes, {
      flag: "wx",
      mode: 0o600,
    });
    fs.renameSync(fresh, privateMessage);
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
    env: parserEnvironment,
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
      messageEvent ? plan.profile + "_message" : plan.profile,
      "--include-managed-config",
      "--",
      plan.runtime,
      "-e",
      plan.runner,
      "--",
      String(header.length),
      plan.git,
      "-C",
      process.cwd(),
      ...hook,
    ],
    {
      env: environment,
      input: header,
      stdio: ["pipe", "inherit", "inherit"],
      windowsHide: true,
    },
  );
  if (result.error) throw result.error;
  // Git keeps a validator's message edits even when it vetoes the commit.
  if (original) {
    const edited = openMessage(privateMessage, fs.constants.O_RDONLY);
    try {
      const bytes = readMessage(edited);
      if (!unchanged(privateMessage, edited))
        throw new Error(
          "The hook's private commit-message file changed while reading it.",
        );
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
    } finally {
      fs.closeSync(edited.fd);
    }
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
    git: string;
    directory: string;
    home: string;
    profile: string;
    data: string;
    message?: string;
    messageDirectory?: string;
    runner: string;
    credentialPattern: string;
    credentialNames: string[];
    stripAwsCredentials: boolean;
  },
): Promise<string[]> {
  const marker = "codexsecurity.hookbridge" + randomUUID().replaceAll("-", "");
  const runner = join(directory, "run.cjs");
  const shell = (value: string) =>
    "'" + value.split(sep).join("/").replaceAll("'", "'\"'\"'") + "'";
  await writeFile(runner, dispatcher, { flag: "wx", mode: 0o600 });
  await writeFile(
    join(directory, "plan.json"),
    JSON.stringify({ ...plan, marker }),
    { flag: "wx", mode: 0o600 },
  );
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
