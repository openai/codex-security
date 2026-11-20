import { afterEach, expect, test } from "bun:test";
import { execFileSync, spawn } from "node:child_process";
import {
  mkdir,
  lstat,
  readFile,
  readdir,
  realpath,
  rename,
  symlink,
  writeFile,
} from "node:fs/promises";
import { delimiter, dirname, join, matchesGlob, relative } from "node:path";
import { createInterface } from "node:readline";
import { PassThrough, Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { readSkillCommandOutput, runRepositoryCommand } from "../src/cli.js";
import {
  capturePatchGitControls,
  type PatchSnapshotConfig,
} from "../src/patch-git-controls.js";
import { runGitRepositoryCommand, runWorkflow } from "./cli-patch-fixtures.js";
import {
  patchSnapshotEnvironment,
  patchSnapshotWindowsConfig,
} from "./support/patch-snapshot-environment.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

type RpcMessage = Record<string, any>;
type PatchPermissions = NonNullable<
  NonNullable<Parameters<typeof readSkillCommandOutput>[1]>["permissions"]
> & { snapshotConfig?: PatchSnapshotConfig };

interface PatchProfileContext {
  name: string;
  administration: string;
  filesystem: RpcMessage;
  modelProfile: RpcMessage;
  snapshotProfile: RpcMessage;
  snapshotConfig?: PatchSnapshotConfig;
  repository: string;
  home: string;
  temporaryDirectory: string;
  storage: string;
  controls: Awaited<ReturnType<typeof capturePatchGitControls>>;
}

async function resolvePatchProfile(
  configured: boolean,
  optionalStorage:
    | false
    | "inside"
    | "outside"
    | "administration"
    | "selected"
    | "direct-administration" = false,
  existingStorage = false,
  exercise?: (
    context: PatchProfileContext,
    inspectModel: (source: string) => Promise<string>,
  ) => Promise<void>,
  capturePermissions?: (repository: string) => Promise<PatchPermissions>,
  shellPolicy?: { set: Record<string, string>; paths: readonly string[] },
): Promise<PatchProfileContext> {
  const root = await fixtures.create("patch-native-profile-");
  const home = join(root, "home");
  const repository = join(root, "repository");
  const extra = join(root, "extra-workspace");
  const temporaryDirectory = join(root, "temp");
  for (const path of [
    // Create the parent directory for the default credential-store deny rule.
    join(home, ".config", "git"),
    repository,
    extra,
    temporaryDirectory,
    join(repository, ".codex"),
  ])
    await mkdir(path, { recursive: true });
  // Native Windows grants persist on disk. Keep config files and temp write
  // roots inside this fixture, away from the shard's shared temporary directory.
  const selectedConfig = join(root, "selected.gitconfig");
  const gitEnvironment = {
    HOME: home,
    USERPROFILE: home,
    GIT_CONFIG_GLOBAL: selectedConfig,
    GIT_CONFIG_NOSYSTEM: "1",
    XDG_CONFIG_HOME: join(home, ".config"),
  };
  execFileSync("git", ["init", "--quiet", repository], {
    env: { ...process.env, ...gitEnvironment },
  });
  const administration = join(repository, ".git");
  let readOnlyPaths: readonly string[] = [administration];
  let modelOnlyReadOnlyPaths: readonly string[] = [];
  let externalCachePaths: readonly string[] = [];
  let controls: Awaited<ReturnType<typeof capturePatchGitControls>>;
  const storage =
    optionalStorage === "inside"
      ? join(repository, "cache-data")
      : optionalStorage === "administration" ||
          optionalStorage === "direct-administration"
        ? administration
        : extra;
  if (optionalStorage) {
    await mkdir(storage, { recursive: true });
    if (existingStorage)
      for (const part of ["objects", "tmp"]) await mkdir(join(storage, part));
    if (
      optionalStorage !== "selected" &&
      optionalStorage !== "direct-administration"
    )
      await symlink(
        storage,
        join(repository, "cache"),
        process.platform === "win32" ? "junction" : "dir",
      );
    if (optionalStorage === "selected") {
      await writeFile(
        selectedConfig,
        '[http]\n extraHeader = "Authorization: Synthetic fixture"\n' +
          "[include]\n path = included.gitconfig\n",
      );
      await writeFile(
        join(root, "included.gitconfig"),
        '[synthetic]\n source = "Included fixture"\n',
      );
    }
    execFileSync(
      "git",
      [
        "config",
        ...(optionalStorage === "selected" ? ["--file", selectedConfig] : []),
        "lfs.storage",
        optionalStorage === "selected" ||
        optionalStorage === "direct-administration"
          ? storage
          : "../cache",
      ],
      {
        cwd: repository,
        env: { ...process.env, ...gitEnvironment },
      },
    );
    controls = await capturePatchGitControls(
      repository,
      async (_root, checkout, args, options) =>
        runGitRepositoryCommand("git", args, checkout, {
          ...options,
          environment: {
            ...gitEnvironment,
            ...options?.environment,
          },
        }),
      true,
      true,
      undefined,
      {
        global: selectedConfig,
        system: undefined,
        noSystem: "1",
        xdgConfigHome: gitEnvironment.XDG_CONFIG_HOME,
        objectDirectory: undefined,
        alternateObjectDirectories: undefined,
      },
      false,
      "sandbox",
      undefined,
      undefined,
      home,
      null,
      gitEnvironment,
    );
    expect(controls).toBeDefined();
    expect([...controls!.externalConfigPaths].sort()).toEqual(
      optionalStorage === "selected"
        ? [selectedConfig, join(root, "included.gitconfig")].sort()
        : [],
    );
    expect(controls!.snapshotStoragePaths).toEqual(
      optionalStorage === "selected" ? [storage] : [],
    );
    readOnlyPaths = controls!.readOnlyPaths;
    modelOnlyReadOnlyPaths = controls!.modelOnlyReadOnlyPaths;
    externalCachePaths = controls!.externalCachePaths;
    if (
      optionalStorage === "administration" ||
      optionalStorage === "selected" ||
      optionalStorage === "direct-administration"
    )
      expect(readOnlyPaths).toContain(await realpath(storage));
    else expect(readOnlyPaths).not.toContain(await realpath(storage));
    const canonicalStorage = await realpath(storage);
    const children = ["objects", "tmp"].map((part) =>
      join(canonicalStorage, part),
    );
    const outside = optionalStorage === "outside";
    expect(modelOnlyReadOnlyPaths).toEqual(outside ? [] : children);
    expect(externalCachePaths).toEqual(outside ? children : []);
    await controls!.validate();
  }
  const captured = await capturePermissions?.(repository);
  const configBefore = await readFile(join(administration, "config"));
  const windows = patchSnapshotWindowsConfig();
  await writeFile(
    join(home, "config.toml"),
    `model_provider = "synthetic"
model = "synthetic-local-only"
sandbox_mode = "workspace-write"
${windows}[analytics]
enabled = false
[features]
plugins = false
[model_providers.synthetic]
name = "Synthetic"
base_url = "http://127.0.0.1:9/v1"
wire_api = "responses"
[projects.${JSON.stringify(repository)}]
trust_level = "trusted"
[sandbox_workspace_write]
network_access = ${configured}
writable_roots = ${JSON.stringify(configured ? [extra] : [])}
exclude_tmpdir_env_var = ${configured}
exclude_slash_tmp = ${configured}
` +
      (shellPolicy
        ? "[shell_environment_policy.set]\n" +
          Object.entries(shellPolicy.set)
            .map(
              ([key, value]) =>
                `${JSON.stringify(key)}=${JSON.stringify(value)}`,
            )
            .join("\n") +
          "\n"
        : ""),
  );
  await writeFile(
    join(repository, ".codex", "config.toml"),
    `[sandbox_workspace_write]
network_access = ${!configured}
writable_roots = ${JSON.stringify([join(root, "project-selected")])}
exclude_tmpdir_env_var = ${!configured}
exclude_slash_tmp = ${!configured}
[permissions.codex_security_patch]
extends = ":workspace"
[permissions.codex_security_patch.filesystem]
glob_scan_max_depth = 8
[permissions.codex_security_patch.filesystem.":workspace_roots"]
".git/hooks" = "write"
`,
  );
  const nativeCli = fileURLToPath(
    new URL("../node_modules/@openai/codex/bin/codex.js", import.meta.url),
  );
  const child = spawn("node", [nativeCli, "app-server"], {
    cwd: repository,
    env: patchSnapshotEnvironment(temporaryDirectory, {
      PATH: process.env["PATH"],
      ...(process.env["SystemRoot"] === undefined
        ? {}
        : { SystemRoot: process.env["SystemRoot"] }),
      HOME: home,
      USERPROFILE: home,
      CODEX_HOME: home,
      RUST_LOG: "off",
    }),
    stdio: ["pipe", "pipe", "pipe"],
  });
  const closed = new Promise<void>((resolve) =>
    child.once("close", () => resolve()),
  );
  const stream = new PassThrough();
  const requests: RpcMessage[] = [];
  const responses: RpcMessage[] = [];
  let forwarding = true;
  let stderr = "";
  let nextId = 100;
  const pending = new Map<
    number,
    { resolve(value: RpcMessage): void; reject(error: Error): void }
  >();
  child.stderr.on("data", (chunk) => {
    stderr += String(chunk);
  });
  child.on("error", (error) => stream.destroy(error));
  const lines = createInterface({ input: child.stdout });
  lines.on("line", (line) => {
    const response = JSON.parse(line) as RpcMessage;
    responses.push(response);
    if (typeof response["id"] === "number" && response["id"] > 100) {
      const waiter = pending.get(response["id"]);
      pending.delete(response["id"]);
      if (response["error"])
        waiter?.reject(new Error(JSON.stringify(response["error"])));
      else waiter?.resolve(response["result"] as RpcMessage);
    } else if (forwarding) stream.write(`${line}\n`);
  });
  const rpc = (method: string, params: RpcMessage) =>
    new Promise<RpcMessage>((resolve, reject) => {
      const id = ++nextId;
      pending.set(id, { resolve, reject });
      child.stdin.write(`${JSON.stringify({ id, method, params })}\n`);
    });
  const stopped = "Synthetic stop before model execution";
  let snapshotsPrepared = false;
  const input = new Writable({
    write(chunk, _encoding, callback) {
      const request = JSON.parse(String(chunk)) as RpcMessage;
      requests.push(request);
      if (request["method"] === "turn/start")
        expect(snapshotsPrepared).toBe(true);
      // Resolve real native policies without executing commands or model turns.
      if (
        request["method"] === "command/exec" ||
        request["method"] === "turn/start"
      ) {
        const response =
          request["method"] === "command/exec"
            ? {
                id: request["id"],
                result: { exitCode: 0, stdout: "", stderr: "" },
              }
            : { id: request["id"], error: { message: stopped } };
        queueMicrotask(() => stream.write(`${JSON.stringify(response)}\n`));
        callback();
      } else child.stdin.write(chunk, callback);
    },
    final(callback) {
      forwarding = false;
      stream.end();
      callback();
    },
  });
  const timeout = setTimeout(() => {
    const error = new Error(`Native profile fixture timed out: ${stderr}`);
    stream.destroy(error);
    for (const waiter of pending.values()) waiter.reject(error);
    child.kill();
  }, 20_000);
  try {
    let snapshotProfile: RpcMessage | undefined;
    const permissions: PatchPermissions = captured ?? {
      name: "codex_security_patch",
      readOnlyPaths,
      modelOnlyReadOnlyPaths,
      externalConfigPaths: controls?.externalConfigPaths,
      externalCachePaths,
      credentialStorePaths: controls?.credentialStorePaths,
    };
    const reader = await readSkillCommandOutput(stream, {
      directory: repository,
      prompt: "Synthetic local-only profile resolution.",
      threadSource: "security_remediation",
      input,
      onPermissions(profile) {
        snapshotProfile = profile;
      },
      async onBeforeTurn() {
        expect(snapshotProfile).toBeDefined();
        expect(requests.at(-1)?.["method"]).toBe("command/exec");
        await new Promise<void>((resolve) => setImmediate(resolve));
        snapshotsPrepared = true;
      },
      permissions,
    });
    expect(reader.error, stderr).toBe(stopped);
    const start = requests.find(
      (request) => request["method"] === "thread/start",
    )!;
    const turn = requests.find(
      (request) => request["method"] === "turn/start",
    )!;
    const legacy = responses.find((response) => response["id"] === 2)![
      "result"
    ] as RpcMessage;
    const configuration = responses.find((response) => response["id"] === 4)![
      "result"
    ] as RpcMessage;
    const expectedPolicy = {
      type: "workspaceWrite",
      writableRoots: configured ? [extra] : [],
      networkAccess: configured,
      excludeTmpdirEnvVar: configured,
      excludeSlashTmp: configured,
    };
    expect(
      configuration["config"].permissions.codex_security_patch.filesystem[
        ":workspace_roots"
      ],
    ).toEqual({ ".git/hooks": "write" });
    expect(
      configuration["config"].sandbox_workspace_write.writable_roots,
    ).toEqual([join(root, "project-selected")]);
    expect(
      configuration["layers"].some(
        (layer: RpcMessage) =>
          layer["name"].type === "project" && layer["disabledReason"] == null,
      ),
    ).toBe(true);
    expect(legacy["activePermissionProfile"]).toBeNull();
    expect(legacy["sandbox"]).toEqual(expectedPolicy);
    const preflight = requests.find(
      (request) => request["method"] === "command/exec",
    )!;
    expect(preflight["params"].sandboxPolicy).toEqual(expectedPolicy);
    const name = turn["params"].permissions as string;
    expect(name).not.toBe("codex_security_patch");
    const profiles = start["params"].config.permissions as Record<
      string,
      RpcMessage
    >;
    expect(Object.keys(profiles)).toEqual([name]);
    const snapshotDenies = Object.entries(
      snapshotProfile!["filesystem"],
    ).filter(
      ([, access]) =>
        access === "deny" || (access as RpcMessage)["."] === "deny",
    );
    const snapshotFilesystem = {
      ...Object.fromEntries(
        permissions.readOnlyPaths.map((path) => [path, { ".": "read" }]),
      ),
      ...Object.fromEntries(snapshotDenies),
      ...(configured ? { ":tmpdir": {}, ":slash_tmp": {} } : {}),
    };
    expect(snapshotProfile).toEqual({
      ...profiles[name],
      filesystem: snapshotFilesystem,
    });
    const cacheAccess =
      process.platform === "linux" && !existingStorage ? "deny" : "read";
    expect(profiles[name]!["filesystem"]).toEqual({
      ...snapshotFilesystem,
      ...Object.fromEntries(
        [
          ...(permissions.modelOnlyReadOnlyPaths ?? []).filter(
            (path) =>
              !permissions.readOnlyPaths.includes(dirname(path)) ||
              (configured && dirname(path) === extra),
          ),
          ...(configured ? (permissions.externalCachePaths ?? []) : []),
        ].map((path) => [path, { ".": cacheAccess }]),
      ),
      ...Object.fromEntries(
        (permissions.externalConfigPaths ?? []).map((path) => [
          path,
          { ".": "deny" },
        ]),
      ),
    });
    expect(await readFile(join(administration, "config"))).toEqual(
      configBefore,
    );
    const context: PatchProfileContext = {
      name,
      administration,
      filesystem: profiles[name]!["filesystem"] as RpcMessage,
      modelProfile: profiles[name]!,
      snapshotProfile: snapshotProfile!,
      snapshotConfig: captured?.snapshotConfig ?? controls?.snapshotConfig,
      repository,
      home,
      temporaryDirectory,
      storage,
      controls,
    };
    clearTimeout(timeout);
    if (exercise) {
      await rpc("config/value/write", {
        keyPath: `permissions.${name}`,
        value: context.modelProfile,
        mergeStrategy: "replace",
        filePath: join(home, "config.toml"),
      });
      await exercise(context, async (source) => {
        // Model tools and command/exec share native permission preparation.
        const result = await rpc("command/exec", {
          command: ["node", "-e", source],
          cwd: repository,
          permissionProfile: name,
          env: patchSnapshotEnvironment(temporaryDirectory, {}),
          timeoutMs: 30_000,
        });
        expect(result["exitCode"] as number, result["stderr"] as string).toBe(
          0,
        );
        return result["stdout"] as string;
      });
    }
    const deniedFiles = new Set([
      ...(permissions.credentialStorePaths ?? []),
      ...(shellPolicy?.paths ?? []),
      ...(process.platform === "win32"
        ? (permissions.externalConfigPaths ?? [])
        : []),
    ]);
    const fileDenies = snapshotDenies.filter(
      ([path]) => !path.endsWith("{*.config.toml,.*.config.toml.tmp}"),
    );
    expect(fileDenies).toHaveLength(deniedFiles.size);
    for (const file of deniedFiles) {
      expect(
        fileDenies.filter(([key, access]) =>
          access === "deny" ? matchesGlob(file, key) : key === file,
        ),
      ).toHaveLength(1);
    }
    // Resolve the selected policy after exercising the normal snapshot/turn order.
    const selected = await rpc("thread/start", {
      cwd: repository,
      ephemeral: true,
      approvalPolicy: "never",
      permissions: turn["params"].permissions,
      config: start["params"].config,
    });
    expect(selected["sandbox"]).toEqual(expectedPolicy);
    expect(selected["sandbox"].writableRoots).not.toContain(
      join(administration, "hooks"),
    );
    expect(selected["activePermissionProfile"]).toEqual({
      id: name,
      extends: ":workspace",
    });
    return context;
  } finally {
    clearTimeout(timeout);
    forwarding = false;
    stream.destroy();
    lines.close();
    child.stdin.end();
    const shutdown = setTimeout(() => child.kill(), 3000);
    await closed;
    clearTimeout(shutdown);
  }
}

test("native patch profiles ignore inactive repository grants and remain isolated between operations", async () => {
  const results = await Promise.allSettled([
    resolvePatchProfile(false),
    resolvePatchProfile(true),
  ]);
  const values = results.map((result) => {
    if (result.status === "rejected") throw result.reason;
    return result.value;
  });
  const first = values[0]!;
  const second = values[1]!;
  expect(first.name).not.toBe(second.name);
  expect(first.filesystem).not.toHaveProperty(second.administration);
  expect(second.filesystem).not.toHaveProperty(first.administration);
}, 30_000);

test.each([false, true])(
  "external cache restrictions follow the operator's writable roots: selected %p",
  async (selected) => {
    await resolvePatchProfile(selected, "outside");
  },
  30_000,
);

test("patch model cannot read external Git configuration used by snapshots", async () => {
  await resolvePatchProfile(
    false,
    "selected",
    true,
    async (context, inspectModel) => {
      const root = dirname(context.repository);
      const selected = join(root, "selected.gitconfig");
      const included = join(root, "included.gitconfig");
      const readConfigs = `const fs = require("node:fs");
const { spawnSync } = require("node:child_process");
const paths = ${JSON.stringify([selected, included])};
for (const path of paths) {
  try { process.stdout.write(fs.readFileSync(path)); }
  catch (error) { process.stdout.write(error.code); }
}
const git = spawnSync("git", ["config", "--file", paths[0], "--get", "http.extraHeader"]);
if (git.stdout) process.stdout.write(git.stdout);`;
      const expectModelDenied = async () => {
        const reads = await inspectModel(readConfigs);
        expect(reads).not.toContain("Synthetic fixture");
        expect(reads).not.toContain("Included fixture");
      };
      const gitEnvironment = {
        GIT_CONFIG_GLOBAL: selected,
        GIT_CONFIG_NOSYSTEM: "1",
      };
      const environment = patchSnapshotEnvironment(context.temporaryDirectory, {
        ...process.env,
        CODEX_HOME: context.home,
        ...gitEnvironment,
      });
      const sandbox = {
        directory: context.repository,
        environment,
        profile: context.snapshotProfile,
        snapshotConfig: context.snapshotConfig,
        gitEnvironment,
      };
      await expectModelDenied();
      expect(
        await runRepositoryCommand(
          "git",
          ["config", "--get", "synthetic.source"],
          context.repository,
          { sandbox },
        ),
      ).toBe("Included fixture");
      if (process.platform === "win32") {
        // Exercise repeated and simultaneous Git reads before giving another
        // command the exact live endpoint under the same sandbox account.
        const marker = join(context.repository, "snapshot-path");
        const done = join(context.repository, "snapshot-done");
        const launch = (input: string) =>
          runRepositoryCommand(
            "git",
            ["-c", "alias.config-reader=!node -", "config-reader"],
            context.repository,
            { sandbox, input },
          );
        const running = launch(`const fs = require("node:fs");
const git = require("node:util").promisify(require("node:child_process").execFile);
async function read() {
  const { stdout } = await git("git", ["config", "--get", "synthetic.source"]);
  if (stdout.trim() !== "Included fixture") throw new Error("Missing snapshot config");
}
async function check() {
  await Promise.all([read(), read(), read(), read()]);
  fs.writeFileSync("path.tmp", process.env.GIT_CONFIG_GLOBAL);
  fs.renameSync("path.tmp", "snapshot-path");
  const end = setTimeout(() => process.exit(1), 10000);
  while (!fs.existsSync("snapshot-done")) await new Promise(resolve => setTimeout(resolve, 10));
  clearTimeout(end);
  await read();
}
check().catch(error => { console.error(error); process.exitCode = 1; });`);
        try {
          while (
            !(await lstat(marker).then(
              () => true,
              () => false,
            ))
          )
            await Promise.race([
              running,
              new Promise((resolve) => setTimeout(resolve, 10)),
            ]);
          const endpoint = await readFile(marker, "utf8");
          expect(endpoint).toStartWith("//./pipe/");
          expect(
            await inspectModel(`const { spawnSync } = require("node:child_process");
const result = spawnSync("git", ["config", "--file", ${JSON.stringify(endpoint)}, "--list"]);
if (result.error) throw result.error;
process.stdout.write(String(result.stdout.length));`),
          ).toBe("0");
        } finally {
          await writeFile(done, "");
          await running;
        }
        // Git can warn and skip a busy endpoint. Even a successful child must
        // fail the snapshot if every listener was occupied at the same time.
        await expect(
          launch(`const fs = require("node:fs");
const clients = [];
for (let i = 0; i < 32; i++) clients.push(fs.openSync(process.env.GIT_CONFIG_GLOBAL, "r"));
for (const fd of clients) fs.closeSync(fd);`),
        ).rejects.toThrow("concurrent readers exhausted the pipe listeners");
      }
      await expectModelDenied();
    },
  );
}, 60000);

async function captureFilterPermissions(
  repository: string,
  environment: NodeJS.ProcessEnv & { HOME: string },
  driver: string,
  program: string,
): Promise<PatchPermissions> {
  for (const [key, value] of [
    // The Windows sandbox can open the script inside its workspace but
    // cannot stat the private parent of the CI fixture during realpath.
    ["clean", "node --preserve-symlinks-main " + program],
    ["required", "true"],
  ] as const)
    execFileSync(
      "git",
      ["config", "--local", `filter.${driver}.${key}`, value],
      { cwd: repository },
    );
  // Collect the permissions the CLI passes to its native app-server.
  let selected: PatchPermissions | undefined;
  const stopped = "Captured synthetic patch permissions";
  const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
    currentDirectory: repository,
    environment: { ...process.env, ...environment },
    manualCodexPreparation: true,
    onRepositoryCommand: (cmd, args, cwd, options) =>
      runGitRepositoryCommand(cmd, args, cwd, {
        ...options,
        environment: { ...environment, ...options?.environment },
      }),
    onCodex: (_args, output) => {
      if (output?.appServer?.permissions)
        selected = {
          ...output.appServer.permissions,
          // Grant ordinary reads in the synthetic operator home so both
          // probes exercise the individual file denies.
          readOnlyPaths: [
            ...output.appServer.permissions.readOnlyPaths,
            environment.HOME,
          ],
          snapshotConfig: output.appServer.snapshotConfig,
        };
      throw new Error(stopped);
    },
  });
  expect(outcome.stderr).toContain(stopped);
  expect(selected).toBeDefined();
  return selected!;
}

test("patch model and snapshot filters cannot recover credentials from Git stores", async () => {
  const gitHome = await fixtures.create("patch-store-home-");
  const configDirectory = join(
    gitHome,
    process.platform === "win32" ? "settings[git]{a,b}" : "settings",
  );
  await mkdir(join(configDirectory, "git"), { recursive: true });
  const config = join(gitHome, "selected.gitconfig");
  const stores = [
    join(gitHome, ".git-credentials"),
    join(configDirectory, "git", "credentials"),
    join(gitHome, "selected-[store]{a,b}.txt"),
  ];
  const environment = {
    HOME: gitHome,
    USERPROFILE: gitHome,
    XDG_CONFIG_HOME: configDirectory,
    GIT_CONFIG_GLOBAL: config,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0",
  };
  const createStore = (index: number) =>
    writeFile(
      stores[index]!,
      `https://fixture:synthetic-fixture-${index}@host-${index}.invalid\n`,
      { mode: 0o600, flag: "wx" },
    );
  await createStore(0);
  const neighbor = join(configDirectory, "git", "config");
  const neighborContents = "[fixture]\n source = neighbor\n";
  await writeFile(neighbor, neighborContents);
  const customHelper =
    "store --file='" +
    stores[2]!.replaceAll("\\", "/").replaceAll("'", "'\\''") +
    "'";
  execFileSync("git", [
    "config",
    "--file",
    config,
    "credential.helper",
    customHelper,
  ]);
  const probe = `const fs = require("node:fs");
const { spawnSync } = require("node:child_process");
if (fs.readFileSync(${JSON.stringify(neighbor)}, "utf8") !== ${JSON.stringify(neighborContents)})
  throw new Error("Cannot read the configuration next to the XDG store");
const stores = ${JSON.stringify(stores)};
const environment = { ...process.env, ...${JSON.stringify(environment)} };
delete environment.GIT_CONFIG_PARAMETERS;
delete environment.GIT_CONFIG_COUNT;
const direct = stores.map((path, index) => {
  try { return fs.readFileSync(path, "utf8").includes("synthetic-fixture-" + index); }
  catch { return false; }
});
function fill(index, helper) {
  const args = [...(helper ? ["-c", "credential.helper=", "-c", "credential.helper=" + helper] : []), "credential", "fill"];
  const directory = fs.mkdtempSync("credential-probe-");
  try {
    fs.writeFileSync(directory + "/request", "protocol=https\\nhost=host-" + index + ".invalid\\n\\n");
    const input = fs.openSync(directory + "/request", "r");
    const output = fs.openSync(directory + "/response", "w");
    try {
      const result = spawnSync("git", args, { env: environment, stdio: [input, output, 2] });
      if (result.error) throw result.error;
    } finally {
       fs.closeSync(input);
       fs.closeSync(output);
    }
    return fs.readFileSync(directory + "/response", "utf8").includes("password=synthetic-fixture-" + index);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
process.stdout.write(JSON.stringify([...direct, fill(2), fill(0, "store"), fill(1, "store"), fill(2, ${JSON.stringify(customHelper)})]));`;
  const protectedResult = JSON.stringify(Array(7).fill(false));
  const probeFile = "store-probe.cjs";
  await resolvePatchProfile(
    false,
    false,
    false,
    async (context, inspectModel) => {
      const repo = context.repository;
      // Git can create the XDG store after the two native profiles have been
      // selected. The model and snapshot filter must honor its deny rule too.
      await createStore(1);
      await createStore(2);
      await writeFile(join(repo, probeFile), probe);
      await writeFile(
        join(repo, ".gitattributes"),
        "candidate.txt filter=snapshot-store\n",
      );
      const git = (args: string[], input: string) =>
        execFileSync("git", args, {
          cwd: repo,
          env: { ...process.env, ...environment },
          input,
          encoding: "utf8",
        }).trim();
      const filtered = ["hash-object", "--path=candidate.txt", "--stdin"];
      const hash = (input: string) => git(["hash-object", "--stdin"], input);
      expect(git(filtered, "synthetic input")).toBe(
        hash(JSON.stringify(Array(7).fill(true))),
      );
      const sandboxEnvironment = patchSnapshotEnvironment(
        context.temporaryDirectory,
        {
          ...process.env,
          ...environment,
          CODEX_HOME: context.home,
        },
      );
      const actual = await runRepositoryCommand("git", filtered, repo, {
        input: "synthetic input",
        sandbox: {
          directory: repo,
          environment: sandboxEnvironment,
          gitEnvironment: environment,
          profile: context.snapshotProfile,
          snapshotConfig: context.snapshotConfig,
        },
      });
      expect(actual).toBe(hash(protectedResult));
      expect(await inspectModel(probe)).toBe(protectedResult);
      expect(git(filtered, "synthetic input")).toBe(
        hash(JSON.stringify(Array(7).fill(true))),
      );
    },
    (repository) =>
      captureFilterPermissions(
        repository,
        environment,
        "snapshot-store",
        probeFile,
      ),
  );
}, 60_000);

test("patch model and clean filters cannot read selected authentication files", async () => {
  const operator = await fixtures.create("patch-http-auth-files-");
  const config = join(operator, "selected.gitconfig");
  const selectedNetrc = join(operator, "selected credentials");
  const awsDirectory = join(operator, ".aws");
  const awsConfig = join(operator, "selected aws config");
  const awsCredentials = join(operator, "selected aws credentials");
  const clusterFiles = [
    join(
      operator,
      process.platform === "win32" ? "cluster;one" : "cluster one",
    ),
    join(operator, "cluster two"),
  ];
  const policyCluster = join(operator, "policy cluster");
  const registry = join(operator, "selected registry");
  const gh = join(operator, "selected gh");
  const glab = join(operator, "selected glab");
  const pgpass = join(operator, "selected pgpass");
  const pgservice = join(operator, "selected pg service");
  const pgKey = join(operator, "selected pg key");
  const pgCert = join(operator, "selected pg cert");
  const terraformConfig = join(operator, "selected terraform config");
  const legacyTerraformConfig = join(operator, "legacy terraform config");
  const defaultGh = join(operator, ".config", "gh");
  const cloudConfig = join(operator, "selected gcloud");
  const cloudKey = join(operator, "selected Google credentials.json");
  const cloudDefault = "application_default_credentials.json";
  const appdata = join(operator, "Roaming");
  const terraformDir =
    process.platform === "win32"
      ? join(appdata, "terraform.d")
      : join(operator, ".terraform.d");
  const pgTlsDir =
    process.platform === "win32"
      ? join(appdata, "postgresql")
      : join(operator, ".postgresql");
  const ssh = join(operator, ".ssh");
  await mkdir(gh);
  await mkdir(ssh);
  await mkdir(defaultGh, { recursive: true });
  await mkdir(terraformDir, { recursive: true });
  const npm = join(operator, "selected npmrc");
  await mkdir(registry);
  const clusterList = (files: string[]) =>
    files
      .map((file) => (process.platform === "win32" ? `"${file}"` : file))
      .join(delimiter);
  const pointers = {
    KUBECONFIG: clusterList(clusterFiles),
    DOCKER_CONFIG: registry,
    GH_CONFIG_DIR: gh,
    GLAB_CONFIG_DIR: glab,
    PGPASSFILE: pgpass,
    PGSERVICEFILE: pgservice,
    PGSSLKEY: pgKey,
    PGSSLCERT: pgCert,
    TF_CLI_CONFIG_FILE: terraformConfig,
    TERRAFORM_CONFIG: legacyTerraformConfig,
    GOOGLE_APPLICATION_CREDENTIALS: cloudKey,
    NPM_CONFIG_USERCONFIG: npm,
  };
  const policySet = {
    ...pointers,
    KUBECONFIG: clusterList([...clusterFiles, policyCluster]),
    FILTER_FIXTURE_SETTING: "from shell policy",
  };
  const environment = {
    ...pointers,
    CODEX_HOME: operator,
    CODEX_SECURITY_STATE_DIR: operator,
    FILTER_FIXTURE_SETTING: "from host",
    AWS_CONFIG_FILE: awsConfig,
    AWS_SHARED_CREDENTIALS_FILE: awsCredentials,
    CLOUDSDK_CONFIG: cloudConfig,
    APPDATA: appdata,
    PGSYSCONFDIR: operator,
    NETRC: selectedNetrc,
    HOME: operator,
    USERPROFILE: operator,
    XDG_CONFIG_HOME: join(operator, "xdg"),
    XDG_CONFIG_DIRS:
      (process.platform === "win32" ? "%USERPROFILE%" : "$HOME") + "/xdg-extra",
    GIT_CONFIG_GLOBAL: config,
    GIT_CONFIG_NOSYSTEM: "1",
  };
  await mkdir(join(environment.XDG_CONFIG_HOME, "git"), { recursive: true });
  const settings = [
    "http.cookieFile",
    "http.sslKey",
    "http.https://scoped.example.invalid/.cookieFile",
    "http.https://scoped.example.invalid/.sslKey",
  ];
  const drive =
    process.platform === "win32" ? /^[a-z]:/iu.exec(operator)?.[0] : undefined;
  if (drive !== undefined)
    settings.push(
      "http.https://drive.example.invalid/.cookieFile",
      "http.https://root.example.invalid/.sslKey",
    );
  const paths = settings.map((_, i) => join(operator, `auth ${i}.txt`));
  const netrc = join(operator, ".netrc");
  const proxyKey = join(operator, "proxy key.pem");
  const scopedProxyKey = join(operator, "scoped proxy key.pem");
  const clientCert = join(operator, "origin identity.pem");
  const proxyCert = join(operator, "proxy identity.pem");
  const existing = [
    ...paths.slice(0, 2),
    netrc,
    proxyKey,
    clientCert,
    join(operator, "selected.config.toml"),
    join(terraformDir, "registry.tfrc"),
    join(terraformDir, "workspace.tfrc.json"),
  ];
  const glabDirectories = [
    glab,
    join(operator, ".config", "glab-cli"),
    join(environment.XDG_CONFIG_HOME, "glab-cli"),
    join(operator, "xdg-extra", "glab-cli"),
  ];
  if (process.platform === "win32")
    glabDirectories.push(join(appdata, "glab-cli"));
  if (process.platform === "darwin")
    glabDirectories.push(
      join(operator, "Library", "Application Support", "glab-cli"),
    );
  const protectedPaths = [
    ...existing,
    ...paths.slice(2),
    join(operator, "after-capture.config.toml"),
    join(operator, "codex-home", "after-capture.config.toml"),
    ...[".codex", ".", "codex-home"].flatMap((home) =>
      ["auth.json", ".credentials.json", "config.toml"].map((file) =>
        join(operator, home, file),
      ),
    ),
    join(operator, "_netrc"),
    scopedProxyKey,
    proxyCert,
    selectedNetrc,
    join(awsDirectory, "config"),
    join(awsDirectory, "credentials"),
    awsConfig,
    awsCredentials,
    ...clusterFiles,
    policyCluster,
    join(registry, "config.json"),
    join(gh, "hosts.yml"),
    join(defaultGh, "hosts.yml"),
    pgpass,
    pgservice,
    pgKey,
    pgCert,
    terraformConfig,
    legacyTerraformConfig,
    process.platform === "win32"
      ? join(appdata, "terraform.rc")
      : join(operator, ".terraformrc"),
    join(terraformDir, "credentials.tfrc.json"),
    join(pgTlsDir, "postgresql.key"),
    join(pgTlsDir, "postgresql.crt"),
    join(operator, "pg_service.conf"),
    process.platform === "win32"
      ? join(appdata, "postgresql", ".pg_service.conf")
      : join(operator, ".pg_service.conf"),
    process.platform === "win32"
      ? join(appdata, "postgresql", "pgpass.conf")
      : join(operator, ".pgpass"),
    ...glabDirectories.map((directory) => join(directory, "config.yml")),
    cloudKey,
    join(cloudConfig, cloudDefault),
    join(operator, ".config", "gcloud", cloudDefault),
    ...(process.platform === "win32"
      ? [join(appdata, "gcloud", cloudDefault)]
      : []),
    join(ssh, "id_rsa"),
    join(operator, ".docker", "config.json"),
    join(operator, ".kube", "config"),
    join(operator, ".npmrc"),
    npm,
  ];
  const contents = protectedPaths.map((_, i) => `synthetic auth input ${i}\n`);
  const createInput = (i: number) =>
    writeFile(protectedPaths[i]!, contents[i]!, { mode: 0o600, flag: "wx" });
  for (const i of existing.keys()) await createInput(i);
  const neighbor = join(registry, "ordinary-sibling.txt");
  await writeFile(neighbor, "ordinary sibling");
  const readFiles = () => `const fs = require("node:fs");
if (fs.readFileSync(${JSON.stringify(join(awsDirectory, "ordinary.txt"))}, "utf8") !== "AWS sibling") throw new Error("Cannot read the ordinary AWS sibling");
if (fs.readFileSync(${JSON.stringify(neighbor)}, "utf8") !== "ordinary sibling")
  throw new Error("Cannot read the ordinary sibling");
if (fs.readFileSync(${JSON.stringify(join(terraformDir, "ordinary.txt"))}, "utf8") !== "Terraform sibling")
  throw new Error("Cannot read the ordinary Terraform sibling");
const contents = [];
for (const path of ${JSON.stringify(protectedPaths)}) {
  try { contents.push(fs.readFileSync(path, "utf8")); }
  catch (error) { if (!["EACCES", "EPERM", "ENOENT"].includes(error.code)) throw error; }
}`;
  const program = "auth-filter.cjs";
  await resolvePatchProfile(
    false,
    false,
    false,
    async (context, inspectModel) => {
      // An operator may have no AWS profile directory when the first model tool runs.
      expect(await inspectModel('process.stdout.write("ready")')).toBe("ready");
      await mkdir(join(operator, ".codex"), { recursive: true });
      await mkdir(join(operator, "codex-home"), { recursive: true });
      await mkdir(awsDirectory);
      await mkdir(join(operator, ".docker"));
      await mkdir(join(operator, ".kube"));
      for (const directory of glabDirectories)
        await mkdir(directory, { recursive: true });
      await mkdir(cloudConfig);
      await mkdir(pgTlsDir, { recursive: true });
      await writeFile(join(terraformDir, "ordinary.txt"), "Terraform sibling");
      await mkdir(join(operator, ".config", "gcloud"));
      if (process.platform === "win32")
        await mkdir(join(appdata, "gcloud"), { recursive: true });
      await writeFile(join(awsDirectory, "ordinary.txt"), "AWS sibling");
      // These files change after profile selection and before the two commands launch.
      for (let i = existing.length; i < protectedPaths.length; i++)
        await createInput(i);
      const replacement = join(operator, "new-netrc");
      await writeFile(replacement, contents[existing.indexOf(netrc)]!, {
        mode: 0o600,
        flag: "wx",
      });
      await rename(replacement, netrc);
      const repo = context.repository;
      const input = "INTENDED PATCH BYTES\n";
      await writeFile(join(repo, "candidate.txt"), input);
      await writeFile(
        join(repo, ".gitattributes"),
        "candidate.txt filter=auth-file\n",
      );
      await writeFile(
        join(repo, program),
        readFiles() +
          `\nprocess.stdout.write(process.env.FILTER_FIXTURE_SETTING + "\\n");
for (const name of ${JSON.stringify(Object.keys(pointers))}) if (name in process.env) contents.push(name);
process.stdout.write(contents.length ? contents.join("") : fs.readFileSync(0, "utf8").toLowerCase());\n`,
      );
      const git = (args: string[], extra: NodeJS.ProcessEnv = {}) =>
        execFileSync("git", args, {
          cwd: repo,
          env: { ...process.env, ...environment, ...extra },
          encoding: "utf8",
        });
      const add = ["add", "--", "candidate.txt"];
      const staged = ["cat-file", "blob", ":candidate.txt"];
      git(add);
      expect(git(staged)).toBe(
        "from host\n" + contents.join("") + Object.keys(pointers).join(""),
      );
      const modelRead =
        readFiles() + "\nprocess.stdout.write(JSON.stringify(contents));";
      expect(await inspectModel(modelRead)).toBe("[]");
      if (patchSnapshotWindowsConfig().includes('"elevated"'))
        console.info(
          "Windows model denied selected authentication files before snapshot",
          protectedPaths.length,
        );
      const snapshot = {
        GIT_INDEX_FILE: join(repo, "snapshot-index"),
        GIT_OBJECT_DIRECTORY: join(repo, "snapshot-objects"),
      };
      await mkdir(snapshot.GIT_OBJECT_DIRECTORY);
      await runRepositoryCommand("git", add, repo, {
        environment: snapshot,
        sandbox: {
          directory: repo,
          environment: patchSnapshotEnvironment(context.temporaryDirectory, {
            ...process.env,
            ...environment,
            CODEX_HOME: context.home,
          }),
          gitEnvironment: {
            ...snapshot,
            GIT_CONFIG_GLOBAL: config,
            GIT_CONFIG_NOSYSTEM: "1",
            HOME: operator,
            USERPROFILE: operator,
            XDG_CONFIG_HOME: environment.XDG_CONFIG_HOME,
            NETRC: environment.NETRC,
          },
          profile: context.snapshotProfile,
          snapshotConfig: context.snapshotConfig,
        },
      });
      const sharedCredentials = join(awsDirectory, "credentials");
      const replacementCredentials = join(awsDirectory, "replacement");
      await writeFile(
        replacementCredentials,
        contents[protectedPaths.indexOf(sharedCredentials)]!,
        { mode: 0o600 },
      );
      await rename(replacementCredentials, sharedCredentials);
      const modelReads = await inspectModel(modelRead);
      expect({ staged: git(staged, snapshot), modelReads }).toEqual({
        staged: "from shell policy\nintended patch bytes\n",
        modelReads: "[]",
      });
      expect(
        git(["hash-object", "--path=candidate.txt", "candidate.txt"]),
      ).toBe(git(["rev-parse", ":candidate.txt"]));
    },
    async (repository) => {
      const literalTilde = join(repository, "~");
      const localGlabDir = join(repository, ".git", "glab-cli");
      glabDirectories.push(localGlabDir);
      protectedPaths.push(join(localGlabDir, "config.yml"));
      contents.push("synthetic local glab login\n");
      await mkdir(literalTilde);
      environment.NETRC = relative(repository, selectedNetrc);
      const scopedCookie = relative(repository, paths[2]!).replaceAll(
        "\\",
        "/",
      );
      expect(scopedCookie.startsWith("../")).toBe(true);
      const values = [paths[0]!, "~/auth 1.txt", scopedCookie, paths[3]!];
      if (drive !== undefined) {
        expect(repository.slice(0, 2).toUpperCase()).toBe(drive.toUpperCase());
        values.push(
          drive + relative(repository, paths[4]!),
          paths[5]!.slice(drive.length),
        );
      }
      for (const [setting, value] of [
        ...settings.map((setting, i) => [setting, values[i]!] as const),
        ["http.sslCert", "~/origin identity.pem"],
        [
          "http.https://proxy.example.invalid/.proxySSLCert",
          "~/" + relative(literalTilde, proxyCert).replaceAll("\\", "/"),
        ],
        ["http.proxySSLKey", proxyKey],
        [
          "http.https://proxy.example.invalid/.proxySSLKey",
          relative(repository, scopedProxyKey).replaceAll("\\", "/"),
        ],
      ] as const)
        execFileSync("git", ["config", "--file", config, setting, value]);
      return captureFilterPermissions(
        repository,
        environment,
        "auth-file",
        program,
      );
    },
    { set: policySet, paths: [policyCluster] },
  );
}, 60_000);

test.each(["administration", "direct-administration"] as const)(
  "storage keeps overlapping Git administration protected in snapshots: %s",
  async (storage) => {
    const context = await resolvePatchProfile(false, storage);
    const environment = patchSnapshotEnvironment(context.temporaryDirectory, {
      ...process.env,
      CODEX_HOME: context.home,
    });
    const source = `const fs=require("node:fs");try{fs.writeFileSync(${JSON.stringify(join(context.storage, "objects", "synthetic"))},"changed");fs.writeSync(1,"allowed");}catch(error){fs.writeSync(1,error.code);}`;
    const output = await runRepositoryCommand(
      "git",
      [
        "-c",
        `alias.inspect=!node -e '${source.replaceAll("'", "'\\''")}'`,
        "inspect",
      ],
      context.repository,
      {
        sandbox: {
          directory: context.repository,
          environment,
          profile: context.snapshotProfile,
          snapshotConfig: context.snapshotConfig,
        },
      },
    );
    expect(["EROFS", "EACCES", "EPERM"]).toContain(output);
    await context.controls!.validate();
  },
  30_000,
);

// The baseline snapshot precedes the model turn. Exercise a model that finds an
// untouched cache in a separate checkout: Windows keeps deny-write ACLs on disk.
test.each(["inside", "outside"] as const)(
  "model cannot populate an absent optional cache: %s",
  async (location) => {
    await resolvePatchProfile(
      location !== "inside",
      location,
      false,
      async (context, inspectModel) => {
        const paths = ["objects", "tmp"].map((part) =>
          join(context.storage, part),
        );
        for (const path of paths)
          await expect(lstat(path)).rejects.toMatchObject({ code: "ENOENT" });
        const attempts = await inspectModel(
          `const fs=require("node:fs");const paths=${JSON.stringify(paths)};
const attempts=paths.map(path=>{
  const attempt=(operation)=>{try{return operation()===undefined?"ok":"created";}catch(error){return error.code;}};
  return [
    attempt(()=>fs.mkdirSync(path,{recursive:true})),
    attempt(()=>fs.mkdirSync(path+"/child")),
    attempt(()=>fs.writeFileSync(path+"/synthetic","changed")),
  ];
});fs.writeSync(1,JSON.stringify(attempts));`,
        );
        const results = JSON.parse(attempts);
        expect(results).toHaveLength(paths.length);
        const denied = ["EACCES", "EPERM", "EROFS", "ENOENT", "ENOTDIR"];
        for (const [index, path] of paths.entries()) {
          const [create, child, write] = results[index];
          // Recursive mkdir finds a protected directory on Windows and a file
          // placeholder inside the Linux mount namespace.
          expect([...denied, "EEXIST", "ok"]).toContain(create);
          expect(denied).toContain(child);
          expect(denied).toContain(write);
          if (process.platform === "win32")
            expect(await readdir(path)).toEqual([]);
          else
            await expect(lstat(path)).rejects.toMatchObject({ code: "ENOENT" });
        }
        await context.controls!.validate();
      },
    );
  },
  30_000,
);

for (const location of ["inside", "outside", "selected"] as const) {
  for (const existing of location === "selected" ? [true] : [false, true]) {
    test(`optional cache keeps model protection and inherited snapshot access: ${location}, existing ${existing}`, async () => {
      await resolvePatchProfile(
        location !== "inside",
        location,
        existing,
        async (context, inspectModel) => {
          const environment = patchSnapshotEnvironment(
            context.temporaryDirectory,
            {
              ...process.env,
              CODEX_HOME: context.home,
            },
          );
          const paths = [
            join(context.storage, "objects"),
            join(context.storage, "tmp"),
          ];
          const file = join(paths[0]!, "synthetic");
          const inspect = (source: string, profile: RpcMessage) =>
            runRepositoryCommand(
              "git",
              [
                "-c",
                `alias.inspect=!node -e '${source.replaceAll("'", "'\\''")}'`,
                "inspect",
              ],
              context.repository,
              {
                sandbox: {
                  directory: context.repository,
                  environment,
                  profile,
                },
              },
            );
          const snapshot = await inspect(
            `const fs=require("node:fs");for(const path of ${JSON.stringify(paths)})fs.mkdirSync(path,{recursive:true});fs.writeFileSync(${JSON.stringify(file)},"unchanged");fs.writeSync(1,"prepared");`,
            location === "selected"
              ? {
                  ...context.snapshotProfile,
                  filesystem: {
                    ...context.snapshotProfile["filesystem"],
                    [context.storage]: { ".": "write" },
                  },
                }
              : context.snapshotProfile,
          );
          expect(snapshot).toBe("prepared");
          await context.controls!.validate();
          const model = await inspectModel(
            `const fs=require("node:fs");try{fs.writeFileSync(${JSON.stringify(file)},"changed");fs.writeSync(1,"allowed");}catch(error){fs.writeSync(1,error.code);}`,
          );
          expect(["EROFS", "EACCES", "EPERM"]).toContain(model);
          expect(await readFile(file, "utf8")).toBe("unchanged");
          await context.controls!.validate();
          await rename(paths[0]!, `${paths[0]}-previous`);
          await mkdir(paths[0]!);
          await expect(context.controls!.validate()).rejects.toThrow(
            "changed location during the patch",
          );
        },
      );
    }, 30_000);
  }
}

(process.platform === "win32" ? test : test.skip)(
  "a verbatim-only missing store stops before snapshot or model execution",
  async () => {
    const requests: string[] = [];
    const stream = new PassThrough();
    const input = new Writable({
      write(chunk, _encoding, callback) {
        requests.push(JSON.parse(String(chunk)).method);
        callback();
      },
    });
    stream.end('{"id":1,"result":{}}\n{"id":4,"result":{"config":{}}}\n');
    await expect(
      readSkillCommandOutput(stream, {
        directory: process.cwd(),
        prompt: "Synthetic patch",
        threadSource: "security_remediation",
        input,
        permissions: {
          name: "synthetic",
          readOnlyPaths: [],
          credentialStorePaths: [String.raw`\\?\C:\synthetic.\credentials`],
        },
      }),
    ).rejects.toThrow("requires verbatim lookup");
    for (const method of ["thread/start", "command/exec", "turn/start"])
      expect(requests).not.toContain(method);
  },
);

test("a failed prepared snapshot prevents the model turn and preserves its diagnostic", async () => {
  const stream = new PassThrough();
  const requests: RpcMessage[] = [];
  const input = new Writable({
    write(chunk, _encoding, callback) {
      requests.push(JSON.parse(String(chunk)));
      callback();
    },
  });
  for (const reply of [
    { id: 1, result: {} },
    { id: 4, result: { config: {} } },
    {
      id: 2,
      result: {
        thread: { id: "synthetic" },
        sandbox: { type: "workspaceWrite" },
      },
    },
    { id: 5, result: { exitCode: 0, stdout: "", stderr: "" } },
  ])
    stream.write(`${JSON.stringify(reply)}\n`);
  stream.end();
  const diagnostic = "Synthetic snapshot error with original details";
  await expect(
    readSkillCommandOutput(stream, {
      directory: process.cwd(),
      prompt: "Synthetic patch",
      threadSource: "security_remediation",
      input,
      permissions: { name: "synthetic", readOnlyPaths: [] },
      async onBeforeTurn() {
        throw new Error(diagnostic);
      },
    }),
  ).rejects.toThrow(diagnostic);
  expect(requests.some((request) => request["method"] === "turn/start")).toBe(
    false,
  );
});
