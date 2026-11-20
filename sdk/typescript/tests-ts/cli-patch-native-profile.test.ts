import { expect, test } from "bun:test";
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
import {
  delimiter,
  dirname,
  join,
  matchesGlob,
  relative,
  resolve,
} from "node:path";
import { createInterface } from "node:readline";
import { PassThrough, Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { readSkillCommandOutput, runRepositoryCommand } from "../src/cli.js";
import {
  capturePatchGitControls,
  type PatchSnapshotConfig,
} from "../src/patch-git-controls.js";
import {
  runGitRepositoryCommand,
  patchDirectories,
  runIssuePatch,
} from "./cli-patch-fixtures.js";
import {
  patchSnapshotEnvironment,
  patchSnapshotWindowsConfig,
} from "./support/patch-snapshot-environment.js";

const fixtures = patchDirectories();

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
  const extra = join(root, "private", "extra-workspace");
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
  const selector = join(root, "lfs.gitconfig");
  const gitEnvironment = {
    HOME: home,
    USERPROFILE: home,
    GIT_CONFIG_GLOBAL: selectedConfig,
    ...(optionalStorage === "selected" && { GIT_CONFIG: selector }),
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
      await writeFile(selector, "[include]\n path = included.gitconfig\n");
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
      {
        environment: gitEnvironment,
        automaticPublication: optionalStorage === "selected",
      },
    );
    expect(controls).toBeDefined();
    expect([...controls!.externalConfigPaths].sort()).toEqual(
      optionalStorage === "selected"
        ? [selectedConfig, selector, join(root, "included.gitconfig")].sort()
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
      // Cache tests include one representative Git store. Credential scenarios
      // supply the full captured profile through captureFilterPermissions.
      credentialStorePaths: controls
        ? [join(home, ".config", "git", "credentials")]
        : process.platform === "linux"
          ? [dirname(extra), join(extra, "session")]
          : [],
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
      ...(snapshotDenies.some(([path]) => path.endsWith("/**}"))
        ? { glob_scan_max_depth: 4096 }
        : {}),
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
    const stores = [...deniedFiles];
    const writable = [repository, ...expectedPolicy.writableRoots];
    const mounts = stores.filter(
      (file) =>
        process.platform !== "linux" ||
        !stores.some(
          (parent) =>
            file.startsWith(parent + "/") &&
            !writable.some(
              (root) =>
                root.startsWith(parent + "/") &&
                (file === root || file.startsWith(root + "/")),
            ),
        ),
    );
    const unused = new Set(fileDenies);
    for (const file of mounts) {
      const matches = fileDenies.filter(([key, access]) =>
        access === "deny" ? matchesGlob(file, key) : key === file,
      );
      expect(matches, file).toHaveLength(1);
      unused.delete(matches[0]!);
    }
    expect([...unused]).toEqual([]);
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
  if (process.platform === "linux") {
    expect(first.filesystem[join(first.storage, "session")]).toBeUndefined();
    expect(second.filesystem[join(second.storage, "session")]).toEqual({
      ".": "deny",
    });
  }
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
      const selector = join(root, "lfs.gitconfig");
      const included = join(root, "included.gitconfig");
      const readConfigs = `const fs = require("node:fs");
const { spawnSync } = require("node:child_process");
const paths = ${JSON.stringify([selected, included, selector])};
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
        expect(reads).not.toContain("[lfs]");
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
      const config = (key: string, file?: string) =>
        runRepositoryCommand(
          "git",
          ["config", "--includes", "--get", key],
          context.repository,
          {
            sandbox: {
              ...sandbox,
              gitEnvironment: { ...gitEnvironment, GIT_CONFIG: file },
            },
          },
        );
      expect(await config("synthetic.source")).toBe("Included fixture");
      expect(await config("synthetic.source", selector)).toBe(
        "Included fixture",
      );
      expect(await config("lfs.storage", selector)).toBe(context.storage);
      if (process.platform === "win32") {
        // Exercise repeated and simultaneous Git reads before giving another
        // command the exact live endpoint under the same sandbox account.
        const marker = join(context.repository, "snapshot-path");
        const done = join(context.repository, "snapshot-done");
        const readPipe = `function readPipe(file) {
  const fs = require("node:fs");
  const fd = fs.openSync(file, "r");
  try { return fs.readSync(fd, Buffer.alloc(1)); }
  catch (error) { if (error.code === "EPIPE") return 0; throw error; }
  finally { fs.closeSync(fd); }
}`;
        const launch = (input: string) =>
          runRepositoryCommand(
            "git",
            ["-c", "alias.config-reader=!node -", "config-reader"],
            context.repository,
            { sandbox, input },
          );
        const running = launch(`const fs = require("node:fs");
const git = require("node:util").promisify(require("node:child_process").execFile);
${readPipe}
async function read() {
  const { stdout } = await git("git", ["config", "--get", "synthetic.source"]);
  if (stdout.trim() !== "Included fixture") throw new Error("Missing snapshot config");
}
async function check() {
  await Promise.all([read(), read(), read(), read()]);
  const endpoint = process.env.GIT_CONFIG_GLOBAL;
  if (!readPipe(endpoint)) throw new Error("Empty snapshot config");
  fs.writeFileSync("path.tmp", endpoint);
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
            await inspectModel(`${readPipe}
process.stdout.write(String(readPipe(${JSON.stringify(endpoint)})));`),
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
  const outcome = await runIssuePatch(repository, {
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
  const windows = process.platform === "win32";
  const mac = process.platform === "darwin";
  const at = (file: string) => join(operator, file);
  const files = (dir: string, ...names: string[]) =>
    names.map((name) => join(dir, name));
  const ghFiles = (dir: string) => files(dir, "hosts.yml", "config.yml");
  const config = at("selected.gitconfig");
  const selectedNetrc = at("selected credentials");
  const awsDirectory = at(".aws");
  const clusterFiles = [
    at(windows ? "cluster;one" : "cluster one"),
    at("cluster two"),
  ];
  const policyCluster = at("policy cluster");
  const gh = "selected gh";
  const cloudConfig = at("selected gcloud");
  const cloudDefault = "application_default_credentials.json";
  const azure = at("selected azure");
  const appdata = at("Roaming");
  const platformConfig = windows
    ? appdata
    : at(mac ? "Library/Application Support" : ".config");
  const pythonLocal = windows ? at("AppData/Local") : platformConfig;
  const terraformDir = windows
    ? join(appdata, "terraform.d")
    : at(".terraform.d");
  const pgTlsDir = windows ? join(appdata, "postgresql") : at(".postgresql");
  const pipConfig = windows ? "pip.ini" : "pip.conf";
  const xdg = at("xdg");
  const clusterList = (files: string[]) =>
    files.map((file) => (windows ? `"${file}"` : file)).join(delimiter);
  const selectedFiles = Object.fromEntries(
    [
      "GIT_SSL_KEY",
      "GIT_PROXY_SSL_CERT",
      "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
      "AWS_WEB_IDENTITY_TOKEN_FILE",
      "PNPM_CONFIG_NPMRC_AUTH_FILE",
      "BUNDLE_USER_CONFIG",
      "HATCH_CONFIG",
      "PDM_CONFIG_FILE",
      "KEYRING_PROPERTY_FILE_PATH",
      "POETRY_CERTIFICATES_PRIVATE_CLIENT_CERT",
      "REGISTRY_AUTH_FILE",
      "RCLONE_CONFIG",
      "_RCLONE_CONFIG_KEY_FILE",
      "RCLONE_GCS_SERVICE_ACCOUNT_FILE",
      "RCLONE_SFTP_KEY_FILE",
      "SSL_CLIENT_CERT",
      "SOPS_AGE_KEY_FILE",
      "SOPS_AGE_SSH_PRIVATE_KEY_FILE",
    ].map((name) => [name, at(name)]),
  );
  const pointers = {
    ...selectedFiles,
    KUBECONFIG: clusterList(clusterFiles),
    DOCKER_CONFIG: at("selected registry"),
    DOCKER_CERT_PATH: at("docker tls"),
    GH_CONFIG_DIR: gh,
    BINSTAR_CONFIG_DIR: at("selected binstar"),
    ANACONDA_AUTH_KEYRING_PATH: "~/${LOGIN_CACHE_NAME}.keyring",
    RATTLER_AUTH_FILE: at("selected rattler"),
    RCLONE_CONFIG_BACKUP_PASS: "synthetic remote password",
    RCLONE_SFTP_KEY_PEM: "synthetic remote key",
    RCLONE_CONFIG_PASS: "synthetic config password",
    RCLONE_PASSWORD_COMMAND: "synthetic-rclone-password",
    GNUPGHOME: at("selected signing home"),
    GLAB_CONFIG_DIR: at("selected glab"),
    GCM_PLAINTEXT_STORE_PATH: at("selected plaintext store"),
    SOPS_AGE_KEY: "synthetic age identity",
    PIP_CONFIG_FILE: at("selected pip config"),
    POETRY_CONFIG_DIR: at("poetry"),
    UV_CREDENTIALS_DIR: at("uv credentials"),
    DEVPI_CLIENTDIR: "~/selected devpi",
    POETRY_PYPI_TOKEN_PRIVATE: "synthetic token",
    POETRY_HTTP_BASIC_PRIVATE_USERNAME: "synthetic auth",
    HATCH_INDEX_AUTH: "synthetic auth",
    UV_INDEX: "private=https://synthetic@example.test/simple",
    PIP_CLIENT_CERT: "~/pip client.pem",
    AZURE_CONFIG_DIR: azure,
    AWS_LOGIN_CACHE_DIRECTORY: "~/${LOGIN_CACHE_NAME}",
    BOTO_CONFIG: "${HOME}/selected boto.cfg",
    PGPASSFILE: at("selected pgpass"),
    PGSERVICEFILE: at("selected pg service"),
    PGSSLKEY: at("selected pg key"),
    PGSSLCERT: at("selected pg cert"),
    TF_CLI_CONFIG_FILE: at("selected terraform config"),
    TERRAFORM_CONFIG: at("legacy terraform config"),
    GOOGLE_APPLICATION_CREDENTIALS: at("selected Google credentials.json"),
    COMPOSER_AUTH: '{"bearer":{"example.invalid":"synthetic"}}',
    PNPM_CONFIG__AUTH: '{"example.invalid":{"authToken":"synthetic"}}',
    YARN_NPM_AUTH_IDENT: "operator:synthetic",
    DENO_AUTH_TOKENS: "synthetic@example.invalid",
    NPM_CONFIG_USERCONFIG: at("selected npmrc"),
    npm_config_globalconfig: "${HOME}/selected global npmrc",
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
    LOGIN_CACHE_NAME: "selected login cache",
    AWS_CONFIG_FILE: at("selected aws config"),
    AWS_SHARED_CREDENTIALS_FILE: at("selected aws credentials"),
    CLOUDSDK_CONFIG: cloudConfig,
    APPDATA: appdata,
    DOTNET_CLI_HOME: at("dotnet"),
    CARGO_HOME: at("cargo"),
    RYE_HOME: at("selected rye"),
    COMPOSER_HOME: "$HOME/selected composer",
    NPM_CONFIG_PREFIX: "~/selected prefix",
    YARN_RC_FILENAME: ".operator-yarnrc.yml",
    GRADLE_USER_HOME: at("gradle"),
    MAVEN_HOME: at("maven"),
    BUNDLE_USER_HOME: at("bundle"),
    HELM_CONFIG_HOME: at("helm"),
    XDG_DATA_HOME: at("data"),
    XDG_RUNTIME_DIR: at("runtime"),
    VIRTUAL_ENV: at("venv"),
    PGSYSCONFDIR: operator,
    NETRC: selectedNetrc,
    HOME: operator,
    USERPROFILE: operator,
    XDG_CONFIG_HOME: xdg,
    XDG_CONFIG_DIRS: (windows ? "%USERPROFILE%" : "$HOME") + "/xdg-extra",
    GIT_CONFIG_GLOBAL: config,
    GIT_CONFIG_NOSYSTEM: "1",
  };
  const drive = windows ? /^[a-z]:/iu.exec(operator)?.[0] : undefined;
  const auth = (i: number) => at(`auth ${i}.txt`);
  const inputs = new Map<string, string>();
  const writeInput = (path: string, contents: string) =>
    writeFile(path, contents, { mode: 0o600, flag: "wx" });
  const createInput = async (
    file: string,
    contents = `synthetic auth input ${inputs.size}\n`,
  ) => {
    const path = resolve(operator, file);
    await mkdir(dirname(path), { recursive: true });
    await writeInput(path, contents);
    inputs.set(path, contents);
  };
  const replaceInput = async (path: string, replacement: string) => {
    await writeInput(replacement, inputs.get(path)!);
    await rename(replacement, path);
  };
  const loginCache = at(environment.LOGIN_CACHE_NAME);
  for (const dir of [
    at(".ssh"),
    at(".config/gh"),
    pointers.DOCKER_CONFIG,
    join(xdg, "git"),
  ])
    await mkdir(dir, { recursive: true });
  const glabRoots = [".config", xdg, "xdg-extra"];
  if (windows || mac) glabRoots.push(platformConfig);
  const data = environment.XDG_DATA_HOME;
  const existing = [
    [auth(0), auth(1), ".netrc"],
    ["signing identity", "signing identity.pub"],
    ["proxy key.pem", "origin identity.pem"],
    ".pypirc",
    files(".anaconda", "keyring", "config.toml"),
    ".mamba/auth/authentication.json",
    ".rattler/credentials.json",
    ".config/rclone/rclone.conf",
    ".continuum/anaconda-client/tokens/example.token",
    join(pointers.BINSTAR_CONFIG_DIR, "data/example.token"),
    loginCache + ".keyring",
    pointers.RATTLER_AUTH_FILE,
    ".gnupg/private-keys-v1.d/default.key",
    join(pointers.GNUPGHOME, "private-keys-v1.d/selected.key"),
    windows ? [join(appdata, "gnupg/private-keys-v1.d/roaming.key")] : [],
    pointers.PIP_CONFIG_FILE,
    files(".gcm", "store/service/account", "msal.cache", "msal/app.cache"),
    ".local/.IdentityService/msal.cache",
    "configured store/service/account",
    join(pointers.GCM_PLAINTEXT_STORE_PATH, "service/account"),
    join(loginCache, "session.json"),
    join(azure, "msal_token_cache.json"),
    files(cloudConfig, "credentials.db", "credentials.db-wal"),
    join(cloudConfig, "legacy_credentials/fixture/.boto"),
    "selected.config.toml",
    files(terraformDir, "registry.tfrc", "workspace.tfrc.json"),
  ].flat();
  for (const file of existing) await createInput(file);

  const lateFiles = [
    [auth(2), auth(3), ...(drive ? [auth(4), auth(5)] : [])],
    ["after-capture.config.toml", "codex-home/after-capture.config.toml"],
    ...[".codex", ".", "codex-home"].map((home) =>
      files(home, "auth.json", ".credentials.json", "config.toml"),
    ),
    "_netrc",
    ["scoped proxy key.pem", "proxy identity.pem"],
    selectedNetrc,
    files(awsDirectory, "config", "credentials"),
    ["cli", "sso", "login"].map((client) =>
      join(awsDirectory, client, "cache/session.json"),
    ),
    join(loginCache, "new session.json"),
    files(".azure", "msal_token_cache.json", "service_principal_entries.json"),
    files(azure, "accessTokens.json", "msal_token_cache.bin"),
    join(azure, "service_principal_entries.json"),
    join(azure, "service_principal_entries.bin"),
    [environment.AWS_CONFIG_FILE, environment.AWS_SHARED_CREDENTIALS_FILE],
    [...clusterFiles, policyCluster],
    join(pointers.DOCKER_CONFIG, "config.json"),
    ".docker/key.pem",
    join(pointers.DOCKER_CERT_PATH, "key.pem"),
    ghFiles(".config/gh"),
    ghFiles(join(xdg, "gh")),
    windows ? ghFiles(join(appdata, "GitHub CLI")) : [],
    [pointers.PGPASSFILE, pointers.PGSERVICEFILE],
    [pointers.PGSSLKEY, pointers.PGSSLCERT],
    [pointers.TF_CLI_CONFIG_FILE, pointers.TERRAFORM_CONFIG],
    windows ? join(appdata, "terraform.rc") : ".terraformrc",
    join(terraformDir, "credentials.tfrc.json"),
    files(pgTlsDir, "postgresql.key", "postgresql.crt"),
    "pg_service.conf",
    windows
      ? files(pgTlsDir, ".pg_service.conf", "pgpass.conf")
      : [".pg_service.conf", ".pgpass"],
    join(pointers.GLAB_CONFIG_DIR, "config.yml"),
    glabRoots.map((dir) => join(dir, "glab-cli/config.yml")),
    Object.values(selectedFiles),
    "pip client.pem",
    "selected boto.cfg",
    files(xdg, join("pip", pipConfig), "sops/age/keys.txt"),
    join(platformConfig, "sops/age/keys.txt"),
    join(environment.VIRTUAL_ENV, pipConfig),
    join(windows ? "pip" : ".pip", pipConfig),
    pointers.GOOGLE_APPLICATION_CREDENTIALS,
    join(cloudConfig, cloudDefault),
    files(cloudConfig, "access_tokens.db", "access_tokens.db-journal"),
    files(".config/gcloud", "credentials.db", cloudDefault),
    windows
      ? files(join(appdata, "gcloud"), cloudDefault, "access_tokens.db")
      : [],
    ".ssh/id_rsa",
    ".dockercfg",
    ".cargo/credentials",
    join(environment.CARGO_HOME, "credentials.toml"),
    join(pointers.POETRY_CONFIG_DIR, "auth.toml"),
    join(pointers.UV_CREDENTIALS_DIR, "credentials.toml"),
    join(xdg, "pypoetry/auth.toml"),
    join(data, "uv/credentials/credentials.toml"),
    join(data, "python_keyring/keyring_pass.cfg"),
    ".rye/credentials",
    join(environment.RYE_HOME, "credentials"),
    ".rclone.conf",
    join(xdg, "rclone/rclone.conf"),
    windows ? [join(appdata, "rclone/rclone.conf")] : [],
    [".devpi/client/auth.json", "selected devpi/auth.json"],
    files(platformConfig, "pypoetry/auth.toml", "pypoetry/config.toml"),
    join(platformConfig, "uv/uv.toml"),
    join(pythonLocal, "hatch/config.toml"),
    join(pythonLocal, windows ? "pdm/pdm/config.toml" : "pdm/config.toml"),
    windows ? [join(appdata, "uv/data/credentials/credentials.toml")] : [],
    ".gradle/gradle.properties",
    join(environment.GRADLE_USER_HOME, "gradle.properties"),
    files(
      ".m2",
      "settings.xml",
      "settings-security.xml",
      "settings-security4.xml",
    ),
    join(environment.MAVEN_HOME, "conf/settings.xml"),
    ".bundle/config",
    join(environment.BUNDLE_USER_HOME, "config"),
    [".gem/credentials", ".local/share/gem/credentials"],
    join(data, "gem/credentials"),
    join(data, "MicrosoftCredentialProvider/SessionTokenCache.dat"),
    ".nuget/NuGet/NuGet.Config",
    join(environment.DOTNET_CLI_HOME, ".nuget/NuGet/NuGet.Config"),
    join(environment.HELM_CONFIG_HOME, "registry/config.json"),
    join(environment.XDG_RUNTIME_DIR, "containers/auth.json"),
    ...[".config", xdg].map((dir) =>
      files(
        dir,
        "gem/gemrc",
        "NuGet/NuGet.Config",
        "helm/repositories.yaml",
        "containers/auth.json",
      ),
    ),
    ".docker/config.json",
    ".kube/config",
    [".npmrc", "selected prefix/etc/npmrc"],
    [".yarnrc", ".yarnrc.yml", environment.YARN_RC_FILENAME],
    files(xdg, ".bunfig.toml", "pnpm/auth.ini"),
    files(".config/pnpm", "rc", "config.yaml"),
    [".composer/auth.json", "selected composer/auth.json"],
    join(xdg, "composer/config.json"),
    [pointers.NPM_CONFIG_USERCONFIG, "selected global npmrc"],
  ].flat();
  const siblings = new Map<string, string>();
  const createSibling = async (path: string, contents: string) => {
    await writeFile(path, contents);
    siblings.set(path, contents);
  };
  await createSibling(join(azure, "config"), "Azure settings");
  await createSibling(at(".config/rclone/ordinary.txt"), "rclone sibling");
  await createSibling(
    join(pointers.DOCKER_CONFIG, "ordinary-sibling.txt"),
    "ordinary sibling",
  );
  const program = "auth-filter.cjs";
  await resolvePatchProfile(
    false,
    false,
    false,
    async (context, inspectModel) => {
      // An operator may have no AWS profile directory when the first model tool runs.
      expect(await inspectModel('process.stdout.write("ready")')).toBe("ready");
      await mkdir(awsDirectory);
      await createSibling(
        join(terraformDir, "ordinary.txt"),
        "Terraform sibling",
      );
      await createSibling(join(awsDirectory, "ordinary.txt"), "AWS sibling");
      // These files change after profile selection and before the two commands launch.
      const repo = context.repository;
      for (const file of lateFiles) await createInput(file);
      const selectedGhFiles = ghFiles(join(repo, gh));
      for (const file of selectedGhFiles)
        await createInput(file, `synthetic selected gh input ${inputs.size}\n`);
      await createInput(
        join(repo, ".git/glab-cli/config.yml"),
        "synthetic local glab login\n",
      );
      await replaceInput(at(".netrc"), at("new-netrc"));
      const relativePaths = [...inputs.keys()].map((path) =>
        relative(operator, path),
      );
      const readFiles = `const fs = require("node:fs");
for (const [path, expected] of ${JSON.stringify([...siblings])}) {
  if (fs.readFileSync(path, "utf8") !== expected) throw new Error("Cannot read ordinary file " + path);
}
const contents = [];
const { resolve } = require("node:path");
for (const file of ${JSON.stringify(relativePaths)}) {
  const path = resolve(${JSON.stringify(operator)}, file);
  try { contents.push(fs.readFileSync(path, "utf8")); }
  catch (error) { if (!["EACCES", "EPERM", "ENOENT"].includes(error.code)) throw error; }
}`;
      const input = "INTENDED PATCH BYTES\n";
      await writeFile(join(repo, "candidate.txt"), input);
      await writeFile(
        join(repo, ".gitattributes"),
        "candidate.txt filter=auth-file\n",
      );
      await writeFile(
        join(repo, program),
        readFiles +
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
        "from host\n" +
          [...inputs.values()].join("") +
          Object.keys(pointers).join(""),
      );
      const modelRead =
        readFiles + "\nprocess.stdout.write(JSON.stringify(contents));";
      const probeWrites = `
fs.writeFileSync(${JSON.stringify(join(repo, "write-control"))}, "writable");
for (const path of ${JSON.stringify(selectedGhFiles)}) {
  try { fs.writeFileSync(path, "changed"); }
  catch (error) { if (!["EACCES", "EPERM", "EROFS", "ENOENT"].includes(error.code)) throw error; }
}`;
      expect(await inspectModel(modelRead + probeWrites)).toBe("[]");
      for (const path of selectedGhFiles)
        expect(await readFile(path, "utf8")).toBe(inputs.get(path)!);
      if (patchSnapshotWindowsConfig().includes('"elevated"'))
        console.info(
          "Windows model denied selected authentication files before snapshot",
          inputs.size,
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
      await replaceInput(
        join(awsDirectory, "credentials"),
        join(awsDirectory, "replacement"),
      );
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
      await mkdir(join(repository, gh));
      await mkdir(literalTilde);
      environment.NETRC = relative(repository, selectedNetrc);
      const relativePath = (file: string, dir = repository) =>
        relative(dir, file).replaceAll("\\", "/");
      const scopedCookie = relativePath(auth(2));
      expect(scopedCookie.startsWith("../")).toBe(true);
      const settings = {
        "http.cookieFile": auth(0),
        "http.sslKey": "~/auth 1.txt",
        "http.https://scoped.example.invalid/.cookieFile": scopedCookie,
        "http.https://scoped.example.invalid/.sslKey": auth(3),
        ...(drive && {
          "http.https://drive.example.invalid/.cookieFile":
            drive + relative(repository, auth(4)),
          "http.https://root.example.invalid/.sslKey": auth(5).slice(
            drive.length,
          ),
        }),
        "gpg.format": "ssh",
        "user.signingKey": "~/signing identity.pub",
        "credential.plaintextStorePath": at("configured store"),
        "http.sslCert": "~/origin identity.pem",
        "http.https://proxy.example.invalid/.proxySSLCert":
          "~/" + relativePath(at("proxy identity.pem"), literalTilde),
        "http.proxySSLKey": at("proxy key.pem"),
        "http.https://proxy.example.invalid/.proxySSLKey": relativePath(
          at("scoped proxy key.pem"),
        ),
      };
      if (drive)
        expect(repository.slice(0, 2).toUpperCase()).toBe(drive.toUpperCase());
      for (const [setting, value] of Object.entries(settings))
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
}, 180_000);

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
