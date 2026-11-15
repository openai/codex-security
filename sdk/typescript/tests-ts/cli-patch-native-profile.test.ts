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
import { dirname, join, matchesGlob } from "node:path";
import { createInterface } from "node:readline";
import { PassThrough, Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { readSkillCommandOutput, runRepositoryCommand } from "../src/cli.js";
import { capturePatchGitControls } from "../src/patch-git-controls.js";
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
>;

interface PatchProfileContext {
  name: string;
  administration: string;
  filesystem: RpcMessage;
  modelProfile: RpcMessage;
  snapshotProfile: RpcMessage;
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
      [],
      {
        global: selectedConfig,
        system: undefined,
        noSystem: "1",
        xdgConfigHome: gitEnvironment.XDG_CONFIG_HOME,
        objectDirectory: undefined,
        alternateObjectDirectories: undefined,
      },
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
`,
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
    const storeDenies = Object.entries(snapshotProfile!["filesystem"]).filter(
      ([, access]) =>
        access === "deny" || (access as RpcMessage)["."] === "deny",
    );
    const stores = permissions.credentialStorePaths ?? [];
    expect(storeDenies).toHaveLength(stores.length);
    for (const store of stores) {
      expect(
        storeDenies.filter(([key, access]) =>
          access === "deny" ? matchesGlob(store, key) : key === store,
        ),
      ).toHaveLength(1);
    }
    const snapshotFilesystem = {
      ...Object.fromEntries(
        permissions.readOnlyPaths.map((path) => [path, { ".": "read" }]),
      ),
      ...Object.fromEntries(storeDenies),
      ...(configured ? { ":tmpdir": {}, ":slash_tmp": {} } : {}),
    };
    expect(snapshotProfile).toEqual({
      ...profiles[name],
      filesystem: snapshotFilesystem,
    });
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
        ].map((path) => [path, { ".": "read" }]),
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
      const reads = await inspectModel(
        `const fs = require("node:fs");
const { spawnSync } = require("node:child_process");
const paths = ${JSON.stringify([selected, included])};
for (const path of paths) {
  try { process.stdout.write(fs.readFileSync(path)); }
  catch (error) { process.stdout.write(error.code); }
}
const git = spawnSync("git", ["config", "--file", paths[0], "--get", "http.extraHeader"]);
if (git.stdout) process.stdout.write(git.stdout);`,
      );
      expect(reads).not.toContain("Synthetic fixture");
      expect(reads).not.toContain("Included fixture");
      const gitEnvironment = {
        GIT_CONFIG_GLOBAL: selected,
        GIT_CONFIG_NOSYSTEM: "1",
      };
      const environment = patchSnapshotEnvironment(context.temporaryDirectory, {
        ...process.env,
        CODEX_HOME: context.home,
        ...gitEnvironment,
      });
      expect(
        await runRepositoryCommand(
          "git",
          ["config", "--get", "synthetic.source"],
          context.repository,
          {
            sandbox: {
              directory: context.repository,
              environment,
              profile: context.snapshotProfile,
              gitEnvironment,
            },
          },
        ),
      ).toBe("Included fixture");
    },
  );
}, 30_000);

test("patch model and snapshot filters cannot recover credentials from Git stores", async () => {
  const gitHome = await fixtures.create("patch-store-home-");
  const configDirectory = join(gitHome, "settings");
  await mkdir(join(configDirectory, "git"), { recursive: true });
  const config = join(gitHome, "selected.gitconfig");
  const stores = [
    join(gitHome, ".git-credentials"),
    join(configDirectory, "git", "credentials"),
    join(gitHome, "selected.store"),
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
  await createStore(2);
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
        },
      });
      expect(actual).toBe(hash(protectedResult));
      expect(await inspectModel(probe)).toBe(protectedResult);
      expect(git(filtered, "synthetic input")).toBe(
        hash(JSON.stringify(Array(7).fill(true))),
      );
    },
    async (repository) => {
      // Collect the permissions the CLI passes to its native app-server.
      execFileSync(
        "git",
        [
          "config",
          "--local",
          "filter.snapshot-store.clean",
          "node " + probeFile,
        ],
        { cwd: repository },
      );
      execFileSync(
        "git",
        ["config", "--local", "filter.snapshot-store.required", "true"],
        { cwd: repository },
      );
      let selected: PatchPermissions | undefined;
      const stopped = "Captured synthetic patch permissions";
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: repository,
          environment: { ...process.env, ...environment },
          manualCodexPreparation: true,
          onRepositoryCommand: (cmd, args, cwd, options) =>
            runGitRepositoryCommand(cmd, args, cwd, {
              ...options,
              environment: { ...environment, ...options?.environment },
            }),
          onCodex: (_args, output) => {
            selected = output?.appServer?.permissions;
            throw new Error(stopped);
          },
        },
      );
      expect(outcome.stderr).toContain(stopped);
      expect(selected).toBeDefined();
      return selected!;
    },
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
