import { expect, test } from "bun:test";
import { execFileSync, spawn } from "node:child_process";
import { writeFile, mkdir, readFile, rename } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  PATCH_GIT_ENVIRONMENT_RUNNER as runner,
  runRepositoryCommand,
} from "../src/cli.js";
import {
  patchSnapshotEnvironment,
  patchSnapshotWindowsConfig,
} from "./support/patch-snapshot-environment.js";
import {
  runGitRepositoryCommand,
  patchDirectories,
  runIssuePatch,
} from "./cli-patch-fixtures.js";

const fixtures = patchDirectories();

function bindingFrame(environment: Record<string, string> = {}): Buffer {
  return Buffer.from(JSON.stringify({ bindings: Object.entries(environment) }));
}

const nativeGrants = ["C:/synthetic/repository", "C:/synthetic/repository/*"];
const cases = [
  { name: "wildcard reset", caller: ["*", ""], active: [] },
  {
    name: "named reset with a later grant",
    caller: ["C:/cleared", "", "C:/retained"],
    active: ["C:/retained"],
  },
  {
    name: "repeated resets",
    caller: ["*", "", "C:/cleared", "", "C:/retained"],
    active: ["C:/retained"],
  },
  {
    name: "case-insensitive reset key",
    caller: ["*", ""],
    active: [],
    resetKey: "SAFE.Directory",
  },
  {
    name: "caller grant without a reset",
    caller: ["C:/retained"],
    active: ["C:/retained"],
  },
];

for (const platform of ["win32", "linux"] as const) {
  for (const { name, caller, active, resetKey } of cases) {
    test(`constructs snapshot Git arguments with ${name} on ${platform}`, () => {
      const entries = caller.map((value) => [
        value === "" ? (resetKey ?? "safe.directory") : "safe.directory",
        value,
      ]);
      entries.push(["filter.synthetic.clean", "synthetic-clean-filter"]);
      const environment = (values: string[][]) => ({
        GIT_CONFIG_COUNT: String(values.length),
        ...Object.fromEntries(
          values.flatMap(([key, value], index) => [
            [`GIT_CONFIG_KEY_${index}`, key],
            [`GIT_CONFIG_VALUE_${index}`, value],
          ]),
        ),
      });
      const original = environment(entries);
      const filtered = environment([
        ...entries,
        ...nativeGrants.map((value) => ["safe.directory", value]),
      ]);
      const header = bindingFrame(original);
      const input = Buffer.from([0, 255, 10, 13]);
      const frame = Buffer.concat([header, input]);
      let consumed = 0;
      const invocations: {
        command: string;
        args: string[];
        environment: object;
      }[] = [];
      const child = { on() {} };
      const process = {
        platform,
        argv: [
          "node",
          String(header.length),
          "git",
          "-C",
          "C:/synthetic/repository",
          "status",
        ],
        env: filtered,
      };
      // Exercise the exact argument construction without starting a child.
      new Function("require", "process", "Buffer", runner)(
        (module: string) => {
          if (module === "node:fs")
            return {
              readSync(
                fd: number,
                buffer: Buffer,
                offset: number,
                length: number,
              ) {
                expect(fd).toBe(0);
                const bytes = Math.min(length, 7, frame.length - consumed);
                frame.copy(buffer, offset, consumed, consumed + bytes);
                consumed += bytes;
                return bytes;
              },
            };
          expect(module).toBe("node:child_process");
          return {
            spawn(command: string, args: string[], options: object) {
              expect(options).toEqual({ stdio: "inherit" });
              invocations.push({
                command,
                args,
                environment: { ...process.env },
              });
              return child;
            },
          };
        },
        process,
        Buffer,
      );
      expect(invocations).toHaveLength(1);
      expect(invocations[0]!.command).toBe("git");
      expect(invocations[0]!.args).toEqual([
        ...(platform === "win32"
          ? [...active, ...nativeGrants].flatMap((value) => [
              "-c",
              `safe.directory=${value}`,
            ])
          : []),
        "-C",
        "C:/synthetic/repository",
        "status",
      ]);
      expect(invocations[0]!.environment).toMatchObject(original);
      expect(frame.subarray(consumed)).toEqual(input);
    });
  }
}

test("snapshot Git keeps credentials out of checkout-filtered blobs and preserves ordinary settings", async () => {
  const cwd = await fixtures.create("patch-snapshot-credentials-");
  const credentials = {
    DOCKER_AUTH_CONFIG: JSON.stringify({
      auths: {
        "registry.example.test": { auth: "synthetic-registry-credential" },
      },
    }),
    DATABASE_URL: "postgresql://fixture:synthetic@db.example.test/fixture",
    MONGODB_URI: "mongodb+srv://fixture:synthetic@db.example.test/fixture",
    REDIS_URI: "redis://:synthetic@cache.example.test",
    MYSQL_PWD: "synthetic-database-password",
    AWS_BEARER_TOKEN_BEDROCK: "synthetic-service-token",
    TF_TOKEN_registry_example_test: "synthetic-terraform-token",
    PIP_INDEX_URL: "https://fixture:synthetic@packages.example.test/simple",
    pip_extra_index_url:
      "https://public.example.test/simple https://synthetic@packages.example.test/simple",
    UV_INDEX: "private=https://synthetic@packages.example.test/simple",
    HTTP_PROXY: "http://fixture:synthetic@proxy.example.test:8080",
    https_proxy: "https://fixture:synthetic@proxy.example.test",
  };
  const env = {
    ...Object.fromEntries(
      Object.entries(process.env).filter(
        ([key]) => !/^(?:https?|all)_proxy$/iu.test(key),
      ),
    ),
    ...credentials,
    TF_VAR_workspace: "example",
    SNAPSHOT_USER_SETTING: "ssh://git@repository.example.test/project",
    PIP_FIND_LINKS: "https://packages.example.test/archives/user@release",
    ALL_PROXY: "socks5://proxy.example.test:1080#note@proxy.example.test",
  };
  const git = (...args: string[]) =>
    execFileSync("git", args, { cwd, env, encoding: "utf8" });
  git("init", "--quiet");
  await writeFile(
    join(cwd, ".gitattributes"),
    "candidate.txt filter=inspect\n",
  );
  await writeFile(join(cwd, "candidate.txt"), "safe patch\n");
  await writeFile(
    join(cwd, "filter.cjs"),
    `const input = require("node:fs").readFileSync(0, "utf8");
process.stdout.write(JSON.stringify({
  input, setting: process.env.SNAPSHOT_USER_SETTING, proxy: process.env.ALL_PROXY,
  workspace: process.env.TF_VAR_workspace, links: process.env.PIP_FIND_LINKS,
  credentialKeys: ${JSON.stringify(Object.keys(credentials))}.filter(key => key in process.env),
}));`,
  );
  const add = [
    "-c",
    "filter.inspect.clean=node filter.cjs",
    "add",
    "--",
    "candidate.txt",
  ];
  const expected = {
    input: "safe patch\n",
    setting: env.SNAPSHOT_USER_SETTING,
    proxy: env.ALL_PROXY,
    workspace: env.TF_VAR_workspace,
    links: env.PIP_FIND_LINKS,
  };
  git(...add);
  expect(JSON.parse(git("show", ":candidate.txt"))).toEqual({
    ...expected,
    credentialKeys: Object.keys(credentials),
  });

  git("read-tree", "--empty");
  const header = bindingFrame();
  execFileSync(
    Bun.which("node")!,
    ["-e", runner, "--", String(header.length), "git", ...add],
    { cwd, env, input: header },
  );
  expect(JSON.parse(git("show", ":candidate.txt"))).toEqual({
    ...expected,
    credentialKeys: [],
  });
});

test("snapshot Git reports an incomplete binding frame before starting the command", async () => {
  const child = spawn(
    process.execPath,
    ["-e", runner, "--", "64", "synthetic-unreachable-command"],
    { stdio: "pipe" },
  );
  let stderr = "";
  let stdout = "";
  child.stderr.setEncoding("utf8").on("data", (chunk) => {
    stderr += chunk;
  });
  child.stdout.setEncoding("utf8").on("data", (chunk) => {
    stdout += chunk;
  });
  const closed = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
  child.stdin.end("[");
  expect(await closed).toEqual({ code: 1, signal: null });
  expect(stdout).toBe("");
  expect(stderr).toContain(
    "Snapshot Git bindings ended before the complete frame.",
  );
  expect(stderr).not.toContain("ENOENT");
});

test("snapshot Git launch failures retain diagnostics with a non-emitting stderr stream", async () => {
  const missingGit = join(await fixtures.create("patch-missing-git-"), "git");
  const results: {
    code: number | null;
    signal: string | null;
    stderr: string;
  }[] = [];
  const header = bindingFrame();
  for (const dummyStderr of [false, true]) {
    const prefix = dummyStderr
      ? 'Object.defineProperty(process,"stderr",{value:new (require("node:stream").Writable)({write(chunk,encoding,callback){callback();}})});'
      : "";
    const child = spawn(
      Bun.which("node")!,
      [
        "-e",
        prefix + runner,
        "--",
        String(header.length),
        missingGit,
        "status",
      ],
      { stdio: "pipe" },
    );
    let stderr = "";
    child.stderr.setEncoding("utf8").on("data", (chunk) => {
      stderr += chunk;
    });
    const closed = new Promise<{ code: number | null; signal: string | null }>(
      (resolve, reject) => {
        child.once("error", reject);
        child.once("close", (code, signal) => resolve({ code, signal }));
      },
    );
    child.stdin.end(header);
    results.push({ ...(await closed), stderr });
  }
  expect(results[0]).toMatchObject({ code: 1, signal: null });
  expect(results[0]!.stderr).toContain(`spawn ${missingGit} ENOENT`);
  expect(results[0]!.stderr).toContain("spawnargs: [ 'status' ]");
  expect(results[1]).toEqual(results[0]);
});

test("snapshot filters receive safe command config from both Git encodings", async () => {
  const cwd = await fixtures.create("snapshot-command-config-");
  const credentials = "synthetic-config-marker";
  const run = (command: string, args: string[], options = {}) =>
    execFileSync(command, args, { cwd, encoding: "utf8", ...options });
  run("git", ["init", "--quiet"]);
  await writeFile(join(cwd, ".gitattributes"), "*.txt filter=check\n");
  await writeFile(join(cwd, "note.txt"), "input\n");
  await writeFile(
    join(cwd, "check.cjs"),
    [
      'const raw = Object.values(process.env).join("\\n");',
      "process.stdout.write(JSON.stringify({",
      '  secret: raw.includes("synthetic-config-marker"),',
      '  input: require("node:fs").readFileSync(0, "utf8"),',
      "}));",
    ].join("\n"),
  );

  const env = {
    ...process.env,
    CODEX_HOME: await fixtures.create("snapshot-config-home-"),
    GIT_CONFIG_COUNT: "5",
    GIT_CONFIG_KEY_0: "demo.value",
    GIT_CONFIG_VALUE_0: "first",
    GIT_CONFIG_KEY_1: "http.extraHeader",
    GIT_CONFIG_VALUE_1: "Authorization: " + credentials,
    GIT_CONFIG_KEY_2: "http.proxy",
    GIT_CONFIG_VALUE_2: "https://proxy.example.test/?route=a@b",
    GIT_CONFIG_KEY_3: "http.proxySSLKey",
    GIT_CONFIG_VALUE_3: "proxy-" + credentials,
    GIT_CONFIG_KEY_4: "imap.pass",
    GIT_CONFIG_VALUE_4: credentials,
    GIT_CONFIG_VALUE_9: credentials,
  };
  const parameters = [
    "'sendemail.smtpPass'='" + credentials + "'",
    "'gitcvs.dbPass'='" + credentials + "'",
    "'receive.certNonceSeed'='" + credentials + "'",
    "'demo.value'='second with spaces'",
    "'demo.a=b.flag'=",
    "'demo.empty'=''",
    "'http.https://example.test/.proxySSLKey'='" + credentials + "'",
    "'demo.value'='third'\\''s'",
    "'remote.origin.proxy'='https:/user:" +
      credentials +
      "@proxy.example.test'",
    "'url.https://user:" + credentials + "@example.test/.insteadOf'='example:'",
  ].join(" ");
  await writeFile(
    join(env.CODEX_HOME, "config.toml"),
    patchSnapshotWindowsConfig() +
      `[shell_environment_policy.set]
GIT_CONFIG_PARAMETERS="'http.extraHeader'='Authorization: synthetic-config-marker'"
`,
  );
  const objects = await fixtures.create("snapshot-config-objects-");
  const filtered = await runRepositoryCommand(
    "git",
    [
      "-c",
      "filter.check.clean=git config --get-all demo.value && git config --type=bool demo.a=b.flag && git config demo.empty && git config http.proxy && node check.cjs",
      "hash-object",
      "-w",
      "--path=note.txt",
      "note.txt",
    ],
    cwd,
    {
      sandbox: {
        directory: cwd,
        environment: patchSnapshotEnvironment(
          await fixtures.create("snapshot-config-temp-"),
          env,
        ),
        gitEnvironment: {
          GIT_CONFIG_PARAMETERS: parameters,
          GIT_OBJECT_DIRECTORY: objects,
        },
        profile: {
          extends: ":workspace",
          network: { enabled: false },
          filesystem: { [objects]: { ".": "write" } },
        },
      },
    },
  );
  const blob = run("git", ["cat-file", "blob", filtered], {
    env: { ...process.env, GIT_OBJECT_DIRECTORY: objects },
  });
  const lines = blob.split("\n");
  expect(lines.slice(0, 6)).toEqual([
    "first",
    "second with spaces",
    "third's",
    "true",
    "",
    env.GIT_CONFIG_VALUE_2,
  ]);
  expect(JSON.parse(lines.slice(6).join("\n"))).toEqual({
    secret: false,
    input: "input\n",
  });
});

test.each(["GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY"] as const)(
  "patch probes nested placeholders independently of selected-root %s",
  async (setting) => {
    const root = await fixtures.create("patch-probe-environment-");
    const support = await fixtures.create("patch-probe-administration-");
    const globalConfig = join(support, "global-config");
    await writeFile(globalConfig, "");
    const environment = {
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: globalConfig,
      LC_ALL: "C",
    };
    const git = (args: string[], overrides: NodeJS.ProcessEnv = {}) =>
      execFileSync("git", args, {
        cwd: root,
        env: { ...process.env, ...environment, ...overrides },
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    git(["init", "--initial-branch=main"]);
    git(["config", "user.name", "Synthetic User"]);
    git(["config", "user.email", "synthetic@example.test"]);
    const marker = join(root, "source", ".git");
    await mkdir(marker, { recursive: true });
    const markerHead = "ref: refs/heads/main\n";
    await writeFile(join(marker, "HEAD"), markerHead);
    if (setting === "GIT_OBJECT_DIRECTORY") await mkdir(join(marker, "refs"));
    const source = join(root, "source", "app.ts");
    await writeFile(source, "before\n");
    git(["add", "source/app.ts"]);
    git(["commit", "-m", "Synthetic environment baseline"]);
    const head = git(["rev-parse", "HEAD"]);
    const index = await readFile(join(root, ".git", "index"));
    const selectedPath =
      setting === "GIT_COMMON_DIR"
        ? join(root, ".git")
        : join(support, "selected-objects");
    if (setting === "GIT_OBJECT_DIRECTORY") {
      await rename(join(root, ".git", "objects"), selectedPath);
    }
    const selectedEnvironment: NodeJS.ProcessEnv = {
      ...environment,
      [setting]: selectedPath,
    };
    if (setting === "GIT_OBJECT_DIRECTORY")
      expect(() => git(["rev-parse", "HEAD"])).toThrow();
    expect(git(["rev-parse", "HEAD"], selectedEnvironment)).toBe(head);
    expect(() => git(["rev-parse", "--resolve-git-dir", marker])).toThrow();
    expect(
      resolve(
        git(["rev-parse", "--resolve-git-dir", marker], selectedEnvironment),
      ),
    ).toBe(marker);

    let launches = 0;
    let rootCommands = 0;
    const outcome = await runIssuePatch(root, {
      environment: selectedEnvironment,
      onRepositoryCommand: (command, args, cwd, options) => {
        const effectiveEnvironment = {
          ...selectedEnvironment,
          ...options?.environment,
        };
        if (!args.includes("--resolve-git-dir") && !args.includes("-C")) {
          expect(effectiveEnvironment[setting]).toBe(selectedPath);
          rootCommands++;
        }
        return runGitRepositoryCommand(command, args, cwd, {
          ...options,
          environment: effectiveEnvironment,
        });
      },
      onCodex: async (_args, output) => {
        launches++;
        await writeFile(source, "after\n");
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });

    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(launches).toBe(1);
    expect(rootCommands).toBeGreaterThan(0);
    expect(await readFile(source, "utf8")).toBe("after\n");
    expect(await readFile(join(marker, "HEAD"), "utf8")).toBe(markerHead);
    expect(git(["rev-parse", "HEAD"], selectedEnvironment)).toBe(head);
    expect(await readFile(join(root, ".git", "index"))).toEqual(index);
  },
);

test("snapshot fixture children use private temporary directories without changing the parent", async () => {
  const shared = await fixtures.create("patch-shared-temp-");
  const directories = await Promise.all([
    fixtures.create("patch-private-temp-"),
    fixtures.create("patch-private-temp-"),
  ]);
  const environment = Object.freeze({
    ...process.env,
    Temp: shared,
    tMp: shared,
    TMPDIR: shared,
    SNAPSHOT_FIXTURE_VALUE: "preserved",
  });
  const parentTemporarySettings = ["TEMP", "TMP", "TMPDIR"].map(
    (name) => process.env[name],
  );
  for (const directory of directories) {
    const selected = patchSnapshotEnvironment(directory, environment);
    const child = JSON.parse(
      execFileSync(
        process.execPath,
        [
          "-e",
          'process.stdout.write(JSON.stringify({directory:require("node:os").tmpdir(),temp:process.env.TEMP,tmp:process.env.TMP,tmpdir:process.env.TMPDIR,value:process.env.SNAPSHOT_FIXTURE_VALUE}))',
        ],
        { env: selected, encoding: "utf8" },
      ),
    );
    expect(child).toEqual({
      directory,
      temp: directory,
      tmp: directory,
      tmpdir: directory,
      value: "preserved",
    });
    expect(selected).not.toHaveProperty("Temp");
    expect(selected).not.toHaveProperty("tMp");
  }
  expect(environment.Temp).toBe(shared);
  expect(environment.tMp).toBe(shared);
  expect(environment.TMPDIR).toBe(shared);
  expect(["TEMP", "TMP", "TMPDIR"].map((name) => process.env[name])).toEqual(
    parentTemporarySettings,
  );
});
