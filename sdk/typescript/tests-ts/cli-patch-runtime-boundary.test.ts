import { afterEach, expect, spyOn, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { runRepositoryCommand } from "../src/cli.js";
import * as runtime from "../src/runtime.js";
import * as executables from "../src/trusted-executable.js";
import { repositoryGit } from "./cli-patch-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

test("snapshot stderr observers retain diagnostics and buffering limits", async () => {
  const name =
    "snapshot stderr observers retain diagnostics and buffering limits";
  if (runTestInSubprocess(fileURLToPath(import.meta.url), name)) return;
  const root = await fixtures.create("patch-stderr-observer-");
  const home = join(root, "home");
  await mkdir(home);
  const native = join(root, "native.cjs");
  await writeFile(
    native,
    `process.stdin.resume();process.stdin.on("end",()=>{process.stderr.write("Synthetic native detail.\\n");process.stdout.write("ok");process.exitCode=process.argv.includes("fail")?17:0;});\n`,
  );
  const command = spyOn(runtime, "resolveCodexCommand").mockReturnValue({
    command: process.execPath,
    args: [native],
  });
  try {
    const observed: Buffer[] = [];
    const options = {
      sandbox: {
        directory: root,
        environment: { ...process.env, CODEX_HOME: home },
        profile: { extends: ":workspace", filesystem: {} },
      },
      onStderr(chunk: Buffer) {
        observed.push(chunk);
        throw new Error("Synthetic observer failure must not interrupt Git");
      },
    };
    expect(await runRepositoryCommand("git", [], root, options)).toBe("ok");
    expect(Buffer.concat(observed).toString()).toBe(
      "Synthetic native detail.\n",
    );
    await expect(
      runRepositoryCommand("git", ["fail"], root, options),
    ).rejects.toMatchObject({
      code: 17,
      stderr: "Synthetic native detail.\n",
    });
    await expect(
      runRepositoryCommand("git", [], root, { ...options, maxBuffer: 4 }),
    ).rejects.toMatchObject({
      code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER",
      stderr: "Synt",
    });
  } finally {
    command.mockRestore();
  }
});

test("snapshot bridge failures after stdin closes retain their diagnostics", async () => {
  const name =
    "snapshot bridge failures after stdin closes retain their diagnostics";
  if (runTestInSubprocess(fileURLToPath(import.meta.url), name)) return;
  const root = await fixtures.create("patch-bridge-failure-");
  const home = join(root, "home");
  await mkdir(home);
  const native = join(root, "native.cjs");
  await writeFile(
    native,
    `const {spawn}=require("node:child_process");
const args=process.argv.slice(process.argv.indexOf("--")+1);
args[args.indexOf("-e")+1]='require("node:fs").readFileSync(0); throw new Error("Synthetic snapshot bridge failure.");';
const child=spawn(args[0],args.slice(1),{stdio:"inherit"});
child.on("error",error=>{console.error(error);process.exitCode=1;});
child.on("exit",code=>process.exitCode=code??1);
`,
  );
  const command = spyOn(runtime, "resolveCodexCommand").mockReturnValue({
    command: Bun.which("node")!,
    args: [native],
  });
  try {
    await expect(
      runRepositoryCommand("git", [], root, {
        sandbox: {
          directory: root,
          environment: { ...process.env, CODEX_HOME: home },
          profile: { extends: ":workspace", filesystem: {} },
        },
      }),
    ).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining("Synthetic snapshot bridge failure."),
    });
  } finally {
    command.mockRestore();
  }
});

for (const configuration of [
  "unset",
  "empty",
  "populated",
  "invalid",
] as const) {
  for (const filtered of [false, true]) {
    const populated = configuration === "populated";
    const name = `snapshot Git child retains Windows ownership grants (caller tuples: ${configuration}, filtered: ${filtered})`;
    test(name, async () => {
      if (runTestInSubprocess(fileURLToPath(import.meta.url), name)) return;
      const root = await fixtures.create("patch-windows-git-");
      const repository = join(root, "repository");
      const callerRepository = join(root, "caller-repository");
      const deniedRepository = join(root, "other-repository");
      const home = join(root, "home");
      await Promise.all(
        [repository, callerRepository, deniedRepository, home].map((path) =>
          mkdir(path),
        ),
      );
      for (const path of [repository, callerRepository, deniedRepository])
        repositoryGit(path)("init", "--initial-branch=main");
      const repositoryToplevel = repositoryGit(repository)(
        "rev-parse",
        "--show-toplevel",
      );
      const callerToplevel = repositoryGit(callerRepository)(
        "rev-parse",
        "--show-toplevel",
      );
      const clean = join(root, "clean.cjs");
      await writeFile(
        clean,
        'const fs=require("node:fs");process.stdout.write(fs.readFileSync(0,"utf8").toUpperCase());\n',
      );
      const cleanCommand = `node ${JSON.stringify(clean.replaceAll("\\", "/"))}`;
      const git = repositoryGit(repository);
      git("config", "filter.snapshot.clean", cleanCommand);
      git("config", "core.autocrlf", "false");
      await writeFile(
        join(repository, ".gitattributes"),
        "data filter=snapshot\n",
      );
      const input = "Synthetic source\r\n";
      const expected = execFileSync("git", ["hash-object", "--stdin"], {
        cwd: repository,
        input: input.toUpperCase(),
        encoding: "utf8",
      }).trim();
      const gitEnvironment: NodeJS.ProcessEnv = {
        GIT_CONFIG_COUNT: populated
          ? "4"
          : configuration === "unset"
            ? undefined
            : configuration === "empty"
              ? ""
              : "invalid",
        GIT_CONFIG_GLOBAL: join(root, "empty.gitconfig"),
        GIT_CONFIG_NOSYSTEM: "1",
        ...(populated
          ? {
              GIT_CONFIG_KEY_0: "safe.directory",
              GIT_CONFIG_VALUE_0: "",
              GIT_CONFIG_KEY_1: "safe.directory",
              GIT_CONFIG_VALUE_1: callerRepository,
              GIT_CONFIG_KEY_2: "filter.snapshot.clean",
              GIT_CONFIG_VALUE_2: cleanCommand,
              GIT_CONFIG_KEY_3: "core.autocrlf",
              GIT_CONFIG_VALUE_3: "false",
            }
          : {}),
      };
      await writeFile(gitEnvironment["GIT_CONFIG_GLOBAL"]!, "");
      const environment: NodeJS.ProcessEnv = {
        ...process.env,
        CODEX_HOME: home,
      };
      for (const key of Object.keys(environment))
        if (/^GIT_/u.test(key)) delete environment[key];
      Object.assign(environment, gitEnvironment);
      const native = join(root, "native.cjs");
      // Replay the native Windows producer's appended grants after shell
      // filtering, then execute the real runner and Git child on this host.
      await writeFile(
        native,
        `const {spawn}=require("node:child_process");
const env={...process.env};
if(${filtered}) {
  for(const key of Object.keys(env)) if(/^GIT_CONFIG_/u.test(key)) delete env[key];
  Object.assign(env,{GIT_CONFIG_COUNT:"2",GIT_CONFIG_KEY_0:"filter.snapshot.clean",GIT_CONFIG_VALUE_0:"cat",GIT_CONFIG_KEY_1:"core.autocrlf",GIT_CONFIG_VALUE_1:"true"});
}
let count=Number(env.GIT_CONFIG_COUNT??0)||0;
for(const path of ${JSON.stringify([repositoryToplevel, `${repositoryToplevel}/*`])}) {
  env["GIT_CONFIG_KEY_"+count]="safe.directory";
  env["GIT_CONFIG_VALUE_"+count]=path;
  count++;
}
env.GIT_CONFIG_COUNT=String(count);
env.GIT_TEST_ASSUME_DIFFERENT_OWNER="1";
const args=process.argv.slice(process.argv.indexOf("--")+1);
args[0]=process.execPath;
const script=args.indexOf("-e")+1;
args[script]='Object.defineProperty(process,"platform",{value:"win32"});'+args[script];
const child=spawn(args[0],args.slice(1),{env,stdio:"inherit"});
child.on("error",error=>{console.error(error);process.exitCode=1;});
child.on("exit",code=>process.exitCode=code??1);
`,
      );
      const command = spyOn(runtime, "resolveCodexCommand").mockReturnValue({
        command: Bun.which("node")!,
        args: [native],
      });
      try {
        const sandbox = {
          environment,
          directory: repository,
          gitEnvironment,
          profile: { extends: ":workspace", filesystem: {} },
        };
        const run = (args: string[], cwd = repository, input?: string) =>
          runRepositoryCommand("git", args, cwd, { sandbox, input });
        if (configuration === "invalid") {
          await expect(
            run(["rev-parse", "--show-toplevel"]),
          ).rejects.toMatchObject({
            code: 128,
            stderr: expect.stringContaining("bogus count in GIT_CONFIG_COUNT"),
          });
          return;
        }
        expect(await run(["rev-parse", "--show-toplevel"])).toBe(
          repositoryToplevel,
        );
        expect(
          await run(
            ["hash-object", "--path=data", "--stdin"],
            repository,
            input,
          ),
        ).toBe(expected);
        expect(await run(["config", "--get", "core.autocrlf"])).toBe("false");
        const grants = (
          await run(["config", "--get-all", "safe.directory"])
        ).split("\n");
        expect(grants).toContain(repositoryToplevel);
        expect(grants).toContain(`${repositoryToplevel}/*`);
        if (populated) {
          expect(grants).toContain(callerRepository);
          expect(
            await run(["rev-parse", "--show-toplevel"], callerRepository),
          ).toBe(callerToplevel);
        }
        await expect(
          run(["rev-parse", "--show-toplevel"], deniedRepository),
        ).rejects.toMatchObject({ code: 128 });
      } finally {
        command.mockRestore();
      }
      expect(await readdir(home)).toEqual([]);
    });
  }
}

for (const denied of ["none", "home", "file"] as const) {
  const name = `snapshot provider credentials require private Windows storage (ACL denied: ${denied})`;
  test(name, async () => {
    if (runTestInSubprocess(fileURLToPath(import.meta.url), name)) return;
    const root = await fixtures.create("patch-private-snapshot-");
    const home = join(root, "home");
    await mkdir(home);
    const marker = join(root, "child-started");
    const native = join(root, "native.cjs");
    await writeFile(
      native,
      `const fs=require("node:fs"),path=require("node:path");
fs.writeFileSync(${JSON.stringify(marker)},"started");
const profile=process.argv[process.argv.indexOf("--profile")+1];
const text=fs.readFileSync(path.join(process.env.CODEX_HOME,profile+".config.toml"),"utf8");
process.stdin.resume();process.stdin.on("end",()=>process.stdout.write(JSON.stringify({text,args:process.argv.slice(2)})));
`,
    );
    const originalPlatform = Object.getOwnPropertyDescriptor(
      process,
      "platform",
    )!;
    let protectedHome = false;
    let protectedFile = false;
    let serialized = false;
    const guard = spyOn(
      runtime,
      "requirePrivateSnapshotProfileHome",
    ).mockImplementation(async (directory) => {
      expect(directory).toBe(home);
      expect(await readdir(home)).toEqual([]);
      expect(serialized).toBe(false);
      if (denied === "home") throw new Error("Synthetic home ACL denial");
      protectedHome = true;
    });
    const fileGuard = spyOn(
      runtime,
      "requirePrivateSnapshotProfileFile",
    ).mockImplementation(async (path) => {
      expect(protectedHome).toBe(true);
      expect(await readFile(path)).toHaveLength(0);
      expect(serialized).toBe(false);
      if (denied === "file") throw new Error("Synthetic file ACL denial");
      protectedFile = true;
    });
    const command = spyOn(runtime, "resolveCodexCommand").mockReturnValue({
      command: process.execPath,
      args: [native],
    });
    const trusted = spyOn(
      executables,
      "resolveTrustedExecutable",
    ).mockResolvedValue({
      executable: process.execPath,
      environment: { ...process.env },
    });
    const provider = {
      experimental_bearer_token: "synthetic-bearer",
      http_headers: { "X-Synthetic-Key": "synthetic-header" },
    };
    try {
      Object.defineProperty(process, "platform", { value: "win32" });
      const result = runRepositoryCommand("git", [], root, {
        sandbox: {
          directory: root,
          environment: { ...process.env, CODEX_HOME: home },
          profile: { extends: ":workspace", filesystem: {} },
          configuration: {
            model_providers: {
              get synthetic() {
                serialized = true;
                return provider;
              },
            },
          },
        },
      });
      if (denied !== "none") {
        await expect(result).rejects.toThrow(`Synthetic ${denied} ACL denial`);
        expect(serialized).toBe(false);
        await expect(readFile(marker)).rejects.toMatchObject({
          code: "ENOENT",
        });
      } else {
        const observed = JSON.parse(await result);
        expect(protectedHome).toBe(true);
        expect(protectedFile).toBe(true);
        expect(serialized).toBe(true);
        expect(observed.text).toContain("synthetic-bearer");
        expect(observed.text).toContain("synthetic-header");
        expect(JSON.stringify(observed.args)).not.toContain("synthetic-bearer");
        expect(JSON.stringify(observed.args)).not.toContain("synthetic-header");
      }
      expect(await readdir(home)).toEqual([]);
    } finally {
      Object.defineProperty(process, "platform", originalPlatform);
      trusted.mockRestore();
      command.mockRestore();
      guard.mockRestore();
      fileGuard.mockRestore();
    }
  });
}
