import { afterEach, expect, test } from "bun:test";
import { readdirSync, statSync } from "node:fs";
import {
  mkdir,
  readFile,
  readdir,
  symlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import type { JsonObject } from "../src/index.js";
import { runRepositoryCommand } from "../src/cli.js";
import {
  patchRiskAssessment,
  publicationRepository,
  runGitRepositoryCommand,
  repositoryGit,
  runWorkflow,
} from "./cli-patch-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  patchSnapshotEnvironment,
  patchSnapshotWindowsConfig,
} from "./support/patch-snapshot-environment.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

test.each([
  ["filter", "Authorization: Bearer synthetic-fixture", true],
  ["filter", "X-Routing-Tag: synthetic", false],
  ["no delegate", "Authorization: Bearer synthetic-fixture", false],
  ["disabled filter", "Authorization: Bearer synthetic-fixture", false],
  ["unused pre-push", "Authorization: Bearer synthetic-fixture", false],
  ["configured index hook", "Authorization: Bearer synthetic-fixture", true],
  ["resume hook", "Authorization: Bearer synthetic-fixture", true],
] as const)(
  "external Git configuration with %s and %s",
  async (delegate, header, blocked) => {
    const { directory, git } = await publicationRepository(fixtures);
    const host = await fixtures.create("patch-filter-host-config-");
    const config = join(host, "gitconfig");
    const included = join(host, "transport-config");
    await writeFile(config, "");
    // The model can change a filter's delegate, and a resumed hook can open an
    // inactive include directly even though Git did not apply it on this branch.
    const resume = delegate === "resume hook";
    git(
      "config",
      "--file",
      config,
      resume ? "includeIf.onbranch:unused.path" : "include.path",
      "transport-config",
    );
    git("config", "--file", included, "http.extraHeader", header);
    git(
      "config",
      "--file",
      included,
      "credential.helper",
      "!gh auth git-credential",
    );
    git("config", "--file", included, "core.sshCommand", "ssh");
    if (delegate.endsWith("filter")) {
      git("config", "--file", config, "filter.synthetic.clean", "cat");
      if (delegate === "disabled filter")
        git("config", "filter.synthetic.clean", "");
    }
    const head = git("rev-parse", "HEAD");
    const branch = "codex-security/saved-filter";
    if (delegate === "configured index hook") {
      git("config", "hook.synthetic.event", "post-index-change");
      git(
        "config",
        "hook.synthetic.command",
        "echo ran > .git/synthetic-index-hook",
      );
    }
    if (resume) {
      git("branch", branch);
      git("config", `branch.${branch}.codexSecurityPatchCommit`, head);
    }
    if (resume || delegate === "unused pre-push") {
      await writeFile(
        join(directory, ".git", "hooks", "pre-push"),
        "#!/bin/sh\nexit 1\n",
        { mode: 0o755 },
      );
    }
    const environment = { GIT_CONFIG_GLOBAL: config, GIT_CONFIG_NOSYSTEM: "1" };
    let model = false;
    let indexHookDisabled = false;
    const outcome = await runWorkflow(
      resume
        ? ["patch", "--resume-pr", branch, "--json"]
        : ["patch", "Synthetic issue", "--json"],
      {
        currentDirectory: directory,
        environment,
        manualCodexPreparation: true,
        onRepositoryCommand: (command, args, cwd, options) => {
          if (command !== "git") throw new Error("Unexpected hosting command");
          if (
            args.includes("read-tree") &&
            delegate === "configured index hook"
          ) {
            expect(args).toContain("hook.synthetic.enabled=false");
            indexHookDisabled = true;
          }
          return runGitRepositoryCommand(command, args, cwd, {
            ...options,
            environment: { ...environment, ...options?.environment },
          });
        },
        onCodex: () => {
          model = true;
          throw new Error("Reached synthetic model");
        },
      },
    );
    expect(outcome.stderr).toContain(
      blocked ? "inline authentication" : "Reached synthetic model",
    );
    expect(model).toBe(!blocked);
    if (delegate === "configured index hook") {
      expect(indexHookDisabled).toBe(true);
      await expect(
        readFile(join(directory, ".git", "synthetic-index-hook")),
      ).rejects.toMatchObject({ code: "ENOENT" });
    }
    expect(git("rev-parse", "HEAD")).toBe(head);
  },
);

// The callback substitutes for the model; bookkeeping uses the real native sandbox.
for (const fixture of [
  { grantOutside: false, subdirectory: false, externalSandbox: false },
  { grantOutside: true, subdirectory: false, externalSandbox: false },
  { grantOutside: false, subdirectory: true, externalSandbox: false },
  { grantOutside: false, subdirectory: false, externalSandbox: true },
]) {
  const { grantOutside, subdirectory, externalSandbox } = fixture;
  test(
    `snapshot filters retain native workspace grants: ${JSON.stringify(fixture)}`,
    async () => {
      const root = await fixtures.create("patch-filter-sandbox-");
      const repository = join(root, "repository");
      const directory = subdirectory ? join(repository, "area") : repository;
      const nested = join(directory, "child");
      const outside = join(subdirectory ? repository : root, "outside");
      const home = join(root, "home");
      await Promise.all([
        mkdir(nested, { recursive: true }),
        mkdir(outside, { recursive: true }),
        mkdir(home),
      ]);
      const witness = join(outside, "witness.txt");
      const filter = join(nested, "clean.cjs");
      const configuration = patchSnapshotWindowsConfig();
      await writeFile(join(home, "config.toml"), configuration);
      const environment = patchSnapshotEnvironment(
        await fixtures.create("patch-filter-temp-"),
        { ...process.env, CODEX_HOME: home },
      );
      const script = (changed: boolean) => `const fs = require("node:fs");
${changed ? `try { fs.writeFileSync(${JSON.stringify(witness)}, "model-changed"); } catch (error) { if (error.code !== "EACCES" && error.code !== "EPERM" && error.code !== "EROFS") throw error; }` : ""}
process.stdout.write(fs.readFileSync(0, "utf8").toUpperCase());\n`;
      const initialize = async (directory: string) => {
        const git = repositoryGit(directory);
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        return git;
      };
      const inner = await initialize(nested);
      await writeFile(filter, script(false));
      await writeFile(
        join(nested, ".gitattributes"),
        "data filter=synthetic\n",
      );
      await writeFile(join(nested, "data"), "original\n");
      inner(
        "config",
        "filter.synthetic.clean",
        `node ${JSON.stringify(filter.replaceAll("\\", "/"))}`,
      );
      inner("config", "filter.synthetic.required", "true");
      inner("config", "core.trustctime", "false");
      await utimes(join(nested, "data"), 1_000_000_000, 1_000_000_000);
      inner("add", ".");
      inner("commit", "-m", "Synthetic child baseline");
      const git = await initialize(repository);
      await writeFile(join(repository, "app.ts"), "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic parent baseline");
      const indexBefore = await readFile(join(nested, ".git", "index"));
      let assessments = 0;
      let snapshots = 0;
      const outcome = await runWorkflow(
        [
          "patch",
          "Synthetic issue",
          "--assess-patch-risk",
          ...(externalSandbox ? ["--external-sandbox"] : []),
          "--json",
        ],
        {
          currentDirectory: directory,
          environment,
          onRepositoryCommand(command, args, cwd, options) {
            if (options?.sandbox !== undefined) {
              snapshots++;
              expect(options.sandbox.directory).toBe(directory);
              expect(options.sandbox.profile["network"]).toEqual({
                enabled: false,
              });
              expect(options.sandbox.profile["workspace_roots"]).toEqual(
                grantOutside ? { [outside]: true } : {},
              );
              expect(
                (options.sandbox.profile["filesystem"] as JsonObject)[
                  join(nested, ".git")
                ],
              ).toEqual({ ".": "read" });
            }
            return runRepositoryCommand(command, args, cwd, {
              ...options,
              environment: { ...environment, ...options?.environment },
            });
          },
          manualCodexPreparation: true,
          onCodex: async (_args, output) => {
            if (
              output?.appServer?.prompt.includes("immutable patch artifact")
            ) {
              assessments++;
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              );
              const patch = await readFile(artifact.path, "utf8");
              expect(patch).toContain("+FIXED");
              expect(patch).toContain("-ORIGINAL");
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            if (!externalSandbox)
              output!.appServer!.onPermissions!({
                directory,
                environment,
                snapshotStoragePaths: output!.appServer!.snapshotStoragePaths,
                profile: {
                  extends: ":workspace",
                  network: { enabled: false },
                  workspace_roots: grantOutside ? { [outside]: true } : {},
                  filesystem: {
                    ...Object.fromEntries(
                      output!.appServer!.permissions!.readOnlyPaths.map(
                        (path) => [path, { ".": "read" }],
                      ),
                    ),
                    ":tmpdir": {},
                    ":slash_tmp": {},
                  },
                },
              });
            await output!.appServer!.onBeforeTurn?.();
            await writeFile(filter, script(true));
            await writeFile(join(nested, "data"), "fixed\n");
            output!.stdout.write("Synthetic patch complete.\n");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(assessments).toBe(1);
      expect(snapshots > 0).toBe(!externalSandbox);
      expect(await readFile(witness, "utf8").catch(() => undefined)).toBe(
        grantOutside || externalSandbox ? "model-changed" : undefined,
      );
      expect(await readFile(join(nested, ".git", "index"))).toEqual(
        indexBefore,
      );
    },
    // Native Windows snapshots repeat account and ACL setup for each Git command.
    process.platform === "win32" && !externalSandbox ? 240_000 : 30_000,
  );
}

for (const linkedHome of [false, true]) {
  test(`snapshot profile files support large metadata and clean up concurrent successes and failures${linkedHome ? " through a directory junction" : ""}`, async () => {
    const root = await fixtures.create("patch-filter-profile-");
    const repository = join(root, "repository");
    const physicalHome = join(root, "home");
    const home = linkedHome ? join(root, "selected-home") : physicalHome;
    await Promise.all([mkdir(repository), mkdir(physicalHome)]);
    if (linkedHome) await symlink(physicalHome, home, "junction");
    repositoryGit(repository)("init", "--initial-branch=main");
    const config = `${patchSnapshotWindowsConfig()}[shell_environment_policy.set]\nSNAPSHOT_FIXTURE_SETTING = "inherited"\n`;
    const auth =
      '{"auth_mode":"api_key","OPENAI_API_KEY":"sk-synthetic-local-only"}\n';
    await writeFile(join(home, "config.toml"), config);
    await writeFile(join(home, "auth.json"), auth);
    await writeFile(
      join(home, "existing.config.toml"),
      "# Synthetic existing profile.\n",
    );
    const protectedFile = join(
      repository,
      process.platform === "win32" ? "literal.path" : 'literal."\\path',
    );
    await writeFile(protectedFile, "unchanged");
    const filesystem = { [protectedFile]: { ".": "read" } };
    const script = join(root, "inspect.cjs");
    await writeFile(
      script,
      `const fs = require("node:fs");
let denied = false;
try { fs.writeFileSync(${JSON.stringify(protectedFile)}, "changed"); } catch (error) { if (!["EACCES", "EPERM", "EROFS"].includes(error.code)) throw error; denied = true; }
fs.writeSync(1, JSON.stringify({ denied, inherited: process.env.SNAPSHOT_FIXTURE_SETTING }));
if (process.argv[2] === "fail") { fs.writeSync(2, "Synthetic snapshot failure detail.\\n"); process.exitCode = 7; }
`,
    );
    const sandbox = {
      directory: repository,
      environment: patchSnapshotEnvironment(
        await fixtures.create("patch-profile-temp-"),
        { ...process.env, CODEX_HOME: home },
      ),
      profile: {
        extends: ":workspace",
        description: "Synthetic profile metadata. ".repeat(6000),
        network: { enabled: false },
        workspace_roots: {},
        filesystem,
      },
    };
    const run = async (fail: boolean) => {
      const output: Buffer[] = [];
      let stderr = "";
      const profiles: { name: string; mode: number; bytes: number }[] = [];
      await runRepositoryCommand(
        "git",
        [
          "-c",
          `alias.inspect=!node ${JSON.stringify(script.replaceAll("\\", "/"))}`,
          "inspect",
          ...(fail ? ["fail"] : []),
        ],
        repository,
        {
          sandbox,
          onStderr(chunk) {
            stderr += chunk.toString();
          },
          onStdout(chunk) {
            output.push(chunk);
            // The parent owns the private home; inspect profiles before cleanup.
            for (const name of readdirSync(home)) {
              if (!/^codex_security_snapshot_.*\.config\.toml$/.test(name))
                continue;
              try {
                const metadata = statSync(join(home, name));
                profiles.push({
                  name,
                  mode: metadata.mode & 0o777,
                  bytes: metadata.size,
                });
              } catch (error) {
                if ((error as NodeJS.ErrnoException).code !== "ENOENT")
                  throw error;
              }
            }
          },
        },
      );
      return {
        stdout: Buffer.concat(output).toString("utf8"),
        stderr,
        profiles,
      };
    };
    // Native Windows account setup is separate from concurrent profile lifecycle.
    if (process.platform === "win32") await run(false);
    const outcomes = await Promise.allSettled([run(false), run(false)]);
    const results = outcomes.map((outcome) => {
      if (outcome.status === "rejected") throw outcome.reason;
      return outcome.value;
    });
    const names = new Set<string>();
    for (const result of results) {
      expect(result.stdout, result.stderr).not.toBe("");
      const inspected = JSON.parse(result.stdout);
      expect(inspected.denied).toBe(true);
      expect(inspected.inherited).toBe("inherited");
      expect(result.profiles.length).toBeGreaterThan(0);
      for (const profile of result.profiles) {
        names.add(profile.name);
        expect(profile.bytes).toBeGreaterThan(128 * 1024);
        if (process.platform !== "win32") expect(profile.mode).toBe(0o600);
      }
    }
    expect(names.size).toBeGreaterThanOrEqual(2);
    await expect(run(true)).rejects.toThrow(
      "Synthetic snapshot failure detail.",
    );
    expect(
      (await readdir(home)).filter((name) =>
        name.startsWith("codex_security_snapshot_"),
      ),
    ).toEqual([]);
    expect(await readFile(join(home, "config.toml"), "utf8")).toBe(config);
    expect(await readFile(join(home, "auth.json"), "utf8")).toBe(auth);
    expect(await readFile(join(home, "existing.config.toml"), "utf8")).toBe(
      "# Synthetic existing profile.\n",
    );
    expect(await readFile(protectedFile, "utf8")).toBe("unchanged");
  }, 30_000);
}
