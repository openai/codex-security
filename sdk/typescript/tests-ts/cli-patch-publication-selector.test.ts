import { afterEach, expect, test } from "bun:test";
import { execFile } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import {
  publicationRepository,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);
const gh = Bun.which("gh");

for (const mode of ["resume", "prepare"]) {
  for (const selector of mode === "resume"
    ? ["unset"]
    : ["unset", "unrelated", "missing", "source alias"]) {
    test.skipIf(gh === null)(
      `${mode} reuses the existing publication with ${selector} GIT_CONFIG`,
      async () => {
        const { directory, git } = await publicationRepository(fixtures);
        const support = await fixtures.create("patch-publication-selector-");
        const config = join(support, "selector");
        const globalConfig = join(support, "global");
        await writeFile(globalConfig, "");
        await writeFile(config, "[synthetic]\n selector = original\n");
        const source = "https://github.com/example/source.git";
        if (selector === "source alias") {
          git(
            "config",
            "url.https://github.com/example/.insteadOf",
            "synthetic:",
          );
          git("remote", "set-url", "origin", "synthetic:source.git");
        } else git("remote", "set-url", "origin", source);
        const branch = "codex-security/patch-scan-1";
        const commit = git("rev-parse", "HEAD");
        if (mode === "resume") {
          git("branch", branch);
          git("config", `branch.${branch}.codexSecurityPatchCommit`, commit);
        }
        const environment: NodeJS.ProcessEnv = {
          PATH: process.env["PATH"],
          SystemRoot: process.env["SystemRoot"],
          HOME: support,
          USERPROFILE: support,
          GH_CONFIG_DIR: support,
          GH_NO_UPDATE_NOTIFIER: "1",
          GH_PROMPT_DISABLED: "1",
          GH_TOKEN: "synthetic-gh-test-token",
          GH_REPO: "github.com/example/upstream",
          GH_HOST: "github.com",
          GIT_CONFIG_GLOBAL: globalConfig,
          GIT_CONFIG_NOSYSTEM: "1",
          GIT_CONFIG_PARAMETERS: "'synthetic.inherited=kept'",
          GIT_CONFIG:
            selector === "unset"
              ? undefined
              : selector === "missing"
                ? join(support, "missing")
                : config,
        };
        const originalEnvironment = { ...environment };
        const originalConfig = await readFile(join(directory, ".git/config"));
        const originalIndex = await readFile(join(directory, ".git/index"));
        const originalRefs = git(
          "for-each-ref",
          "--format=%(refname):%(objectname)",
        );
        const originalSource = await readFile(
          join(directory, "src/finding-1.ts"),
        );
        const url = "https://github.com/example/upstream/pull/1";
        const identities: NodeJS.ProcessEnv[] = [];
        let models = 0;
        let pushes = 0;
        let creates = 0;
        const result = resultWithFindings(["high"]);
        const outcome = await runWorkflow(
          mode === "resume"
            ? ["patch", "--resume-pr", branch, "--json"]
            : ["patch", "--scan", "scan-1", "--create-pr", "--json"],
          {
            currentDirectory: directory,
            environment,
            result,
            onWorkbench: () => savedScan(result, "scan-1", directory),
            onCodex: () => {
              models++;
              throw new Error("Existing publication must prevent a model turn");
            },
            onRepositoryCommand: async (command, args, cwd, options) => {
              const effectiveEnvironment = {
                ...environment,
                ...options?.environment,
              };
              if (command === "git") {
                if (args.includes("push")) {
                  pushes++;
                  throw new Error("Existing publication must prevent a push");
                }
                if (args.includes("ls-remote")) return "";
                return runGitRepositoryCommand(command, args, cwd, {
                  ...options,
                  environment: effectiveEnvironment,
                });
              }
              expect(command).toBe("gh");
              if (args[0] === "pr" && args[1] === "list") {
                expect(args).toContain(branch);
                expect(effectiveEnvironment["GH_REPO"]).toBe(
                  environment["GH_REPO"],
                );
                expect(effectiveEnvironment["GIT_CONFIG"]).toBe(
                  environment["GIT_CONFIG"],
                );
                return JSON.stringify([
                  {
                    url,
                    head: commit,
                    state: "OPEN",
                    repositoryId: "R_source",
                    crossRepository: true,
                  },
                ]);
              }
              if (args[0] === "pr" && args[1] === "create") {
                creates++;
                throw new Error(
                  "Existing publication must prevent duplicate creation",
                );
              }
              expect(args[0]).toBe("repo");
              identities.push(effectiveEnvironment);
              if (args[1] === "set-default") {
                expect(args).toEqual(["repo", "set-default", "--view"]);
                const { stdout } = await promisify(execFile)(gh!, [...args], {
                  cwd: options?.directory ?? cwd,
                  env: effectiveEnvironment,
                  encoding: "utf8",
                });
                const selected = stdout.trim();
                if (selected)
                  expect(selected.replace(/^github\.com\//u, "")).toBe(
                    "example/source",
                  );
                return selected;
              }
              expect(args).toEqual([
                "repo",
                "view",
                "--json",
                "id,url",
                "--jq",
                "tojson",
              ]);
              expect(
                runGitRepositoryCommand(
                  "git",
                  ["config", "--get", "synthetic.inherited"],
                  cwd,
                  {
                    ...options,
                    environment: effectiveEnvironment,
                  },
                ),
              ).toBe("kept");
              return JSON.stringify({
                id: "R_source",
                url: "https://github.com/example/source",
              });
            },
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(
          mode === "resume" ? 0 : 2,
        );
        if (mode === "resume")
          expect(JSON.parse(outcome.stdout).pullRequest.url).toBe(url);
        else expect(outcome.stderr).toContain("already exists");
        expect(identities).toHaveLength(2);
        for (const identity of identities) {
          expect(identity["GIT_CONFIG"]).toBeUndefined();
          expect(identity["GIT_CONFIG_GLOBAL"]).toBe(globalConfig);
          expect(identity["GIT_CONFIG_NOSYSTEM"]).toBe("1");
          expect(identity["GIT_CONFIG_PARAMETERS"]).toContain(
            environment["GIT_CONFIG_PARAMETERS"]!,
          );
          expect(identity["GH_REPO"]).toBe("");
          expect(identity["GH_TOKEN"]).toBe(environment["GH_TOKEN"]);
        }
        expect({ models, pushes, creates }).toEqual({
          models: 0,
          pushes: 0,
          creates: 0,
        });
        expect(environment).toEqual(originalEnvironment);
        expect(await readFile(config, "utf8")).toBe(
          "[synthetic]\n selector = original\n",
        );
        expect(await readFile(join(directory, ".git/config"))).toEqual(
          originalConfig,
        );
        expect(await readFile(join(directory, ".git/index"))).toEqual(
          originalIndex,
        );
        expect(git("for-each-ref", "--format=%(refname):%(objectname)")).toBe(
          originalRefs,
        );
        expect(git("rev-parse", "HEAD")).toBe(commit);
        expect(await readFile(join(directory, "src/finding-1.ts"))).toEqual(
          originalSource,
        );
      },
    );
  }
}
