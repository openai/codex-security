import { afterEach, expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  completePatches,
  publicationRepository,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

test.each(
  [false, true].flatMap((resume) =>
    ["github.com", "gitlab.com"].map((host) => ({ resume, host })),
  ),
)(
  "keeps HTTP transport credentials out of publication arguments: $host, resume=$resume",
  async ({ resume, host }) => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    const password = "SYNTHETIC_PASSWORD%40value";
    const prefix = `https://synthetic-user:${password}@${host}/example/`;
    const resolved = `${prefix}repository.git`;
    const project = `https://${host}/example/repository.git`;
    const configured = resume ? resolved : "synthetic:repository.git";
    git("remote", "set-url", "origin", configured);
    git("config", `url.${prefix}.insteadOf`, "synthetic:");
    // A resolved URL must not undergo a second insteadOf expansion.
    if (!resume)
      git("config", "url.https://unused.example.test/.insteadOf", prefix);
    const branch = "codex-security/patch-scan-1";
    const original = git("rev-parse", "HEAD");
    if (resume) {
      git("branch", branch);
      git("config", `branch.${branch}.codexSecurityPatchCommit`, original);
    }
    const environment: NodeJS.ProcessEnv = {
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "synthetic.inherited",
      GIT_CONFIG_VALUE_0: "count value",
      GIT_CONFIG_PARAMETERS: `'synthetic.parameter=parameter value' 'remote.origin.pushurl=${configured}'`,
    };
    const inherited = { ...environment };
    let preflights = 0;
    let identities = 0;
    let creates = 0;
    let pushes = 0;
    const request = `https://${host}/example/repository/${host === "gitlab.com" ? "-/merge_requests" : "pull"}/1`;
    const outcome = await runWorkflow(
      resume
        ? ["patch", "--resume-pr", branch, "--json"]
        : ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        environment,
        onWorkbench: () =>
          savedScan(resultWithFindings(["high"]), "scan-1", directory),
        onCodex: async (args, output) => {
          await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
          completePatches(args, output);
          return 0;
        },
        onRepositoryCommand: async (command, args, cwd, options) => {
          expect(args.join("\n")).not.toContain(password);
          const effective = {
            ...options,
            environment: { ...environment, ...options?.environment },
          };
          const readGit = (arguments_: readonly string[]) =>
            runGitRepositoryCommand("git", arguments_, cwd, effective);
          if (command === "git") {
            if (args[0] === "ls-remote") {
              preflights++;
              expect(await readGit(["ls-remote", "--get-url", args[3]!])).toBe(
                resolved,
              );
              expect(
                await readGit(["config", "--get", "synthetic.inherited"]),
              ).toBe("count value");
              expect(
                await readGit(["config", "--get", "synthetic.parameter"]),
              ).toBe("parameter value");
              return "";
            }
            if (args[0] === "push") {
              pushes++;
              expect(
                await readGit(["remote", "get-url", "--push", "origin"]),
              ).toBe(resolved);
              return readGit(
                args.map((argument) =>
                  argument === "origin" ? remote : argument,
                ),
              );
            }
            return readGit(args);
          }
          if (command === "glab") {
            expect(args[args.indexOf("--repo") + 1]).toBe(project);
            if (args[1] === "list") return "";
            expect(args[args.indexOf("--head") + 1]).toBe(project);
          } else {
            if (args[1] === "list") return "[]";
            if (args.at(-1) === ".url") return project.replace(/\.git$/u, "");
            if (args[0] === "repo") {
              identities++;
              expect(
                await readGit([
                  "ls-remote",
                  "--get-url",
                  "codex-security-push",
                ]),
              ).toBe(resolved);
              expect(
                await readGit(["config", "--get", "synthetic.inherited"]),
              ).toBe("count value");
              return args[1] === "set-default"
                ? "example/repository"
                : JSON.stringify({
                    id: "synthetic-origin-id",
                    url: project.replace(/\.git$/u, ""),
                  });
            }
          }
          creates++;
          return request;
        },
      },
      { localHosting: false },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(preflights).toBe(resume ? 0 : 1);
    expect(identities).toBe(host === "github.com" ? 2 : 0);
    expect(pushes).toBe(1);
    expect(creates).toBe(1);
    expect(environment).toEqual(inherited);
    expect(git("remote", "get-url", "--push", "origin")).toBe(resolved);
    expect(JSON.parse(outcome.stdout).pullRequest.url).toBe(request);
  },
);
