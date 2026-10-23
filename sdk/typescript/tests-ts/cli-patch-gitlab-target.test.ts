import { afterEach, describe, expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  completePatches,
  publicationRepository,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";

describe("GitLab patch destinations", () => {
  const fixtures = createTemporaryDirectories(true);
  afterEach(fixtures.cleanup);

  test.each([
    ...[false, true].flatMap((resume) =>
      [
        "fork HTTPS",
        "fork SSH",
        "same project",
        "local fetch",
        "different port mirror",
        "default port mirror",
        "same port fork",
        "explicit default port fork",
        "explicit HTTP port fork",
        "explicit SSH default port fork",
        "implicit SSH default port fork",
        "distinct SSH transport ports fork",
        "git+ssh transport port fork",
      ].map((mode) => ({
        mode,
        resume,
      })),
    ),
    ...[
      "file fetch",
      "fork credentials",
      "GitHub mirror",
      "Bitbucket mirror",
      "GitLab instance mirror",
      "self-managed fork",
      "same project over SSH",
      "existing fork request",
      "other fork request",
      "upstream request",
      "different saved commit",
      "source lookup failure",
    ].map((mode) => ({ mode, resume: true })),
  ])(
    "uses the selected source and target: $mode, resume=$resume",
    async ({ mode, resume }) => {
      const { directory, git, remote } = await publicationRepository(fixtures);
      const portCase = mode.includes("port");
      const host =
        mode === "self-managed fork" || portCase
          ? "gitlab.example.test"
          : "gitlab.com";
      const explicitDefault = mode.startsWith("explicit");
      const protocol = mode === "explicit HTTP port fork" ? "http" : "https";
      const fetchPort = explicitDefault
        ? protocol === "http"
          ? ":80"
          : ":443"
        : portCase && mode !== "default port mirror"
          ? ":8443"
          : "";
      const pushPort =
        portCase && !explicitDefault
          ? mode === "different port mirror"
            ? ":9443"
            : ":8443"
          : "";
      const upstream =
        mode === "explicit SSH default port fork"
          ? `ssh://git@${host}:22/example/repository.git`
          : mode === "implicit SSH default port fork"
            ? `ssh://git@${host}/example/repository.git`
            : mode === "distinct SSH transport ports fork"
              ? `ssh://git@${host}:2222/example/repository.git`
              : mode === "git+ssh transport port fork"
                ? `git+ssh://git@${host}:2222/example/repository.git`
                : `${protocol}://${host}${fetchPort}/example/repository.git`;
      const fork =
        mode === "explicit SSH default port fork" ||
        mode === "git+ssh transport port fork"
          ? `git@${host}:synthetic-user/repository.git`
          : mode === "implicit SSH default port fork"
            ? `ssh://git@${host}:22/synthetic-user/repository.git`
            : mode === "distinct SSH transport ports fork"
              ? `ssh://git@${host}:2200/synthetic-user/repository.git`
              : `${protocol}://${host}${pushPort}/synthetic-user/repository.git`;
      const sameProject = mode.startsWith("same project");
      const localFetch = mode === "local fetch" || mode === "file fetch";
      const push =
        mode === "fork credentials"
          ? "https://synthetic-user:synthetic-token@gitlab.com/synthetic-user/repository.git"
          : mode === "fork SSH"
            ? "git@gitlab.com:synthetic-user/repository.git"
            : mode === "same project over SSH"
              ? "ssh://git@gitlab.com/example/repository.git"
              : sameProject
                ? upstream
                : fork;
      const source =
        mode === "explicit SSH default port fork" ||
        mode === "git+ssh transport port fork"
          ? `ssh://git@${host}/synthetic-user/repository.git`
          : mode === "fork credentials"
            ? fork
            : mode === "fork SSH"
              ? "ssh://git@gitlab.com/synthetic-user/repository.git"
              : push;
      const mirror = mode.endsWith("mirror");
      const target = localFetch || mirror ? source : upstream;
      const sourceId = sameProject ? 11 : 22;
      const targetId = localFetch || mirror ? sourceId : 11;
      git(
        "remote",
        "set-url",
        "origin",
        mode === "local fetch"
          ? remote
          : mode === "file fetch"
            ? pathToFileURL(remote).href
            : mirror && !portCase
              ? `https://${mode === "GitHub mirror" ? "github.com" : mode === "Bitbucket mirror" ? "bitbucket.org" : "gitlab.example.test"}/example/repository.git`
              : mode === "fork credentials"
                ? "https://synthetic-user:synthetic-token@gitlab.com/example/repository.git"
                : upstream,
      );
      git("remote", "set-url", "--push", "origin", push);
      const branch = "codex-security/patch-scan-1";
      const commit = git("rev-parse", "HEAD");
      if (resume) {
        git("branch", branch);
        git("config", `branch.${branch}.codexSecurityPatchCommit`, commit);
      }
      const existing =
        mode === "existing fork request" || mode === "different saved commit";
      const requestSource =
        mode === "other fork request"
          ? 33
          : mode === "upstream request"
            ? targetId
            : sourceId;
      const hasRequest = existing || mode.endsWith("request");
      const url = "https://gitlab.com/example/repository/-/merge_requests/14";
      const listedTargets: string[] = [];
      const creations: string[][] = [];
      let pushes = 0;
      let lookups = 0;
      const outcome = await runWorkflow(
        resume
          ? ["patch", "--resume-pr", branch, "--json"]
          : ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          environment:
            mode === "self-managed fork" || portCase
              ? { GITLAB_HOST: host }
              : {},
          onWorkbench: () =>
            savedScan(resultWithFindings(["high"]), "scan-1", directory),
          onCodex: async (args, output) => {
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "git") {
              if (args.includes("ls-remote"))
                return runGitRepositoryCommand(
                  command,
                  ["ls-remote", "--heads", "--", remote],
                  cwd,
                  options,
                );
              if (args[0] === "push") {
                pushes++;
                return runGitRepositoryCommand(
                  command,
                  args.map((arg) => (arg === "origin" ? remote : arg)),
                  cwd,
                  options,
                );
              }
              return runGitRepositoryCommand(command, args, cwd, options);
            }
            expect(command).toBe("glab");
            if (args[0] === "repo") {
              expect(args).toEqual([
                "repo",
                "view",
                source,
                "--output",
                "json",
                "--jq",
                ".id",
              ]);
              lookups++;
              if (mode === "source lookup failure")
                throw new Error("Synthetic project lookup unavailable");
              return String(sourceId);
            }
            if (args[1] === "list") {
              const selectedTarget = args[args.indexOf("--repo") + 1]!;
              listedTargets.push(selectedTarget);
              expect(args[args.indexOf("--source-branch") + 1]).toBe(branch);
              // Emulate glab's project filter against a branch-matched API row.
              const query = args[args.indexOf("--jq") + 1]!;
              const selectedSource = /\.source_project_id == (\d+)/u.exec(
                query,
              );
              const matches = selectedSource
                ? requestSource === Number(selectedSource[1])
                : requestSource === targetId;
              return hasRequest && selectedTarget === target && matches
                ? JSON.stringify({
                    url,
                    head: mode === "different saved commit" ? "other" : commit,
                  })
                : "";
            }
            expect(args[1]).toBe("create");
            creations.push([...args]);
            return url;
          },
        },
        { localHosting: false },
      );
      const blocked =
        mode === "different saved commit" || mode === "source lookup failure";
      expect(outcome.exitCode, outcome.stderr).toBe(blocked ? 2 : 0);
      if (mode === "source lookup failure") {
        expect(outcome.stderr).toContain(
          "Synthetic project lookup unavailable",
        );
        expect(listedTargets).toEqual([]);
      } else {
        expect(listedTargets.length).toBeGreaterThan(0);
        expect(new Set(listedTargets)).toEqual(new Set([target]));
      }
      if (mode === "different saved commit")
        expect(outcome.stderr).toContain(
          "does not contain the saved patch commit",
        );
      expect(lookups > 0).toBe(source !== target);
      expect(creations.length).toBe(existing || blocked ? 0 : 1);
      expect(pushes).toBe(creations.length);
      if (creations.length) {
        const args = creations[0]!;
        expect(args[args.indexOf("--repo") + 1]).toBe(target);
        expect(args[args.indexOf("--head") + 1]).toBe(source);
        expect(git("--git-dir", remote, "rev-parse", branch)).toBe(
          git("rev-parse", branch),
        );
      }
      if (!blocked)
        expect(JSON.parse(outcome.stdout).pullRequest.url).toBe(url);
    },
  );
});
