import { afterEach, expect, mock, test } from "bun:test";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  publicationRepository,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

test.each(["github.example.test", "gitlab.com"])(
  "keeps remote credentials in Git configuration for %s",
  async (host) => {
    const { directory, git } = await publicationRepository(fixtures);
    const credential = "synthetic-token%40literal";
    const remote = `https://synthetic-user:${credential}@${host}/example/repository.git`;
    git("remote", "set-url", "origin", remote);
    const diagnostic = `Synthetic transport failure: ${credential}`;
    const model = mock(async () => 0);
    const environment = {
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "codexsecurity.synthetic",
      GIT_CONFIG_VALUE_0: "preserved",
    };
    let transports = 0;
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        environment,
        onWorkbench: () =>
          savedScan(resultWithFindings(["high"]), "scan-1", directory),
        onCodex: model,
        onRepositoryCommand: (command, args, cwd, options) => {
          expect(args.join("\n")).not.toContain(credential);
          if (command !== "git") {
            if (command === "glab")
              expect(args[args.indexOf("--repo") + 1]).toBe(
                `https://${host}/example/repository.git`,
              );
            return command === "glab" ? "" : "[]";
          }
          const commandOptions = {
            ...options,
            environment: { ...environment, ...options?.environment },
          };
          const transport = args.indexOf("ls-remote");
          if (transport >= 0) {
            const alias = args[args.indexOf("--", transport) + 1]!;
            expect(
              runGitRepositoryCommand(
                "git",
                [...args.slice(0, transport), "ls-remote", "--get-url", alias],
                cwd,
                commandOptions,
              ),
            ).toBe(remote);
            expect(
              runGitRepositoryCommand(
                "git",
                ["config", "--get", "codexsecurity.synthetic"],
                cwd,
                commandOptions,
              ),
            ).toBe("preserved");
            transports++;
            throw new Error(diagnostic);
          }
          return runGitRepositoryCommand(command, args, cwd, commandOptions);
        },
      },
      { localHosting: false },
    );
    expect(outcome.exitCode).toBe(2);
    expect(transports, outcome.stderr).toBe(1);
    expect(outcome.stderr).toContain(diagnostic);
    expect(model).not.toHaveBeenCalled();
  },
);
