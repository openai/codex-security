import { afterEach, expect, test } from "bun:test";
import { mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import { delimiter, join } from "node:path";
import {
  publicationRepository,
  runGitRepositoryCommand,
  runWorkflow,
  resultWithFindings,
  savedScan,
} from "./cli-patch-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);
test.each(["compiled exec directory", "config separator in executable path"])(
  "native Git proxy resolves the %s",
  async (scenario) => {
    const { directory, git } = await publicationRepository(fixtures);
    const host = "127.0.0.1:1";
    git("remote", "set-url", "origin", `git://${host}/team/repository.git`);
    const external = await fixtures.create("patch-proxy-search-");
    const bin = join(external, "tools for proxy");
    await mkdir(bin);
    const compiled = scenario === "compiled exec directory";
    const name = compiled ? "git-remote-http" : "proxy-tool";
    const file = join(bin, name);
    const program = '#!/bin/sh\nprintf "%s\\n" "$@" > "$0.invoked"\nexit 1\n';
    await writeFile(file, program, { mode: 0o700 });
    const environment: NodeJS.ProcessEnv = {
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: join(external, "gitconfig"),
      GITLAB_HOST: host,
      PATH: bin + delimiter + process.env["PATH"],
    };
    if (compiled) environment["GIT_PROXY_COMMAND"] = name;
    else
      git(
        "config",
        "--file",
        environment["GIT_CONFIG_GLOBAL"]!,
        "core.gitProxy",
        name + " for " + host,
      );
    let selected: string | undefined;
    const result = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        environment,
        onWorkbench: () =>
          savedScan(resultWithFindings(["high"]), "scan-1", directory),
        onRepositoryCommand: (tool, args, cwd, options) => {
          if (tool !== "git") return "";
          if (compiled && args.includes("ls-remote")) {
            selected = options?.environment?.["GIT_PROXY_COMMAND"];
            throw new Error("Fixture stopped the transport");
          }
          return runGitRepositoryCommand(tool, args, cwd, {
            ...options,
            environment: { ...environment, ...options?.environment },
          });
        },
      },
      { localHosting: false },
    );
    expect(result.exitCode).toBe(2);
    if (compiled) {
      const executable = name + (process.platform === "win32" ? ".exe" : "");
      expect(selected).toBe(
        await realpath(join(git("--exec-path"), executable)),
      );
    } else {
      expect(
        await readFile(file + ".invoked", "utf8").catch(() => undefined),
        result.stderr,
      ).toBe("127.0.0.1\n1\n");
    }
  },
);

test("one native push uses the configured proxy for each destination", async () => {
  const { directory, git } = await publicationRepository(fixtures);
  const external = await fixtures.create("patch-proxy-routes-");
  const system = join(external, "system.gitconfig");
  const include = join(external, "operator.gitconfig");
  const environment: NodeJS.ProcessEnv = {
    GIT_CONFIG_NOSYSTEM: "0",
    GIT_CONFIG_SYSTEM: system,
    GIT_CONFIG_GLOBAL: join(external, "empty.gitconfig"),
    GITLAB_HOST: "127.0.0.1:1",
    PATH: external + delimiter + process.env["PATH"],
  };
  git(
    "config",
    "--file",
    system,
    "includeIf.onbranch:main.path",
    "operator.gitconfig",
  );
  git("config", "--file", include, "patchFixture.original", "enabled");
  const branch = "codex-security/patch-scan-1";
  git("branch", branch);
  const commit = git("rev-parse", "HEAD");
  git("config", `branch.${branch}.codexSecurityPatchCommit`, commit);
  const receivers: string[] = [];
  for (const port of [1, 2]) {
    const host = "127.0.0.1:" + port;
    const remote = "git://" + host + "/team/repository.git";
    if (port === 1) git("remote", "set-url", "origin", remote);
    git("config", "--add", "remote.origin.pushurl", remote);
    const receiver = join(external, "receiver-" + port);
    git("init", "--bare", receiver);
    receivers.push(receiver);
    const name = "proxy-" + port;
    const literal =
      "'" + receiver.replaceAll("\\", "/").replaceAll("'", "'\\''") + "'";
    await writeFile(
      join(external, name),
      `#!/bin/sh
header=$(dd bs=1 count=4 2>/dev/null) || exit 1
dd bs=1 count=$((0x$header - 4)) of=/dev/null 2>/dev/null || exit 1
exec git receive-pack ${literal}
`,
      { mode: 0o700 },
    );
    git(
      "config",
      "--file",
      include,
      "--add",
      "core.gitProxy",
      name + " for " + host,
    );
  }
  let pushes = 0;
  const outcome = await runWorkflow(
    ["patch", "--resume-pr", branch, "--json"],
    {
      currentDirectory: directory,
      environment,
      onRepositoryCommand: async (tool, args, cwd, options) => {
        if (tool !== "git")
          return args[1] === "create"
            ? "https://gitlab.example.test/team/repository/-/merge_requests/17"
            : "";
        // Git versions before 2.42 do not expose this variable.
        if (args[0] === "var" && args[1] === "GIT_CONFIG_SYSTEM")
          throw Object.assign(new Error("usage: git var (-l | <variable>)"), {
            status: 129,
          });
        const bound = {
          ...options,
          environment: { ...environment, ...options?.environment },
        };
        if (args[0] === "push") {
          pushes++;
          expect(
            await runGitRepositoryCommand(
              tool,
              ["config", "--get", "patchFixture.original"],
              cwd,
              bound,
            ),
          ).toBe("enabled");
        }
        return runGitRepositoryCommand(tool, args, cwd, bound);
      },
    },
    { localHosting: false },
  );
  expect(pushes, outcome.stderr).toBe(1);
  for (const receiver of receivers)
    expect(
      git("--git-dir", receiver, "rev-parse", "refs/heads/" + branch),
    ).toBe(commit);
});
