import { afterEach, expect, test } from "bun:test";
import { link, mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import { delimiter, join, relative } from "node:path";
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

test("HTTPS preflight rejects a checkout-relative Git exec directory without a push hook", async () => {
  const { directory, git } = await publicationRepository(fixtures);
  const host = "127.0.0.1:1";
  git("remote", "set-url", "origin", `https://${host}/team/repository.git`);
  const result = await runWorkflow(
    ["patch", "Synthetic issue", "--create-pr"],
    {
      currentDirectory: join(directory, "src"),
      environment: { GITLAB_HOST: host, GIT_EXEC_PATH: "tools" },
      onRepositoryCommand: (tool, args, cwd, options) => {
        if (tool !== "git") return "";
        if (args.includes("ls-remote")) throw new Error("Reached transport");
        return runGitRepositoryCommand(tool, args, cwd, options);
      },
    },
    { localHosting: false },
  );
  expect(result.stderr).toContain("outside patch-writable directories");
});

test("hook-free publication binds the native HTTPS helper before the patch turn", async () => {
  const { directory, git } = await publicationRepository(fixtures);
  const tools = await fixtures.create("patch-https-helper-");
  const helper = join(tools, "git-remote-https");
  const alias = join(directory, "launcher");
  const marker = join(tools, "invoked");
  // Answer the remote-helper protocol with an empty ref list for ls-remote.
  await writeFile(
    helper,
    `#!/bin/sh
while read -r command; do
  case "$command" in
    capabilities) printf 'fetch\\npush\\n\\n' ;;
    list) echo preflight > "$PATCH_HELPER_LOG"; echo ;;
    *) exit ;;
  esac
done
`,
    { mode: 0o700 },
  );
  await link(helper, alias);
  git("add", "launcher");
  git("commit", "-m", "Add synthetic launcher");
  const host = "127.0.0.1:1";
  git("remote", "set-url", "origin", `https://${host}/team/repository.git`);
  const environment = {
    GIT_CONFIG_GLOBAL: join(tools, "gitconfig"),
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_EXEC_PATH: relative(directory, tools),
    GITLAB_HOST: host,
    PATCH_HELPER_LOG: marker,
  };
  const outcome = await runWorkflow(
    ["patch", "Synthetic issue", "--create-pr", "--json"],
    {
      currentDirectory: directory,
      environment,
      onRepositoryCommand: (tool, args, cwd, options) =>
        tool === "git"
          ? runGitRepositoryCommand(tool, args, cwd, {
              ...options,
              environment: { ...environment, ...options?.environment },
            })
          : "",
      onCodex: async (_args, output) => {
        await writeFile(
          alias,
          '#!/bin/sh\necho replacement > "$PATCH_HELPER_LOG"\nexit 1\n',
        );
        output?.stdout.write("Fixed and verified.");
        return 0;
      },
    },
    { localHosting: false },
  );
  expect(outcome.exitCode, outcome.stderr).toBe(2);
  expect(outcome.stderr).toContain("transport executable changed");
  expect(await readFile(marker, "utf8")).toBe("preflight\n");
});

test("one native push uses the configured proxy for each destination", () =>
  checkNativePush("approved"));
test("one native push uses the configured SSH launcher for its second destination", () =>
  checkNativePush("approved", "ssh"));
test("one checkout-selected mirror blocks a native push to all destinations", () =>
  checkNativePush("unapproved mirror"));
test("a pre-push hook cannot modify the next destination's proxy through a hard link", () =>
  checkNativePush("linked launcher"));
test("a pre-push hook cannot modify the next destination's SSH launcher through a hard link", () =>
  checkNativePush("linked launcher", "ssh"));
test("a pre-push hook cannot modify the next destination's SSH script operand through a hard link", () =>
  checkNativePush("linked launcher", "ssh-script"));
test.skipIf(process.platform === "win32")(
  "a pre-push hook cannot replace the HTTPS helper for the next destination",
  () => checkNativePush("linked launcher", "https"),
);
test.skipIf(process.platform === "win32").each([0o700, 0o600])(
  "a pre-push hook cannot replace the Git child launcher (initial mode %d) for a single destination",
  (mode) => checkNativePush("linked launcher", "single", mode),
);
test.skipIf(process.platform === "win32")(
  "a pre-push hook cannot replace a Git child in a checkout-selected exec directory",
  () => checkNativePush("checkout launcher", "single"),
);
test.skipIf(process.platform === "win32")(
  "a single destination with a pre-push hook accepts Git installation hard links",
  () => checkNativePush("approved", "single"),
);

async function checkNativePush(
  scenario:
    "approved" | "unapproved mirror" | "linked launcher" | "checkout launcher",
  route: "proxy" | "ssh" | "ssh-script" | "https" | "single" = "proxy",
  childMode = 0o700,
) {
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
  for (const port of route === "single" ? [1] : [1, 2]) {
    const host = "127.0.0.1:" + port;
    const ssh = port === 2 && route.startsWith("ssh");
    const https = port === 2 && route === "https";
    const protocol = ssh ? "ssh://git@" : https ? "https://" : "git://";
    const remote = protocol + host + "/team/repository.git";
    if (port === 1) git("remote", "set-url", "origin", remote);
    git(
      "config",
      ...(scenario !== "unapproved mirror" || port === 1
        ? ["--file", include]
        : []),
      "--add",
      "remote.origin.pushurl",
      remote,
    );
    const receiver = join(external, "receiver-" + port);
    git("init", "--bare", receiver);
    receivers.push(receiver);
    if (https) continue;
    const name = "transport-" + port;
    const launcher = join(external, name);
    const literal =
      "'" + receiver.replaceAll("\\", "/").replaceAll("'", "'\\''") + "'";
    if (ssh) {
      if (route === "ssh-script")
        environment["GIT_SSH_COMMAND"] =
          "sh " + JSON.stringify(launcher.replaceAll("\\", "/"));
      else environment["GIT_SSH"] = launcher;
      environment["GIT_SSH_VARIANT"] = "ssh";
    } else {
      git(
        "config",
        "--file",
        include,
        "--add",
        "core.gitProxy",
        name + " for " + host,
      );
    }
    const request = ssh
      ? ""
      : `header=$(dd bs=1 count=4 2>/dev/null) || exit 1
dd bs=1 count=$((0x$header - 4)) of=/dev/null 2>/dev/null || exit 1
`;
    await writeFile(
      launcher,
      `#!/bin/sh\n${request}exec git receive-pack ${literal}\n`,
      {
        mode: 0o700,
      },
    );
  }
  if (scenario === "linked launcher" || route === "single") {
    const home = await fixtures.create("patch-proxy-home-");
    environment["CODEX_HOME"] = home;
    await writeFile(
      join(home, "config.toml"),
      "[sandbox_workspace_write]\nexclude_slash_tmp=true\nexclude_tmpdir_env_var=true\n",
    );
    let launcher = join(external, "transport-2");
    if (route === "https") {
      environment["GIT_EXEC_PATH"] = external;
      launcher = join(external, "git-remote-https");
      await writeFile(launcher, "#!/bin/sh\nexit 1\n", { mode: 0o700 });
    } else if (route === "single") {
      const root = scenario === "checkout launcher" ? directory : external;
      const execPath = join(root, "libexec", "git-core");
      await mkdir(execPath, { recursive: true });
      environment["GIT_EXEC_PATH"] = execPath;
      launcher = join(execPath, "git");
      const gitPath = Bun.which("git")!.replaceAll("'", "'\\''");
      await writeFile(launcher, `#!/bin/sh\nexec '${gitPath}' "$@"\n`, {
        mode: childMode,
      });
      const bin = join(external, "bin");
      await mkdir(bin);
      await link(launcher, join(bin, "git"));
    }
    if (scenario === "linked launcher" || scenario === "checkout launcher")
      await link(launcher, join(directory, "launcher-alias"));
    await writeFile(
      join(directory, ".git", "hooks", "pre-push"),
      "#!/bin/sh\nprintf '%s\\n' '#!/bin/sh' 'echo changed-launcher \"$1\" >&2; exit 1' > launcher-alias\n" +
        (route === "single" ? "chmod 700 launcher-alias\n" : ""),
      { mode: 0o700 },
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
  if (scenario !== "approved") {
    const reason = {
      "linked launcher": "hard-linked transport file",
      "checkout launcher": "outside patch-writable directories",
      "unapproved mirror": "multiple destinations",
    };
    expect(outcome.stderr).toContain(reason[scenario]);
    expect(pushes).toBe(0);
    for (const receiver of receivers)
      expect(git("--git-dir", receiver, "for-each-ref")).toBe("");
    return;
  }
  expect(pushes, outcome.stderr).toBe(1);
  for (const receiver of receivers)
    expect(
      git("--git-dir", receiver, "rev-parse", "refs/heads/" + branch),
    ).toBe(commit);
}
