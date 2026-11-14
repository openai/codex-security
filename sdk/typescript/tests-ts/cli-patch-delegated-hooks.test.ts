import { afterEach, expect, test } from "bun:test";
import { chmod, readFile, writeFile } from "node:fs/promises";
import { join, sep } from "node:path";
import { runRepositoryCommand } from "../src/cli.js";
import {
  publicationRepository,
  repositoryGit,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";
import {
  patchSnapshotEnvironment,
  patchSnapshotWindowsConfig,
} from "./support/patch-snapshot-environment.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);
const shell = (value: string) =>
  "'" + value.split(sep).join("/").replaceAll("'", "'\"'\"'") + "'";

for (const outside of [true, false])
  test(
    `publication runs an unchanged hook's model-edited delegate under the verified permissions (outside: ${outside})`,
    async () => {
      const { directory, remote, git } = await publicationRepository(fixtures);
      const home = await fixtures.create("hook-policy-home-");
      const tmp = await fixtures.create("hook-policy-tmp-");
      const privateFile = join(
        await fixtures.create("hook-policy-outside-"),
        "marker",
      );
      const allowed = await fixtures.create("hook-approved-output-");
      await chmod(home, 0o700);
      await writeFile(
        join(home, "config.toml"),
        patchSnapshotWindowsConfig() +
          "[sandbox_workspace_write]\nexclude_slash_tmp=true\nexclude_tmpdir_env_var=true\n" +
          '[shell_environment_policy.set]\nGIT_ASKPASS="unused-git-prompt"\nSSH_ASKPASS="unused-ssh-prompt"\n',
      );
      const environment = patchSnapshotEnvironment(tmp, {
        ...process.env,
        CODEX_HOME: home,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
      });
      const delegate = join(directory, "check.sh");
      await writeFile(delegate, "exit 0\n");
      git("add", "check.sh");
      git("commit", "-m", "Synthetic delegated validator");
      for (const [name, body] of [
        ["pre-commit", "exec sh ./check.sh"],
        [
          "prepare-commit-msg",
          'test "$2" = message\ntest "${1##*/}" = COMMIT_EDITMSG\nprintf \'Verified synthetic message\\n\' > "$1"',
        ],
        [
          "commit-msg",
          [
            "git diff --cached --name-only | grep -Fx src/finding-1.ts >/dev/null",
            "original=$(git rev-parse --git-path COMMIT_EDITMSG)",
            'grep -Fx "Verified synthetic message" "$original" >/dev/null',
            'git interpret-trailers --in-place --trailer "Reviewed-by: Synthetic Validator" "$1"',
            // The original Git file remains protected until this hook returns.
            'if grep -F "Reviewed-by:" "$original" >/dev/null; then exit 14; fi',
            'if (printf "unverified" >> "$original") 2>/dev/null; then exit 14; fi',
          ].join("\n"),
        ],
        [
          "pre-push",
          'test "$1" = origin\ngrep -F refs/heads/codex-security/patch-scan-1 >/dev/null',
        ],
      ]) {
        const file = join(directory, ".git", "hooks", name!);
        await writeFile(file, "#!/bin/sh\nset -eu\n" + body + "\n");
        await chmod(file, 0o755);
      }
      const result = resultWithFindings(["high"]);
      let trustedHostPush = false;
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          result,
          environment,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onRepositoryCommand: (cmd, args, cwd, options) => {
            if (cmd !== "git")
              return args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1";
            if (!options?.hookSandbox)
              return runGitRepositoryCommand(cmd, args, cwd, options);
            if (args.includes("push"))
              trustedHostPush = options.sandbox === undefined;
            return runRepositoryCommand(cmd, args, cwd, {
              ...options,
              environment: {
                ...environment,
                ...options.environment,
                GIT_ASKPASS: "unused-host-git-prompt",
                SSH_ASKPASS: "unused-host-ssh-prompt",
                HTTPS_PROXY:
                  "http://synthetic:SYNTHETIC_HOOK_PROXY@proxy.invalid",
                GIT_CONFIG_PARAMETERS:
                  "'http.extraheader'='Authorization: SYNTHETIC_HOOK_SECRET' 'demo.sentinel'='benign preserved' " +
                  "'url.https://synthetic:SYNTHETIC_HOOK_SECRET@unused.invalid/.insteadof'='https://unused.invalid/old' " +
                  "'remote.unused.pushurl'='https://SYNTHETIC_HOOK_SECRET@unused.invalid/' " +
                  "'url.ssh://git@benign.invalid/.insteadof'='ssh://git@old.invalid/'",
              },
            });
          },
          onCodex: async (_args, output) => {
            const server = output!.appServer!;
            server.onPermissions!({
              directory,
              environment,
              snapshotStoragePaths: server.snapshotStoragePaths,
              profile: {
                extends: ":workspace",
                network: { enabled: false },
                workspace_roots: {},
                filesystem: {
                  ...Object.fromEntries(
                    server.permissions!.readOnlyPaths.map((path) => [
                      path,
                      { ".": "read" },
                    ]),
                  ),
                  ":tmpdir": {},
                  ":slash_tmp": {},
                  [allowed]: { ".": "write" },
                },
              },
            });
            await server.onBeforeTurn?.();
            await writeFile(
              delegate,
              [
                "set -eu",
                'test -z "${GIT_ASKPASS+x}${SSH_ASKPASS+x}"',
                'test "$(git config --get demo.sentinel)" = "benign preserved"',
                "if git config --get http.extraheader >/dev/null; then exit 15; fi",
                "if git config --list | grep -Fq SYNTHETIC_HOOK_SECRET; then exit 15; fi",
                'test "$(git config --get url.ssh://git@benign.invalid/.insteadof)" = "ssh://git@old.invalid/"',
                'case "${HTTPS_PROXY-}" in *SYNTHETIC_HOOK_PROXY*) exit 16;; esac',
                "printf reached > " + shell(join(allowed, "hook-ran")),
                ...(outside
                  ? ["printf synthetic > " + shell(privateFile)]
                  : []),
              ].join("\n") + "\n",
            );
            await writeFile(
              join(directory, "src/finding-1.ts"),
              "verified synthetic edit\n",
            );
            output!.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: "verified",
                    files: ["src/finding-1.ts", "check.sh"],
                    verification: "Synthetic regression passed.",
                  },
                ],
              }),
            );
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(outside ? 2 : 0);
      expect(await readFile(join(allowed, "hook-ran"), "utf8")).toBe("reached");
      expect(await readFile(privateFile).catch(() => null)).toBeNull();
      expect(trustedHostPush).toBe(!outside);
      const receiver = repositoryGit(remote);
      expect(receiver("for-each-ref", "--format=%(refname)")).toBe(
        outside ? "" : "refs/heads/codex-security/patch-scan-1",
      );
      if (!outside)
        expect(
          receiver(
            "log",
            "-1",
            "--format=%B",
            "refs/heads/codex-security/patch-scan-1",
          ),
        ).toBe(
          "Verified synthetic message\n\nReviewed-by: Synthetic Validator",
        );
    },
    process.platform === "win32" ? 300000 : 90000,
  );

test.each(["workspace", "read-only", "named", "danger-full-access"])(
  "resumed publication uses patch workspace permissions for the original pre-push hook with operator default %s",
  async (selection) => {
    const { directory, remote, git } = await publicationRepository(fixtures);
    const branch = "codex-security/saved-hook";
    git("branch", branch);
    git(
      "config",
      `branch.${branch}.codexSecurityPatchCommit`,
      git("rev-parse", "HEAD"),
    );
    const home = await fixtures.create("resume-hook-home-");
    const temporary = await fixtures.create("resume-hook-tmp-");
    const allowed = await fixtures.create("resume-hook-approved-output-");
    const outside = await fixtures.create("resume-hook-outside-");
    const denied = join(outside, "marker");
    await chmod(home, 0o700);
    await writeFile(
      join(home, "config.toml"),
      patchSnapshotWindowsConfig() +
        (selection === "named"
          ? 'default_permissions="qa-hook"\n'
          : selection === "workspace"
            ? ""
            : "sandbox_mode=" + JSON.stringify(selection) + "\n") +
        '\nmodel_provider="hook-fixture"\n' +
        '[model_providers.hook-fixture]\nname="Synthetic"\nbase_url="http://127.0.0.1:1/v1"\nenv_key="SYNTHETIC_MODEL_ACCESS"\n' +
        "[sandbox_workspace_write]\n" +
        "exclude_slash_tmp=true\nexclude_tmpdir_env_var=true\n" +
        "writable_roots=[" +
        JSON.stringify(allowed) +
        "]\n" +
        (selection === "named"
          ? '[permissions.qa-hook]\nextends=":read-only"\nfilesystem={' +
            JSON.stringify(outside) +
            '={ "."="write" }}\n'
          : ""),
    );
    const environment = patchSnapshotEnvironment(temporary, {
      ...process.env,
      CODEX_HOME: home,
      SYNTHETIC_MODEL_ACCESS: "synthetic fixture credential",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
    });
    const hook = join(directory, ".git", "hooks", "pre-push");
    await writeFile(
      hook,
      [
        "#!/bin/sh",
        "set -eu",
        'test "$1" = origin',
        'test -z "${SYNTHETIC_MODEL_ACCESS-}"',
        `grep -F 'refs/heads/${branch}' >/dev/null`,
        "echo 'Entered synthetic resumed hook' >&2",
        "echo reached > " + shell(join(allowed, "ran")),
        "echo denied > " + shell(denied),
      ].join("\n") + "\n",
      { mode: 0o755 },
    );
    const outcome = await runWorkflow(
      ["patch", "--resume-pr", branch, "--json"],
      {
        currentDirectory: directory,
        environment,
        onCodex: () => {
          throw new Error("Resuming a verified commit started a model turn.");
        },
        onRepositoryCommand: (command, args, cwd, options) =>
          command === "git"
            ? options?.hookSandbox
              ? runRepositoryCommand(command, args, cwd, {
                  ...options,
                  environment: { ...environment, ...options.environment },
                })
              : runGitRepositoryCommand(command, args, cwd, options)
            : args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1",
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(2);
    expect(outcome.stderr).toContain("Entered synthetic resumed hook");
    expect(
      await readFile(join(allowed, "ran"), "utf8").catch(() => null),
      outcome.stderr,
    ).toBe("reached\n");
    expect(await readFile(denied).catch(() => null)).toBeNull();
    expect(repositoryGit(remote)("for-each-ref", "--format=%(refname)")).toBe(
      "",
    );
  },
  process.platform === "win32" ? 300000 : 90000,
);

for (const linked of [false, true]) {
  test(
    `the commit-message hook veto keeps only validated edits (linked: ${linked})`,
    async () => {
      const { directory, git } = await publicationRepository(fixtures);
      const home = await fixtures.create("hook-veto-home-");
      const tmp = await fixtures.create("hook-veto-tmp-");
      await chmod(home, 0o700);
      await writeFile(join(home, "config.toml"), patchSnapshotWindowsConfig());
      const environment = patchSnapshotEnvironment(tmp, {
        ...process.env,
        CODEX_HOME: home,
      });
      const admin = join(directory, ".git");
      const message = join(admin, "COMMIT_EDITMSG");
      const hook = join(admin, "hooks", "commit-msg");
      await writeFile(
        hook,
        [
          "#!/bin/sh",
          "set -eu",
          ...(linked
            ? [
                `node -e 'const fs = require("node:fs"); const message = process.argv[1]; fs.linkSync(message, message + ".link"); fs.appendFileSync(message, "Reviewed-by: synthetic\\n");' "$1"`,
              ]
            : [
                'git interpret-trailers --in-place --trailer "Reviewed-by: synthetic" -- "$1"',
                "exit 7",
              ]),
        ].join("\n") + "\n",
        { mode: 0o755 },
      );
      const head = git("rev-parse", "HEAD");
      const result = runRepositoryCommand(
        "git",
        ["commit", "--allow-empty", "-m", "Synthetic candidate"],
        directory,
        {
          environment,
          publicationHooks: {
            gitDirectory: admin,
            events: new Set(["commit-msg"]),
            configured: new Set(),
          },
          hookMessagePath: message,
          hookSandbox: {
            directory,
            environment,
            profile: {
              extends: ":workspace",
              network: { enabled: false },
              filesystem: {
                [admin]: { ".": "read" },
                ":tmpdir": {},
                ":slash_tmp": {},
              },
            },
          },
        },
      );
      if (linked)
        await expect(result).rejects.toThrow(
          // The native Windows sandbox can deny creating the link before copyback.
          process.platform === "win32"
            ? /regular, unlinked COMMIT_EDITMSG|EPERM: operation not permitted, link .*COMMIT_EDITMSG' -> '.*COMMIT_EDITMSG\.link'/u
            : "regular, unlinked COMMIT_EDITMSG",
        );
      else await expect(result).rejects.toThrow();
      expect(git("rev-parse", "HEAD")).toBe(head);
      const retained = await readFile(message, "utf8");
      expect(retained).toContain("Synthetic candidate");
      expect(retained.includes("Reviewed-by: synthetic")).toBe(!linked);
    },
    process.platform === "win32" ? 120000 : 30000,
  );
}
