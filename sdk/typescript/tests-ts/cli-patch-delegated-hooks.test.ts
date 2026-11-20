import { expect, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { chmod, mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { runRepositoryCommand } from "../src/cli.js";
import { resolveCodexCommand } from "../src/runtime.js";
import {
  verifiedPatchResponse,
  publicationRepository,
  repositoryGit,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
  patchDirectories,
} from "./cli-patch-fixtures.js";
import {
  patchSnapshotEnvironment,
  patchSnapshotWindowsConfig,
} from "./support/patch-snapshot-environment.js";

const fixtures = patchDirectories();
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
      const operator = await fixtures.create("hook-operator-config-");
      const global = join(operator, "operator.gitconfig");
      const branchConfig = join(directory, ".git", "branch.gitconfig");
      const credential = join(operator, "selected-netrc");
      await writeFile(
        credential,
        "machine example.invalid login fixture password synthetic\n",
      );
      git(
        "config",
        "--file",
        global,
        "filter.fixture=driver.clean",
        "git hash-object --stdin",
      );
      git("config", "filter.checkout.clean", "cat");
      git("config", "--file", branchConfig, "filter.branchonly.clean", "cat");
      git(
        "config",
        "--file",
        global,
        "includeIf.onbranch:codex-security/**.path",
        branchConfig,
      );
      const environment = patchSnapshotEnvironment(tmp, {
        ...process.env,
        CODEX_HOME: home,
        NETRC: credential,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: global,
      });
      await writeFile(
        join(directory, ".gitattributes"),
        "hook-check-input filter=fixture=driver\n",
      );
      const delegate = join(directory, "check.sh");
      await writeFile(delegate, "exit 0\n");
      git("add", "check.sh", ".gitattributes");
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
      const invoke = (args: string[]) =>
        runWorkflow(args, {
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
              return runGitRepositoryCommand(cmd, args, cwd, {
                ...options,
                environment: { ...environment, ...options?.environment },
              });
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
                GIT_CONFIG_PARAMETERS: [
                  "'http.extraheader'='Authorization: SYNTHETIC_HOOK_SECRET' 'demo.sentinel'='benign preserved' " +
                    "'demo.command=setting.value'='preserve quoted key' " +
                    "'url.https://synthetic:SYNTHETIC_HOOK_SECRET@unused.invalid/.insteadof'='https://unused.invalid/old' " +
                    "'remote.unused.pushurl'='https://SYNTHETIC_HOOK_SECRET@unused.invalid/' " +
                    "'url.ssh://git@benign.invalid/.insteadof'='ssh://git@old.invalid/'",
                  options.environment?.["GIT_CONFIG_PARAMETERS"],
                ]
                  .filter(Boolean)
                  .join(" "),
              },
            });
          },
          onCodex: async (_args, output) => {
            const server = output!.appServer!;
            expect(server.permissions!.credentialStorePaths).toContain(
              credential,
            );
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
                  [credential]: { ".": "deny" },
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
                'test "$(git config --get demo.command=setting.value)" = "preserve quoted key"',
                'test "$(git config --get filter.fixture=driver.clean)" = "git hash-object --stdin"',
                'test "$(git config --get filter.checkout.clean)" = ""',
                'test "$(git config --get filter.branchonly.clean)" = ""',
                "expected=$(printf ordinary | git hash-object --stdin | git hash-object --stdin)",
                'test "$(printf ordinary | git hash-object --path=hook-check-input --stdin)" = "$expected"',
                "if cat " +
                  shell(credential) +
                  " >/dev/null 2>&1; then exit 17; fi",
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
              verifiedPatchResponse(
                ["src/finding-1.ts", "check.sh"],
                "Synthetic regression passed.",
              ),
            );
            return 0;
          },
        });
      const outcome = await invoke([
        "patch",
        "--scan",
        "scan-1",
        "--create-pr",
        "--json",
      ]);
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(
        await readFile(join(allowed, "hook-ran"), "utf8").catch(() => null),
        outcome.stderr,
      ).toBe("reached");
      expect(await readFile(privateFile).catch(() => null)).toBeNull();
      expect(trustedHostPush).toBe(false);
      const receiver = repositoryGit(remote);
      expect(receiver("for-each-ref", "--format=%(refname)")).toBe("");
      if (outside) return;
      const branch = "codex-security/patch-scan-1";
      const commit = git("rev-parse", branch);
      expect(git("log", "-1", "--format=%B", commit)).toBe(
        "Verified synthetic message\n\nReviewed-by: Synthetic Validator",
      );
      expect(outcome.stderr).toContain(commit);
      expect(outcome.stderr).toContain(`patch --resume-pr ${branch}`);
      const resumed = await invoke(["patch", "--resume-pr", branch, "--json"]);
      expect(resumed.exitCode, resumed.stderr).toBe(0);
      expect(trustedHostPush).toBe(true);
      expect(receiver("rev-parse", branch)).toBe(commit);
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
    const allowed =
      process.platform === "linux"
        ? join(home, "approved-output")
        : await fixtures.create("resume-hook-approved-output-");
    await mkdir(allowed, { recursive: true });
    const login = join(allowed, "selected-netrc");
    await writeFile(login, "synthetic login");
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
        '[model_providers.hook-fixture]\nname="Synthetic"\nbase_url="http://127.0.0.1:1/v1"\nenv_key="Synthetic_Model_Access"\n' +
        '[shell_environment_policy.set]\nSynthetic_Model_Access="synthetic policy credential"\n' +
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
      NETRC: login,
      Synthetic_Model_Access: "synthetic fixture credential",
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
        `if grep -q 'synthetic login' ${shell(login)}; then exit 16; fi`,
        'if test -n "${Synthetic_Model_Access+x}"; then echo "Hook received the configured provider credential" >&2; exit 15; fi',
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

for (const mode of ["veto", "hardlink", "junction"]) {
  const linked = mode === "hardlink";
  const junction = mode === "junction";
  test.skipIf(junction && process.platform !== "win32")(
    junction
      ? "Windows commit-message copyback rejects a redirected staging directory"
      : `the commit-message hook veto keeps only validated edits (linked: ${linked})`,
    async () => {
      const { directory, git } = await publicationRepository(fixtures);
      const home = await fixtures.create("hook-veto-home-");
      const tmp = await fixtures.create("hook-veto-tmp-");
      await chmod(home, 0o700);
      await writeFile(join(home, "config.toml"), patchSnapshotWindowsConfig());
      const environment = patchSnapshotEnvironment(tmp, {
        ...process.env,
        CODEX_HOME: home,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
      });
      const bootstrapMarker = join(home, "checked-message-bootstrap");
      if (!linked && process.platform !== "win32") {
        const native = resolveCodexCommand(environment).command;
        const wrapper = join(home, "codex-hook-bootstrap");
        await writeFile(
          wrapper,
          [
            "#!/bin/sh",
            "set -eu",
            'test -z "${LD_LIBRARY_PATH-}"',
            'for argument in "$@"; do last=$argument; done',
            'case "${last-}" in */COMMIT_EDITMSG)',
            '  if test -e "$last"; then echo "private message existed before sandbox provisioning" >&2; exit 73; fi',
            `  printf checked > ${shell(bootstrapMarker)} ;;`,
            "esac",
            `exec ${shell(native)} "$@"`,
          ].join("\n") + "\n",
          { mode: 0o700 },
        );
        environment["CODEX_CLI_PATH"] = wrapper;
      }
      const admin = join(directory, ".git");
      const message = join(admin, "COMMIT_EDITMSG");
      const hook = join(admin, "hooks", "commit-msg");
      const subject = junction
        ? "Synthetic candidate " + randomUUID()
        : "Synthetic candidate";
      const hostTemp = await realpath(tmpdir());
      const stagePath =
        /^codex-security-hook-message-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}[\\/]message[\\/]COMMIT_EDITMSG$/iu;
      const outside = junction
        ? await fixtures.create("hook-junction-target-")
        : undefined;
      if (outside) {
        await writeFile(
          join(outside, "COMMIT_EDITMSG"),
          "Outside fixture sentinel\n",
        );
        // Only move the fixture's nonce-marked message stage into its disposable checkout.
        await writeFile(
          join(admin, "redirect-message.cjs"),
          `
const fs = require("node:fs"), path = require("node:path");
const [message, root, target, subject] = process.argv.slice(2);
const stage = path.dirname(path.resolve(message));
if (!${stagePath}.test(path.relative(root, path.resolve(message))) ||
    path.relative(stage, fs.realpathSync.native(stage)) ||
    !fs.lstatSync(message).isFile() || !fs.readFileSync(message, "utf8").includes(subject))
  throw new Error("Unexpected message stage");
const record = status => fs.writeFileSync("junction-progress", status);
record("attempted");
let syscall = "rename";
try {
  fs.renameSync(stage, "displaced-stage");
  syscall = "symlink";
  fs.symlinkSync(target, stage, "junction");
  record("redirected");
} catch (e) {
  if (e.syscall !== syscall || !["EPERM", "EACCES", "EBUSY"].includes(e.code) ||
      path.relative(stage, syscall === "rename" ? e.path : e.dest)) throw e;
  record("denied " + syscall);
  process.exitCode = 7;
}
`,
        );
      }
      await writeFile(
        hook,
        [
          "#!/bin/sh",
          "set -eu",
          ...(outside
            ? [
                'exec node .git/redirect-message.cjs "$1" ' +
                  [hostTemp, outside, subject].map(shell).join(" "),
              ]
            : linked
              ? [
                  `node -e 'const fs = require("node:fs"); const message = process.argv[1]; fs.linkSync(message, message + ".link"); fs.appendFileSync(message, "Reviewed-by: synthetic\\n");' "$1"`,
                ]
              : [
                  'printf "\\nReviewed-by: synthetic\\n" >> "$1"',
                  'cat "$1" > veto-progress',
                  'printf "%s" "$1" > veto-stage-path',
                  'echo "Synthetic veto stdout"',
                  'echo "Synthetic veto stderr" >&2',
                  "exit 7",
                ]),
        ].join("\n") + "\n",
        { mode: 0o755 },
      );
      const head = git("rev-parse", "HEAD");
      const result = runRepositoryCommand(
        "git",
        ["commit", "--allow-empty", "-m", subject],
        directory,
        {
          environment: { ...environment, LD_LIBRARY_PATH: directory },
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
      if (outside) {
        const failure = await result.then(
          () => undefined,
          (error: Error) => error,
        );
        expect(failure).toBeInstanceOf(Error);
        const receipt = await readFile(
          join(directory, "junction-progress"),
          "utf8",
        );
        expect(
          ["redirected", "denied rename", "denied symlink"],
          failure?.message,
        ).toContain(receipt);
        expect(await readFile(join(outside, "COMMIT_EDITMSG"), "utf8")).toBe(
          "Outside fixture sentinel\n",
        );
        expect(await readFile(message, "utf8")).not.toContain(
          "Outside fixture sentinel",
        );
      } else if (linked)
        await expect(result).rejects.toThrow(
          // The native Windows sandbox can deny creating the link before copyback.
          process.platform === "win32"
            ? /regular, unlinked COMMIT_EDITMSG|EPERM: operation not permitted, link .*COMMIT_EDITMSG' -> '.*COMMIT_EDITMSG\.link'/u
            : "regular, unlinked COMMIT_EDITMSG",
        );
      else {
        const failure = await result.then(
          () => undefined,
          (error: Error) => error,
        );
        expect(failure).toBeInstanceOf(Error);
        expect(failure?.message).toContain("Synthetic veto stdout");
        expect(failure?.message).toContain("Synthetic veto stderr");
        if (process.platform === "win32") {
          const staged = await readFile(
            join(directory, "veto-stage-path"),
            "utf8",
          );
          expect(relative(hostTemp, staged)).toMatch(stagePath);
        }
        // Record the bytes before vetoing, independently of Git's diagnostic.
        const edited = await readFile(
          join(directory, "veto-progress"),
          "utf8",
        ).catch((error: NodeJS.ErrnoException) => error.code);
        expect(edited, failure?.message).toContain("Reviewed-by: synthetic");
        expect(edited).toBe(await readFile(message, "utf8"));
        if (process.platform !== "win32")
          expect(await readFile(bootstrapMarker, "utf8")).toBe("checked");
      }
      expect(git("rev-parse", "HEAD")).toBe(head);
      const retained = await readFile(message, "utf8");
      expect(retained).toContain("Synthetic candidate");
      expect(retained.includes("Reviewed-by: synthetic")).toBe(mode === "veto");
    },
    process.platform === "win32" ? 120000 : 30000,
  );
}
