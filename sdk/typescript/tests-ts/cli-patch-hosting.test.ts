import { gitText } from "./support/shell.js";
import { afterEach, describe, expect, test, mock } from "bun:test";
import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import { dependencies } from "./cli-fixtures.js";
import { throwing } from "./support/errors.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

import {
  resultWithFindings,
  savedScan,
  completePatches,
  runWorkflow,
  runGitRepositoryCommand,
  publicationRepository as createPublicationRepository,
} from "./cli-patch-fixtures.js";

describe("patch change tracking", () => {
  const fixtures = createTemporaryDirectories(true);
  afterEach(fixtures.cleanup);
  const publicationRepository = () => createPublicationRepository(fixtures);

  test.each(
    ["local", "remote"].flatMap((location) =>
      [
        "codex-security",
        "codex-security/patch-scan-1",
        "codex-security/patch-scan-1/other",
        "codex-security/patch-scan-10",
        "archive/refs/heads/codex-security",
        "archive/refs/heads/codex-security/patch-scan-1",
        "archive/refs/heads/codex-security/patch-scan-1/other",
      ].map((existing) => [location, existing] as const),
    ),
  )(
    "checks %s branch namespace %s before patching",
    async (location, existing) => {
      const { directory, git, remote } = await publicationRepository();
      if (location === "remote")
        git("push", "origin", `HEAD:refs/heads/${existing}`);
      else git("branch", existing);
      const head = git("rev-parse", "HEAD");
      const before = git("ls-remote", remote);
      const blocked = [
        "codex-security",
        "codex-security/patch-scan-1",
        "codex-security/patch-scan-1/other",
      ].includes(existing);
      const result = resultWithFindings(["high"]);
      const onCodex = mock(
        async (
          args: readonly string[],
          output?: Parameters<ReturnType<typeof dependencies>["runCodex"]>[1],
        ) => {
          await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
          completePatches(args, output);
          return 0;
        },
      );
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onCodex,
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1",
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(blocked ? 2 : 0);
      expect(onCodex).toHaveBeenCalledTimes(blocked ? 0 : 1);
      if (blocked) {
        expect(git("rev-parse", "HEAD")).toBe(head);
        expect(git("branch", "--show-current")).toBe("main");
        expect(git("ls-remote", remote)).toBe(before);
      }
    },
  );

  test.each([
    ["insteadOf", "free"],
    ["insteadOf", "decoy"],
    ["insteadOf", "destination"],
    ["pushInsteadOf", "free"],
    ["pushInsteadOf", "decoy"],
    ["pushInsteadOf", "destination"],
  ] as const)(
    "checks the once-rewritten push destination: %s, collision=%s",
    async (rewrite, collision) => {
      const { directory, git } = await publicationRepository();
      const destination = await fixtures.create("patch-rewrite-destination=");
      const decoy = await fixtures.create("patch-rewrite-decoy-");
      for (const remote of [destination, decoy])
        git("clone", "--bare", directory, remote);
      const alias = join(directory, "rewrite-alias");
      git("remote", "set-url", "origin", alias);
      git("config", `url.${destination}.${rewrite}`, alias);
      git("config", `url.${decoy}.insteadOf`, destination);
      const branch = "codex-security/patch-scan-1";
      const head = git("rev-parse", "HEAD");
      if (collision !== "free")
        git(
          "--git-dir",
          collision === "decoy" ? decoy : destination,
          "update-ref",
          `refs/heads/${branch}`,
          head,
        );
      const decoyRefs = git("--git-dir", decoy, "show-ref");
      const configuration = git("config", "--get-regexp", "^(remote|url)\\.");
      expect(git("remote", "get-url", "--push", "origin")).toBe(destination);
      const result = resultWithFindings(["high"]);
      const onCodex = mock(
        async (
          args: readonly string[],
          output?: Parameters<ReturnType<typeof dependencies>["runCodex"]>[1],
        ) => {
          await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
          completePatches(args, output);
          return 0;
        },
      );
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onCodex,
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1",
        },
      );
      const blocked = collision === "destination";
      expect(outcome.exitCode, outcome.stderr).toBe(blocked ? 2 : 0);
      expect(onCodex).toHaveBeenCalledTimes(blocked ? 0 : 1);
      expect(git("--git-dir", decoy, "show-ref")).toBe(decoyRefs);
      expect(git("config", "--get-regexp", "^(remote|url)\\.")).toBe(
        configuration,
      );
      if (blocked) {
        expect(git("rev-parse", "HEAD")).toBe(head);
        expect(git("--git-dir", destination, "rev-parse", branch)).toBe(head);
      } else {
        expect(
          git("--git-dir", destination, "show", `${branch}:src/finding-1.ts`),
        ).toBe("fixed");
      }
    },
  );

  test.each([false, true])(
    "preserves remote proxy settings with collision=%j",
    async (collision) => {
      const { directory, git, remote } = await publicationRepository();
      const secondary = await fixtures.create("patch-proxy-secondary-");
      git("init", "--bare", secondary);
      for (const destination of [remote, secondary])
        git("--git-dir", destination, "config", "http.receivepack", "true");
      if (collision) git("push", secondary, "HEAD:refs/heads/codex-security");
      let requests = 0;
      const environment = { ...process.env };
      for (const key of Object.keys(environment))
        if (/^(?:https?|all|no)_proxy$/iu.test(key)) delete environment[key];
      const proxy = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        async fetch(request) {
          requests++;
          const url = new URL(request.url);
          const child = Bun.spawn(["git", "http-backend"], {
            env: {
              ...environment,
              GIT_PROJECT_ROOT: dirname(remote),
              GIT_HTTP_EXPORT_ALL: "1",
              REQUEST_METHOD: request.method,
              PATH_INFO: url.pathname,
              QUERY_STRING: url.search.slice(1),
              CONTENT_TYPE: request.headers.get("content-type") ?? "",
              CONTENT_LENGTH: request.headers.get("content-length") ?? "0",
              REMOTE_USER: "synthetic",
              GIT_PROTOCOL: request.headers.get("git-protocol") ?? "",
            },
            stdin: new Uint8Array(await request.arrayBuffer()),
            stdout: "pipe",
            stderr: "pipe",
          });
          const response = Buffer.from(
            await new Response(child.stdout).arrayBuffer(),
          );
          const errors = await new Response(child.stderr).text();
          expect(await child.exited, errors).toBe(0);
          const boundary = response.indexOf("\r\n\r\n");
          const headers = new Headers();
          let status = 200;
          for (const line of response
            .subarray(0, boundary)
            .toString()
            .split("\r\n")) {
            const colon = line.indexOf(":");
            const key = line.slice(0, colon),
              value = line.slice(colon + 1).trim();
            if (key.toLowerCase() === "status") status = Number.parseInt(value);
            else headers.set(key, value);
          }
          return new Response(response.subarray(boundary + 4), {
            status,
            headers,
          });
        },
      });
      try {
        git(
          "remote",
          "set-url",
          "origin",
          `http://127.0.0.2:${proxy.port}/${remote.split(/[\\/]/u).at(-1)!}`,
        );
        for (const destination of [remote, secondary])
          git(
            "remote",
            "set-url",
            "--add",
            "--push",
            "origin",
            `http://127.0.0.2:${proxy.port}/${destination.split(/[\\/]/u).at(-1)!}`,
          );
        git("config", "remote.origin.proxy", `http://127.0.0.1:${proxy.port}`);
        const remoteConfig = git("config", "--get-regexp", "^remote\\.");
        let models = 0;
        const outcome = await runWorkflow(
          ["patch", "Synthetic issue", "--create-pr", "--json"],
          {
            currentDirectory: directory,
            environment,
            onRepositoryCommand: async (command, args, cwd, options) => {
              if (command !== "git")
                return args[1] === "list"
                  ? "[]"
                  : "https://github.example.test/example/repository/pull/1";
              const child = promisify(execFile)("git", [...args], {
                cwd,
                env: { ...environment, ...options?.environment },
                maxBuffer: options?.maxBuffer,
              });
              child.child.stdin?.end(options?.input);
              const { stdout } = await child;
              return options?.trim === false ? stdout : stdout.trim();
            },
            onCodex: async (_args, output) => {
              models++;
              await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
              output?.stdout.write("Fixed and verified.");
              return 0;
            },
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(collision ? 2 : 0);
        expect(models).toBe(collision ? 0 : 1);
        expect(requests).toBeGreaterThanOrEqual(2);
        expect(git("config", "--get-regexp", "^remote\\.")).toBe(remoteConfig);
        if (collision) expect(outcome.stderr).toContain("already exists");
        else
          for (const destination of [remote, secondary])
            expect(
              git(
                "--git-dir",
                destination,
                "show",
                `${git("branch", "--show-current")}:src/finding-1.ts`,
              ),
            ).toBe("fixed");
      } finally {
        proxy.stop(true);
      }
    },
  );

  test.each([
    "free",
    "occupied",
    "race",
    "option",
    "uploadpack",
    "legacy-free",
    "legacy-occupied",
    "legacy-settings",
  ] as const)(
    "preserves all push destinations: second destination=%s",
    async (destination) => {
      const occupied =
        destination === "occupied" ||
        destination === "race" ||
        destination === "legacy-occupied" ||
        destination === "legacy-settings";
      const option = destination === "option";
      const { directory, git, remote } = await publicationRepository();
      const secondary = await fixtures.create("patch-destination-secondary-");
      git("clone", "--bare", directory, secondary);
      const branch = "codex-security/patch-scan-1";
      const original = git("rev-parse", "HEAD");
      const occupy = () =>
        git(
          "--git-dir",
          secondary,
          "update-ref",
          `refs/heads/${branch}`,
          original,
        );
      if (occupied && destination !== "race") occupy();
      git("remote", "set-url", "--add", "--push", "origin", remote);
      const marker = join(directory, "upload-pack-marker");
      const script = join(directory, "upload-pack.cjs");
      if (option)
        await writeFile(
          script,
          "require('node:fs').writeFileSync(process.argv[2], 'synthetic');\n",
        );
      const commandPath = (value: string) => `"${value.replaceAll("\\", "/")}"`;
      git(
        "config",
        "--add",
        "remote.origin.pushurl",
        option
          ? `--upload-pack=${commandPath(process.execPath)} ${commandPath(script)} ${commandPath(marker)}`
          : secondary,
      );
      const uploadTrace = join(directory, ".git", "transport-trace");
      if (destination === "uploadpack") {
        const transportDirectory = await fixtures.create("patch-transport-");
        const transport = join(transportDirectory, "transport.cjs");
        await writeFile(
          transport,
          `
const { spawnSync } = require("node:child_process");
const { appendFileSync } = require("node:fs");
if (process.argv[2] === "upload-pack") appendFileSync(${JSON.stringify(uploadTrace)}, process.argv[3] + "\\n");
const result = spawnSync(${JSON.stringify(Bun.which("git")!)}, [process.argv[2], process.argv[3].replace(/\\.logical$/, "")], { stdio: "inherit" });
process.exit(result.status ?? 1);
`,
        );
        for (const operation of ["upload", "receive"])
          git(
            "config",
            `remote.origin.${operation}pack`,
            `${commandPath(process.execPath)} ${commandPath(transport)} ${operation}-pack`,
          );
        git("config", "--unset-all", "remote.origin.pushurl");
        git("config", "--add", "remote.origin.pushurl", `${remote}.logical`);
        git("config", "--add", "remote.origin.pushurl", `${secondary}.logical`);
        git("push", "origin", "HEAD:refs/heads/native-control");
        git("ls-remote", "origin");
        await writeFile(uploadTrace, "");
      }
      if (destination.startsWith("legacy-")) {
        git("config", "--remove-section", "remote.origin");
        await mkdir(join(directory, ".git", "remotes"));
        await writeFile(
          join(directory, ".git", "remotes", "origin"),
          `URL: ${remote}\nURL: ${secondary}\nPull: refs/heads/main:refs/remotes/origin/main\n`,
        );
        if (destination === "legacy-settings")
          git("config", "remote.origin.skipDefaultUpdate", "true");
      }
      const before = git("ls-remote", secondary, `refs/heads/${branch}`);
      const result = resultWithFindings(["high"]);
      const onCodex = mock(
        async (
          args: readonly string[],
          output?: Parameters<ReturnType<typeof dependencies>["runCodex"]>[1],
        ) => {
          if (destination === "race") occupy();
          await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
          completePatches(args, output);
          return 0;
        },
      );
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onCodex,
          onRepositoryCommand: async (command, args, cwd, options) => {
            if (command === "git") {
              const execution = promisify(execFile)("git", [...args], {
                cwd: options?.directory ?? cwd,
                env: { ...process.env, ...options?.environment },
                maxBuffer: options?.maxBuffer,
              });
              execution.child.stdin?.end(options?.input);
              const { stdout } = await execution;
              return options?.trim === false ? stdout : stdout.trim();
            }
            return args[0] === "repo"
              ? "synthetic-origin-id"
              : args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1";
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(occupied || option ? 2 : 0);
      if (destination === "uploadpack")
        expect(
          (await readFile(uploadTrace, "utf8")).trim().split("\n"),
        ).toEqual([`${remote}.logical`, `${secondary}.logical`]);
      expect(onCodex).toHaveBeenCalledTimes(
        (occupied && destination !== "race") || option ? 0 : 1,
      );
      await expect(readFile(marker)).rejects.toMatchObject({ code: "ENOENT" });
      if ((occupied && destination !== "race") || option) {
        if (destination.startsWith("legacy-"))
          expect(outcome.stderr).toContain("already exists");
        expect(git("rev-parse", "HEAD")).toBe(original);
        expect(git("ls-remote", remote, `refs/heads/${branch}`)).toBe("");
        expect(git("ls-remote", secondary, `refs/heads/${branch}`)).toBe(
          before,
        );
        return;
      }
      if (occupied) {
        if (occupied)
          expect(
            git("--git-dir", secondary, "rev-parse", `refs/heads/${branch}`),
          ).toBe(original);
        else
          expect(git("ls-remote", secondary, `refs/heads/${branch}`)).toBe(
            before,
          );
        const saved = git(
          "config",
          "--get",
          `branch.${branch}.codexSecurityPatchCommit`,
        );
        expect(saved).toBe(git("rev-parse", `refs/heads/${branch}`));
        expect(saved).not.toBe(original);
        expect(git("ls-remote", remote, `refs/heads/${branch}`)).toContain(
          saved,
        );
        expect(outcome.stderr).toContain("--resume-pr");
      } else {
        for (const target of [remote, secondary])
          expect(git("ls-remote", target, `refs/heads/${branch}`)).toContain(
            git("rev-parse", "HEAD"),
          );
      }
    },
  );

  test.each(
    [
      "local",
      "www",
      "www-mixed",
      "www-scp",
      "ssh-mirror",
      "https-mirror",
      "ssh-mirror-only",
      "https-mirror-only",
      "renamed",
      "transferred",
      "multiple-hosted",
      "no-candidates",
      "local-first",
      "file-first",
      "windows-first",
      "local-fetch",
      "local-fetch-ghrepo",
      "local-push-only",
      "network-push-only",
      "ssh-api",
      "ssh-api-port",
      "https-api-port",
      "scp-absolute-api-port",
      "ssh-uri-api-port",
      "ssh-uri-git+ssh-api-port",
      "ssh-uri-ssh+git-api-port",
      "ssh-enterprise",
      "scp",
      "scp-userless",
      "scp-ipv6",
      "scp-ipv6-userless",
      "scp-ipv6-api",
      "scp-expanded-ipv6-api",
      "scp-ipv6-scoped",
      "scp-ipv6-scoped-userless",
      "scp-percent",
      "ssh-uri-percent",
      "scp-mixed",
      "scp-absolute",
      "scp-absolute-command",
      "ssh-uri",
      "ssh-uri-mixed",
      "ssh-uri-git+ssh",
      "ssh-uri-ssh+git",
      "ssh-uri-git+ssh-command",
      "ssh-uri-ssh+git-command",
      "ssh-missing",
      "ssh-failed",
      "ssh-host",
      "ssh-empty",
      "scp-core",
      "ssh-uri-core",
      "scp-command",
      "ssh-uri-command",
      "scp-executable",
      "ssh-uri-executable",
      "scp-core-executable",
      "ssh-uri-core-executable",
    ].flatMap((transport) =>
      [false, true].flatMap((resume) =>
        (transport === "no-candidates" ? [false] : [false, true]).map(
          (ownIncluded) => ({
            transport,
            resume,
            ownIncluded,
          }),
        ),
      ),
    ),
  )(
    "uses the push repository for $transport: resume=$resume, own PR=$ownIncluded",
    async ({ transport, resume, ownIncluded }) => {
      const { directory, git, remote } = await publicationRepository();
      const configuredCommand = 'ssh -F "synthetic config"';
      const coreCommand = transport.includes("core")
        ? configuredCommand
        : transport.endsWith("command")
          ? "ignored-ssh"
          : undefined;
      const environment: NodeJS.ProcessEnv = transport.endsWith("command")
        ? { GIT_SSH_COMMAND: configuredCommand, GIT_SSH: "ignored-ssh" }
        : transport.endsWith("executable")
          ? { GIT_SSH: "synthetic path/ssh" }
          : {};
      if (transport === "local-fetch-ghrepo" || transport.endsWith("push-only"))
        environment["GH_REPO"] = "upstream-owner/repository";
      const effectiveCommand =
        environment["GIT_SSH_COMMAND"] ??
        coreCommand ??
        (environment["GIT_SSH"] === undefined ? "ssh" : '"$GIT_SSH"');
      const alias = transport.includes("ipv6")
        ? transport.includes("scoped")
          ? "[fe80::1%lo]"
          : transport.endsWith("ipv6-api")
            ? transport.includes("expanded")
              ? "[0:0:0:0:0:0:0:1]"
              : "[::1]"
            : "[2001:db8::1]"
        : transport.endsWith("-mixed")
          ? "GitHub-Work"
          : "github-work";
      const localFirst = [
        "local-first",
        "file-first",
        "windows-first",
      ].includes(transport);
      const localOnly =
        transport.startsWith("local-fetch") || transport === "local-push-only";
      const apiPort = transport.endsWith("-api-port") ? ":8443" : "";
      const hostingHost = transport.endsWith("ipv6-api")
        ? "[::1]"
        : transport === "ssh-enterprise" || apiPort
          ? "enterprise.example.test"
          : "github.com";
      const hostingUrl = `https://${hostingHost}${apiPort}`;
      if (apiPort)
        environment["GH_REPO"] = `${hostingHost}${apiPort}/upstream/repository`;
      const fetchRemote = `${hostingUrl}/fetch-owner/repository.git`;
      const mirror = transport.includes("mirror")
        ? `${transport.startsWith("ssh") ? "ssh://git@" : "https://"}mirror.example.test/srv/git/repository.git`
        : undefined;
      const sshScheme = transport.includes("git+ssh")
        ? "git+ssh"
        : transport.includes("ssh+git")
          ? "ssh+git"
          : "ssh";
      const remoteUser = transport.includes("percent") ? "git%2Duser" : "git";
      const repositoryPath = transport.includes("percent")
        ? "example/repository%2Dname.git"
        : "example/repository.git";
      const pushRemote =
        transport === "https-api-port"
          ? `${hostingUrl}/push-owner/repository.git`
          : transport === "www-scp"
            ? "git@www.github.com:push-owner/repository.git"
            : transport === "www" || transport === "www-mixed"
              ? `https://${transport === "www-mixed" ? "www.GitHub.COM" : "www.github.com"}/push-owner/repository.git`
              : mirror && transport.endsWith("only")
                ? mirror
                : transport === "renamed"
                  ? `${hostingUrl}/push-owner/old-name.git`
                  : transport === "transferred"
                    ? `${hostingUrl}/old-owner/repository.git`
                    : localFirst ||
                        mirror ||
                        [
                          "network-push-only",
                          "multiple-hosted",
                          "no-candidates",
                        ].includes(transport)
                      ? `${hostingUrl}/push-owner/repository.git`
                      : transport === "local" || localOnly
                        ? remote
                        : transport.endsWith("userless")
                          ? `${transport === "scp-userless" ? "github.com" : alias}:example/repository.git`
                          : transport === "ssh-api" ||
                              transport === "ssh-api-port"
                            ? `git@${hostingHost}:push-owner/repository.git`
                            : transport === "ssh-enterprise"
                              ? "git@enterprise.example.test:push-owner/other-repository.git"
                              : transport.startsWith("scp")
                                ? `${remoteUser}@${alias}:${transport.includes("absolute") ? "/" : ""}${repositoryPath}`
                                : transport.startsWith("ssh-uri")
                                  ? `${sshScheme}://${remoteUser}@${alias}:2222/${repositoryPath}`
                                  : `git@${["ssh-missing", "ssh-failed", "ssh-empty"].includes(transport) ? alias : "ssh.github.com"}:example/repository.git`;
      const aliasLookup =
        (transport.startsWith("scp") &&
          transport !== "scp-userless" &&
          !transport.endsWith("ipv6-api")) ||
        transport.startsWith("ssh-uri") ||
        ["ssh-missing", "ssh-failed", "ssh-empty"].includes(transport);
      const lookupRemote =
        transport === "local" || transport === "local-push-only"
          ? undefined
          : localOnly ||
              (mirror && transport.endsWith("only")) ||
              ["ssh-missing", "ssh-failed", "ssh-empty"].includes(transport)
            ? `${hostingHost}${apiPort}/fetch-owner/repository`
            : transport === "renamed"
              ? `${hostingHost}/push-owner/old-name`
              : transport === "transferred"
                ? `${hostingHost}/old-owner/repository`
                : transport === "ssh-enterprise"
                  ? `${hostingHost}/push-owner/other-repository`
                  : localFirst ||
                      mirror ||
                      [
                        "www",
                        "www-mixed",
                        "www-scp",
                        "network-push-only",
                        "multiple-hosted",
                        "no-candidates",
                        "ssh-api",
                        "ssh-api-port",
                        "https-api-port",
                      ].includes(transport)
                    ? `${hostingHost}${apiPort}/push-owner/repository`
                    : `${hostingHost}${apiPort}/example/${transport === "scp-percent" ? "repository%2Dname" : transport === "ssh-uri-percent" ? "repository-name" : "repository"}`;
      const sshArguments = [
        ...(transport.startsWith("ssh-uri") ? ["-p", "2222"] : []),
        transport.includes("ipv6")
          ? `${transport.endsWith("userless") ? "" : "git@"}${alias.slice(1, -1)}`
          : transport === "scp-userless"
            ? "github.com"
            : `${transport === "ssh-uri-percent" ? "git-user" : remoteUser}@${aliasLookup ? alias : "ssh.github.com"}`,
      ];
      if (transport !== "local") {
        git("remote", "set-url", "origin", fetchRemote);
        git(
          "remote",
          "set-url",
          "--push",
          "origin",
          mirror ??
            (transport === "multiple-hosted"
              ? `${hostingUrl}/first-owner/repository.git`
              : localFirst
                ? transport === "file-first"
                  ? pathToFileURL(remote).href
                  : transport === "windows-first"
                    ? "C:\\synthetic\\mirror.git"
                    : remote
                : pushRemote),
        );
        if (
          localFirst ||
          (mirror && !transport.endsWith("only")) ||
          transport === "multiple-hosted"
        )
          git("remote", "set-url", "--add", "--push", "origin", pushRemote);
        git(
          "remote",
          "add",
          "upstream",
          `${hostingUrl}/upstream-owner/repository.git`,
        );
      }
      if (transport.endsWith("push-only"))
        git("config", "--unset-all", "remote.origin.url");
      const branch = "codex-security/patch-scan-1";
      const commit = git("rev-parse", "HEAD");
      if (resume) {
        git("branch", branch);
        git("config", `branch.${branch}.codexSecurityPatchCommit`, commit);
        git(
          "config",
          `branch.${branch}.codexSecurityPatchPullRequestBody`,
          "Synthetic body",
        );
      }
      const unresolvedPush =
        ["ssh-missing", "ssh-failed", "ssh-empty"].includes(transport) ||
        transport === "ssh-mirror-only" ||
        transport === "https-mirror-only";
      const matchingRequest = ownIncluded && !unresolvedPush;
      const result = resultWithFindings(["high"]);
      let modelCalls = 0;
      let pushes = 0;
      let repositoryLookups = 0;
      let sshLookups = 0;
      const ownUrl = `${hostingUrl}/upstream/repository/pull/8`;
      const createdUrl = `${hostingUrl}/upstream/repository/pull/9`;
      const outcome = await runWorkflow(
        resume
          ? ["patch", "--resume-pr", branch, "--json"]
          : ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          environment,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "git") {
              if (args.join(" ") === "config --get core.sshCommand") {
                if (coreCommand !== undefined) return coreCommand;
                throw Object.assign(new Error("Synthetic missing Git config"), {
                  code: 1,
                });
              }
              if (args[2] === "codex-security-ssh-config") {
                sshLookups++;
                expect(args.slice(0, 3)).toEqual([
                  "-c",
                  `alias.codex-security-ssh-config=!${effectiveCommand} -G`,
                  "codex-security-ssh-config",
                ]);
                if (
                  mirror?.startsWith("ssh:") &&
                  args.at(-1) === "git@mirror.example.test"
                ) {
                  expect(args.slice(3)).toEqual(["git@mirror.example.test"]);
                  return "hostname mirror.example.test";
                }
                expect(args.slice(3)).toEqual(sshArguments);
                if (transport === "ssh-missing" || transport === "ssh-failed")
                  throw Object.assign(
                    new Error("Synthetic SSH lookup failure"),
                    {
                      code: transport === "ssh-missing" ? 127 : 1,
                    },
                  );
                return transport === "ssh-empty"
                  ? ""
                  : `hostname ${transport.endsWith("ipv6-api") ? "::1" : transport === "ssh-host" ? "ssh.github.com" : hostingHost}`;
              }
              if (args[0] === "ls-remote") {
                expect(args.slice(0, 3)).toEqual([
                  "ls-remote",
                  "--heads",
                  "--",
                ]);
                expect(args.slice(4)).toEqual([
                  "refs/heads/codex-security",
                  `refs/heads/${branch}`,
                  `refs/heads/${branch}/*`,
                ]);
                return runGitRepositoryCommand(
                  command,
                  [...args.slice(0, 3), remote, ...args.slice(4)],
                  cwd,
                  options,
                );
              }
              if (args[0] === "push") {
                pushes++;
                expect(args).toEqual([
                  "push",
                  "--set-upstream",
                  `--force-with-lease=refs/heads/${branch}:`,
                  "origin",
                  branch,
                ]);
                return runGitRepositoryCommand(
                  command,
                  [
                    "push",
                    "--set-upstream",
                    `--force-with-lease=refs/heads/${branch}:`,
                    remote,
                    branch,
                  ],
                  cwd,
                  options,
                );
              }
              return runGitRepositoryCommand(command, args, cwd, options);
            }
            if (args[0] === "repo") {
              const selectedToken = gitText(
                ["config", "--get", "remote.codex-security-push.url"],
                {
                  cwd: options?.directory ?? cwd,
                  env: {
                    ...process.env,
                    ...environment,
                    ...options?.environment,
                  },
                },
              ).trim();
              const selectedRemote = gitText(
                ["ls-remote", "--get-url", selectedToken],
                {
                  cwd: options?.directory ?? cwd,
                  env: {
                    ...process.env,
                    ...environment,
                    ...options?.environment,
                  },
                },
              ).trim();
              expect(options?.environment?.["GH_REPO"]).toBe("");
              expect(options?.environment?.["GH_HOST"]).toBe(hostingHost);
              const unresolved =
                selectedRemote === remote ||
                selectedRemote === "origin" ||
                selectedRemote.startsWith("file:") ||
                selectedRemote.startsWith("C:\\") ||
                selectedRemote.includes("mirror.example.test") ||
                selectedRemote.toLowerCase().includes("github-work");
              const first = selectedRemote.includes("/first-owner/repository");
              const expected = first
                ? `${hostingHost}${apiPort}/first-owner/repository`
                : lookupRemote!;
              const selectedRepository = expected?.slice(
                expected.indexOf("/") + 1,
              );
              if (args[1] === "set-default") {
                expect(args).toEqual(["repo", "set-default", "--view"]);
                return unresolved ? "" : selectedRepository;
              }
              expect(unresolved).toBe(false);
              expect(args).toEqual([
                "repo",
                "view",
                ...(apiPort
                  ? [`${hostingHost}${apiPort}/${selectedRepository}`]
                  : []),
                "--json",
                "id,url",
                "--jq",
                "tojson",
              ]);
              repositoryLookups++;
              expect(
                decodeURIComponent(new URL(selectedRemote).pathname)
                  .replace(/^\/+|\/+$/gu, "")
                  .replace(/\.git$/u, ""),
              ).toBe(selectedRepository);
              return JSON.stringify({
                id: first ? "synthetic-first-id" : "synthetic-origin-id",
                url: `${hostingUrl}/${first ? "first-owner" : "canonical-owner"}/repository`,
              });
            }
            if (args[1] === "list") {
              expect(args).toEqual([
                "pr",
                "list",
                "--head",
                branch,
                "--state",
                "all",
                "--json",
                "url,state,headRefOid,headRepository,isCrossRepository",
                "--jq",
                "map({url, head: .headRefOid, state, repositoryId: .headRepository.id, crossRepository: .isCrossRepository}) | tojson",
              ]);
              return JSON.stringify(
                transport === "no-candidates"
                  ? []
                  : [
                      {
                        url: `${hostingUrl}/upstream/repository/pull/7`,
                        head: commit,
                        repositoryId: "synthetic-foreign-id",
                        state: "OPEN",
                        crossRepository: true,
                      },
                      ...(ownIncluded
                        ? [
                            {
                              url: ownUrl,
                              head: commit,
                              repositoryId: "synthetic-origin-id",
                              state: "OPEN",
                              crossRepository: !!lookupRemote,
                            },
                          ]
                        : []),
                    ],
              );
            }
            return createdUrl;
          },
          onCodex: async (args, output) => {
            modelCalls++;
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(
        !resume && matchingRequest ? 2 : 0,
      );
      const attempts = !resume && !matchingRequest ? 2 : 1;
      expect(repositoryLookups).toBe(
        (!lookupRemote || unresolvedPush || transport === "no-candidates"
          ? 0
          : transport === "multiple-hosted"
            ? 2
            : 1) * attempts,
      );
      expect(sshLookups).toBe(
        (aliasLookup || mirror?.startsWith("ssh:") ? 1 : 0) * attempts,
      );
      expect(modelCalls).toBe(resume || matchingRequest ? 0 : 1);
      expect(pushes).toBe(matchingRequest ? 0 : 1);
      if (resume || !matchingRequest)
        expect(JSON.parse(outcome.stdout).pullRequest.url).toBe(
          matchingRequest ? ownUrl : createdUrl,
        );
    },
  );

  test("resumes publication with SSH available only in Git's subprocess PATH", async () => {
    const { directory, git } = await publicationRepository();
    const sshDirectory = await fixtures.create("patch-git-ssh-");
    await writeFile(
      join(sshDirectory, "ssh"),
      '#!/bin/sh\n[ "$1" = "-G" ] && [ "$2" = "git@GitHub-Work" ] || exit 1\nprintf "hostname github.com\\n"\n',
      { mode: 0o755 },
    );
    const emptyPath = await fixtures.create("patch-no-ssh-");
    const gitExecutable = Bun.which("git")!;
    expect(Bun.which("ssh", { PATH: emptyPath })).toBeNull();
    const environment = {
      PATH: emptyPath,
      GIT_EXEC_PATH: sshDirectory,
      GIT_SSH: undefined,
      GIT_SSH_COMMAND: undefined,
    };
    git(
      "remote",
      "set-url",
      "origin",
      "https://github.com/example/repository.git",
    );
    git(
      "remote",
      "set-url",
      "--push",
      "origin",
      "git@GitHub-Work:example/repository.git",
    );
    const branch = "codex-security/saved-patch";
    const commit = git("rev-parse", "HEAD");
    git("branch", branch);
    git("config", `branch.${branch}.codexSecurityPatchCommit`, commit);
    const url = "https://github.com/example/repository/pull/1";
    let repositoryLookups = 0;
    const outcome = await runWorkflow(
      ["patch", "--resume-pr", branch, "--json"],
      {
        currentDirectory: directory,
        environment,
        onRepositoryCommand: async (command, args, cwd, options) => {
          if (command === "gh") {
            if (args[0] === "pr" && args[1] === "list")
              return JSON.stringify([
                {
                  url,
                  head: commit,
                  repositoryId: "synthetic-id",
                  state: "OPEN",
                  crossRepository: true,
                },
              ]);
            if (args[1] === "set-default") {
              expect(args).toEqual(["repo", "set-default", "--view"]);
              return "example/repository";
            }
            expect(args).toEqual([
              "repo",
              "view",
              "--json",
              "id,url",
              "--jq",
              "tojson",
            ]);
            repositoryLookups++;
            return JSON.stringify({
              id: "synthetic-id",
              url: "https://github.com/example/repository",
            });
          }
          const { stdout } = await promisify(execFile)(
            command === "git" ? gitExecutable : command,
            args,
            {
              cwd,
              env: { ...process.env, ...environment, ...options?.environment },
              encoding: "utf8",
            },
          );
          return options?.trim === false ? stdout : stdout.trim();
        },
        onCodex: throwing("must reuse the saved patch"),
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(JSON.parse(outcome.stdout).pullRequest.url).toBe(url);
    expect(repositoryLookups).toBe(1);
  });
});
