import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import {
  capture,
  dependencies,
  fakePreflight,
  fakeResult,
} from "./support/cli.js";

describe("CLI authentication", () => {
  test("delegates login and logout to bundled Codex without starting a scan", async () => {
    const cases = [
      ["login"],
      ["login", "--device-auth"],
      ["login", "--with-api-key"],
      ["login", "--with-access-token"],
      ["login", "status"],
      ["logout"],
    ] as const;
    for (const argv of cases) {
      const stdout = capture();
      const stderr = capture();
      const deps = dependencies();
      let forwarded: readonly string[] | undefined;
      deps.createSecurity = () => {
        throw new Error("must not initialize Codex Security");
      };
      deps.runCodex = async (args) => {
        forwarded = args;
        return 17;
      };
      expect(await main(argv, stdout.stream, stderr.stream, deps)).toBe(17);
      expect(forwarded).toEqual([
        argv[0],
        ...argv.slice(1),
        "-c",
        'cli_auth_credentials_store="file"',
      ]);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toBe("");
    }
  });

  test("explains when an environment API key overrides the stored login", async () => {
    for (const [environment, expectedSource] of [
      [{ OPENAI_API_KEY: "sk-proj-SYNTHETIC_SECRET_123" }, "OPENAI_API_KEY"],
      [{ Codex_Api_Key: "sk-proj-SYNTHETIC_SECRET_456" }, "CODEX_API_KEY"],
    ] as const) {
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          ["login", "status"],
          stdout.stream,
          stderr.stream,
          dependencies({ environment }),
        ),
      ).toBe(0);
      expect(stderr.text()).toContain(
        `Effective scan authentication: API key from ${expectedSource}.`,
      );
      expect(stderr.text()).toContain(
        "To use a ChatGPT sign-in, unset OPENAI_API_KEY and CODEX_API_KEY.",
      );
      expect(stderr.text()).not.toContain("SYNTHETIC_SECRET");
    }
  });

  test("keeps stored-login status unchanged when no environment key is set", async () => {
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        ["login", "status"],
        stdout.stream,
        stderr.stream,
        dependencies({ environment: { OPENAI_API_KEY: "   " } }),
      ),
    ).toBe(0);
    expect(stderr.text()).toBe("");
  });

  test("reports effective environment credentials without a stored sign-in", async () => {
    const stdout = capture();
    const stderr = capture();
    const environment: NodeJS.ProcessEnv = {
      OPENAI_API_KEY: "synthetic-primary-key",
      CODEX_API_KEY: "synthetic-secondary-key",
    };
    expect(
      await main(
        ["login", "status"],
        stdout.stream,
        stderr.stream,
        dependencies({ environment, onCodex: () => 1 }),
      ),
    ).toBe(0);
    expect(stderr.text()).toContain("API key from OPENAI_API_KEY");
    expect(stderr.text()).not.toContain("synthetic");

    delete environment["OPENAI_API_KEY"];
    const rotated = capture();
    expect(
      await main(
        ["login", "status"],
        capture().stream,
        rotated.stream,
        dependencies({ environment, onCodex: () => 1 }),
      ),
    ).toBe(0);
    expect(rotated.text()).toContain("API key from CODEX_API_KEY");

    expect(
      await main(
        ["login", "status"],
        capture().stream,
        capture().stream,
        dependencies({ environment: {}, onCodex: () => 1 }),
      ),
    ).toBe(1);

    expect(
      await main(
        ["login", "status"],
        capture().stream,
        capture().stream,
        dependencies({
          environment: { OPENAI_API_KEY: "synthetic-key" },
          onCodex: () => 17,
        }),
      ),
    ).toBe(17);
  });

  test("keeps delegated credentials in the configured Codex home", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-login-home-"));
    const repository = join(root, "repository");
    const relativeHome = join(repository, ".codex-security-home");
    const tildeHome = join(root, ".codex-security-home");
    const mountedHome = join(root, "mounted-codex-home");
    const defaultHome = join(root, ".codex");
    await mkdir(relativeHome, { recursive: true });
    await mkdir(tildeHome, { recursive: true });
    await mkdir(mountedHome, { recursive: true });
    await mkdir(defaultHome, { recursive: true });
    try {
      for (const [configuredHome, expectedHome, userHome] of [
        [".codex-security-home", relativeHome, root],
        ["~/.codex-security-home", tildeHome, root],
        [mountedHome, mountedHome, join(root, "missing-home")],
        ...(process.platform === "win32"
          ? []
          : ([
              ["", defaultHome, root],
              ["   ", defaultHome, root],
            ] as const)),
      ] as const) {
        const environment = {
          ...process.env,
          HOME: userHome,
          USERPROFILE: userHome,
          CODEX_HOME: configuredHome,
          OPENAI_API_KEY: undefined,
          CODEX_API_KEY: undefined,
        };
        const run = (args: string[], input?: string): number | null =>
          spawnSync(
            process.execPath,
            [join(import.meta.dir, "../src/cli.ts"), ...args],
            {
              cwd: repository,
              env: environment,
              input,
              encoding: "utf8",
            },
          ).status;
        expect(run(["login", "--with-api-key"], "synthetic-key\n")).toBe(0);
        expect(await stat(join(expectedHome, "auth.json"))).toBeDefined();
        await expect(stat(join(repository, "auth.json"))).rejects.toThrow();
        expect(run(["login", "status"])).toBe(0);
        expect(run(["logout"])).toBe(0);
      }
      expect(
        spawnSync(
          process.execPath,
          [join(import.meta.dir, "../src/cli.ts"), "login", "--help"],
          {
            cwd: repository,
            env: {
              ...process.env,
              CODEX_HOME: undefined,
              Codex_Home: "   ",
            },
            encoding: "utf8",
          },
        ).status,
      ).toBe(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);

  test("reports selected scan credentials without contaminating JSON output", async () => {
    const stdout = capture();
    const stderr = capture(true);
    const deps = dependencies();
    deps.createSecurity = () => ({
      run: async (_repository, options) => {
        options?.onAuthentication?.({
          method: "api_key",
          source: "OPENAI_API_KEY",
          verified: false,
        });
        options?.onScanStarted?.();
        return fakeResult();
      },
      preflight: async () => fakePreflight(),
      close: async () => {},
    });

    expect(
      await main(["scan", "--json"], stdout.stream, stderr.stream, deps),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(stderr.text()).toContain(
      "Authentication: API key from OPENAI_API_KEY.",
    );
    expect(stderr.text()).toContain(
      process.platform === "win32"
        ? "unset OPENAI_API_KEY and CODEX_API_KEY, then retry the scan"
        : "env -u OPENAI_API_KEY -u CODEX_API_KEY codex-security scan ...",
    );
  });

  test("reports stored and secondary-key scan authentication on stderr", async () => {
    for (const [authentication, expected] of [
      [
        { method: "stored_credentials", verified: false },
        "Authentication: stored Codex credentials.",
      ],
      [
        { method: "api_key", source: "CODEX_API_KEY", verified: false },
        "Authentication: API key from CODEX_API_KEY.",
      ],
    ] as const) {
      const stdout = capture();
      const stderr = capture();
      const deps = dependencies();
      deps.createSecurity = () => ({
        run: async (_repository, options) => {
          options?.onAuthentication?.(authentication);
          return fakeResult();
        },
        preflight: async () => fakePreflight(),
        close: async () => {},
      });

      expect(
        await main(["scan", "--json"], stdout.stream, stderr.stream, deps),
      ).toBe(0);
      expect(stderr.text()).toContain(expected);
      expect(stderr.text()).not.toContain("env -u");
      expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    }
  });

  test("keeps selected dry-run authentication metadata safe and machine readable", async () => {
    const stdout = capture();
    const stderr = capture();
    const authentication = {
      method: "api_key" as const,
      source: "CODEX_API_KEY" as const,
      verified: false as const,
    };
    expect(
      await main(
        ["scan", "repo", "--dry-run", "--json"],
        stdout.stream,
        stderr.stream,
        dependencies({
          environment: { CODEX_API_KEY: "synthetic-private-key" },
          preflight: { ...fakePreflight("repo"), authentication },
        }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toMatchObject({ authentication });
    expect(`${stdout.text()}${stderr.text()}`).not.toContain("synthetic");
  });
});
