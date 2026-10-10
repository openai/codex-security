import { createCliTest, runCapturedCli } from "./support/cli-run.js";
import { once } from "node:events";
import { resolving } from "./support/promises.js";
import { describe, expect, test, mock } from "bun:test";
import {
  checkForUpdate,
  formatUpdateNotice,
  updateCommand,
} from "../src/version.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { main } from "../src/cli.js";
import { rejecting } from "./support/errors.js";
import { responding } from "./support/responses.js";

function registryResponse(version: unknown) {
  return async () => new Response(JSON.stringify({ version }));
}

describe("CLI update notice", () => {
  test("checks the npm latest tag and reports a newer version", async () => {
    let requestedUrl: string | undefined;
    const notice = await checkForUpdate({
      environment: { npm_command: "exec" },
      currentVersion: "0.1.0",
      fetch: async (url) => {
        requestedUrl = url.toString();
        return new Response(JSON.stringify({ version: "0.2.0" }));
      },
    });

    expect(requestedUrl).toBe(
      "https://registry.npmjs.org/%40openai%2Fcodex-security/latest",
    );
    expect(notice).toEqual({
      currentVersion: "0.1.0",
      latestVersion: "0.2.0",
      command: "npx @openai/codex-security@latest",
    });
  });

  test("uses the configured npm registry", async () => {
    let requestedUrl: string | undefined;
    await checkForUpdate({
      environment: { npm_config_registry: "https://registry.example.test/npm" },
      currentVersion: "0.1.0",
      fetch: async (url) => {
        requestedUrl = url.toString();
        return new Response(JSON.stringify({ version: "0.2.0" }));
      },
    });

    expect(requestedUrl).toBe(
      "https://registry.example.test/npm/%40openai%2Fcodex-security/latest",
    );
  });

  test("cancels registry requests when the caller aborts", async () => {
    const controller = new AbortController();
    let requestSignal: AbortSignal | undefined;
    const pending = checkForUpdate({
      environment: {},
      signal: controller.signal,
      fetch: async (_url, options) => {
        requestSignal = options?.signal ?? undefined;
        await once(requestSignal!, "abort");
        throw requestSignal!.reason;
      },
    });

    controller.abort();
    expect(requestSignal?.aborted).toBe(true);
    await expect(pending).resolves.toBeUndefined();
  });

  test("recognizes npx and local or global npm, pnpm, Yarn, and Bun", () => {
    const installed = "/workspace/node_modules/pkg/dist/version.js";
    const packageName = "@openai/codex-security@latest";

    for (const [environment, entrypoint, command] of [
      [{ npm_command: "exec" }, installed, `npx ${packageName}`],
      [{}, "/cache/_npx/pkg", `npx ${packageName}`],
      [{}, installed, `npm install ${packageName}`],
      [{}, "/usr/lib/node_modules/pkg", `npm install -g ${packageName}`],
      [
        {},
        "C:\\AppData\\Roaming\\npm\\node_modules\\pkg",
        `npm install -g ${packageName}`,
      ],
      [
        { npm_config_user_agent: "pnpm/10.0.0" },
        installed,
        `pnpm add ${packageName}`,
      ],
      [
        { npm_config_user_agent: "pnpm/10.0.0" },
        "/pnpm/global/pkg",
        `pnpm add -g ${packageName}`,
      ],
      [
        { npm_config_user_agent: "yarn/1.22.0" },
        installed,
        `yarn add ${packageName}`,
      ],
      [{}, "/.yarn/global/pkg", `yarn global add ${packageName}`],
      [{}, "/.config/yarn/global/pkg", `yarn global add ${packageName}`],
      [
        { npm_config_user_agent: "bun/1.3.0" },
        installed,
        `bun add ${packageName}`,
      ],
      [{}, "/.bun/install/global/pkg", `bun add -g ${packageName}`],
      [
        {},
        "/release/.install/node_modules/pkg",
        "download and extract the latest Codex Security release",
      ],
      [{}, "/workspace/src/version.ts", `npx ${packageName}`],
    ] as const) {
      expect(updateCommand(environment, entrypoint)).toBe(command);
    }
  });

  test("ignores current, older, invalid, and lower prerelease versions", async () => {
    for (const [current, latest, available] of [
      ["0.1.0", "0.1.0", false],
      ["0.1.0+local", "0.1.0+registry", false],
      ["0.2.0", "0.1.0", false],
      ["0.2.0", "not-a-version", false],
      ["not-a-version", "0.2.0", false],
      ["0.2.0", "0.2.0-beta.1", false],
      ["0.2.0-beta.2", "0.2.0-beta.1", false],
      ["0.2.0-beta.1", "0.2.0-beta.2", true],
      ["0.2.0-beta.9", "0.2.0-beta.10", true],
      ["0.2.0-beta.1", "0.2.0", true],
    ] as const) {
      const notice = await checkForUpdate({
        environment: {},
        currentVersion: current,
        fetch: registryResponse(latest),
      });
      expect(notice !== undefined).toBe(available);
    }

    expect(
      await checkForUpdate({
        environment: {},
        currentVersion: "0.1.0",
        fetch: registryResponse(null),
      }),
    ).toBeUndefined();
  });

  test("orders prerelease identifiers by SemVer precedence, not locale collation", async () => {
    for (const [current, latest, available] of [
      // ASCII case ordering: "a" (97) sorts after "A" (65) in SemVer.
      ["1.0.0-A", "1.0.0-a", true],
      ["1.0.0-a", "1.0.0-A", false],
      // Numeric identifiers have lower precedence than non-numeric ones.
      ["1.0.0-1", "1.0.0-alpha", true],
      ["1.0.0-alpha", "1.0.0-1", false],
      // When shared identifiers are equal, the longer list wins.
      ["1.0.0-alpha", "1.0.0-alpha.1", true],
      ["1.0.0-alpha.1", "1.0.0-alpha", false],
      // Numeric identifiers compare numerically regardless of width.
      ["1.0.0-alpha.9", "1.0.0-alpha.10", true],
      ["1.0.0-alpha.10", "1.0.0-alpha.9", false],
      // Mixed identifier lists follow pairwise precedence.
      ["1.0.0-alpha.2", "1.0.0-alpha.10", true],
      ["1.0.0-alpha.2", "1.0.0-alpha.beta", true],
    ] as const) {
      const notice = await checkForUpdate({
        environment: {},
        currentVersion: current,
        fetch: registryResponse(latest),
      });
      expect(notice !== undefined).toBe(available);
    }
  });

  test("suppresses registry checks in CI or when disabled", async () => {
    const fetchLatest = mock(registryResponse("0.2.0"));

    for (const environment of [
      { CODEX_SECURITY_NO_UPDATE_NOTICE: "1" },
      { NO_UPDATE_NOTIFIER: "1" },
      { CI: "true" },
    ]) {
      expect(
        await checkForUpdate({
          environment,
          currentVersion: "0.1.0",
          fetch: fetchLatest,
        }),
      ).toBeUndefined();
    }

    expect(fetchLatest).toHaveBeenCalledTimes(0);
  });

  test("ignores unavailable registries and invalid registry responses", async () => {
    for (const fetchLatest of [
      rejecting("network unavailable"),
      responding("unavailable", 503),
      responding("not JSON", 200),
    ]) {
      expect(
        await checkForUpdate({
          environment: {},
          currentVersion: "0.1.0",
          fetch: fetchLatest,
        }),
      ).toBeUndefined();
    }
  });

  test("prints the update banner to interactive stderr without changing JSON", async () => {
    const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });

    const notice = {
      currentVersion: "0.1.0",
      latestVersion: "0.2.0",
      command: "npm install -g @openai/codex-security@latest",
    };

    expect(
      await runCli(
        ["info", "--json"],
        dependencies({ onUpdateCheck: async () => notice }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toMatchObject({
      cliVersion: expect.any(String),
    });
    expect(stderr.text()).toBe(formatUpdateNotice(notice));
    expect(stderr.text()).not.toContain("CODEX_SECURITY_NO_UPDATE_NOTICE");
  });

  test("finishes the command and aborts an unfinished update check", async () => {
    const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });

    const onUpdateCheck = mock(async (_signal: AbortSignal) => {
      return await new Promise<undefined>(() => {});
    });
    const result = await runCli(
      ["info", "--json"],
      dependencies({
        onUpdateCheck,
      }),
    );

    expect(result).toBe(0);
    expect(onUpdateCheck.mock.lastCall?.[0]?.aborted).toBe(true);
    expect(JSON.parse(stdout.text())).toMatchObject({
      cliVersion: expect.any(String),
    });
    expect(stderr.text()).toBe("");
  });

  test("skips checks for noninteractive output, help, dry runs, and disabled notices", async () => {
    const onUpdateCheck = mock(resolving(undefined));

    await runCapturedCli(
      main,
      ["info", "--json"],
      dependencies({ onUpdateCheck }),
    );
    for (const argv of [
      ["--help"],
      ["--version"],
      ["scan", "--dry-run"],
      ["info", "--workers"],
    ]) {
      await main(
        argv,
        capture().stream,
        capture(true).stream,
        dependencies({ onUpdateCheck }),
      );
    }
    await main(
      ["info", "--json"],
      capture().stream,
      capture(true).stream,
      dependencies({
        environment: { CODEX_SECURITY_NO_UPDATE_NOTICE: "1" },
        onUpdateCheck,
      }),
    );

    expect(onUpdateCheck).toHaveBeenCalledTimes(0);
  });

  test("keeps commands successful when the update check fails", async () => {
    const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });

    expect(
      await runCli(
        ["info", "--json"],
        dependencies({
          onUpdateCheck: rejecting("registry unavailable"),
        }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toMatchObject({
      cliVersion: expect.any(String),
    });
    expect(stderr.text()).toBe("");
  });
});
