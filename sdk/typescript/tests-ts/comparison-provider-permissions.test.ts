import { afterEach, expect, spyOn, test } from "bun:test";
import * as childProcess from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdir, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parse } from "smol-toml";
import { accountStatus, loginApiKey } from "../src/auth.js";
import { deepMerge, type JsonObject } from "../src/config.js";
import { ScanPermissionError } from "../src/scan-execution.js";
import {
  comparisonEnvironment,
  runReadOnlyCodex,
} from "../src/scan-comparison.js";
import {
  prepareCodexSecurityCredentialHome,
  resolveCodexCommand,
} from "../src/runtime.js";
import { CODEX_SECURITY_THREAD_SOURCES } from "../src/thread-source.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const fixtures = createApiTestFixtures();
afterEach(fixtures.cleanup);
const provider = {
  name: "Synthetic private provider",
  wire_api: "responses",
  base_url: "https://provider.example.test/v1",
  experimental_bearer_token: "synthetic-private-bearer",
  http_headers: { "X-Synthetic": "synthetic-private-header" },
};
function argvConfig(args: readonly string[]): JsonObject {
  return args
    .flatMap((arg, i) =>
      arg === "-c" || arg === "--config" ? [args[i + 1]!] : [],
    )
    .reduce(
      (config, override) => deepMerge(config, parse(override) as JsonObject),
      {} as JsonObject,
    );
}

for (const role of ["comparison", "classification"] as const) {
  for (const inherited of [false, true]) {
    for (const scenario of ["accepted", "rejected", "fallback"] as const) {
      const name = `${role} protects private provider files (inherited: ${inherited}, ${scenario})`;
      test(name, async () => {
        if (runTestInSubprocess(import.meta.filename, name)) return;
        const root = await fixtures.temporaryDirectory();
        const cwd = join(root, "repository");
        await mkdir(cwd);
        const source = {
          CODEX_HOME: join(root, "ambient"),
          CODEX_SECURITY_STATE_DIR: join(root, "state"),
        };
        const home = await prepareCodexSecurityCredentialHome(source);
        const environment = {
          ...source,
          CODEX_HOME: home,
          PATH: process.env["PATH"],
        };
        const stub = join(root, "model.mjs");
        const warning =
          "Configured value for `permission_profile` is disallowed by requirements; falling back from `codex_security_comparison` to required value `:read-only`.";
        await writeFile(
          stub,
          `
process.stdin.resume();
await new Promise(resolve => process.stdin.on("end", resolve));
console.log(JSON.stringify({type:"thread.started",thread_id:"synthetic-read-only"}));
${scenario === "fallback" ? `console.log(JSON.stringify({type:"error",message:${JSON.stringify(warning)}}));` : ""}
console.log(JSON.stringify({type:"item.completed",item:{id:"answer",type:"agent_message",text:"{}"}}));
console.log(JSON.stringify({type:"turn.completed",usage:{input_tokens:1,cached_input_tokens:0,output_tokens:1}}));
`,
        );
        const executions: Array<{ args: string[]; config: JsonObject }> = [];
        const preflights: string[][] = [];
        const original = childProcess.spawn;
        const spawn = spyOn(childProcess, "spawn").mockImplementation(((
          ...parameters: Parameters<typeof childProcess.spawn>
        ) => {
          const [command, args, options] = parameters;
          const argv = Array.isArray(args) ? args.map(String) : [];
          if (argv.includes("app-server")) {
            preflights.push(argv);
            if (scenario === "rejected")
              argv.splice(
                argv.indexOf("app-server"),
                0,
                "--config",
                'default_permissions=":read-only"',
              );
            return original(command, argv, options ?? {});
          }
          if (argv.includes("exec")) {
            const name = argv[argv.indexOf("--profile") + 1]!;
            executions.push({
              args: argv,
              config: parse(
                readFileSync(join(home, `${name}.config.toml`), "utf8"),
              ) as JsonObject,
            });
            return original(process.execPath, [stub], options ?? {});
          }
          return original(command, args ?? [], options ?? {});
        }) as typeof childProcess.spawn);
        try {
          const result = runReadOnlyCodex(
            "Synthetic findings are supplied in the prompt.",
            { type: "object" },
            {
              environment,
              workingDirectory: cwd,
              preserveProviderEnvironment: true,
              config: {
                codexOverrides: {
                  model_provider: "synthetic.private",
                  model_providers: { "synthetic.private": provider },
                },
              },
              ...(inherited
                ? {
                    inheritedPermissions: {
                      filesystem: {
                        [join(root, "denied")]: "deny",
                        [cwd]: "write",
                        glob_scan_max_depth: 6,
                      },
                      network: { enabled: true },
                    },
                  }
                : {}),
            },
            {
              surface: "sdk",
              command: role,
              threadSource:
                role === "comparison"
                  ? CODEX_SECURITY_THREAD_SOURCES.scanComparison
                  : CODEX_SECURITY_THREAD_SOURCES.severityClassification,
            },
          );
          if (scenario === "accepted") expect(await result).toBe("{}");
          else await expect(result).rejects.toBeInstanceOf(ScanPermissionError);
          expect(preflights).toHaveLength(1);
          expect(executions).toHaveLength(scenario === "rejected" ? 0 : 1);
          const expected = {
            extends: ":read-only",
            filesystem: {
              ":root": "read",
              [home]: { ".": "deny" },
              ...(inherited
                ? {
                    [join(root, "denied")]: "deny",
                    [cwd]: "read",
                    glob_scan_max_depth: 6,
                  }
                : {}),
            },
            network: { enabled: false },
          };
          for (const args of [
            ...preflights,
            ...executions.map((value) => value.args),
          ]) {
            const config = argvConfig(args);
            expect(config["permissions"]).toMatchObject({
              codex_security_comparison: expected,
            });
            expect(args).not.toContain("--sandbox");
            expect(args.join("\n")).not.toContain("synthetic-private-");
          }
          for (const execution of executions)
            expect(execution.config["model_providers"]).toMatchObject({
              "synthetic.private": provider,
            });
          expect(
            (await readdir(home)).filter((name) =>
              /^codex_security_.*\.config\.toml$/.test(name),
            ),
          ).toEqual([]);
        } finally {
          spawn.mockRestore();
        }
      });
    }
  }
}

test("comparison login status retains a provider defined outside the credential home", async () => {
  const root = await fixtures.temporaryDirectory();
  const ambient = join(root, "ambient");
  await mkdir(ambient);
  const environment = {
    CODEX_HOME: ambient,
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
    PATH: process.env["PATH"],
  };
  const home = await prepareCodexSecurityCredentialHome(environment);
  const command = resolveCodexCommand(environment);
  const login = await loginApiKey(
    {
      ...command,
      args: [
        ...(command.args ?? []),
        "-c",
        'cli_auth_credentials_store="file"',
      ],
    },
    { ...environment, CODEX_HOME: home },
    "synthetic-stored-key",
  );
  expect(login.success, login.stderr).toBe(true);
  await writeFile(
    join(home, "config.toml"),
    'model_provider="synthetic.private"\ncli_auth_credentials_store="file"\n',
  );
  const calls: string[][] = [];
  const selected = await comparisonEnvironment(
    environment,
    async (command, ...args) => {
      calls.push([...(command.args ?? [])]);
      return await accountStatus(command, ...args);
    },
    undefined,
    undefined,
    {
      model_provider: "synthetic.private",
      model_providers: { "synthetic.private": provider },
    },
  );
  expect(selected["CODEX_HOME"]).toBe(home);
  expect(calls).toHaveLength(1);
  expect(argvConfig(calls[0]!)["model_providers"]).toMatchObject({
    "synthetic.private": { name: provider.name, wire_api: provider.wire_api },
  });
  expect(calls[0]!.join("\n")).not.toContain("synthetic-private-");
});
