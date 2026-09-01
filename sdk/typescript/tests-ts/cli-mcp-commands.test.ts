import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  buildCliMcpArguments,
  buildCliMcpCommands,
  parseCliMcpResult,
  runCliMcpCommand,
  type CliMcpCommand,
  type CliMcpManifest,
} from "../src/cli-mcp-commands.js";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function command(
  name: string,
  schema: NonNullable<CliMcpManifest["commands"][number]["schema"]> = {},
): CliMcpCommand {
  return buildCliMcpCommands({ commands: [{ name, schema }] })[0]!;
}

async function script(source: string) {
  const cwd = await mkdtemp(join(tmpdir(), "codex-security-mcp-command-"));
  directories.push(cwd);
  const entrypoint = join(cwd, "command.mjs");
  await writeFile(entrypoint, source);
  return {
    executable: process.execPath,
    entrypoint,
    cwd,
    environment: {
      ...(process.platform === "win32"
        ? { SystemRoot: process.env["SystemRoot"] }
        : {}),
      MCP_TEST_VALUE: "synthetic value",
    },
  };
}

describe("CLI MCP command schemas", () => {
  test("uses named CLI leaves without duplicating tools or exposing findings service commands", () => {
    expect(
      buildCliMcpCommands({
        commands: [
          { name: "scan" },
          { name: "info" },
          { name: "serve" },
          { name: "dedupe" },
          { name: "findings false-positive", description: "Save a decision." },
          { name: "scans list" },
        ],
      }).map(({ name, path, description }) => ({ name, path, description })),
    ).toEqual([
      {
        name: "findings_false-positive",
        path: ["findings", "false-positive"],
        description: "Save a decision.",
      },
      {
        name: "scans_list",
        path: ["scans", "list"],
        description: "scans list",
      },
    ]);
  });

  test("exposes logout and only explicit login status, without credential inputs", () => {
    const login = command("login", {
      args: {
        type: "object",
        properties: { action: { type: "string", enum: ["status"] } },
        additionalProperties: false,
      },
      options: {
        properties: {
          deviceAuth: { type: "boolean" },
          withApiKey: { type: "boolean" },
        },
      },
    });
    expect(login.inputSchema).toMatchObject({
      required: ["args"],
      properties: {
        args: {
          required: ["action"],
          properties: { action: { enum: ["status"] } },
        },
      },
    });
    expect(login.inputSchema.properties).not.toHaveProperty("options");
    expect(login.description).toContain("Complete sign-in locally");
    expect(buildCliMcpArguments(login, { args: { action: "status" } })).toEqual(
      ["login", "status"],
    );
    expect(command("logout").inputSchema).toEqual({
      type: "object",
      properties: {
        workingDirectory: {
          type: "string",
          description: expect.stringContaining("Working directory"),
        },
      },
      additionalProperties: false,
    });
  });

  test("keeps colliding positional and option names separate and defaults optional", () => {
    const schema = {
      args: {
        type: "object",
        properties: { scanDir: { type: "string" } },
        additionalProperties: false,
      },
      options: {
        type: "object",
        properties: {
          scanDir: { type: "array", items: { type: "string" }, default: [] },
          to: { type: "string", default: "linear" },
          csv: { type: "boolean", default: false },
          findingsUrl: { type: "string" },
          workflowId: { type: "string" },
          project: { type: "string", minLength: 1 },
        },
        required: ["scanDir", "to", "project"],
        additionalProperties: false,
      },
    };
    const tool = command("publish scan", schema);
    expect(tool.inputSchema).toMatchObject({
      required: ["options"],
      additionalProperties: false,
      properties: {
        args: { properties: { scanDir: { type: "string" } } },
        options: {
          required: ["project"],
          properties: {
            scanDir: { type: "array", default: [] },
            to: { type: "string", default: "linear", enum: ["linear"] },
            project: { type: "string", minLength: 1 },
          },
        },
      },
    });
    expect(schema.options.required).toEqual(["scanDir", "to", "project"]);
    expect(schema.options.properties.to).not.toHaveProperty("enum");
    for (const field of ["csv", "findingsUrl", "workflowId"]) {
      expect(
        tool.inputSchema.properties?.["options"]?.properties,
      ).not.toHaveProperty(field);
    }
  });

  test("converts required and optional variadic operands to arrays", () => {
    for (const required of [true, false]) {
      const tool = command("validate", {
        args: {
          type: "object",
          properties: {
            "findings...": {
              type: "string",
              minLength: 1,
              description: "Finding text.",
            },
          },
          ...(required ? { required: ["findings..."] } : {}),
          additionalProperties: false,
        },
      });
      expect(tool.inputSchema.properties?.["args"]?.properties).toEqual({
        findings: {
          type: "array",
          description: expect.stringContaining("Finding text."),
          items: {
            type: "string",
            minLength: 1,
            description: expect.stringContaining(
              "Positional values cannot start",
            ),
          },
          ...(required ? { minItems: 1 } : {}),
        },
      });
      expect(tool.inputSchema.required).toEqual(
        required ? ["args"] : undefined,
      );
      expect(tool.inputSchema.properties?.["args"]?.required).toEqual(
        required ? ["findings"] : undefined,
      );
    }
  });

  test("requests structured output only where the command supports it", () => {
    expect(
      command("import github", { output: { type: "array" } }).jsonOutput,
    ).toBe(true);
    expect(command("patch", { output: { type: "object" } }).jsonOutput).toBe(
      false,
    );
    expect(command("export").jsonOutput).toBe(false);
  });
});

describe("CLI MCP command arguments", () => {
  test("advertises an optional working directory without serializing it as argv", () => {
    const tool = command("scans list");
    const input = { workingDirectory: "relative project" };
    expect(tool.inputSchema.properties?.["workingDirectory"]).toMatchObject({
      type: "string",
    });
    expect(tool.inputSchema.required).toBeUndefined();
    expect(buildCliMcpArguments(tool, input)).toEqual(["scans", "list"]);
    expect(input.workingDirectory).toBe("relative project");
  });

  test("preserves argument order, repeated values, booleans, and exact option strings", () => {
    const tool = command("example run", {
      args: {
        properties: {
          repository: { type: "string" },
          "findings...": { type: "string" },
        },
      },
      options: {
        properties: {
          outputDir: { type: "string" },
          workers: { type: "number" },
          codex: { type: "array", items: { type: "string" } },
          enabled: { type: "boolean", default: false },
          disabled: { type: "boolean", default: true },
        },
      },
      output: { type: "object" },
    });
    expect(
      buildCliMcpArguments(tool, {
        args: { repository: "project folder", findings: ["first", "second"] },
        options: {
          outputDir: "--help",
          workers: 3,
          codex: ['model="example"', "a=b=c"],
          enabled: true,
          disabled: false,
        },
      }),
    ).toEqual([
      "example",
      "run",
      "--json",
      "--output-dir=--help",
      "--workers=3",
      '--codex=model="example"',
      "--codex=a=b=c",
      "--enabled",
      "--no-disabled",
      "project folder",
      "first",
      "second",
    ]);
  });

  test("lets the CLI apply omitted defaults and accepts a per-call output choice", () => {
    const tool = command("patch", { output: { type: "object" } });
    expect(buildCliMcpArguments(tool, {})).toEqual(["patch"]);
    expect(buildCliMcpArguments(tool, {}, { jsonOutput: true })).toEqual([
      "patch",
      "--json",
    ]);
  });

  test("does not shift a later positional into an omitted earlier argument", () => {
    const tool = command("scans compare", {
      args: {
        properties: {
          beforeId: { type: "string" },
          afterId: { type: "string" },
        },
      },
    });
    expect(() =>
      buildCliMcpArguments(tool, { args: { afterId: "scan-after" } }),
    ).toThrow("'afterId' requires the preceding 'beforeId'");
  });

  test("keeps whitespace, quotes, Unicode, and newlines in positional values", () => {
    const tool = command("validate", {
      args: { properties: { "findings...": { type: "string" } } },
    });
    const findings = ['space and "quotes"', "λ\nnext line", "./--help"];
    expect(buildCliMcpArguments(tool, { args: { findings } })).toEqual([
      "validate",
      ...findings,
    ]);
  });
});

describe("CLI MCP command results", () => {
  test("retains structured arrays and successful stderr diagnostics", () => {
    expect(
      parseCliMcpResult(0, '[{"number":7}]\n', "completed\n", {
        jsonOutput: true,
      }),
    ).toEqual({
      exitCode: 0,
      data: [{ number: 7 }],
      diagnostics: "completed\n",
    });
  });

  test("preserves raw exports and direct workflow text without parsing", () => {
    expect(parseCliMcpResult(0, "id,title\n7,example\n", "")).toEqual({
      exitCode: 0,
      output: "id,title\n7,example\n",
    });
    expect(parseCliMcpResult(0, '{"raw":true}', "")).toEqual({
      exitCode: 0,
      output: '{"raw":true}',
    });
    expect(parseCliMcpResult(0, "", "Wrote findings.json\n")).toEqual({
      exitCode: 0,
      diagnostics: "Wrote findings.json\n",
    });
  });

  test("reports failures while retaining any structured partial result", () => {
    expect(
      parseCliMcpResult(1, '{"completed":2}', "failed\n", {
        jsonOutput: true,
      }),
    ).toEqual({ exitCode: 1, data: { completed: 2 }, error: "failed" });
    expect(parseCliMcpResult(2, "", "")).toEqual({
      exitCode: 2,
      error: "Command exited with status 2.",
    });
  });

  test("does not report malformed structured output as a successful tool result", () => {
    expect(parseCliMcpResult(0, "not json", "", { jsonOutput: true })).toEqual({
      exitCode: 2,
      output: "not json",
      error: "Command returned invalid JSON.",
    });
  });
});

describe("CLI MCP command processes", () => {
  test("captures isolated streams, working directory, environment, and argv", async () => {
    const options = await script(`
      process.stdout.write(JSON.stringify({
        argv: process.argv.slice(2), cwd: process.cwd(),
        value: process.env.MCP_TEST_VALUE,
      }));
      process.stderr.write("progress λ\\n");
    `);
    const chunks: string[] = [];
    const result = await runCliMcpCommand(
      command("scans list", { output: { type: "object" } }),
      {},
      {
        ...options,
        onStderr: (chunk) => {
          chunks.push(chunk);
          throw new Error("observer");
        },
      },
    );
    expect(result).toEqual({
      exitCode: 0,
      data: {
        argv: ["scans", "list", "--json"],
        cwd: await realpath(options.cwd),
        value: "synthetic value",
      },
      diagnostics: "progress λ\n",
    });
    expect(chunks.join("")).toBe("progress λ\n");
  });

  test("reports launch failures and already-cancelled calls", async () => {
    const options = await script("process.exit(0)");
    expect(
      await runCliMcpCommand(
        command("export"),
        {},
        {
          ...options,
          executable: join(options.cwd, "missing-executable"),
        },
      ),
    ).toMatchObject({ exitCode: 2, error: expect.stringContaining("ENOENT") });
    expect(
      await runCliMcpCommand(
        command("export"),
        {},
        {
          ...options,
          signal: AbortSignal.abort(),
        },
      ),
    ).toEqual({ exitCode: 130, error: "Command cancelled." });
  });

  test.each(["--mcp", "--help", "--json", "-v"])(
    "rejects positional %s before a child can reinterpret it as a flag",
    async (finding) => {
      const options = await script(`
        import { writeFileSync } from "node:fs";
        writeFileSync("started", "unexpected invocation");
      `);
      const result = await runCliMcpCommand(
        command("validate", {
          args: { properties: { "findings...": { type: "string" } } },
        }),
        { args: { findings: [finding] } },
        options,
      );
      expect(result).toMatchObject({
        exitCode: 2,
        error: expect.stringContaining(
          "cannot start with '-'; prefix paths with './'",
        ),
      });
      expect(
        await readFile(join(options.cwd, "started")).catch(() => undefined),
      ).toBeUndefined();
    },
  );

  test.each([
    ["same-group", false, 0],
    ["detached", true, 50],
  ] as const)(
    "cancellation waits for CLI cleanup of its %s descendant",
    async (_name, detached, handlerDelay) => {
      const options = await script(`
      import { spawn } from "node:child_process";
      const child = spawn(process.execPath, ["-e", [
        'process.on("SIGTERM", () => {});',
        'console.log("ready");',
        'setInterval(() => {}, 1000);',
      ].join("")], {
        stdio: ["ignore", "pipe", "ignore"],
        detached: process.platform !== "win32" && ${detached},
        windowsHide: true,
      });
      process.on("SIGTERM", () => setTimeout(() => {
        child.kill("SIGTERM");
        setTimeout(() => child.kill("SIGKILL"), 1000);
      }, ${handlerDelay}));
      child.once("close", () => {
        process.stdout.write("cleanup completed\\n");
        process.exit(0);
      });
      child.stdout.once("data", () => process.stderr.write(JSON.stringify([process.pid, child.pid]) + "\\n"));
    `);
      // Exercise the installed CLI runtime, rather than Bun's signal behavior.
      options.executable = execFileSync("node", ["-p", "process.execPath"], {
        encoding: "utf8",
      }).trim();
      const controller = new AbortController();
      let pids: number[] = [];
      let progress = "";
      try {
        const result = await runCliMcpCommand(
          command("validate"),
          {},
          {
            ...options,
            signal: controller.signal,
            onStderr: (chunk) => {
              progress += chunk;
              if (progress.includes("\n")) {
                pids = JSON.parse(progress) as number[];
                controller.abort();
              }
            },
          },
        );
        expect(result).toMatchObject({
          exitCode: 130,
          error: "Command cancelled.",
        });
        expect(pids).toHaveLength(2);
        if (process.platform !== "win32") {
          expect(result.output).toBe("cleanup completed\n");
        }
        for (const pid of pids) expect(await processHasExited(pid)).toBe(true);
      } finally {
        controller.abort();
        for (const pid of pids) {
          try {
            process.kill(pid, "SIGKILL");
          } catch {
            /* Already exited. */
          }
        }
      }
    },
    10_000,
  );
});

async function processHasExited(pid: number): Promise<boolean> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      process.kill(pid, 0);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ESRCH") return true;
      throw error;
    }
    if (process.platform === "linux") {
      const stat = await readFile(`/proc/${pid}/stat`, "utf8").catch(
        () => undefined,
      );
      if (stat === undefined || /\) Z /u.test(stat)) return true;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return false;
}
