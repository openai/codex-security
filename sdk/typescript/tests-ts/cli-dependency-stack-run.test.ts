import { describe, expect, test } from "bun:test";
import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { main, runCodexSkillCommand } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { git } from "./git-fixture.js";
import { createCliTest } from "./support/cli-run.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

async function fixture(root: string) {
  const packet = join(root, "captured packet");
  await promisify(execFile)(process.execPath, [
    fileURLToPath(
      new URL(
        "../../../evals/dependency-reachability/fixtures/stack-workflow/prepare.mjs",
        import.meta.url,
      ),
    ),
    packet,
    "unbound",
  ]);
  return {
    target: join(packet, "target"),
    args: [
      "exploitability",
      "check",
      "CVE-2099-0001",
      "--json",
      "--sources",
      join(packet, "sources.json"),
      "--sinks",
      join(packet, "sinks.json"),
      "--stacks",
      join(packet, "stacks.json"),
    ],
  };
}

async function callTool(state: string, verb: string, json?: unknown) {
  const io = createCliTest(main);
  const deps = dependencies();
  const args = ["exploitability", "run", verb, "--state", state];
  if (json !== undefined) {
    args.push("--json-stdin");
    deps.recordsInput = Readable.from([JSON.stringify(json)]);
  }
  const exit = await io.runCli(args, deps);
  expect(exit, io.stderr.text()).toBe(0);
  return JSON.parse(io.stdout.text());
}

describe("supplied-stack CLI", () => {
  test("only the full packet selects the single-investigator workflow", async () => {
    await using temp = await scopedTemporaryDirectory("stack-cli-selection-");
    git(temp.path, "init", "--quiet");
    let openGrepChecks = 0;
    const deps = dependencies({
      currentDirectory: temp.path,
      onRepositoryCommand(command) {
        if (command === "opengrep") ++openGrepChecks;
        throw new Error("OpenGrep fixture");
      },
    });
    const partial = createCliTest(main);
    expect(
      await partial.runCli(
        ["exploitability", "check", "CVE-2099-0001", "--sources", "only.json"],
        deps,
      ),
    ).toBe(2);
    expect(partial.stderr.text()).toContain(
      "--sources, --sinks and --stacks together",
    );
    expect(openGrepChecks).toBe(0);
    const legacy = createCliTest(main);
    expect(
      await legacy.runCli(["exploitability", "check", "CVE-2099-0001"], deps),
    ).toBe(2);
    expect(legacy.stderr.text()).toContain("OpenGrep");
    expect(openGrepChecks).toBe(1);
  });

  test("one investigator drives the advertised commands and publishes its finalized report", async () => {
    await using temp = await scopedTemporaryDirectory(
      "stack-cli-investigator-",
    );
    const { target, args } = await fixture(temp.path);
    const reportFile = join(temp.path, "report.json");
    let calls = 0;
    let finalized: unknown;
    const deps = dependencies({
      currentDirectory: target,
      async onCodex(argv, output, _env, prompt) {
        calls++;
        expect(argv[0]).toBe("exec");
        expect(argv).toContain("features.multi_agent_v2=false");
        expect(output?.appServer).toBeUndefined();
        const parameters = JSON.parse(
          prompt!.split("\n").find((line) => line.startsWith('{"command":'))!,
        );
        expect(parameters.repo).toBe(target);
        expect(argv[argv.indexOf("--cd") + 1]).toBe(parameters.directory);
        const { commands } = await callTool(parameters.state, "tools");
        const query = commands.find(
          (tool: { name: string }) => tool.name === "query-claims",
        );
        expect(query.inputSchema.properties.ids).toBeDefined();
        const result = await callTool(parameters.state, query.name, {
          ids: ["example-claim"],
        });
        expect(result.claims).toEqual([]);
        const next = await callTool(parameters.state, "next");
        await callTool(parameters.state, "record-assessments", {
          items: [
            {
              workItemId: next.workItem.id,
              verdict: "unknown",
              reason:
                "The captured stack does not identify the deployed version.",
              remainingQuestions: [
                "Which package version ran in this workload?",
              ],
            },
          ],
        });
        finalized = await callTool(parameters.state, "finalize");
        output?.stdout.write("An investigator's final prose");
        return 0;
      },
    });
    const io = createCliTest(main);
    expect(
      await io.runCli([...args, "--report-file", reportFile], deps),
      io.stderr.text(),
    ).toBe(0);
    expect(calls).toBe(1);
    expect(JSON.parse(io.stdout.text())).toEqual(finalized);
    expect(JSON.parse(await readFile(reportFile, "utf8"))).toEqual(finalized);
  });

  test("the process uses the selected home provider and keeps its credential paths out of the investigator shell", async () => {
    await using temp = await scopedTemporaryDirectory("stack-cli-provider-");
    const home = join(temp.path, "home");
    const workspace = join(temp.path, "work");
    const target = join(temp.path, "target");
    await Promise.all([home, workspace, target].map((path) => mkdir(path)));
    git(target, "init", "--quiet");
    await writeFile(
      join(home, "config.toml"),
      [
        'model_provider = "fixture"',
        "[model_providers.fixture]",
        'name = "Fixture provider"',
        'env_key = "STACK_SYNTHETIC_TOKEN"',
      ].join("\n"),
    );
    const program = `
      const fs = require("node:fs"); const path = require("node:path");
      const config = fs.readFileSync(path.join(process.env.CODEX_HOME, "config.toml"), "utf8");
      const policy = process.argv.find(value => value.startsWith("permissions.codex_security_stacks="));
      const result = {
        selected: /model_provider\\s*=\\s*["']fixture["']/.test(config),
        hasDefinition: config.includes("STACK_SYNTHETIC_TOKEN"),
        nativeHome: process.env.CODEX_HOME,
        policy,
      };
      console.log(JSON.stringify({type: "item.completed", item: {id:"r", type:"agent_message", text:JSON.stringify(result)}}));
      console.log(JSON.stringify({type:"turn.completed"}));
    `;
    const stdout = capture();
    const stderr = capture();
    const result = await runCodexSkillCommand(
      ["-e", program, "--"],
      {
        command: "exploitability check",
        auth: "auto",
        stackTarget: target,
        directory: workspace,
        stdout: stdout.stream,
        stderr: stderr.stream,
      },
      { command: process.execPath },
      {
        PATH: process.env["PATH"],
        CODEX_HOME: home,
        STACK_SYNTHETIC_TOKEN: "synthetic-local-test",
      },
    );
    expect(result, stderr.text()).toBe(0);
    const observed = JSON.parse(stdout.text());
    expect(observed).toMatchObject({ selected: true, hasDefinition: true });
    expect(observed.nativeHome).not.toBe(home);
    expect(observed.policy).toContain(JSON.stringify(workspace));
    expect(observed.policy).toContain(JSON.stringify(home));
    expect(observed.policy).toContain(JSON.stringify(observed.nativeHome));
    expect(observed.policy).toContain('"deny"');
  });
  test("a successful model exit without a finalized investigation fails the check", async () => {
    await using temp = await scopedTemporaryDirectory("stack-cli-incomplete-");
    const { target, args } = await fixture(temp.path);
    const io = createCliTest(main);
    const deps = dependencies({
      currentDirectory: target,
      onCodex(_args, out) {
        out?.stdout.write('{"verdict":"ruled_out"}');
        return 0;
      },
    });
    expect(await io.runCli(args, deps)).toBe(2);
    expect(io.stderr.text()).toContain("did not finalize");
  });
});
