import { expect, mock, test } from "bun:test";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { main, runCodexSkillCommand } from "../src/cli.js";
import { bundledPluginRoot } from "../src/runtime.js";
import { dependencies } from "./cli-fixtures.js";
import { git } from "./git-fixture.js";
import { createCliTest, runCapturedCli } from "./support/cli-run.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

const advisory = {
  cve: "CVE-2024-1000",
  advisories: [
    {
      url: "https://example.invalid/advisory",
      summary: "Synthetic decoder advisory",
      affected: [
        {
          package: { ecosystem: "npm", name: "sample-decoder" },
          ranges: [
            { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2" }] },
          ],
        },
      ],
    },
  ],
};
const args = ["exploitability", "check", advisory.cve, "--json"];

test("runs the bundled attack-path-analysis skill from the checkout root with the public advisory", async () => {
  await using temp = await scopedTemporaryDirectory("cve-skill-");
  const repo = temp.path;
  git(repo, "init", "--quiet");
  const nested = join(repo, "app");
  await mkdir(nested);
  await writeFile(
    join(nested, "index.ts"),
    'import "sample-decoder"; // checkout-only marker\n',
  );
  const assessment = {
    status: "ruled_out",
    uses: [
      {
        location: "app",
        component: "sample-decoder",
        version: null,
        verdict: "unknown",
        deployment: "unknown",
        reason: "The import does not identify a resolved version.",
        evidence: [{ path: "app/index.ts", startLine: 1, endLine: 1 }],
      },
    ],
    limitations: ["No resolved version."],
  };
  const usage = {
    input_tokens: 120,
    cached_input_tokens: 40,
    cache_write_input_tokens: 0,
    output_tokens: 12,
    reasoning_output_tokens: 4,
  };
  const nativeEvents =
    [
      {
        type: "item.completed",
        item: { type: "agent_message", text: JSON.stringify(assessment) },
      },
      { type: "turn.completed", usage },
    ]
      .map((event) => JSON.stringify(event))
      .join("\n") + "\n";

  const deps = dependencies({
    currentDirectory: nested,
    onCodex: async (argv, output, _env, input) => {
      expect(argv[argv.indexOf("--cd") + 1]).toBe(repo);
      expect(argv).toContain('web_search="disabled"');
      const skill = join(
        await bundledPluginRoot(),
        "skills",
        "attack-path-analysis",
      );
      expect(output?.readOnlySkillRoot).toBe(skill);
      expect(input).toContain(JSON.stringify(join(skill, "SKILL.md")));
      expect(input).toContain(advisory.advisories[0]!.summary);
      expect(input).not.toContain("checkout-only marker");
      const schema = JSON.parse(
        await readFile(argv[argv.indexOf("--output-schema") + 1]!, "utf8"),
      );
      expect(schema.required).toContain("uses");
      expect(schema.properties).not.toHaveProperty("usage");

      // Drive the production event decoder with the same JSONL protocol as codex exec.
      return runCodexSkillCommand(
        ["-e", `process.stdout.write(${JSON.stringify(nativeEvents)})`],
        { ...output!, auth: undefined, readOnlySkillRoot: undefined },
        { command: process.execPath },
        {},
      );
    },
  });
  deps.lookupDependencyAdvisory = async (cve, signal) => {
    expect(cve).toBe(advisory.cve);
    expect(signal).toBeInstanceOf(AbortSignal);
    return advisory;
  };
  const { runCli, stdout, stderr } = createCliTest(main);
  expect(await runCli(args, deps), stderr.text()).toBe(0);
  expect(JSON.parse(stdout.text())).toEqual({
    ...assessment,
    status: "unknown",
    cve: advisory.cve,
    advisories: [advisory.advisories[0]!.url],
    usage,
  });
});

test("preserves the native skill's nonzero exit", async () => {
  await using temp = await scopedTemporaryDirectory("cve-skill-");
  git(temp.path, "init", "--quiet");
  const deps = dependencies({ currentDirectory: temp.path, onCodex: () => 23 });
  deps.lookupDependencyAdvisory = async () => advisory;
  expect(await runCapturedCli(main, args, deps)).toBe(23);
});

test("requires one positional CVE before looking up the advisory", async () => {
  const deps = dependencies();
  deps.lookupDependencyAdvisory = mock(async () => {
    throw new Error("Unexpected advisory lookup");
  });
  for (const positionals of [[], [advisory.cve, "/messages"]]) {
    expect(
      await runCapturedCli(
        main,
        ["exploitability", "check", ...positionals],
        deps,
      ),
    ).toBe(2);
  }
  expect(deps.lookupDependencyAdvisory).not.toHaveBeenCalled();
});
