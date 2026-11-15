import { expect, mock, test } from "bun:test";
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, realpath, writeFile } from "node:fs/promises";
import { join, sep } from "node:path";
import { promisify } from "node:util";
import { parse as parseToml } from "smol-toml";
import { main } from "../src/cli.js";
import type { JsonObject } from "../src/config.js";
import { DependencyReportCoverage } from "../src/dependency-report-coverage.js";
import { bundledPluginRoot } from "../src/runtime.js";
import { dependencies, type OnCodex } from "./cli-fixtures.js";
import { git } from "./git-fixture.js";
import { createCliTest, runCapturedCli } from "./support/cli-run.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

const decoder = { ecosystem: "npm", name: "sample-decoder" };
const advisory = {
  cve: "CVE-2024-1000",
  advisories: [
    {
      url: "https://example.invalid/advisory",
      summary: "Synthetic decoder advisory",
      affected: [
        {
          package: decoder,
          ranges: [
            { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2" }] },
          ],
        },
      ],
    },
  ],
};
const args = ["exploitability", "check", advisory.cve, "--json"];
const defaultCallerScope =
  "Assess production services, jobs (including distributed job executors), workers, scheduled or background workloads, and code they deploy or import at runtime. Independent test runners and CI or build surfaces are outside this scope unless the production runtime invokes them.";

async function submitUses(
  tool: NonNullable<
    NonNullable<Parameters<OnCodex>[1]>["appServer"]
  >["dependencyReport"],
  report: { uses: unknown[]; limitations: string[] },
) {
  assert(tool?.queue && tool.submit);
  const queued = await tool.queue({
    items: report.uses.map((use, index) => ({
      id: `use-${index}`,
      kind: "use",
      candidateIds: [],
      use,
    })),
  });
  return queued.queued
    ? tool.submit({
        reviewItems: queued.items,
        candidateGeneration: 0,
        limitations: report.limitations,
      })
    : { accepted: false, feedback: queued.feedback };
}

async function assertNativeEffort({
  configured,
  native,
  options,
  expected,
  model = "configured-investigator-model",
  expectedModel = model,
  extraCodex = {},
  expectedCapacity,
  expectedDaybreak,
  expectedFeatures,
  allowed = true,
}: {
  configured: string;
  native?: string;
  options: readonly string[];
  expected: string;
  model?: string;
  expectedModel?: string;
  extraCodex?: JsonObject;
  expectedCapacity?: string | null;
  expectedDaybreak?: boolean;
  expectedFeatures?: JsonObject;
  allowed?: boolean;
}) {
  await using temp = await scopedTemporaryDirectory("cve-native-effort-");
  const repository = join(temp.path, "repository");
  await mkdir(repository);
  git(repository, "init", "--quiet");
  const config = join(temp.path, "project.json");
  await writeFile(
    config,
    JSON.stringify({
      codex: {
        model,
        model_reasoning_effort: configured,
        ...(native === undefined
          ? {}
          : { agents: { default_subagent_reasoning_effort: native } }),
        ...extraCodex,
      },
    }),
  );
  const onCodex = mock<OnCodex>((argv, output) => {
    expect(
      parseToml(argv.find((value) => value.startsWith("model="))!),
    ).toEqual({
      model: expectedModel,
    });
    expect(argv).toContain('model_reasoning_effort="high"');
    const nativeSetting = argv.find((value) =>
      value.startsWith("agents.default_subagent_reasoning_effort="),
    );
    expect(nativeSetting).toBeDefined();
    expect(parseToml(nativeSetting!)).toEqual({
      agents: { default_subagent_reasoning_effort: expected },
    });
    if (expectedCapacity !== undefined) {
      expect(
        argv.filter((value) =>
          /^(features\.multi_agent_v2|agents)\.max_concurrent_threads_per_session=/u.test(
            value,
          ),
        ),
      ).toEqual(expectedCapacity === null ? [] : [expectedCapacity]);
    }
    if (expectedDaybreak !== undefined) {
      expect(argv).toContain(`daybreak=${expectedDaybreak}`);
      expect(output?.codexOverrides?.["daybreak"]).toBe(expectedDaybreak);
    }
    if (expectedFeatures !== undefined) {
      const features = argv.find((value) => value.startsWith("features="));
      expect(features).toBeDefined();
      expect(parseToml(features!)["features"]).toMatchObject(expectedFeatures);
      expect(output?.codexOverrides?.["features"]).toMatchObject(
        expectedFeatures,
      );
    }
    return 1;
  });
  const deps = dependencies({
    currentDirectory: repository,
    environment: { PATH: process.env["PATH"] },
    onCodex,
  });
  deps.lookupDependencyAdvisory = async () => advisory;
  const { runCli, stderr } = createCliTest(main);
  assert.equal(
    await runCli([...args, "--config", config, ...options], deps),
    allowed ? 1 : 2,
    stderr.text(),
  );
  expect(onCodex).toHaveBeenCalledTimes(allowed ? 1 : 0);
  if (!allowed) expect(stderr.text()).toContain("Skill commands only support");
}

test.each([
  { configured: "xhigh", options: [], expected: "xhigh" },
  {
    configured: "xhigh",
    options: ["--effort", "medium"],
    expected: "medium",
  },
  {
    configured: "medium",
    native: "xhigh",
    options: [],
    expected: "xhigh",
  },
  {
    configured: "xhigh",
    native: "low",
    options: ["--effort", "medium"],
    expected: "low",
  },
  {
    configured: "xhigh",
    options: ["--model", "cli-investigator-model"],
    expected: "xhigh",
    expectedModel: "cli-investigator-model",
  },
  {
    configured: 'future-"effort"\\雪',
    options: [],
    expected: 'future-"effort"\\雪',
  },
  {
    configured: "xhigh",
    native: "future-native-effort",
    options: ["--effort", "low"],
    expected: "future-native-effort",
  },
])(
  "keeps configured investigator effort while the native coordinator uses high %j",
  assertNativeEffort,
);

test("isolates native investigator settings between concurrent projects", async () => {
  await Promise.all([
    assertNativeEffort({
      configured: "xhigh",
      options: [],
      expected: "xhigh",
      model: "first-project-model",
    }),
    assertNativeEffort({
      configured: "medium",
      native: "low",
      options: [],
      expected: "low",
      model: "second-project-model",
    }),
  ]);
});

test("merges trusted access settings with CLI capacity without leaking between checks", async () => {
  await Promise.all([
    assertNativeEffort({
      configured: "xhigh",
      expected: "xhigh",
      extraCodex: { daybreak: true, features: { cli_daybreak: true } },
      options: [
        "--codex",
        "features.multi_agent_v2.max_concurrent_threads_per_session=49",
      ],
      expectedDaybreak: true,
      expectedFeatures: { cli_daybreak: true },
      expectedCapacity:
        "features.multi_agent_v2.max_concurrent_threads_per_session=49",
    }),
    assertNativeEffort({
      configured: "medium",
      expected: "medium",
      extraCodex: { daybreak: false, features: { cli_daybreak: false } },
      options: [
        "--codex",
        "features.multi_agent_v2.max_concurrent_threads_per_session=7",
      ],
      expectedDaybreak: false,
      expectedFeatures: { cli_daybreak: false },
      expectedCapacity:
        "features.multi_agent_v2.max_concurrent_threads_per_session=7",
    }),
  ]);
});

test("an explicit CLI access choice overrides the trusted project selection", async () => {
  await assertNativeEffort({
    configured: "xhigh",
    expected: "xhigh",
    extraCodex: { daybreak: true, features: { cli_daybreak: true } },
    options: [
      "--codex",
      "daybreak=false",
      "--codex",
      "features.multi_agent_v2.max_concurrent_threads_per_session=49",
    ],
    expectedDaybreak: false,
    expectedFeatures: { cli_daybreak: true },
    expectedCapacity:
      "features.multi_agent_v2.max_concurrent_threads_per_session=49",
  });
});

const nativeCapacityCases: Array<{
  extraCodex: JsonObject;
  options: string[];
  expectedCapacity: string | null;
}> = [
  {
    extraCodex: {},
    options: [],
    expectedCapacity: null,
  },
  {
    extraCodex: {
      features: { multi_agent_v2: { max_concurrent_threads_per_session: 49 } },
    },
    options: [],
    expectedCapacity:
      "features.multi_agent_v2.max_concurrent_threads_per_session=49",
  },
  {
    extraCodex: {
      features: { multi_agent_v2: { max_concurrent_threads_per_session: 3 } },
    },
    options: [
      "--codex",
      "features.multi_agent_v2.max_concurrent_threads_per_session=49",
    ],
    expectedCapacity:
      "features.multi_agent_v2.max_concurrent_threads_per_session=49",
  },
  {
    extraCodex: { agents: { max_concurrent_threads_per_session: 48 } },
    options: [],
    expectedCapacity: "agents.max_concurrent_threads_per_session=48",
  },
  {
    extraCodex: {
      agents: { max_concurrent_threads_per_session: 48 },
      features: { multi_agent_v2: { max_concurrent_threads_per_session: 7 } },
    },
    options: [],
    expectedCapacity:
      "features.multi_agent_v2.max_concurrent_threads_per_session=7",
  },
  {
    extraCodex: {},
    options: [
      "--codex",
      "features.multi_agent_v2.max_concurrent_threads_per_session=0",
    ],
    expectedCapacity:
      "features.multi_agent_v2.max_concurrent_threads_per_session=0",
  },
];
test.each(nativeCapacityCases)(
  "preserves selected native capacity without changing the dependency default %j",
  async (settings) => {
    await assertNativeEffort({
      configured: "medium",
      expected: "medium",
      ...settings,
    });
  },
);

test("isolates explicit native capacities between concurrent dependency checks", async () => {
  await Promise.all(
    [49, 7].map((capacity) =>
      assertNativeEffort({
        configured: "medium",
        expected: "medium",
        options: [
          "--codex",
          `features.multi_agent_v2.max_concurrent_threads_per_session=${capacity}`,
        ],
        expectedCapacity: `features.multi_agent_v2.max_concurrent_threads_per_session=${capacity}`,
      }),
    ),
  );
});

test("a dependency capacity override does not enable other feature passthrough", async () => {
  await assertNativeEffort({
    configured: "medium",
    expected: "medium",
    options: [
      "--codex",
      "features.multi_agent_v2.max_concurrent_threads_per_session=49",
      "--codex",
      "features.apps=true",
    ],
    allowed: false,
  });
});

test("keeps each trusted project's provider paired with its selected model", async () => {
  await Promise.all(
    ["first", "second"].map(async (name) => {
      await using temp = await scopedTemporaryDirectory("cve-native-provider-");
      const repository = join(temp.path, "repository");
      await mkdir(repository);
      const provider = `${name}-provider`;
      const providerConfig = {
        name: `${name} gateway`,
        base_url: `https://${name}.example.test/v1`,
        wire_api: "responses",
        env_key: `${name.toUpperCase()}_GATEWAY_KEY`,
      };
      const config = join(temp.path, "project.json");
      await writeFile(
        config,
        JSON.stringify({
          codex: {
            model: `${name}-model`,
            model_provider: provider,
            model_providers: {
              [provider]: providerConfig,
              unused: { name: "Unused provider" },
            },
          },
        }),
      );
      const onCodex = mock<OnCodex>((argv, output) => {
        expect(argv).toContain(`model="${name}-model"`);
        expect(argv).toContain(`model_provider="${provider}"`);
        expect(output?.modelProvider).toBe(provider);
        expect(output?.codexOverrides?.["model_providers"]).toEqual({
          [provider]: providerConfig,
          unused: { name: "Unused provider" },
        });
        return 1;
      });
      const deps = dependencies({
        currentDirectory: repository,
        environment: { PATH: process.env["PATH"] },
        onCodex,
      });
      deps.lookupDependencyAdvisory = async () => advisory;
      const { runCli, stderr } = createCliTest(main);
      expect(
        await runCli([...args, "--config", config], deps),
        stderr.text(),
      ).toBe(1);
      expect(onCodex).toHaveBeenCalledTimes(1);
    }),
  );
});

test("preserves CLI provider definitions when the provider is selected by its home", async () => {
  await using temp = await scopedTemporaryDirectory("cve-implicit-provider-");
  const repository = join(temp.path, "repository");
  const home = join(temp.path, "home");
  await mkdir(repository);
  await mkdir(home);
  await writeFile(join(home, "config.toml"), 'model_provider="implicit"\n');
  const provider = {
    name: "Implicit gateway",
    env_key: "IMPLICIT_GATEWAY_KEY",
  };
  const onCodex = mock<OnCodex>((argv, output) => {
    expect(output?.codexOverrides?.["model_providers"]).toEqual({
      implicit: provider,
    });
    expect(
      parseToml(argv.find((value) => value.startsWith("model_providers="))!),
    ).toEqual({ model_providers: { implicit: provider } });
    return 1;
  });
  const deps = dependencies({
    currentDirectory: repository,
    environment: { PATH: process.env["PATH"], CODEX_HOME: home },
    onCodex,
  });
  deps.lookupDependencyAdvisory = async () => advisory;
  const { runCli, stderr } = createCliTest(main);
  expect(
    await runCli(
      [
        ...args,
        "--codex",
        'model_providers.implicit.name="Implicit gateway"',
        "--codex",
        'model_providers.implicit.env_key="IMPLICIT_GATEWAY_KEY"',
      ],
      deps,
    ),
    stderr.text(),
  ).toBe(1);
  expect(onCodex).toHaveBeenCalledTimes(1);
});

const unresolvedDecoder = {
  status: "unknown",
  uses: [
    {
      location: "app",
      component: decoder.name,
      version: null as string | null,
      verdict: "unknown",
      deployment: "unknown",
      reason: "The import does not identify a resolved version.",
      evidence: [
        { path: "app/index.ts", startLine: 1, endLine: 1, supports: [] },
      ],
      observations: [],
    },
  ],
  limitations: ["No resolved version."],
};

function reviewDecision(
  prompt: string,
  accepted: boolean,
  reason = "The citation supports the conclusion.",
  citedVersion: string | null = null,
) {
  const packet = JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1)) as {
    items: {
      id: string;
      revision: number;
      excerptIds: string[];
      receiptIds: string[];
    }[];
  };
  return JSON.stringify({
    items: packet.items.map((item) => ({
      id: item.id,
      revision: item.revision,
      accepted,
      reason,
      citedVersion,
      evidenceIds: [...item.excerptIds, ...item.receiptIds],
    })),
  });
}

test.each(["ordinary error", "child process failure"] as const)(
  "stops before advisory lookup on an OpenGrep probe %s",
  async (failure) => {
    await using temp = await scopedTemporaryDirectory("cve-opengrep-");
    const repo = temp.path;
    git(repo, "init", "--quiet");
    const nested = join(repo, "app");
    await mkdir(nested);
    const onCodex = mock<OnCodex>().mockReturnValue(0);
    const diagnostic = "scanner runtime unavailable";
    let original: Error | undefined;
    const deps = dependencies({
      currentDirectory: nested,
      onCodex,
      onRepositoryCommand: async (command, argv, repository, options) => {
        expect(command).toBe("opengrep");
        expect(argv).toEqual(["--version"]);
        expect(repository).toBe(repo);
        expect(options?.signal).toBeInstanceOf(AbortSignal);
        const cwd = await realpath(options!.cwd!);
        expect(cwd).not.toBe(repo);
        expect(cwd.startsWith(repo + sep)).toBe(false);
        if (failure === "ordinary error") throw new Error(diagnostic);
        try {
          const { stdout } = await promisify(execFileCallback)(
            process.execPath,
            [
              "-e",
              'process.stdout.write("probe output\\n"); process.stderr.write("runtime detail\\n"); process.exitCode = 23;',
            ],
            { cwd, signal: options?.signal },
          );
          return stdout;
        } catch (error) {
          assert(error instanceof Error);
          original = error;
          throw error;
        }
      },
    });
    deps.lookupDependencyAdvisory = mock(async () => advisory);
    const { runCli, stderr } = createCliTest(main);
    expect(await runCli(args, deps), stderr.text()).toBe(2);
    const message = stderr.text();
    if (failure === "ordinary error") {
      expect(message).toContain(diagnostic);
    } else {
      assert(original);
      expect(message).toContain(original.message.split("\n")[0]!);
      for (const detail of [
        "code: 23",
        "signal: null",
        "killed: false",
        "stdout: probe output",
        "stderr: runtime detail",
      ])
        expect(message).toContain(detail);
    }
    expect(deps.lookupDependencyAdvisory).not.toHaveBeenCalled();
    expect(onCodex).not.toHaveBeenCalled();
  },
);

test("returns only the report accepted after the investigator corrects a rejected submission", async () => {
  await using temp = await scopedTemporaryDirectory("cve-skill-");
  const repo = temp.path;
  git(repo, "init", "--quiet");
  const nested = join(repo, "app");
  await mkdir(nested);
  await writeFile(
    join(nested, "index.ts"),
    'import "sample-decoder"; // checkout-only marker\n',
  );
  const usage = {
    input_tokens: 120,
    cached_input_tokens: 40,
    cache_write_input_tokens: 0,
    output_tokens: 12,
    reasoning_output_tokens: 4,
  };
  const reviewUsage = { ...usage, input_tokens: 19, cached_input_tokens: 4 };
  const gap = "The citation does not resolve which version was installed.";
  const selectedEnvironment = {
    CODEX_HOME: join(repo, "fixture-home"),
    SYNTHETIC_PROVIDER_KEY: "fixture",
  };
  const provider = {
    model_provider: "private",
    model_providers: { private: { env_key: "SYNTHETIC_PROVIDER_KEY" } },
  };

  const deps = dependencies({
    currentDirectory: nested,
    environment: { PATH: process.env["PATH"] },
    onCodex: async (argv, output) => {
      const session = output!.appServer!;
      expect(argv).toContain("app-server");
      expect(session.directory).toBe(repo);
      expect(argv).toContain('web_search="disabled"');
      expect(argv).toContain("tools.update_plan.enabled=true");
      const skill = join(
        await bundledPluginRoot(),
        "skills",
        "dependency-exploitability",
      );
      expect(output?.readOnlySkillRoot).toBe(skill);
      expect(output?.allowedMcpServers).toEqual([]);
      expect(argv).toContain("project_root_markers=[]");
      const { mcp_servers: servers } = parseToml(
        argv.find((arg) => arg.startsWith("mcp_servers="))!,
      );
      expect(servers).toEqual({});
      const graph = session.dependencyGraph!;
      expect(graph.tools.map(({ name }) => name)).toEqual([
        "fetch_dependency_source",
        "read_dependency_source",
        "review_dependency_advisory",
        "trace_codex_security_code",
        "resolve_codex_security_services",
        "query_codex_security_graph",
        "record_codex_security_evidence",
      ]);
      const paths = ["app/index.ts"];
      const serviceResolution = {
        services_found: 0,
        services: [],
        service_resolution: {
          catalog_configured: false,
          pending: 0,
          checked: 0,
        },
      };
      expect(
        await graph.call("resolve_codex_security_services", { paths }),
      ).toMatchObject(serviceResolution);
      await expect(
        graph.call("resolve_codex_security_services", {
          paths,
          resolutions: [
            {
              path: paths[0],
              services: [{ name: "sample-decoder" }],
              source: "app/index.ts",
            },
          ],
        }),
      ).rejects.toThrow("Unrecognized key");
      expect(await graph.call("query_codex_security_graph", {})).toMatchObject(
        serviceResolution,
      );
      expect(session.prompt).toContain(JSON.stringify(join(skill, "SKILL.md")));
      expect(session.prompt).toContain(advisory.advisories[0]!.summary);
      expect(session.prompt.split("\n")).toContain(
        JSON.stringify(defaultCallerScope),
      );
      expect(session.prompt).not.toContain("checkout-only marker");

      const tool = session.dependencyReport!;
      assert(tool.submit);
      tool.bindReviewer!(selectedEnvironment, provider);
      const first = structuredClone(unresolvedDecoder);
      first.uses[0]!.version = "1.0.0";
      const rejection = await submitUses(tool, first);
      expect(rejection.accepted).toBe(false);
      expect(rejection.feedback).toContain(gap);
      expect((await submitUses(tool, unresolvedDecoder)).accepted).toBe(true);
      output!.onUsage?.({ ...usage, total_tokens: 132 });
      output!.stdout.write(JSON.stringify(first));
      return 0;
    },
  });
  let submissions = 0;
  const review = mock<NonNullable<typeof deps.reviewDependencyReport>>(
    async (prompt, _schema, options) => {
      expect(prompt).toContain("checkout-only marker");
      const packet = JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1));
      expect(packet.callerScope).toBe(defaultCallerScope);
      expect(options.selectedEnvironment).toEqual(selectedEnvironment);
      expect(options.config?.codexOverrides).toEqual(provider);
      options.onUsage?.(reviewUsage);
      return ++submissions === 1
        ? reviewDecision(prompt, false, gap)
        : reviewDecision(prompt, true);
    },
  );
  deps.reviewDependencyReport = review;
  deps.lookupDependencyAdvisory = async (cve, signal) => {
    expect(cve).toBe(advisory.cve);
    expect(signal).toBeInstanceOf(AbortSignal);
    return advisory;
  };
  const { runCli, stdout, stderr } = createCliTest(main);
  expect(await runCli(args, deps), stderr.text()).toBe(0);
  const report = JSON.parse(stdout.text());
  expect(report).not.toHaveProperty("status");
  expect(report).toMatchObject({
    schemaVersion: 2,
    assumptions: [defaultCallerScope],
    uses: unresolvedDecoder.uses,
    limitations: unresolvedDecoder.limitations,
    cve: advisory.cve,
    advisories: [advisory.advisories[0]!.url],
    advisoryDetails: advisory.advisories,
    usage: {
      input_tokens: 158,
      cached_input_tokens: 48,
      cache_write_input_tokens: 0,
      output_tokens: 36,
      reasoning_output_tokens: 12,
    },
  });
  expect(report.uses[0]).toMatchObject({
    place: { environment: null, kind: "unknown" },
    decidingEvidence: [{ kind: "source", path: "app/index.ts" }],
  });
  expect(review).toHaveBeenCalledTimes(2);
});

async function runPackageCheck(
  repo: string,
  records: { id: string; advisories: typeof advisory.advisories }[],
  ...flags: string[]
) {
  git(repo, "init", "--quiet");
  await mkdir(join(repo, "app"));
  await writeFile(join(repo, "app", "index.ts"), 'import "sample-decoder";\n');
  const prompts: string[] = [];
  const reviews: unknown[] = [];
  const signals: AbortSignal[] = [];
  const deps = dependencies({
    currentDirectory: repo,
    onCodex: async (_argv, output) => {
      const signal = output!.signal!;
      expect(signals.every((previous) => previous.aborted)).toBe(true);
      expect(signal.aborted).toBe(false);
      signals.push(signal);
      const session = output!.appServer!;
      prompts.push(session.prompt);
      const record = records.find(({ id }) => session.prompt.includes(id));
      const result = await submitUses(session.dependencyReport, {
        ...unresolvedDecoder,
        limitations: record
          ? [`The installed version for ${record.id} is unknown.`]
          : unresolvedDecoder.limitations,
      });
      expect(result.accepted, result.feedback).toBe(true);
      return 0;
    },
  });
  deps.lookupDependencyAdvisory = mock(async () => advisory);
  const packageLookup = mock<NonNullable<typeof deps.lookupPackageAdvisories>>(
    async () => records,
  );
  deps.lookupPackageAdvisories = packageLookup;
  deps.reviewDependencyReport = async (prompt) => {
    reviews.push(
      JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1)).advisory,
    );
    return reviewDecision(prompt, true);
  };
  const { runCli, stdout, stderr } = createCliTest(main);
  const exit = await runCli(
    ["exploitability", "check", "npm:sample-decoder", ...flags, "--json"],
    deps,
  );
  expect(exit, stderr.text()).toBe(0);
  expect(deps.lookupDependencyAdvisory).not.toHaveBeenCalled();
  return {
    report: JSON.parse(stdout.text()),
    packageLookup,
    prompts,
    reviews,
    signals,
  };
}

test("assesses a supplied vulnerability description without looking it up in OSV", async () => {
  await using temp = await scopedTemporaryDirectory("package-description-");
  const description =
    'The "raw" decoder may ignore a limit.\nSee the local release notes.';
  const { report, packageLookup, prompts, reviews } = await runPackageCheck(
    temp.path,
    [],
    "--vuln-description",
    description,
  );
  expect(packageLookup).not.toHaveBeenCalled();
  expect(prompts).toHaveLength(1);
  expect(prompts[0]).toContain(decoder.name);
  expect(prompts[0]).toContain("See the local release notes.");
  expect(prompts[0]).not.toContain(description);
  expect(reviews).toEqual([
    expect.objectContaining({ package: decoder, vulnDescription: description }),
  ]);
  expect(report).toMatchObject({
    package: decoder,
    vulnDescription: description,
    checks: [{ advisoryId: null, advisories: [], schemaVersion: 2 }],
  });
  expect(report).not.toHaveProperty("cve");
  expect(report.checks[0]).not.toHaveProperty("advisoryDetails");
  expect(report.checks[0]).not.toHaveProperty("cve");
  expect(report.checks[0]).not.toHaveProperty("status");
});

test("reviews each published advisory for a package independently", async () => {
  await using temp = await scopedTemporaryDirectory("package-advisories-");
  const records = ["OSV-EXAMPLE-1", "OSV-EXAMPLE-2"].map((id) => ({
    id,
    advisories: [
      { ...advisory.advisories[0]!, url: "https://example.invalid/" + id },
    ],
  }));
  const { packageLookup, prompts, reviews, report, signals } =
    await runPackageCheck(temp.path, records);
  expect(signals.map((signal) => signal.aborted)).toEqual([true, true]);
  expect(packageLookup).toHaveBeenCalledTimes(1);
  expect(packageLookup).toHaveBeenCalledWith(decoder, expect.any(AbortSignal));
  expect(prompts).toHaveLength(records.length);
  expect(reviews).toHaveLength(records.length);
  expect(report.package).toEqual(decoder);
  expect(report.checks).toHaveLength(records.length);
  for (const record of records) {
    expect(prompts.filter((prompt) => prompt.includes(record.id))).toHaveLength(
      1,
    );
    expect(reviews).toContainEqual(
      expect.objectContaining({
        package: decoder,
        id: record.id,
        advisories: record.advisories,
      }),
    );
    expect(report.checks).toContainEqual(
      expect.objectContaining({
        advisoryId: record.id,
        advisories: [record.advisories[0]!.url],
        advisoryDetails: record.advisories,
        limitations: [`The installed version for ${record.id} is unknown.`],
        schemaVersion: 2,
      }),
    );
  }
});

test("returns an empty package result without investigating when OSV has no advisories", async () => {
  await using temp = await scopedTemporaryDirectory("package-no-advisories-");
  const { report, packageLookup, prompts, reviews } = await runPackageCheck(
    temp.path,
    [],
  );
  expect(packageLookup).toHaveBeenCalledTimes(1);
  expect(prompts).toEqual([]);
  expect(reviews).toEqual([]);
  expect(report).toMatchObject({ package: decoder, checks: [] });
});

test("runtime citations require a successful result from the selected service catalog in this check", async () => {
  await using temp = await scopedTemporaryDirectory("cve-inventory-");
  const repo = temp.path;
  git(repo, "init", "--quiet");
  const config = join(repo, "inventory.json");
  await writeFile(
    config,
    JSON.stringify({
      exploitability: { service_catalog_mcps: ["catalog"] },
      codex: {
        mcp_servers: { catalog: { url: "https://catalog.invalid/mcp" } },
      },
    }),
  );
  await writeFile(
    join(repo, "app.ts"),
    'import {decode} from "sample-decoder";\ndecode(input);\n',
  );
  const record = "reader@rev7/public";
  const assessment = {
    status: "exploitable",
    uses: [
      {
        location: "reader",
        component: "sample-decoder",
        version: "1",
        verdict: "exploitable",
        deployment: "confirmed",
        reason: "The lookup identifies the running public reader.",
        evidence: [
          {
            path: "app.ts",
            startLine: 1,
            endLine: 2,
            supports: ["affected_copy", "affected_use"],
          },
        ],
        observations: [
          { server: "catalog", record, supports: ["running", "access"] },
        ],
      },
    ],
    limitations: [],
  };
  const result = {
    content: [
      {
        type: "text",
        text: "runtime-record-23: reader@rev7/public observed running revision 7 and receiving a public request",
      },
    ],
  };
  for (const observed of [
    "catalog",
    "codex_security_dependency",
    "unselected",
    undefined,
  ]) {
    const deps = dependencies({
      currentDirectory: repo,
      environment: { PATH: process.env["PATH"] },
      onCodex: async (_argv, output) => {
        const tool = output!.appServer!.dependencyReport!;
        assert(tool.submit);
        if (observed) tool.recordInventory(observed, result);
        const outcome = await submitUses(tool, assessment);
        expect(outcome.accepted).toBe(observed === "catalog");
        if (!outcome.accepted) expect(outcome.feedback).toContain("catalog");
        return 0;
      },
    });
    deps.lookupDependencyAdvisory = async () => advisory;
    const review = mock<NonNullable<typeof deps.reviewDependencyReport>>(
      async (prompt) => {
        expect(prompt).toContain("runtime-record-23");
        return reviewDecision(prompt, true, undefined, "1");
      },
    );
    deps.reviewDependencyReport = review;
    const { runCli, stdout, stderr } = createCliTest(main);
    const exit = await runCli([...args, "--config", config], deps);
    if (observed === "catalog") {
      expect(exit, stderr.text()).toBe(0);
      const report = JSON.parse(stdout.text());
      expect(report).not.toHaveProperty("status");
      expect(report.uses[0].verdict).toBe("exploitable");
      expect(review).toHaveBeenCalledTimes(1);
    } else {
      expect(exit).toBe(2);
      expect(review).not.toHaveBeenCalled();
      expect(stdout.text()).not.toContain('"status":"exploitable"');
    }
  }
});

test("finishing with a valid-looking final message cannot produce an unverified report", async () => {
  await using temp = await scopedTemporaryDirectory("cve-bypass-");
  git(temp.path, "init", "--quiet");
  const draft = {
    status: "unknown",
    uses: [],
    limitations: ["Source coverage incomplete."],
  };
  const deps = dependencies({
    currentDirectory: temp.path,
    environment: { PATH: process.env["PATH"] },
    onCodex: (_argv, output) => {
      output!.stdout.write(JSON.stringify(draft));
      return 0;
    },
  });
  deps.lookupDependencyAdvisory = async () => advisory;
  deps.reviewDependencyReport = mock(async () => {
    throw new Error("Unrequested review");
  });
  const { runCli, stdout, stderr } = createCliTest(main);
  expect(await runCli(args, deps)).toBe(2);
  expect(stderr.text()).toContain("report");
  expect(stdout.text()).not.toContain(draft.limitations[0]!);
  expect(deps.reviewDependencyReport).not.toHaveBeenCalled();
});

test("the native coordinator queues observed candidates and retains independent review", async () => {
  await using temp = await scopedTemporaryDirectory("cve-group-order-");
  git(temp.path, "init", "--quiet");
  await writeFile(
    join(temp.path, "scope.txt"),
    "Selected dependency build is unknown.\n",
  );
  const evidence = [
    { path: "scope.txt", startLine: 1, endLine: 1, supports: [] },
  ];
  const direct = {
    id: "direct",
    kind: "use",
    candidateIds: [],
    use: {
      location: "scope.txt:1",
      component: "sample-decoder",
      version: null,
      verdict: "unknown",
      deployment: "unknown",
      reason: "The selected dependency build is unknown.",
      evidence,
      observations: [],
    },
  };
  const deps = dependencies({
    currentDirectory: temp.path,
    environment: { PATH: process.env["PATH"] },
    onCodex: async (argv, output) => {
      expect(argv).toContain("features.multi_agent_v2=true");
      expect(argv).toContain("features.multi_agent_v2_dynamic_tools=true");
      // The default is selected after reading native home configuration.
      expect(argv).not.toContain(
        "features.multi_agent_v2.max_concurrent_threads_per_session=16",
      );
      expect(output?.appServer?.prompt).toContain("Use native update_plan");
      expect(output?.appServer?.prompt).toContain("Use native spawn_agent");
      const tool = output?.appServer?.dependencyReport;
      assert(tool?.observeGraph && tool.queue && tool.status && tool.submit);
      const [candidate] = await tool.observeGraph("trace_codex_security_code", {
        trace: [
          {
            relation: "candidate_call",
            evidence: [{ source: "scope.txt", lines: [1] }],
          },
        ],
      });
      assert(candidate);
      const queue = {
        items: [
          {
            id: "scope",
            kind: "unresolved",
            candidateIds: [candidate.id],
            reason: "Consumer selection missing.",
            evidence,
            observations: [],
          },
        ],
      };
      expect(await tool.queue({ items: [direct] })).toMatchObject({
        queued: true,
      });
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(review).toHaveBeenCalledTimes(1);
      expect(await tool.queue(queue)).toMatchObject({ queued: true });
      const result = await tool.submit({
        reviewItems: ["direct", "scope"].map((id) => ({ id, revision: 1 })),
        candidateGeneration: 1,
        limitations: [],
      });
      expect(result.accepted, result.feedback).toBe(true);
      return 0;
    },
  });
  deps.lookupDependencyAdvisory = async () => advisory;
  const reviewed: { id: string; revision: number; kind: string }[] = [];
  const review = mock(async (prompt: string) => {
    const packet = JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1));
    for (const item of packet.items) {
      reviewed.push({ id: item.id, revision: item.revision, kind: item.kind });
      expect(item.excerptIds).not.toBeEmpty();
      expect(packet.excerpts[item.excerptIds[0]].text).toBe(
        "Selected dependency build is unknown.",
      );
    }
    return reviewDecision(prompt, true);
  });
  deps.reviewDependencyReport = review;
  const { runCli, stdout, stderr } = createCliTest(main);
  expect(await runCli(args, deps), stderr.text()).toBe(0);
  expect(JSON.parse(stdout.text())).not.toHaveProperty("status");
  expect(review).toHaveBeenCalledTimes(2);
  expect(reviewed).toEqual([
    { id: "direct", revision: 1, kind: "use" },
    { id: "scope", revision: 1, kind: "unresolved" },
  ]);
});

test("preserves a sibling's fixing hunk when revising the selected copy assessment", async () => {
  await using temp = await scopedTemporaryDirectory("cve-native-evidence-");
  git(temp.path, "init", "--quiet");
  await mkdir(join(temp.path, "app"));
  await writeFile(
    join(temp.path, "app", "index.ts"),
    'import { decode } from "./parser"; decode(input);\n',
  );
  await writeFile(
    join(temp.path, "app", "parser.ts"),
    "export function decode(input: string) { if (input.length > 8) return null; return input; }\n",
  );
  await writeFile(
    join(temp.path, "app", "package.json"),
    '{"name":"sample-decoder","version":"1.0.0"}\n',
  );
  const callerScope =
    "Assess the CI runner that submits bytes to the fixture POST /decode route.";
  const use = { ...unresolvedDecoder.uses[0]! };
  const revisedUse = {
    ...use,
    version: "1.0.0",
    verdict: "ruled_out",
    deployment: "configured",
    reason:
      "The source copy selected by the handler includes the fixing length guard.",
    evidence: [
      ...use.evidence,
      {
        path: "app/package.json",
        startLine: 1,
        endLine: 1,
        supports: ["affected_copy"],
      },
      {
        path: "app/parser.ts",
        startLine: 1,
        endLine: 1,
        supports: ["affected_use"],
      },
    ],
  };
  const releaseInitialReview = Promise.withResolvers<void>();
  const deps = dependencies({
    currentDirectory: temp.path,
    environment: { PATH: process.env["PATH"] },
    onCodex: async (argv, output) => {
      expect(argv).toContain('model_reasoning_effort="high"');
      const session = output!.appServer!;
      expect(session.prompt.split("\n")).toContain(JSON.stringify(callerScope));
      expect(session.prompt).not.toContain(defaultCallerScope);
      const tool = session.dependencyReport!;
      assert(tool.observeGraph && tool.queue && tool.status && tool.submit);
      const [candidate] = await tool.observeGraph("trace_codex_security_code", {
        trace: [
          {
            relation: "candidate_call",
            evidence: [{ source: "app/index.ts", lines: [1] }],
          },
        ],
      });
      assert(candidate);
      const original = {
        id: "decoder",
        kind: "use",
        candidateIds: [candidate.id],
        use,
      };
      expect(await tool.queue({ items: [original] })).toMatchObject({
        queued: true,
      });
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(review).toHaveBeenCalledTimes(1);

      // A sibling writes its finding before returning a summary or an assessment.
      const saved = await session.dependencyGraph!.call(
        "record_codex_security_evidence",
        {
          question: "Does the selected parser contain the length guard?",
          scope: "app/parser.ts",
          claim: "The checked-in parser has the fixing guard.",
          evidence: [{ path: "app/parser.ts", startLine: 1, endLine: 1 }],
        },
      );
      const note = saved["source_evidence"] as { id: string };
      const retrieved = await session.dependencyGraph!.call(
        "query_codex_security_graph",
        {
          evidence: { id: note.id },
        },
      );
      expect(retrieved).toMatchObject({
        source_evidence: {
          id: note.id,
          excerpts: [
            {
              path: "app/parser.ts",
              text: expect.stringContaining("input.length > 8"),
            },
          ],
        },
      });
      const details = (await tool.status({ assessmentIds: ["decoder"] })) as {
        assessmentItems: { item: typeof original }[];
      };
      expect(details.assessmentItems[0]!.item.use).toEqual(use);
      expect(
        await tool.queue({ items: [{ ...original, use: revisedUse }] }),
      ).toMatchObject({ queued: true });
      releaseInitialReview.resolve();
      const stale = await tool.submit({
        reviewItems: [{ id: "decoder", revision: 1 }],
        candidateGeneration: 1,
        limitations: [],
      });
      expect(stale.accepted).toBe(false);
      expect(stale.feedback).toContain("changed from revision 1 to 2");
      const result = await tool.submit({
        reviewItems: [{ id: "decoder", revision: 2 }],
        candidateGeneration: 1,
        limitations: [],
      });
      expect(result.accepted, result.feedback).toBe(true);
      return 0;
    },
  });
  deps.lookupDependencyAdvisory = async () => advisory;
  const reviewedRevisions: number[] = [];
  const review = mock(async (prompt: string) => {
    const packet = JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1));
    expect(packet.callerScope).toBe(callerScope);
    expect(packet.items).toHaveLength(1);
    const item = packet.items[0];
    expect(item.id).toBe("decoder");
    reviewedRevisions.push(item.revision);
    if (item.revision === 1) {
      expect(item.use.reason).toBe(use.reason);
      await releaseInitialReview.promise;
      return reviewDecision(prompt, false, "The selected copy is unresolved.");
    }
    expect(item.revision).toBe(2);
    expect(item.use.reason).toBe(revisedUse.reason);
    expect(prompt).toContain("app/parser.ts");
    expect(prompt).toContain("input.length > 8");
    expect(prompt).toContain('\"revision\":2');
    return reviewDecision(
      prompt,
      true,
      "The selected parser includes the fixing guard.",
      "1.0.0",
    );
  });
  deps.reviewDependencyReport = review;
  const { runCli, stdout, stderr } = createCliTest(
    (argv, out, err, dependencies) =>
      main(argv, out, err, dependencies, {
        dependencyCallerScope: callerScope,
      }),
  );
  expect(await runCli(args, deps), stderr.text()).toBe(0);
  expect(review).toHaveBeenCalledTimes(2);
  expect(reviewedRevisions).toEqual([1, 2]);
  const report = JSON.parse(stdout.text());
  expect(report).not.toHaveProperty("status");
  expect(report).toMatchObject({
    assumptions: [callerScope],
    uses: [revisedUse],
  });
});

test.each([
  {
    terminal: "review rejections",
    gap: "The justification for the reported scope is missing.",
  },
  { terminal: "reviewer outage", gap: "review provider unavailable" },
] as const)(
  "shows the final gap without publishing a report after $terminal",
  async ({ terminal, gap }) => {
    await using temp = await scopedTemporaryDirectory("cve-review-failed-");
    git(temp.path, "init", "--quiet");
    await writeFile(
      join(temp.path, "scope.txt"),
      "Consumer selection is not recorded.\n",
    );
    const limitation = "Consumer selection missing.";
    let continuedAfterRejection = false;
    const deps = dependencies({
      currentDirectory: temp.path,
      environment: { PATH: process.env["PATH"] },
      onCodex: async (_argv, output) => {
        const tool = output!.appServer!.dependencyReport!;
        assert(tool.queue && tool.submit);
        const queued = await tool.queue({
          items: [
            {
              id: "scope",
              kind: "unresolved",
              candidateIds: [],
              reason: limitation,
              evidence: [
                { path: "scope.txt", startLine: 1, endLine: 1, supports: [] },
              ],
              observations: [],
            },
          ],
        });
        assert(queued.queued, queued.feedback);
        const draft = {
          reviewItems: queued.items,
          candidateGeneration: 0,
          limitations: [limitation],
        };
        if (terminal === "reviewer outage") {
          expect((await tool.submit(draft)).accepted).toBe(false);
        } else {
          for (let attempt = 1; attempt < 10; attempt++)
            expect((await tool.submit(draft)).accepted).toBe(false);
          await tool.submit(draft);
          continuedAfterRejection = true;
        }
        return 0;
      },
    });
    deps.lookupDependencyAdvisory = async () => advisory;
    const review = mock(async (prompt: string) => {
      if (terminal === "reviewer outage") throw new Error(gap);
      return reviewDecision(prompt, false, gap);
    });
    deps.reviewDependencyReport = review;
    const { runCli, stdout, stderr } = createCliTest(main);
    expect(await runCli(args, deps)).toBe(2);
    expect(stderr.text()).toContain(gap);
    expect(continuedAfterRejection).toBe(false);
    expect(stdout.text()).not.toContain(limitation);
    expect(review).toHaveBeenCalledTimes(1);
  },
);

test("rejects invalid subjects and descriptions before looking up an advisory", async () => {
  const onCodex = mock<OnCodex>().mockReturnValue(0);
  const deps = dependencies({ onCodex });
  deps.lookupDependencyAdvisory = mock(async () => {
    throw new Error("Unexpected advisory lookup");
  });
  deps.lookupPackageAdvisories = mock(async () => []);
  for (const positionals of [
    [],
    [advisory.cve, "/messages"],
    ["sample-decoder"],
    [advisory.cve, "--vuln-description", "A reported condition"],
    ["npm:sample-decoder", "--vuln-description", "   "],
  ]) {
    expect(
      await runCapturedCli(
        main,
        ["exploitability", "check", ...positionals],
        deps,
      ),
    ).toBe(2);
  }
  expect(deps.lookupDependencyAdvisory).not.toHaveBeenCalled();
  expect(deps.lookupPackageAdvisories).not.toHaveBeenCalled();
  expect(onCodex).not.toHaveBeenCalled();
});

test("the CLI captures upstream receipts and reuses sink profiles through its graph tools", async () => {
  await using temp = await scopedTemporaryDirectory("cve-evidence-");
  git(temp.path, "init", "--quiet");
  await mkdir(join(temp.path, "app"));
  await writeFile(
    join(temp.path, "app", "index.ts"),
    'import "sample-decoder";\n',
  );
  const config = join(temp.path, "explicit.json");
  await writeFile(
    config,
    JSON.stringify({
      exploitability: { runtime_mcps: ["profiles"] },
      codex: {
        mcp_servers: {
          profiles: {
            command: "fixture-profiles",
            enabled_tools: ["profiles.stacks"],
          },
        },
      },
    }),
  );
  const deps = dependencies({
    currentDirectory: temp.path,
    environment: { PATH: process.env["PATH"] },
    onCodex: async (_argv, output) => {
      const graph = output!.appServer!.dependencyGraph!;
      const coverage = new DependencyReportCoverage();
      let callId = 0;
      async function callGraph(
        name: string,
        args: unknown,
        rpc?: Parameters<typeof graph.call>[2],
      ) {
        const item = {
          type: "mcpToolCall",
          server: "codex_security_dependency",
          id: String(++callId),
        };
        coverage.observe("item/started", item);
        const result = await graph.call(name, args, rpc);
        coverage.observe("item/completed", {
          ...item,
          status: "completed",
          result: { structuredContent: result },
        });
        expect(coverage.incomplete).toBe(false);
        expect(result).not.toHaveProperty("graph_evidence");
        return result;
      }
      const capture = await callGraph("fetch_dependency_source", {
        kind: "github",
        owner: "example",
        repository: "decoder",
        commit: "a".repeat(40),
        path: "decoder.c",
      });
      const excerpt = await callGraph("read_dependency_source", {
        sourceId: capture["sourceId"],
        startLine: 1,
        endLine: 1,
      });
      expect(excerpt["text"]).toBe("check_length(value);\n");
      expect(typeof excerpt["receiptId"]).toBe("string");
      const note = await callGraph("record_codex_security_evidence", {
        question: "Which dependency does this checkout import?",
        scope: "app/index.ts",
        claim: "The caller imports sample-decoder.",
        evidence: [{ path: "app/index.ts", startLine: 1, endLine: 1 }],
      });
      const saved = await callGraph("query_codex_security_graph", {
        evidence: { id: (note["source_evidence"] as JsonObject)["id"] },
      });
      expect(saved).toMatchObject({
        source_evidence: {
          excerpts: [
            {
              path: "app/index.ts",
              sourceIdentity: {
                kind: "git",
                status: "unavailable",
                contentSha256: createHash("sha256")
                  .update('import "sample-decoder";\n')
                  .digest("hex"),
              },
            },
          ],
        },
      });
      expect(
        await callGraph("review_dependency_advisory", {
          question: "Does the advisory include the streaming entrypoint?",
          interpretations: ["decode only", "both entrypoints"],
          evidenceIds: ["advisory-1", excerpt["receiptId"]],
        }),
      ).toMatchObject({ decision: "resolved", searchOperations: ["decode"] });
      const uri = "fixture://profiles";
      const format = "codex-security-graph-evidence/v1";
      const selector = {
        service: "decoder",
        cluster: "fixture",
        frames: ["decode"],
      };
      const window = {
        start: "2026-01-01T00:00:00.000Z",
        end: "2026-01-01T01:00:00.000Z",
      };
      const query = { selector, window, limit: 2 };
      const resource = JSON.stringify({
        format,
        frame_order: "root_first",
        metadata: {
          scope: { ...selector, ...window, frame_match: "any_exact_name" },
          coverage: {
            result_complete: true,
            backend_partial: false,
            returned_stack_count: 2,
          },
          limits: { stack_limit: query.limit, truncated: false },
        },
        observations: [1, 2].map((row) => ({
          id: `stack-${row}`,
          kind: "sampled_stack",
          scope: {
            service: selector.service,
            cluster: selector.cluster,
            window,
            observed_image: { name: "decoder", tag: "a" },
          },
          frames: [
            { kind: "function", name: "handler" },
            { kind: "function", name: "decode" },
          ],
        })),
      });
      const call = mock(
        async (server: string, tool: string, args: JsonObject) => {
          expect([server, tool, args]).toEqual([
            "profiles",
            "profiles.stacks",
            query,
          ]);
          return {
            structuredContent: {
              graph_evidence: {
                format,
                uri,
                sha256: createHash("sha256").update(resource).digest("hex"),
              },
            },
          };
        },
      );
      const rpc = {
        list: async () => ({
          data: [
            {
              name: "profiles",
              tools: {
                "profiles.stacks": { annotations: { readOnlyHint: true } },
              },
            },
          ],
        }),
        call,
        read: async () => ({ contents: [{ uri, text: resource }] }),
      };
      const profiles = await callGraph(
        "collect_dependency_profiles",
        query,
        rpc,
      );
      expect(profiles).toMatchObject({
        uncovered: [],
        slices: [{ outcome: "found_stacks", cached: false }],
      });
      expect(
        await callGraph("collect_dependency_profiles", query, rpc),
      ).toMatchObject({
        uncovered: [],
        slices: [{ outcome: "found_stacks", cached: true }],
      });
      expect(call).toHaveBeenCalledTimes(1);
      const collectionId = (profiles["slices"] as JsonObject[])[0]![
        "collectionId"
      ];
      const witnesses = await callGraph("read_dependency_profile_stacks", {
        collectionId,
        firstRow: 1,
        lastRow: 1,
      });
      const receiptSelection = (witnesses["stacks"] as JsonObject[])[0]![
        "receiptSelection"
      ];
      const report = output!.appServer!.dependencyReport!;
      const use = {
        ...unresolvedDecoder.uses[0]!,
        observations: [
          {
            server: "codex_security_upstream_source",
            record: "Exact upstream line 1",
            supports: [],
          },
          {
            server: "codex_security_sampled_profiles",
            record: "stack-1",
            supports: [],
          },
        ],
      };
      const item = {
        id: "decoder",
        kind: "use",
        candidateIds: [],
        use,
        receiptIds: [excerpt["receiptId"]],
        receiptSelections: [receiptSelection],
      };
      const result = await report.queue!({ items: [item] });
      expect(result.queued, result.feedback).toBe(true);
      const submitted = await report.submit!({
        reviewItems: [{ id: "decoder", revision: 1 }],
        candidateGeneration: 0,
        limitations: unresolvedDecoder.limitations,
      });
      expect(submitted.accepted, submitted.feedback).toBe(true);
      return 0;
    },
  });
  deps.lookupDependencyAdvisory = async () => advisory;
  deps.reviewDependencyReport = async (prompt) => {
    expect(prompt).toContain("check_length(value);");
    if (prompt.startsWith("Independently resolve")) {
      return JSON.stringify({
        decision: "resolved",
        reason: "The guard is on decode.",
        interpretations: [
          {
            component: "sample-decoder",
            affectedVersions: "1.x",
            operations: ["decode"],
            conditions: [],
            exclusions: [],
            evidenceIds: ["advisory-1"],
          },
        ],
      });
    }
    expect(prompt).toContain("stack-1");
    expect(prompt).not.toContain("stack-2");
    const packet = JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1));
    expect(Object.values(packet.excerpts)).toContainEqual(
      expect.objectContaining({
        path: "app/index.ts",
        sourceIdentity: expect.objectContaining({
          kind: "git",
          status: "unavailable",
          contentSha256: createHash("sha256")
            .update('import "sample-decoder";\n')
            .digest("hex"),
        }),
      }),
    );
    return reviewDecision(prompt, true);
  };
  const requests: string[] = [];
  const fetchSource: typeof fetch = Object.assign(
    async (input: Parameters<typeof fetch>[0]) => {
      requests.push(String(input));
      return new Response("check_length(value);\n");
    },
    { preconnect: fetch.preconnect },
  );
  deps.fetchDependencySource = fetchSource;
  const { runCli, stderr, stdout } = createCliTest(main);
  expect(await runCli([...args, "--config", config], deps), stderr.text()).toBe(
    0,
  );
  expect(JSON.parse(stdout.text()).limitations.join("\n")).toMatch(
    /^Profile collection [a-f0-9]{64} has unassessed rows 2–2\.$/mu,
  );
  expect(requests).toEqual([
    `https://raw.githubusercontent.com/example/decoder/${"a".repeat(40)}/decoder.c`,
  ]);
});

test("a runtime-only MCP reaches the investigator without enabling catalog resolution", async () => {
  await using temp = await scopedTemporaryDirectory("cve-runtime-mcp-");
  git(temp.path, "init", "--quiet");
  const config = join(temp.path, "explicit.json");
  const artifacts = {
    command: "fixture-artifacts",
    enabled_tools: ["read_artifact"],
  };
  await writeFile(
    config,
    JSON.stringify({
      exploitability: { runtime_mcps: ["artifacts"] },
      codex: { mcp_servers: { artifacts } },
    }),
  );
  const deps = dependencies({
    currentDirectory: temp.path,
    environment: { PATH: process.env["PATH"] },
    onCodex: async (argv, output) => {
      const session = output!.appServer!;
      const { mcp_servers } = parseToml(
        argv.find((arg) => arg.startsWith("mcp_servers="))!,
      );
      expect(mcp_servers).toEqual({ artifacts });
      expect(output?.allowedMcpServers).toEqual(["artifacts"]);
      expect(session.prompt).toContain(
        "Servers selected for source-to-service catalog lookup: [].",
      );
      expect(
        await session.dependencyGraph!.call("query_codex_security_graph", {}),
      ).toMatchObject({ service_resolution: { catalog_configured: false } });
      expect(
        session.dependencyReport!.recordInventory(
          "artifacts",
          { digest: "a" },
          {
            tool: "read_artifact",
          },
        ),
      ).toBeDefined();
      return 23;
    },
  });
  deps.lookupDependencyAdvisory = async () => advisory;
  deps.resolveDependencyServices = mock(async () => []);
  expect(await runCapturedCli(main, [...args, "--config", config], deps)).toBe(
    23,
  );
  expect(deps.resolveDependencyServices).not.toHaveBeenCalled();
});

test("shares catalog MCPs, but not runtime-only MCPs, with the resolver", async () => {
  await using temp = await scopedTemporaryDirectory("cve-config-");
  const repo = temp.path;
  git(repo, "init", "--quiet");
  const config = join(repo, "explicit.json");
  const file = "src/worker.ts";
  await mkdir(join(repo, "src"));
  await writeFile(join(repo, file), 'import "sample-decoder";\n');
  const catalog = {
    url: "https://catalog.invalid/mcp",
    enabled_tools: ["find_service", "read_revision"],
  };
  const artifacts = {
    command: "fixture-artifacts",
    enabled_tools: ["read_artifact"],
  };
  const instructions = "Read available deployments and retain coverage gaps.";
  await writeFile(
    config,
    JSON.stringify({
      exploitability: {
        service_catalog_mcps: ["catalog"],
        runtime_mcps: ["catalog", "artifacts"],
      },
      codex: {
        mcp_servers: {
          catalog: { ...catalog, instructions },
          artifacts: { ...artifacts, instructions: "Use exact artifact IDs." },
          unrelated: { command: "unrelated" },
        },
      },
    }),
  );
  const selectedEnvironment = { CODEX_HOME: join(repo, "fixture-home") };
  const provider = {
    model_provider: "openai",
    model: "synthetic",
    daybreak: true,
    features: { cli_daybreak: true },
  };
  const service = { name: "catalog-worker", scope: "catalog:svc-1" };
  const source = "catalog/read_service#svc-1";
  const onCodex = mock<OnCodex>(async (argv, output) => {
    const session = output!.appServer!;
    const { mcp_servers } = parseToml(
      argv.find((arg) => arg.startsWith("mcp_servers="))!,
    );
    expect(mcp_servers).toEqual({ catalog, artifacts });
    expect(output?.allowedMcpServers).toEqual(["catalog", "artifacts"]);
    expect(session.prompt).toContain(JSON.stringify(["catalog"]));
    expect(session.prompt).toContain(instructions);
    expect(session.prompt).not.toContain(catalog.url);

    session.dependencyReport!.bindReviewer!(
      selectedEnvironment,
      provider,
      "daybreak_blue",
    );
    const graph = session.dependencyGraph!;
    const resolve = "resolve_codex_security_services";
    const query = "query_codex_security_graph";
    const request = { paths: ["src/./worker.ts", file], project: "src" };
    await expect(
      graph.call(resolve, {
        ...request,
        observations: [{ service: "sample-decoder", source: file }],
      }),
    ).rejects.toThrow("Unrecognized key");
    expect(await graph.call(query, {})).toMatchObject({ services_found: 0 });
    const resolved = await graph.call(resolve, request);
    expect(resolved).toMatchObject({
      services_found: 1,
      services: [service],
      service_resolution: { catalog_configured: true, pending: 0, checked: 1 },
    });
    expect(await graph.call(query, { node: file })).toMatchObject({
      evidence: [expect.objectContaining({ relation: "uses", source })],
    });
    expect(await graph.call(resolve, request)).toEqual(resolved);
    return 23;
  });
  const deps = dependencies({
    currentDirectory: repo,
    environment: { PATH: process.env["PATH"] },
    onCodex,
  });
  const resolveServices = mock<
    NonNullable<typeof deps.resolveDependencyServices>
  >(
    async ({
      servers,
      instructions: guidance,
      repository,
      requests,
      runtime,
      signal,
    }) => {
      expect(servers).toEqual({ catalog });
      expect(guidance).toEqual({ catalog: instructions });
      expect(repository).toBe(repo);
      expect(requests).toEqual([{ path: file, project: "src" }]);
      expect(runtime.selectedEnvironment).toEqual(selectedEnvironment);
      expect(runtime.config?.codexOverrides).toEqual(provider);
      expect(runtime.cyberAccessProgram).toBe("daybreak_blue");
      expect(signal).toBeInstanceOf(AbortSignal);
      return [
        {
          path: file,
          source,
          services: [{ ...service, source }],
          reason:
            "The catalog identifies this worker as a consumer of the source project.",
        },
      ];
    },
  );
  deps.resolveDependencyServices = resolveServices;
  deps.lookupDependencyAdvisory = async () => advisory;
  expect(await runCapturedCli(main, [...args, "--config", config], deps)).toBe(
    23,
  );
  expect(onCodex).toHaveBeenCalledTimes(1);
  expect(resolveServices).toHaveBeenCalledTimes(1);
});
