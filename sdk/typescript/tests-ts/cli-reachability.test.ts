import { expect, mock, spyOn, test } from "bun:test";
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  readFile,
  readlink,
  realpath,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import * as filesystem from "node:fs/promises";
import { basename, dirname, join, sep } from "node:path";
import { promisify } from "node:util";
import { parse as parseToml } from "smol-toml";
import { main } from "../src/cli.js";
import type { JsonObject } from "../src/config.js";
import type { DependencyUse } from "../src/dependency-reachability.js";
import { DependencyReportCoverage } from "../src/dependency-report-coverage.js";
import type { DependencyProgressEvent } from "../src/dependency-progress.js";
import { createDependencyVerdictProgress } from "../src/dependency-verdict-progress.js";
import { canonicalJson } from "../src/record.js";
import { bundledPluginRoot } from "../src/runtime.js";
import { dependencies, FakeSignals, type OnCodex } from "./cli-fixtures.js";
import { git } from "./git-fixture.js";
import { createCliTest, runCapturedCli } from "./support/cli-run.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

async function waitForReviewStart(predicate: () => boolean) {
  const deadline = Date.now() + 2_000;
  while (!predicate()) {
    if (Date.now() > deadline)
      throw new Error("Expected the background reviewer to start.");
    await Bun.sleep(1);
  }
}

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
      hash: string;
      excerptIds: string[];
      receiptIds: string[];
    }[];
  };
  return JSON.stringify({
    items: packet.items.map((item) => ({
      id: item.id,
      revision: item.revision,
      hash: item.hash,
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
        "record_codex_security_source_work",
        "record_codex_security_endpoint",
        "record_codex_security_evidence",
      ]);
      const paths = ["app/index.ts"];
      const work = (input: JsonObject) =>
        graph.call("record_codex_security_source_work", { work: input });
      await work({
        operation: "append_roster_page",
        id: "decoder-discovery",
        owner: "coordinator",
        paths,
        declaredComplete: true,
        search: "Find the decoder import",
        sourceRefs: ["source-read"],
        gaps: [],
      });
      await work({
        operation: "assign_partition",
        id: "caller",
        rosterId: "decoder-discovery",
        owner: "first",
        paths,
      });
      await work({
        operation: "offer_handoff",
        partitionId: "caller",
        owner: "first",
        expectedRevision: 1,
        recipient: "second",
        newPartitionId: "continued-caller",
        paths,
      });
      await work({
        operation: "accept_handoff",
        partitionId: "caller",
        recipient: "second",
        expectedRevision: 2,
      });
      await work({
        operation: "record_examined",
        partitionId: "continued-caller",
        owner: "second",
        expectedRevision: 1,
        paths,
      });
      expect(
        await graph.call("query_codex_security_graph", { sourceWork: {} }),
      ).toMatchObject({
        source_work: {
          rosterCount: 1,
          gapCount: 0,
          unassignedFileCount: 0,
          remainingFileCount: 0,
          pendingHandoffCount: 0,
        },
      });
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
      expect(session.prompt).toContain(
        "production discovery defaults skip conventional example, test, and documentation paths",
      );
      expect(session.prompt).toContain("including nested SECURITY.md");
      expect(session.prompt).toContain(
        "case-insensitive conventional path exclusions",
      );
      expect(session.prompt).not.toContain("**/examples/**");
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

test.each([false, true])(
  "preserves a destination present before or during the check (race=%s)",
  async (race) => {
    await using temp = await scopedTemporaryDirectory(
      "dependency-report-existing-",
    );
    const reportFile = join(temp.path, "report.json");
    const contents = "existing report\n";
    if (!race) await writeFile(reportFile, contents);
    const deps = dependencies({ currentDirectory: temp.path });
    deps.lookupPackageAdvisories = mock(async () => {
      await writeFile(reportFile, contents);
      return [];
    });
    const { runCli, stdout, stderr } = createCliTest(main);
    expect(
      await runCli(
        [
          "exploitability",
          "check",
          `npm:${decoder.name}`,
          "--json",
          "--report-file",
          "report.json",
        ],
        deps,
      ),
    ).toBe(2);
    expect(deps.lookupPackageAdvisories).toHaveBeenCalledTimes(race ? 1 : 0);
    expect(await readFile(reportFile, "utf8")).toBe(contents);
    expect(stderr.text()).toContain(
      `Report destination already exists: ${reportFile}`,
    );
    expect(stderr.text()).not.toContain("Report saved");
    expect(stdout.text()).toBe("");
  },
);

test.skipIf(process.platform === "win32")(
  "rejects a dangling symlink as a report destination",
  async () => {
    await using temp = await scopedTemporaryDirectory(
      "dependency-report-symlink-",
    );
    const reportFile = join(temp.path, "report.json");
    await symlink("missing.json", reportFile, "file");
    const deps = dependencies({ currentDirectory: temp.path });
    deps.lookupPackageAdvisories = mock(async () => []);
    const { runCli, stderr } = createCliTest(main);
    expect(
      await runCli(
        [
          "exploitability",
          "check",
          `npm:${decoder.name}`,
          "--report-file",
          reportFile,
        ],
        deps,
      ),
    ).toBe(2);
    expect(deps.lookupPackageAdvisories).not.toHaveBeenCalled();
    expect(await readlink(reportFile)).toBe("missing.json");
    expect(stderr.text()).not.toContain("Report saved");
  },
);

test("does not save or announce a completed report after an interrupt", async () => {
  await using temp = await scopedTemporaryDirectory(
    "dependency-report-interrupted-",
  );
  const reportFile = join(temp.path, "report.json");
  const eventFile = join(temp.path, "progress.jsonl");
  const signals = new FakeSignals();
  const deps = dependencies({ currentDirectory: temp.path, signals });
  deps.lookupPackageAdvisories = async () => {
    signals.emit("SIGINT");
    return [];
  };
  const { runCli, stderr } = createCliTest(main);
  expect(
    await runCli(
      [
        "exploitability",
        "check",
        `npm:${decoder.name}`,
        "--report-file",
        reportFile,
        "--progress-events",
        eventFile,
      ],
      deps,
    ),
  ).toBe(130);
  await expect(readFile(reportFile, "utf8")).rejects.toMatchObject({
    code: "ENOENT",
  });
  const events = (await readFile(eventFile, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as DependencyProgressEvent);
  expect(events.some(({ type }) => type === "report_ready")).toBe(false);
  expect(events.at(-1)).toMatchObject({
    type: "finished",
    outcome: "interrupted",
  });
  expect(stderr.text()).not.toContain("Report saved");
});

test.each([
  { boundary: "staging write", signal: "SIGINT", status: 130 },
  { boundary: "review cleanup", signal: "SIGTERM", status: 143 },
  { boundary: "staging cleanup", signal: "SIGINT", status: 0 },
] as const)(
  "linearizes report publication when interrupted during $boundary",
  async ({ boundary, signal, status }) => {
    await using checkout = await scopedTemporaryDirectory("report-checkout-");
    await using output = await scopedTemporaryDirectory("report-output-");
    const reportFile = join(output.path, "report.json");
    const eventFile = join(output.path, "progress.jsonl");
    const signals = new FakeSignals();
    let reviewDirectory: string | undefined;
    const deps = dependencies({
      currentDirectory: checkout.path,
      signals,
      onRepositoryCommand(command, _args, _repository, options) {
        if (command === "opengrep") reviewDirectory = options?.cwd;
        return "";
      },
    });
    deps.lookupPackageAdvisories = async () => [];
    const entered = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    async function gate() {
      entered.resolve();
      await release.promise;
    }
    const { rm: remove, writeFile: write } = filesystem;
    const writeSpy = spyOn(filesystem, "writeFile").mockImplementation(
      async (path, data, options) => {
        await write(path, data, options);
        if (
          boundary === "staging write" &&
          typeof path === "string" &&
          basename(dirname(path)).startsWith(".report-")
        )
          await gate();
      },
    );
    const removeSpy = spyOn(filesystem, "rm").mockImplementation(
      async (path, options) => {
        await remove(path, options);
        if (
          (boundary === "review cleanup" &&
            reviewDirectory !== undefined &&
            path === reviewDirectory) ||
          (boundary === "staging cleanup" &&
            typeof path === "string" &&
            basename(path).startsWith(".report-"))
        ) {
          await gate();
          if (boundary === "staging cleanup")
            throw new Error("Simulated staging cleanup failure");
        }
      },
    );
    const { runCli, stdout, stderr } = createCliTest(main);
    const running = runCli(
      [
        "exploitability",
        "check",
        `npm:${decoder.name}`,
        "--json",
        "--report-file",
        reportFile,
        "--progress-events",
        eventFile,
      ],
      deps,
    );
    async function readEvents() {
      return (await readFile(eventFile, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as DependencyProgressEvent);
    }
    try {
      await Promise.race([
        entered.promise,
        running.then(() => {
          throw new Error(`Expected a pause during ${boundary}`);
        }),
      ]);
      const committed = status === 0;
      if (committed) {
        expect(JSON.parse(await readFile(reportFile, "utf8"))).toEqual({
          package: decoder,
          checks: [],
        });
      } else {
        await expect(readFile(reportFile, "utf8")).rejects.toMatchObject({
          code: "ENOENT",
        });
      }
      expect(
        (await readEvents()).some(({ type }) => type === "report_ready"),
      ).toBe(committed);
      signals.emit(signal);
      release.resolve();
      expect(await running, stderr.text()).toBe(status);
      const events = await readEvents();
      expect(events.at(-1)).toMatchObject({
        type: "finished",
        outcome: committed ? "completed" : "interrupted",
      });
      expect(events.some(({ type }) => type === "report_ready")).toBe(
        committed,
      );
      expect(stderr.text().includes("Report saved")).toBe(committed);
      if (committed) {
        expect(JSON.parse(await readFile(reportFile, "utf8"))).toEqual(
          JSON.parse(stdout.text()),
        );
      } else {
        await expect(readFile(reportFile, "utf8")).rejects.toMatchObject({
          code: "ENOENT",
        });
        expect(stdout.text()).toBe("");
      }
    } finally {
      release.resolve();
      await running.catch(() => {});
      writeSpy.mockRestore();
      removeSpy.mockRestore();
    }
  },
);

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
      await waitForReviewStart(() => review.mock.calls.length > 0);
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
      expect(session.prompt).not.toContain("production discovery defaults");
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
      await waitForReviewStart(() => review.mock.calls.length > 0);
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
    const eventFile = join(temp.path, "progress.jsonl");
    const reportFile = join(temp.path, "report.json");
    expect(
      await runCli(
        [...args, "--report-file", reportFile, "--progress-events", eventFile],
        deps,
      ),
    ).toBe(2);
    await expect(readFile(reportFile, "utf8")).rejects.toMatchObject({
      code: "ENOENT",
    });
    const events = (await readFile(eventFile, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as DependencyProgressEvent);
    expect(events.some(({ type }) => type === "report_ready")).toBe(false);
    expect(stderr.text()).not.toContain("Report saved");
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
      const largeDiagnostic = "fixture backend details ".repeat(8192);
      const failedResult = {
        is_error: true,
        content: [{ type: "text", text: largeDiagnostic }],
      };
      let profileRequests = 0;
      const call = mock(
        async (server: string, tool: string, args: JsonObject) => {
          expect([server, tool, args]).toEqual([
            "profiles",
            "profiles.stacks",
            query,
          ]);
          profileRequests++;
          if (profileRequests === 1) return failedResult;
          if (profileRequests === 2) throw new Error(largeDiagnostic);
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
      const report = output!.appServer!.dependencyReport!;
      for (const original of [failedResult, { error: largeDiagnostic }]) {
        const reply = await callGraph(
          "collect_dependency_profiles",
          query,
          rpc,
        );
        expect(reply).toMatchObject({
          uncovered: [window],
          slices: [
            { outcome: "failed", cached: false, receiptId: expect.any(String) },
          ],
        });
        expect(JSON.stringify(reply)).not.toContain("fixture backend details");
        const { inventoryReceipts } = await report.status!({
          inventoryReceipts: true,
        });
        expect(inventoryReceipts).toContainEqual(
          expect.objectContaining({
            id: (reply["slices"] as JsonObject[])[0]!["receiptId"],
            server: "profiles",
            tool: "profiles.stacks",
            arguments: query,
            originalPayloadSha256: createHash("sha256")
              .update(canonicalJson(original))
              .digest("hex"),
            outcome: "failed",
            current: true,
          }),
        );
      }
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
      expect(call).toHaveBeenCalledTimes(3);
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

test("streams accepted callsite verdicts before the final JSON report", async () => {
  await using temp = await scopedTemporaryDirectory("dependency-progress-");
  git(temp.path, "init", "--quiet");
  await writeFile(
    join(temp.path, "app.ts"),
    [
      ...Array.from({ length: 28 }, () => "read(input);"),
      'read(input, "strict");',
      'read(input, "validated");',
    ].join("\n") + "\n",
  );
  await writeFile(join(temp.path, "reader.ts"), "decode(validated(input));\n");
  await writeFile(join(temp.path, "other.ts"), "decode(validated(input));\n");
  const config = join(temp.path, "inventory.json");
  await writeFile(
    config,
    JSON.stringify({
      exploitability: { service_catalog_mcps: ["catalog"] },
      codex: {
        mcp_servers: { catalog: { url: "https://catalog.invalid/mcp" } },
      },
    }),
  );

  type Verdict =
    "ruled_out" | "unknown" | "potentially_exploitable" | "exploitable";
  const record = "reader@rev1";
  function assessment(
    id: string,
    line: number,
    verdict: Verdict = "ruled_out",
  ) {
    const affected =
      verdict === "potentially_exploitable" || verdict === "exploitable";
    return {
      id,
      kind: "use",
      candidateIds: [],
      receiptIds: [] as string[],
      supportingClaims: [] as { id: string; revision: number; hash: string }[],
      use: {
        location: `app.ts:${line}`,
        component: decoder.name,
        version: affected ? "1" : null,
        verdict,
        deployment: verdict === "exploitable" ? "confirmed" : "unknown",
        place:
          undefined as import("../src/dependency-reachability.js").DependencyUse["place"],
        reason:
          verdict === "ruled_out"
            ? "The shared reader validates input."
            : "The selected reader is uncertain.",
        evidence: [
          {
            path: "app.ts",
            startLine: line,
            endLine: line,
            supports: affected ? ["affected_copy", "affected_use"] : [],
          },
          { path: "reader.ts", startLine: 1, endLine: 1, supports: [] },
        ],
        observations:
          verdict === "exploitable"
            ? [{ server: "catalog", record, supports: ["running", "access"] }]
            : [],
        proof: {
          sink: {
            function: "decode",
            callSite: { path: "reader.ts", line: 1 },
          },
          conditions: [
            {
              label: "Unvalidated input",
              status: "ruled_out",
              explanation: "The shared reader validates input.",
              citations: [{ path: "reader.ts", line: 1 }],
            },
          ],
        },
      },
    };
  }

  const { runCli, stdout, stderr } = createCliTest(main);
  const eventFile = join(temp.path, "progress.jsonl");
  await using outputDirectory =
    await scopedTemporaryDirectory("dependency-report-");
  const reportFile = join(outputDirectory.path, "report.json");
  const events = async () =>
    (await readFile(eventFile, "utf8"))
      .trimEnd()
      .split("\n")
      .map(
        (line) =>
          JSON.parse(line) as DependencyProgressEvent & {
            schemaVersion: number;
          },
      );
  const lines = () =>
    stderr
      .text()
      .split("\n")
      .filter((line) => /(?:RULED OUT|UNKNOWN|EXPLOITABLE)  /u.test(line));
  const delayed = Promise.withResolvers<void>();
  let staleStarted = false;
  const started = new Set<string>();
  const holds = new Map<
    string,
    ReturnType<typeof Promise.withResolvers<void>>
  >();
  const deps = dependencies({
    currentDirectory: temp.path,
    onCodex: async (_argv, output) => {
      expect(stderr.text()).toContain("Starting source investigation");
      expect((await events()).at(-1)).toMatchObject({
        schemaVersion: 1,
        type: "stage",
        stage: "investigate",
      });
      expect(stderr.text()).not.toContain("Reviewing evidence");
      expect(stdout.text()).toBe("");
      expect(lines()).toEqual([]);
      const tool = output!.appServer!.dependencyReport;
      assert(
        tool?.queue && tool.queueClaims && tool.queryClaims && tool.submit,
      );
      const trace = {
        id: "progress-trace",
        tool: "trace_codex_security_code",
        arguments: { rules: {}, paths: ["app.ts"] },
      };
      tool.recordGraphEvent("item/started", trace);
      expect(stderr.text()).toContain("app.ts");
      const sink = {
        id: "progress-sink",
        tool: "record_codex_security_endpoint",
      };
      tool.recordGraphEvent("item/completed", {
        ...sink,
        status: "completed",
        result: {
          structuredContent: {
            endpoints: {
              endpoint: {
                role: "sink",
                origin: "advisory",
                function: "Reader.decode",
                path: "reader.ts",
                line: 1,
              },
            },
          },
        },
      });
      const traced = { ...trace, id: "progress-partial" };
      tool.recordGraphEvent("item/started", traced);
      tool.recordGraphEvent("item/completed", {
        ...traced,
        status: "completed",
        result: {
          structuredContent: {
            coverage: { complete: false, searched_paths: ["lib"] },
          },
        },
      });
      const native = {
        id: "native-search",
        type: "commandExecution",
        cwd: temp.path,
        commandActions: [
          {
            type: "search",
            path: "src",
            command: "private command",
            query: "secret query",
          },
          { type: "read", path: join(temp.path, "reader.ts") },
        ],
      };
      output!.appServer!.onEvent?.({
        method: "item/started",
        params: { item: native },
      });
      output!.appServer!.onEvent?.({
        method: "item/completed",
        params: { item: { ...native, status: "completed" } },
      });
      tool.recordGraphEvent("item/completed", { ...trace, status: "failed" });
      const savedEvents = await events();
      const search = savedEvents.find(
        (event) => event.type === "activity_started",
      );
      expect(search).toMatchObject({
        activity: "opengrep",
        scope: { directories: ["app.ts"] },
      });
      assert(search?.type === "activity_started");
      expect(savedEvents).toContainEqual(
        expect.objectContaining({
          type: "activity_finished",
          id: search.id,
          outcome: "failed",
        }),
      );
      expect(savedEvents).toContainEqual(
        expect.objectContaining({
          type: "activity_finished",
          outcome: "partial",
          searchedPaths: ["lib"],
        }),
      );
      expect(savedEvents).toContainEqual(
        expect.objectContaining({
          type: "proposed_sink",
          function: "Reader.decode",
          path: "reader.ts",
          origin: "advisory",
        }),
      );
      expect(savedEvents).toContainEqual(
        expect.objectContaining({
          type: "proposed_sink",
          function: "decode",
          origin: "advisory_record",
        }),
      );
      expect(savedEvents).toContainEqual(
        expect.objectContaining({
          type: "activity_started",
          activity: "source_search",
          scope: { directories: ["src"] },
        }),
      );
      expect(savedEvents).toContainEqual(
        expect.objectContaining({
          type: "activity_started",
          activity: "source_read",
          scope: { files: ["reader.ts"] },
        }),
      );
      expect(JSON.stringify(savedEvents)).not.toContain("private command");
      expect(JSON.stringify(savedEvents)).not.toContain("secret query");
      expect(stderr.text()).toContain("Synthetic decoder advisory");
      expect(stderr.text()).toContain(
        "Reader.decode · advisory-derived · reader.ts:1",
      );
      expect(stderr.text()).toContain("Searching with OpenGrep · app.ts");
      const selected = new Map<string, { id: string; revision: number }>();
      const enqueue = async (...items: ReturnType<typeof assessment>[]) => {
        const result = await tool.queue!({ items });
        expect(result.queued, result.feedback).toBe(true);
        for (const entry of result.items!) selected.set(entry.id, entry);
      };
      await tool.queueClaims({
        claims: [
          {
            id: "validation",
            payload: "The shared reader validates input.",
            scope: "Shared reader",
            evidence: [{ path: "reader.ts", startLine: 1, endLine: 1 }],
          },
          {
            id: "advisory-note",
            payload: "The advisory applies to unvalidated input.",
            scope: "Advisory prerequisites",
          },
        ],
      });
      const approvalDeadline = Date.now() + 2_000;
      const queryPremises = () =>
        tool.queryClaims!({ ids: ["validation", "advisory-note"] });
      let premises = (await queryPremises()).claims;
      while (!premises.every(({ state }) => state === "approved")) {
        if (Date.now() > approvalDeadline)
          throw new Error("The premises were not approved.");
        await new Promise<void>((resolve) => setImmediate(resolve));
        premises = (await queryPremises()).claims;
      }
      const advisoryNote = premises.find(({ id }) => id === "advisory-note")!;
      const validation = premises.find(({ id }) => id === "validation")!;
      expect(lines()).toEqual([]);
      await enqueue(assessment("first", 1));
      await waitForReviewStart(() => lines().length > 0);
      expect(lines()[0]).toContain("RULED OUT  app.ts:1");
      expect(stderr.text()).toContain("The shared reader validates input.");
      expect(stderr.text()).not.toContain("Source checked.");
      expect(await events()).toContainEqual(
        expect.objectContaining({
          type: "reviewed",
          verdict: "ruled_out",
          location: "app.ts:1",
          reason: "The shared reader validates input.",
        }),
      );
      expect(stdout.text()).toBe("");

      const other = assessment("other", 4);
      other.use.evidence[1]!.path = "other.ts";
      other.use.proof.sink.callSite.path = "other.ts";
      other.use.proof.conditions[0]!.citations[0]!.path = "other.ts";
      await enqueue(
        assessment("second", 2),
        assessment("third", 3),
        assessment("first-alias", 1),
        other,
      );
      await waitForReviewStart(() =>
        lines().some((line) => line.includes("3 reviewed calls")),
      );
      expect(
        lines().filter((line) => line.includes("share this proof")),
      ).toHaveLength(1);
      expect(lines().some((line) => line.includes("RULED OUT  app.ts:4"))).toBe(
        true,
      );
      expect(lines().filter((line) => line.includes("app.ts:1"))).toHaveLength(
        2,
      );

      const replacement = Promise.withResolvers<void>();
      holds.set("second:2", replacement);
      try {
        await enqueue(assessment("second", 2, "unknown"));
        await waitForReviewStart(() => started.has("second:2"));
        await enqueue(
          assessment("while-pending-a", 9),
          assessment("while-pending-b", 26),
        );
        await waitForReviewStart(() =>
          lines().some((line) => line.includes("4 reviewed calls")),
        );
        expect(lines().some((line) => line.includes("5 reviewed calls"))).toBe(
          false,
        );
      } finally {
        replacement.resolve();
      }
      await waitForReviewStart(() =>
        lines().some((line) => line.includes("app.ts:2 · was ruled out")),
      );
      expect(
        lines().some((line) =>
          line.includes("UNKNOWN  app.ts:2 · was ruled out"),
        ),
      ).toBe(true);
      const otherPlace = assessment(
        "other-place",
        1,
        "potentially_exploitable",
      );
      otherPlace.use.location = "Configured reader (app.ts:1)";
      const receipt = tool.recordInventory(
        "catalog",
        { content: [{ type: "text", text: record }] },
        { tool: "lookup" },
      );
      assert(receipt);
      otherPlace.receiptIds.push(receipt);
      otherPlace.use.observations.push({
        server: "catalog",
        record,
        supports: [],
      });
      const running = assessment("running", 5, "exploitable");
      running.receiptIds.push(receipt);
      await enqueue(otherPlace, running);
      await waitForReviewStart(() =>
        lines().some((line) => line.includes("EXPLOITABLE  app.ts:5")),
      );
      expect(
        lines().some((line) =>
          line.includes("POTENTIALLY EXPLOITABLE  app.ts:1"),
        ),
      ).toBe(true);

      try {
        await enqueue(assessment("late", 6));
        await waitForReviewStart(() => staleStarted);
        expect(lines().some((line) => line.includes("app.ts:6"))).toBe(false);
        await enqueue(assessment("late", 6, "unknown"));
      } finally {
        delayed.resolve();
      }
      await waitForReviewStart(() =>
        lines().some((line) => line.includes("UNKNOWN  app.ts:6")),
      );
      expect(lines().filter((line) => line.includes("app.ts:6"))).toHaveLength(
        1,
      );
      // Restore a previously reviewed exact fingerprint while its new
      // revision remains in flight. The host can use its cached approval.
      const cacheGate = Promise.withResolvers<void>();
      holds.set("first:2", cacheGate);
      const cacheRevision = assessment("first", 1, "unknown");
      try {
        const before = lines().length;
        await enqueue(cacheRevision);
        await waitForReviewStart(() => started.has("first:2"));
        await enqueue(assessment("first", 1));
        expect(selected.get("first")?.revision).toBe(3);
        expect(lines()).toHaveLength(before);
      } finally {
        cacheGate.resolve();
      }

      // Windows are distinct place assessments of the same physical call.
      const scoped = (window: string) => {
        const item = assessment(window, 1);
        item.use.place = {
          kind: "library_caller",
          environment: null,
          revision: null,
          artifact: null,
          observationWindow: window,
          deploymentBasis: "configured",
          deploymentDetail: null,
          dependencySelection: null,
          patch: null,
          unresolvedQuestions: [],
        };
        return item;
      };
      const local = (line: number, advisoryOnly = false) => {
        const item = assessment(
          `${advisoryOnly ? "advisory-" : ""}mode-${line}`,
          line,
        );
        item.use.proof.conditions[0]!.citations[0] = { path: "app.ts", line };
        if (advisoryOnly) {
          const { id, revision, hash } = advisoryNote;
          item.supportingClaims.push({ id, revision, hash });
        }
        return item;
      };
      const selectedMode = (line: number) => {
        const item = assessment(`selected-mode-${line}`, line);
        const { id, revision, hash } = validation;
        item.supportingClaims.push({ id, revision, hash });
        return item;
      };
      const ambiguous = (line: number) => {
        const item = assessment(`ambiguous-${line}`, line);
        item.use.location = `app.ts:${line}, app.ts:${line + 1}`;
        item.use.evidence.push({
          path: "app.ts",
          startLine: line + 1,
          endLine: line + 1,
          supports: [],
        });
        return item;
      };
      await enqueue(
        scoped("window-a"),
        scoped("window-b"),
        local(7),
        local(8),
        local(27, true),
        local(28, true),
        selectedMode(29),
        selectedMode(30),
        ambiguous(7),
        ambiguous(8),
      );
      await waitForReviewStart(() =>
        lines().some((line) =>
          line.includes("4 reviewed calls share this proof, 6 assessments"),
        ),
      );
      expect(
        (await events()).filter(
          (event) =>
            event.type === "reviewed" &&
            event.location === "app.ts:1" &&
            event.verdict === "ruled_out",
        ),
      ).toHaveLength(3);
      expect(
        lines().filter((line) =>
          line.match(/RULED OUT  app\.ts:(?:[78]|2[789]|30)$/u),
        ),
      ).toHaveLength(6);
      expect(
        (await events()).filter(
          (event) => event.type === "reviewed" && event.locationKind === "sink",
        ),
      ).toHaveLength(2);

      // Each queue waits for its own review to start, so these occupy all
      // 16 actual batch slots. Deliver them in reverse order.
      const concurrent = Array.from({ length: 16 }, (_, i) =>
        assessment(`parallel-${i}`, i + 10),
      );
      try {
        for (const item of concurrent) {
          const key = `${item.id}:1`;
          holds.set(key, Promise.withResolvers<void>());
          await enqueue(item);
          await waitForReviewStart(() => started.has(key));
        }
        expect(stdout.text()).toBe("");
        expect(lines().some((line) => line.includes("20 reviewed calls"))).toBe(
          false,
        );
      } finally {
        for (const item of [...concurrent].reverse())
          holds.get(`${item.id}:1`)?.resolve();
      }
      await waitForReviewStart(() =>
        lines().some((line) =>
          line.includes("20 reviewed calls share this proof, 22 assessments"),
        ),
      );
      expect(started.has("first:3")).toBe(false);
      expect(stderr.text()).not.toContain("\x1b");
      expect(stdout.text()).toBe("");
      await expect(readFile(reportFile, "utf8")).rejects.toMatchObject({
        code: "ENOENT",
      });

      const outcome = await tool.submit({
        candidateGeneration: 0,
        reviewItems: [...selected.values()],
        limitations: [],
      });
      expect(outcome.accepted, outcome.feedback).toBe(true);
      return 0;
    },
  });
  deps.lookupDependencyAdvisory = async () => {
    const progress = stderr.text();
    expect(progress).toContain(advisory.cve);
    expect(progress).toContain("Looking up advisories");
    expect((await events()).map(({ type }) => type)).toEqual([
      "started",
      "stage",
    ]);
    expect(progress).not.toContain("Starting source investigation");
    expect(stdout.text()).toBe("");
    return {
      ...advisory,
      advisories: advisory.advisories.map((record) => ({
        ...record,
        vulnerableFunctions: ["decode"],
      })),
    };
  };
  deps.reviewDependencyReport = async (prompt) => {
    expect(stderr.text()).toContain("Reviewing evidence");
    const packet = JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1)) as {
      excerpts: Record<string, { path: string }>;
      items: (Pick<ReturnType<typeof assessment>, "use"> & {
        advisoryEvidenceId?: string;
        id: string;
        revision: number;
        hash: string;
        excerptIds: string[];
        receiptIds: string[];
      })[];
    };
    return JSON.stringify({
      items: await Promise.all(
        packet.items.map(async (item) => {
          const key = `${item.id}:${item.revision}`;
          started.add(key);
          await holds.get(key)?.promise;
          if (item.id === "late" && item.revision === 1) {
            staleStarted = true;
            await delayed.promise;
          }
          return {
            id: item.id,
            revision: item.revision,
            hash: item.hash,
            accepted: true,
            reason: "Source checked.\n\x1b[31mShared validation.\x1b[0m",
            citedVersion: ["exploitable", "potentially_exploitable"].includes(
              item.use?.verdict,
            )
              ? "1"
              : null,
            evidenceIds: item.id.startsWith("advisory-mode-")
              ? [
                  ...item.excerptIds.filter(
                    (id) => packet.excerpts[id]?.path === "app.ts",
                  ),
                  "claim:advisory-note",
                ]
              : [
                  ...item.excerptIds,
                  ...item.receiptIds,
                  ...(item.advisoryEvidenceId && !item.excerptIds.length
                    ? [item.advisoryEvidenceId]
                    : []),
                  ...(item.id.startsWith("selected-mode-")
                    ? ["claim:validation"]
                    : []),
                ],
          };
        }),
      ),
    });
  };
  expect(
    await runCli(
      [
        ...args,
        "--config",
        config,
        "--progress-events",
        eventFile,
        "--report-file",
        reportFile,
      ],
      deps,
    ),
    stderr.text(),
  ).toBe(0);
  expect(JSON.parse(stdout.text())).toMatchObject({
    cve: advisory.cve,
    schemaVersion: 2,
    uses: expect.arrayContaining([
      expect.objectContaining({ location: "app.ts:2", verdict: "unknown" }),
      expect.objectContaining({ location: "app.ts:5", verdict: "exploitable" }),
      expect.objectContaining({ location: "app.ts:6", verdict: "unknown" }),
    ]),
  });
  expect(JSON.parse(stdout.text()).uses).toHaveLength(36);
  expect(JSON.parse(await readFile(reportFile, "utf8"))).toEqual(
    JSON.parse(stdout.text()),
  );
  if (process.platform !== "win32")
    expect((await stat(reportFile)).mode & 0o777).toBe(0o600);
  expect(stderr.text()).toContain("Investigation summary · 36 reviewed uses");
  expect(stderr.text()).toContain(`Report saved  ${reportFile}`);
  expect(stderr.text().match(/Reviewing evidence/g)).toHaveLength(1);
  expect((await events()).at(-1)).toMatchObject({
    type: "finished",
    outcome: "completed",
  });
  const eventsAfter = await events();
  expect(
    eventsAfter.filter((event) => event.type === "assessment_finished"),
  ).toMatchObject([{ uses: 36 }]);
  expect(eventsAfter.at(-2)).toMatchObject({
    type: "report_ready",
    path: reportFile,
    verdicts: expect.objectContaining({ exploitable: 1 }),
  });
  expect(eventsAfter).toContainEqual(
    expect.objectContaining({
      type: "reviewed",
      previousVerdict: "ruled_out",
      verdict: "unknown",
    }),
  );
});

test("renders a live terminal header and leaves diagnostics readable when an event file exists", async () => {
  await using temp = await scopedTemporaryDirectory("dependency-tty-");
  const eventFile = join(temp.path, "progress.jsonl");
  await writeFile(eventFile, "already here\n");
  const deps = dependencies({ currentDirectory: temp.path });
  deps.lookupDependencyAdvisory = async () => {
    throw new Error("Advisory service unavailable");
  };
  const { runCli, stdout, stderr } = createCliTest(main, { stderr: true });
  expect(await runCli([...args, "--progress-events", eventFile], deps)).toBe(2);
  expect(await readFile(eventFile, "utf8")).toBe("already here\n");
  expect(stderr.text()).toContain("Exploitability");
  expect(stderr.text()).toContain("\r\x1b[2K");
  expect(stderr.text()).toContain("Could not create progress file");
  expect(stderr.text()).toContain("Advisory service unavailable");
  expect(stdout.text()).toBe("");
});

test.each([
  ["standard", "WARNING: DAYBREAK IS NOT ACTIVE"],
  ["unconfirmed", "WARNING: DAYBREAK ACCESS NOT CONFIRMED"],
  ["daybreak_blue", "Daybreak Blue"],
  ["daybreak_red", "Daybreak Red"],
] as const)(
  "shows the selected access program and prints one clean failure (%s)",
  async (program, label) => {
    await using temp = await scopedTemporaryDirectory(
      "dependency-access-display-",
    );
    const eventFile = join(temp.path, "progress.jsonl");
    const diagnostic =
      "Codex declined this turn.\nThe provider supplied this reason.";
    const deps = dependencies({
      currentDirectory: temp.path,
      onCodex: async (_argv, output) => {
        const report = output!.appServer!.dependencyReport!;
        report.onAccessProgram!(program);
        report.onAccessProgram!(program);
        await output!.onDiagnostic!(diagnostic, "failure");
        return 1;
      },
    });
    deps.lookupDependencyAdvisory = async () => advisory;
    const { runCli, stdout, stderr } = createCliTest(main, { stderr: true });
    expect(await runCli([...args, "--progress-events", eventFile], deps)).toBe(
      1,
    );
    const output = stderr.text();
    expect(output).toContain(label);
    expect(output.split(label)).toHaveLength(2);
    expect(output.split(diagnostic)).toHaveLength(2);
    expect(output).toContain(`\r\x1b[2Kcodex-security: ${diagnostic}\n`);
    expect(output).not.toContain("Dependency assessment exited");
    expect(output).not.toContain("Investigation failed");
    expect(stdout.text()).toBe("");
    const events = (await readFile(eventFile, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as DependencyProgressEvent);
    expect(events.filter(({ type }) => type === "access_program")).toEqual([
      expect.objectContaining({ program }),
    ]);
    expect(events.at(-1)).toMatchObject({
      type: "finished",
      outcome: "failed",
    });
  },
);

test("removes invalidated approvals before a coalesced verdict update", () => {
  const output: DependencyProgressEvent[] = [];
  const progress = createDependencyVerdictProgress("example", (event) =>
    output.push(event),
  );
  function approve(
    id: string,
    line: number,
    verdict: DependencyUse["verdict"] = "ruled_out",
  ) {
    const reason = "The wrapper validates input.";
    progress.update(id, {
      callSite: { path: "app.ts", line },
      use: {
        location: `app.ts:${line}`,
        component: "example",
        version: null,
        verdict,
        deployment: "unknown",
        reason,
        evidence: [
          { path: "app.ts", startLine: line, endLine: line, supports: [] },
        ],
        observations: [],
      },
      reason: `Reviewed ${id}. ${reason}`,
      evidenceKeys: [`excerpt:call-${line}`, "excerpt:wrapper"],
      sharedEvidenceKeys: ["excerpt:wrapper"],
    });
  }
  approve("first", 1);
  approve("second", 2);
  progress.update("second");
  progress.flush();
  expect(output).toHaveLength(1);
  approve("third", 3);
  approve("fourth", 4);
  progress.flush();
  expect(output[1]).toMatchObject({ type: "reviewed_group", callsites: 3 });
  approve("second", 2, "unknown");
  expect(output[2]).toMatchObject({
    type: "reviewed",
    location: "app.ts:2",
    previousVerdict: "ruled_out",
    verdict: "unknown",
  });
  progress.flush();
  expect(output).toHaveLength(3);

  const group = output[1];
  assert(group?.type === "reviewed_group");
  for (const id of ["first", "third", "fourth"]) progress.update(id);
  progress.flush();
  expect(output[3]).toMatchObject({
    type: "reviewed_group",
    groupId: group.groupId,
    callsites: 0,
    assessments: 0,
  });
  approve("first", 1);
  const restored = output[4];
  assert(restored?.type === "reviewed");
  expect(restored.groupId).toBeDefined();
  expect(restored.groupId).not.toBe(group.groupId);
});

test.each([true, false])(
  "keeps distinct deciding reasons out of a shared proof group (conditions=%s)",
  (withConditions) => {
    const events: DependencyProgressEvent[] = [];
    const progress = createDependencyVerdictProgress("example", (event) =>
      events.push(event),
    );
    function approve(line: number, explanation: string) {
      const callSite = { path: "app.ts", line };
      progress.update(`call-${line}`, {
        callSite,
        use: {
          location: `app.ts:${line}`,
          component: "example",
          version: null,
          verdict: "ruled_out",
          deployment: "unknown",
          reason: withConditions
            ? "The guard rules out the call."
            : explanation,
          evidence: [],
          observations: [],
          proof: {
            sink: { function: "read", callSite },
            conditions: withConditions
              ? [
                  {
                    label: "Input guard",
                    status: "ruled_out",
                    explanation,
                    citations: [{ path: "guard.ts", line: 7 }],
                  },
                ]
              : [],
          },
        },
        reason: "Reviewed the guard.",
        evidenceKeys: [`excerpt:call-${line}`, "excerpt:guard"],
        sharedEvidenceKeys: ["excerpt:guard"],
      });
    }
    approve(1, "The guard validates the length.");
    approve(2, "The guard authenticates the input.");
    progress.flush();
    expect(events.map(({ type }) => type)).toEqual(["reviewed", "reviewed"]);
    approve(3, "The guard validates the length.");
    progress.flush();
    expect(events.at(-1)).toMatchObject({
      type: "reviewed_group",
      callsites: 2,
      assessments: 2,
    });
  },
);

test("keeps reviewed stderr concise without merging distinct places", () => {
  const output: DependencyProgressEvent[] = [];
  const progress = createDependencyVerdictProgress("example", (event) =>
    output.push(event),
  );
  const path = `src/${"nested/".repeat(14)}reader.ts`;
  const callSite = { path, line: 7 };
  const longReason = "The selected reader has its own review findings. ".repeat(
    20,
  );
  const context = "Unresolved consumer route; ".repeat(20);
  const use: DependencyUse = {
    location: `${path}:7`,
    component: "example",
    version: null,
    verdict: "ruled_out",
    deployment: "configured",
    reason: longReason,
    evidence: [{ path, startLine: 7, endLine: 7, supports: [] }],
    observations: [],
    proof: {
      sink: { function: "read", callSite },
      conditions: [
        {
          label: "Unsafe input",
          status: "ruled_out",
          explanation: "The reader validates the input before opening it.",
          citations: [callSite],
        },
      ],
    },
    place: {
      kind: "service",
      environment: "staging",
      revision: "revision123456789",
      artifact: `sha256:${"a".repeat(64)}`,
      observationWindow: "first observation window",
      deploymentBasis: "configured",
      deploymentDetail: "Long internal deployment narrative. ".repeat(20),
      dependencySelection: "Long component-selection narrative. ".repeat(20),
      patch: null,
      unresolvedQuestions: ["Lengthy deciding questions. ".repeat(20)],
    },
  };
  const firstPlace = use.place!;
  const review = {
    use,
    callSite,
    reason: longReason,
    evidenceKeys: ["source"],
    sharedEvidenceKeys: ["source"],
  };
  progress.update("first-place", review);
  progress.update("second-place", {
    ...review,
    use: {
      ...use,
      place: { ...firstPlace, observationWindow: "second observation window" },
    },
  });
  progress.flush();

  expect(output).toHaveLength(3);
  const [first, second] = output;
  assert(first?.type === "reviewed" && second?.type === "reviewed");
  expect(first.location).toBe(`${path}:7`);
  expect(first.scope).toContain("staging, sha256:");
  expect(first.reason).toBe(
    "The reader validates the input before opening it.",
  );
  expect(first.scope).toContain("first observation window");
  expect(second.scope).toContain("second observation window");
  expect(output[2]).toMatchObject({
    type: "reviewed_group",
    callsites: 1,
    assessments: 2,
  });
  for (const record of output) {
    expect(JSON.stringify(record)).not.toContain("narrative");
    expect(JSON.stringify(record)).not.toContain(longReason);
  }

  progress.update("ambiguous", {
    ...review,
    callSite: undefined,
    use: {
      ...use,
      location: `\x1b[31m${context}\x1b[0m\n`,
      verdict: "unknown",
    },
  });
  const ambiguous = output.at(-1);
  assert(ambiguous?.type === "reviewed");
  expect(ambiguous).toMatchObject({
    location: `${path}:7`,
    locationKind: "sink",
  });
  expect(ambiguous.scope).toContain("submitted location:");
  expect(ambiguous.scope).not.toContain(context);
  expect(ambiguous.scope).not.toContain("\x1b");
  expect(ambiguous.scope!.length).toBeLessThanOrEqual(120);
  expect(ambiguous.reason).toEndWith("…");
  expect(ambiguous.reason.length).toBeLessThanOrEqual(180);
  expect(use.reason).toBe(longReason);
});
