import { expect, mock, test } from "bun:test";
import { mkdir, realpath, writeFile } from "node:fs/promises";
import { join, sep } from "node:path";
import { parse as parseToml } from "smol-toml";
import { main } from "../src/cli.js";
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

test("requires a working OpenGrep before advisory lookup or model startup", async () => {
  await using temp = await scopedTemporaryDirectory("cve-opengrep-");
  const repo = temp.path;
  git(repo, "init", "--quiet");
  const nested = join(repo, "app");
  await mkdir(nested);
  const onCodex = mock<OnCodex>().mockReturnValue(0);
  const diagnostic = "scanner runtime unavailable";
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
      throw new Error(diagnostic);
    },
  });
  deps.lookupDependencyAdvisory = mock(async () => advisory);
  const { runCli, stderr } = createCliTest(main);
  expect(await runCli(args, deps), stderr.text()).toBe(2);
  expect(stderr.text()).toContain(diagnostic);
  expect(deps.lookupDependencyAdvisory).not.toHaveBeenCalled();
  expect(onCodex).not.toHaveBeenCalled();
});

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
        "trace_codex_security_code",
        "resolve_codex_security_services",
        "query_codex_security_graph",
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
      expect(session.prompt).not.toContain("checkout-only marker");

      const tool = session.dependencyReport!;
      tool.bindReviewer!(selectedEnvironment, provider);
      const first = structuredClone(unresolvedDecoder);
      first.uses[0]!.version = "1.0.0";
      const rejection = await tool.submit(first);
      expect(rejection.accepted).toBe(false);
      expect(rejection.feedback).toContain(gap);
      expect((await tool.submit(unresolvedDecoder)).accepted).toBe(true);
      output!.onUsage?.({ ...usage, total_tokens: 132 });
      output!.stdout.write(JSON.stringify(first));
      return 0;
    },
  });
  let submissions = 0;
  const review = mock<NonNullable<typeof deps.reviewDependencyReport>>(
    async (prompt, _schema, options) => {
      expect(prompt).toContain("checkout-only marker");
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
  expect(JSON.parse(stdout.text())).toEqual({
    ...unresolvedDecoder,
    status: "unknown",
    cve: advisory.cve,
    advisories: [advisory.advisories[0]!.url],
    usage: {
      input_tokens: 158,
      cached_input_tokens: 48,
      cache_write_input_tokens: 0,
      output_tokens: 36,
      reasoning_output_tokens: 12,
    },
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
      const result = await session.dependencyReport!.submit({
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
    checks: [{ advisoryId: null, advisories: [], status: "unknown" }],
  });
  expect(report).not.toHaveProperty("cve");
  expect(report.checks[0]).not.toHaveProperty("cve");
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
        limitations: [`The installed version for ${record.id} is unknown.`],
        status: "unknown",
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

test("preserves the native skill's nonzero exit", async () => {
  await using temp = await scopedTemporaryDirectory("cve-skill-");
  git(temp.path, "init", "--quiet");
  const deps = dependencies({
    currentDirectory: temp.path,
    environment: { PATH: process.env["PATH"] },
    onCodex: () => 23,
  });
  deps.lookupDependencyAdvisory = async () => advisory;
  expect(await runCapturedCli(main, args, deps)).toBe(23);
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
        if (observed) tool.recordInventory(observed, result);
        const outcome = await tool.submit(assessment);
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
      expect(JSON.parse(stdout.text()).status).toBe("exploitable");
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

test("the tenth rejected submission reports the final gap and publishes no draft", async () => {
  await using temp = await scopedTemporaryDirectory("cve-review-denied-");
  git(temp.path, "init", "--quiet");
  await writeFile(
    join(temp.path, "scope.txt"),
    "Consumer selection is not recorded.\n",
  );
  const draft = {
    status: "unknown",
    uses: [],
    limitations: ["Consumer selection missing."],
  };
  const gap = "The justification for the reported scope is missing.";
  let continuedAfterRejection = false;
  const deps = dependencies({
    currentDirectory: temp.path,
    environment: { PATH: process.env["PATH"] },
    onCodex: async (_argv, output) => {
      const tool = output!.appServer!.dependencyReport!;
      expect(
        await tool.queue!({
          items: [
            {
              id: "scope",
              kind: "unresolved",
              candidateIds: [],
              reason: draft.limitations[0],
              evidence: [
                { path: "scope.txt", startLine: 1, endLine: 1, supports: [] },
              ],
              observations: [],
            },
          ],
        }),
      ).toMatchObject({ queued: true });
      for (let attempt = 1; attempt < 10; attempt++) {
        expect((await tool.submit(draft)).accepted).toBe(false);
      }
      await tool.submit(draft);
      continuedAfterRejection = true;
      return 0;
    },
  });
  deps.lookupDependencyAdvisory = async () => advisory;
  const review = mock(async (prompt: string) =>
    reviewDecision(prompt, false, gap),
  );
  deps.reviewDependencyReport = review;
  const { runCli, stdout, stderr } = createCliTest(main);
  expect(await runCli(args, deps)).toBe(2);
  expect(stderr.text()).toContain(gap);
  expect(continuedAfterRejection).toBe(false);
  expect(stdout.text()).not.toContain(draft.limitations[0]!);
  expect(review).toHaveBeenCalledTimes(1);
});

test("a reviewer outage fails the command without publishing the draft", async () => {
  await using temp = await scopedTemporaryDirectory("cve-review-outage-");
  git(temp.path, "init", "--quiet");
  await writeFile(
    join(temp.path, "scope.txt"),
    "Consumer selection is not recorded.\n",
  );
  const draft = {
    status: "unknown",
    uses: [],
    limitations: ["No confirmed consumer."],
  };
  const deps = dependencies({
    currentDirectory: temp.path,
    environment: { PATH: process.env["PATH"] },
    onCodex: async (_argv, output) => {
      const tool = output!.appServer!.dependencyReport!;
      expect(
        await tool.queue!({
          items: [
            {
              id: "scope",
              kind: "unresolved",
              candidateIds: [],
              reason: draft.limitations[0],
              evidence: [
                { path: "scope.txt", startLine: 1, endLine: 1, supports: [] },
              ],
              observations: [],
            },
          ],
        }),
      ).toMatchObject({ queued: true });
      expect((await tool.submit(draft)).accepted).toBe(false);
      return 0;
    },
  });
  deps.lookupDependencyAdvisory = async () => advisory;
  deps.reviewDependencyReport = async () => {
    throw new Error("review provider unavailable");
  };
  const { runCli, stdout, stderr } = createCliTest(main);
  expect(await runCli(args, deps)).toBe(2);
  expect(stderr.text()).toContain("review provider unavailable");
  expect(stdout.text()).not.toContain(draft.limitations[0]!);
});

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

test("shares service catalog MCPs between the resolver and investigator", async () => {
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
  await writeFile(
    config,
    JSON.stringify({
      exploitability: {
        service_catalog_mcps: ["catalog"],
      },
      codex: {
        mcp_servers: {
          catalog,
          unrelated: { command: "unrelated" },
        },
      },
    }),
  );
  const selectedEnvironment = { CODEX_HOME: join(repo, "fixture-home") };
  const provider = { model_provider: "private" };
  const service = { name: "catalog-worker", scope: "catalog:svc-1" };
  const source = "catalog/read_service#svc-1";
  const onCodex = mock<OnCodex>(async (argv, output) => {
    const session = output!.appServer!;
    const { mcp_servers } = parseToml(
      argv.find((arg) => arg.startsWith("mcp_servers="))!,
    );
    expect(mcp_servers).toEqual({ catalog });
    expect(output?.allowedMcpServers).toEqual(["catalog"]);
    expect(session.prompt).toContain(JSON.stringify(["catalog"]));
    expect(session.prompt).not.toContain(catalog.url);

    session.dependencyReport!.bindReviewer!(selectedEnvironment, provider);
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
  >(async ({ servers, repository, requests, runtime, signal }) => {
    expect(servers).toEqual({ catalog });
    expect(repository).toBe(repo);
    expect(requests).toEqual([{ path: file, project: "src" }]);
    expect(runtime.selectedEnvironment).toEqual(selectedEnvironment);
    expect(runtime.config?.codexOverrides).toEqual(provider);
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
  });
  deps.resolveDependencyServices = resolveServices;
  deps.lookupDependencyAdvisory = async () => advisory;
  expect(await runCapturedCli(main, [...args, "--config", config], deps)).toBe(
    23,
  );
  expect(onCodex).toHaveBeenCalledTimes(1);
  expect(resolveServices).toHaveBeenCalledTimes(1);
});
