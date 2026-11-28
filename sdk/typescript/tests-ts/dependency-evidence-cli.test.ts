import { parse as parseToml } from "smol-toml";
import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { dependencyRecordHash } from "../src/exploitability/attempt-store.js";
import { exploitabilityReportSchema } from "../src/exploitability/report/schema.js";
import { synthesisAnswer } from "./support/dependency-report-fixtures.js";
import type { PremiseRef } from "../src/exploitability/analyzers/repository/review-queue.js";
import { main, readSkillCommandOutput } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { requestMetadata } from "./support/request-metadata.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

async function* commandOutput(...events: object[]) {
  for (const event of events) yield JSON.stringify(event) + "\n";
}

test("check advertises a single report schema for every analyzer", async () => {
  const stdout = capture(),
    stderr = capture();
  expect(
    await main(
      ["exploitability", "check", "--schema", "--json"],
      stdout.stream,
      stderr.stream,
      dependencies({
        environment: { CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY: "1" },
      }),
    ),
    stderr.text(),
  ).toBe(0);
  const schema = JSON.parse(stdout.text()).output.anyOf.find(
    (variant: { type: string }) => variant.type === "object",
  );
  expect(schema.required).toEqual(
    expect.arrayContaining([
      "schemaVersion",
      "subject",
      "status",
      "vulnerabilities",
    ]),
  );
  expect(schema.properties.schemaVersion.const).toBe(3);
});

function approve({ id, revision, hash }: PremiseRef) {
  return {
    id,
    revision,
    hash,
    approved: true,
    evidenceKeys: [],
    reason: "Verified.",
  };
}

async function commitFixture(path: string) {
  const git = (...args: string[]) => execFileSync("git", args, { cwd: path });
  git("init", "-q");
  await writeFile(
    join(path, "caller.js"),
    "export const decode = value => value;\n",
  );
  await writeFile(
    join(path, "package.json"),
    JSON.stringify({ name: "fixture", version: "1.0.0" }),
  );
  git("add", "caller.js", "package.json");
  git(
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.invalid",
    "commit",
    "-qm",
    "fixture",
  );
}

test("check rejects invalid analyzer options before launching an investigation", async () => {
  await using repo = await scopedTemporaryDirectory(
    "dependency-analyzer-options-",
  );
  await commitFixture(repo.path);
  const config = join(repo.path, "project.json");
  let launches = 0;
  const deps = dependencies({
    currentDirectory: repo.path,
    environment: { CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY: "1" },
    onCodex() {
      launches++;
      return 1;
    },
  });
  for (const [project, flags, problem] of [
    [{ analyzers: {} }, [], /at least 1|fewer than 1|at least one/i],
    [{ analyzers: { other: {} } }, [], /additional properties|unknown/i],
    [{ analyzers: { stacks: {} } }, [], /No analyzer has input/],
    [
      { analyzers: { repository: {} } },
      ["--analyzer-input", "stacks=unused"],
      /unknown or disabled/,
    ],
    [undefined, ["--sources", "  "], /sources/],
    [undefined, ["--sinks="], /sinks/],
    [
      undefined,
      ["--analyzer-input", "repository=unused"],
      /takes no input path/,
    ],
    [undefined, ["--analyzer-input", "stacks"], /NAME=PATH/],
    [
      undefined,
      ["--analyzer-input", "stacks=a", "--analyzer-input", "stacks=b"],
      /Duplicate --analyzer-input/,
    ],
    [
      undefined,
      ["--analyzer-input", "stacks=missing-capture"],
      /missing-capture|does not exist/,
    ],
  ] as const) {
    const stdout = capture(),
      stderr = capture();
    if (project)
      await writeFile(config, JSON.stringify({ exploitability: project }));
    const code = await main(
      [
        "exploitability",
        "check",
        "CVE-2099-1000",
        ...(project ? ["--config", config] : []),
        ...flags,
      ],
      stdout.stream,
      stderr.stream,
      deps,
    );
    expect(code).not.toBe(0);
    expect(stderr.text() + stdout.text()).toMatch(problem);
  }
  expect(launches).toBe(0);
});

test.each([
  ["project", { model_provider: "openrouter" }, "--model is required"],
  ["selected profile", { model_provider: "openrouter" }, "--model is required"],
  [
    "profile provider",
    {
      model_provider: "gateway",
      model: "fixture-model",
      model_providers: { gateway: { base_url: "https://profile.invalid/" } },
    },
    "provider definitions in a selected profile",
  ],
  [
    "OpenAI gateway",
    { model_provider: "openai", openai_base_url: "https://profile.invalid/" },
    "custom OpenAI or ChatGPT endpoints",
  ],
] satisfies [string, object, string][])(
  "rejects invalid investigator settings from the %s",
  async (source, review, reason) => {
    await using repo = await scopedTemporaryDirectory("investigator-provider-");
    await commitFixture(repo.path);
    const config = join(repo.path, "project.json");
    const codex =
      source === "project"
        ? review
        : {
            model_provider: "gateway",
            profile: "review",
            profiles: { review },
          };
    await writeFile(config, JSON.stringify({ codex }));
    await writeFile(
      join(repo.path, "config.toml"),
      '[model_providers.gateway]\nbase_url="https://ambient.invalid/"',
    );
    const stderr = capture();
    const stdout = capture();
    const status = await main(
      [
        "exploitability",
        "check",
        "npm:sample",
        "--config",
        config,
        "--vuln-description",
        "Synthetic issue",
        "--json",
      ],
      stdout.stream,
      stderr.stream,
      dependencies({
        currentDirectory: repo.path,
        async onCodex() {
          throw new Error("Unexpected investigator launch");
        },
        environment: {
          CODEX_HOME: repo.path,
          CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY: "1",
        },
      }),
    );
    expect(status, stderr.text()).toBe(2);
    expect(JSON.parse(stdout.text())).toMatchObject({
      status: "blocked",
      reason: expect.stringContaining(reason),
    });
  },
);

test.each(["inline", "native"] as const)(
  "a reviewed check using the %s profile calls only selected evidence sources and reviews the original replies",
  checkReviewed,
);

async function checkReviewed(source: "inline" | "native") {
  await using repo = await scopedTemporaryDirectory("dependency-evidence-cli-");
  await commitFixture(repo.path);
  const server = { command: "fixture-server", enabled_tools: ["read_build"] };
  const config = join(repo.path, "investigation.json");
  await using home = await scopedTemporaryDirectory("investigator-home-");
  if (source === "native") {
    await writeFile(
      join(home.path, "review.config.toml"),
      'model = "fixture-model"\n[model_providers.unused]\nexperimental_bearer_token = "synthetic-private-value"\n',
    );
  }
  await writeFile(
    config,
    JSON.stringify({
      codex: {
        profile: "review",
        ...(source === "inline" && {
          profiles: { review: { model: "fixture-model" } },
        }),
        agents: {
          max_concurrent_threads_per_session: 7,
          default_subagent_reasoning_effort: "xhigh",
        },
        mcp_servers: { builds: server, unused: { command: "unselected" } },
      },
      exploitability: {
        evidence_sources: [
          { server: "builds", instructions: "Look up the deployed build." },
        ],
      },
    }),
  );
  const result = { content: [{ type: "text", text: "Build unavailable." }] };
  const wireReceipts = new Map<string, Record<string, unknown>>();
  let traceSearchedPaths: string[] | undefined;
  let reviewed = false;
  const stdout = capture();
  const stderr = capture();
  const reportPath = join(repo.path, "report.json");
  const eventsPath = join(repo.path, "progress.jsonl");
  const status = await main(
    [
      "exploitability",
      "check",
      "npm:sample",
      "--config",
      config,
      "--codex",
      'model_provider="openrouter"',
      "--codex",
      "features.multi_agent_v2.max_concurrent_threads_per_session=49",
      "--codex",
      'model_reasoning_effort="medium"',
      "--vuln-description",
      "A parser issue",
      ...(source === "inline"
        ? [
            "--sources",
            "handle",
            "--sources",
            "loadConfig",
            "--sinks",
            "decode",
          ]
        : []),
      "--json",
      "--report-file",
      reportPath,
      "--progress-events",
      eventsPath,
    ],
    stdout.stream,
    stderr.stream,
    dependencies({
      currentDirectory: repo.path,
      environment: {
        CODEX_HOME: home.path,
        CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY: "1",
      },
      async onCodex(args, output, _environment, prompt) {
        expect(args.join(" ")).not.toContain("synthetic-private-value");
        expect(args).toContain('model_provider="openrouter"');
        expect(args).toContain('model="fixture-model"');
        expect(args[0]).toBe(output?.appServer ? "app-server" : "exec");
        expect(requestMetadata(args)).toMatchObject({
          codex_security_surface: "cli",
          codex_security_command: "exploitability check",
        });
        const text = (prompt ?? output?.appServer?.prompt)!;
        const synthesis = synthesisAnswer(text);
        if (synthesis) {
          expect(output?.readOnly).toBe(true);
          output!.stdout.write(JSON.stringify(synthesis));
          return 0;
        }
        const payload = JSON.parse(text.split("\n\n").at(-1)!);
        if (source === "inline") {
          expect(payload.sources).toEqual([
            { function: "handle" },
            { function: "loadConfig" },
          ]);
          expect(payload.sinks).toEqual([{ function: "decode" }]);
        } else {
          expect(payload).not.toHaveProperty("sources");
          expect(payload).not.toHaveProperty("sinks");
        }
        const features = parseToml(
          args.find((v) => v.startsWith("features="))!,
        )["features"];
        expect(
          parseToml(args.find((v) => v.startsWith("model_reasoning_effort="))!)[
            "model_reasoning_effort"
          ],
        ).toBe(payload.claims ? "low" : "high");
        const endpoint = output!.investigationServers![
          "dependency_investigation"
        ] as { url: string };
        const call = async (method: string, params: unknown = {}) => {
          const response = await fetch(endpoint.url, {
            method: "POST",
            headers: {
              Accept: "application/json, text/event-stream",
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
          });
          expect(response.status).toBe(200);
          return (
            (await response.json()) as {
              result: {
                tools?: { name: string }[];
                content?: { text: string }[];
              };
            }
          ).result;
        };
        const listed = (await call("tools/list")).tools!.map((t) => t.name);
        if (payload.claims) {
          expect(Object.keys(output?.investigationServers ?? {})).toEqual([
            "dependency_investigation",
          ]);
          expect(features).toMatchObject({
            apps: false,
            multi_agent_v2: false,
          });
          expect(
            output!.investigationServers!["dependency_investigation"],
          ).toMatchObject({ default_tools_approval_mode: "approve" });
          expect(listed).toContain("read_dependency_evidence");
          for (const write of [
            "submit_dependency_claims",
            "submit_dependency_assessments",
            "update_codex_security_graph",
            "resolve_codex_security_services",
          ])
            expect(listed).not.toContain(write);
          expect(payload.evidence).toMatchObject([
            { server: "builds", tool: "read_build", arguments: {}, result },
          ]);
          output!.stdout.write(
            JSON.stringify({ decisions: payload.claims.map(approve) }),
          );
          reviewed = true;
        } else {
          expect(output?.appServer?.resumableCoordinator).toBe(true);
          const requests: { method?: string; params?: object }[] = [];
          await readSkillCommandOutput(
            commandOutput({
              id: 2,
              result: {
                thread: { id: "investigator", ephemeral: true },
                activePermissionProfile: { id: "dependency_investigation" },
                model: "fixture",
                modelProvider: "fixture",
                sandbox: {},
              },
            }),
            {
              ...output!.appServer!,
              linkedEvidence: undefined,
              cyberAccessProgram: "standard",
              input: new Writable({
                write(chunk, _encoding, done) {
                  requests.push(JSON.parse(chunk.toString()));
                  done();
                },
              }),
            },
          );
          expect(
            requests.find((r) => r.method === "turn/start")?.params,
          ).toMatchObject({ cyberAccessProgram: "standard" });
          expect(output?.investigationServers).toEqual({
            builds: server,
            dependency_investigation: expect.objectContaining({
              required: true,
              default_tools_approval_mode: "approve",
            }),
          });
          expect(features).toMatchObject({ apps: false, multi_agent_v2: true });
          expect(
            parseToml(args.find((v) => v.startsWith("agents="))!)["agents"],
          ).toMatchObject({
            max_concurrent_threads_per_session: 49,
            default_subagent_reasoning_effort: "xhigh",
          });
          expect(listed).toContain("trace_codex_security_code");
          expect(listed).toContain("submit_dependency_assessments");
          expect(args.find((s) => s.startsWith("mcp_servers="))).toContain(
            "read_build",
          );
          // A source trace with no structural rule returns incomplete coverage.
          // The plugin's in-memory partial scope has optional undefined properties.
          for (const [name, arguments_] of [
            [
              "trace_codex_security_code",
              {
                package: "sample",
                paths: ["."],
                source_terms: ["decode"],
                symbol: "decode",
                max_hops: 0,
                time_budget_ms: 1000,
              },
            ],
            [
              "trace_codex_security_code",
              {
                package: "fixture",
                files: ["package.json"],
                max_hops: 0,
                time_budget_ms: 1000,
                rules: [
                  {
                    id: "fixture",
                    metadata: JSON.parse(
                      '{"__proto__":{"observed":true},"labels":[null,false,{"name":"fixture"}]}',
                    ),
                  },
                ],
              },
            ],
            ["query_codex_security_graph", { node: "caller.js" }],
          ] as const) {
            const reply = await call("tools/call", {
              name,
              arguments: arguments_,
            });
            const value = JSON.parse(reply.content![0]!.text);
            if (
              name === "trace_codex_security_code" &&
              !("rules" in arguments_)
            ) {
              expect(value.coverage.complete).toBe(false);
              expect(value.coverage.partial.length).toBeGreaterThan(0);
              traceSearchedPaths = value.coverage.searched_paths;
            }
            const original = {
              server: "dependency_investigation",
              tool: name,
              arguments: arguments_,
              result: { structuredContent: value },
            };
            wireReceipts.set(dependencyRecordHash(original), original);
          }
          await readSkillCommandOutput(
            commandOutput(
              {
                type: "turn.completed",
                usage: {
                  input_tokens: 12,
                  cached_input_tokens: 2,
                  output_tokens: 6,
                },
              },
              {
                type: "item.completed",
                item: {
                  type: "mcp_tool_call",
                  status: "completed",
                  server: "builds",
                  tool: "read_build",
                  arguments: {},
                  result,
                },
              },
            ),
            undefined,
            output?.onExecEvent,
          );
          output!.stdout.write(
            JSON.stringify({
              uses: [],
              limitations: ["No running build was established."],
            }),
          );
        }
        return 0;
      },
    }),
  );
  expect(status, stderr.text() + stdout.text()).toBe(0);
  expect(reviewed).toBe(true);
  const json = JSON.parse(stdout.text());
  expect(JSON.parse(await readFile(reportPath, "utf8"))).toEqual(json);
  const report = exploitabilityReportSchema.parse(json);
  const events = (await readFile(eventsPath, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  expect(events.filter((e) => e.type === "access_program")).toEqual([
    expect.objectContaining({
      schemaVersion: 1,
      subject: "sample",
      program: "standard",
    }),
  ]);
  const trace = events.find(
    (e) =>
      e.type === "activity_finished" &&
      e.activity === "trace" &&
      e.scope?.symbol === "decode",
  );
  expect(trace).toMatchObject({
    outcome: "partial",
    scope: { directories: ["."] },
  });
  // The requested directory is only reported as searched if a search completed.
  expect(trace.searchedPaths ?? []).toEqual(traceSearchedPaths);
  expect(events.find((e) => e.type === "report_ready")).toMatchObject({
    path: reportPath,
    verdicts: { unknown: 1 },
  });
  expect(events.at(-1)).toMatchObject({
    type: "finished",
    outcome: "completed",
  });
  expect(stderr.text()).toContain("standard");
  expect(stderr.text()).toContain(reportPath);
  expect(stderr.text()).not.toContain("\u001b");
  expect(report.subject).toEqual({
    kind: "package",
    ecosystem: "npm",
    name: "sample",
  });
  const vulnerability = report.vulnerabilities[0]!;
  expect(vulnerability).toMatchObject({
    kind: "hypothesis",
    description: "A parser issue",
    result: { verdict: "unknown", review: { status: "approved" } },
    analyses: [
      { analyzer: "repository", status: "complete" },
      { analyzer: "stacks", status: "skipped" },
    ],
  });
  const check = vulnerability.analyses.find(
    (a) => a.analyzer === "repository",
  )!;
  const receipts = check.evidence!.receipts;
  for (const [id, row] of wireReceipts)
    expect(receipts[id]).toEqual({ ...row, sha256: id });
  expect(check.audit?.usage).toMatchObject({
    input_tokens: 12,
    output_tokens: 6,
  });
}

const outputFlags = {
  md: ["--format", "md"],
  html: ["--format", "html"],
  summary: [],
};
test.each(Object.keys(outputFlags) as (keyof typeof outputFlags)[])(
  "saves the report and prints the requested %s output",
  checkCoordinatorOutput,
);

async function checkCoordinatorOutput(format: keyof typeof outputFlags) {
  await using repo = await scopedTemporaryDirectory("dependency-output-");
  await commitFixture(repo.path);
  const stdout = capture(format === "summary"),
    stderr = capture(false);
  // The suffix alone must not turn a canonical JSON report into HTML.
  const requestedPath = join(
    repo.path,
    format === "summary" ? "report.html" : "report." + format,
  );
  const status = await main(
    [
      "exploitability",
      "check",
      "npm:sample",
      "--vuln-description",
      "Supplied condition",
      ...(format === "html" ? [] : ["--report-file", requestedPath]),
      ...outputFlags[format],
    ],
    stdout.stream,
    stderr.stream,
    dependencies({
      currentDirectory: repo.path,
      environment: {
        CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY: "1",
        TERM: "dumb",
      },
      async onCodex(_args, output, _env, prompt) {
        const text = (prompt ?? output?.appServer?.prompt)!;
        const synthesis = synthesisAnswer(text);
        if (synthesis) {
          output!.stdout.write(JSON.stringify(synthesis));
          return 0;
        }
        const packet = JSON.parse(text.split("\n\n").at(-1)!);
        output!.stdout.write(
          JSON.stringify(
            packet.claims
              ? { decisions: packet.claims.map(approve) }
              : { uses: [], limitations: ["No applicable package was found."] },
          ),
        );
        return 0;
      },
    }),
  );
  expect(status, stderr.text() + stdout.text()).toBe(0);
  const reportPath =
    format === "html"
      ? stdout.text().trimEnd().split("\n").at(-1)!
      : requestedPath;
  if (format === "html") {
    expect(reportPath.startsWith(repo.path)).toBe(true);
    expect(reportPath).toMatch(/exploitability_report_\d{8}T\d{9}Z\.html$/u);
    const contents = await readFile(reportPath, "utf8");
    expect(contents).toStartWith("<!doctype html>");
    expect(contents).toContain("No applicable package was found.");
  } else if (format === "md") {
    const contents = await readFile(reportPath, "utf8");
    expect(contents).toStartWith("# ");
    expect(contents).toContain("No applicable package was found.");
    expect(stdout.text().trimEnd()).toEndWith(reportPath);
  } else {
    const saved = JSON.parse(await readFile(reportPath, "utf8"));
    expect(saved.vulnerabilities[0]).toMatchObject({
      kind: "hypothesis",
      description: "Supplied condition",
      result: { review: { status: "approved" } },
    });
  }
  const summary = stdout.text().trim();
  expect(summary).not.toContain("<!doctype html>");
  expect(summary).toContain("Runtime reachability is unresolved.");
}
