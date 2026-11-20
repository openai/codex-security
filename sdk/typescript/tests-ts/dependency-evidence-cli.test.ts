import { parse as parseToml } from "smol-toml";
import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { dependencyRecordHash } from "../src/dependency-attempt-store.js";
import { dependencyCheckOutputSchema } from "../src/dependency-reachability.js";
import { main, readSkillCommandOutput } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

async function* commandOutput(...events: object[]) {
  for (const event of events) yield JSON.stringify(event) + "\n";
}

test("command schema exposes complete and blocked reports as direct output alternatives", async () => {
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
  const { anyOf } = JSON.parse(stdout.text()).output;
  const variant = (...required: string[]) =>
    anyOf.find((branch: { required?: string[] }) =>
      required.every((field) => branch.required?.includes(field)),
    );
  expect(variant("cve", "uses")).toBeDefined();
  expect(variant("checks", "package")).toBeDefined();
  expect(variant("runId", "assessments")).toBeDefined();
  expect(
    variant("status", "code", "affectedScope", "retainedEvidence"),
  ).toBeDefined();
  const packageCheck = variant("status", "code", "checks", "package");
  expect(packageCheck.properties.checks.items.anyOf).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        required: expect.arrayContaining(["uses", "advisoryId"]),
      }),
      expect.objectContaining({
        required: expect.arrayContaining([
          "status",
          "retainedEvidence",
          "advisoryId",
        ]),
      }),
    ]),
  );
});

test("a reviewed check calls only selected evidence sources and reviews the original replies", async () => {
  await using repo = await scopedTemporaryDirectory("dependency-evidence-cli-");
  const git = (...args: string[]) =>
    execFileSync("git", args, { cwd: repo.path });
  git("init", "-q");
  await writeFile(
    join(repo.path, "caller.js"),
    "export const decode = value => value;\n",
  );
  await writeFile(
    join(repo.path, "package.json"),
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
  const server = { command: "fixture-server", enabled_tools: ["read_build"] };
  const config = join(repo.path, "investigation.json");
  await writeFile(
    config,
    JSON.stringify({
      codex: {
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
      "features.multi_agent_v2.max_concurrent_threads_per_session=49",
      "--codex",
      'model_reasoning_effort="medium"',
      "--vuln-description",
      "A parser issue",
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
      environment: { CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY: "1" },
      async onCodex(args, output, _environment, prompt) {
        const payload = JSON.parse(
          (prompt ?? output?.appServer?.prompt)!.split("\n\n").at(-1)!,
        );
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
            JSON.stringify({
              decisions: payload.claims.map(
                ({
                  id,
                  revision,
                  hash,
                }: {
                  id: string;
                  revision: number;
                  hash: string;
                }) => ({
                  id,
                  revision,
                  hash,
                  evidenceKeys: [],
                  approved: true,
                  reason: "The reported gap matches the evidence.",
                }),
              ),
            }),
          );
          reviewed = true;
        } else {
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
          expect(output?.investigationServers).toMatchObject({
            builds: server,
            dependency_investigation: {
              required: true,
              default_tools_approval_mode: "approve",
            },
          });
          expect(output!.investigationServers!["builds"]).toEqual(server);
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
  const report = dependencyCheckOutputSchema.parse(JSON.parse(stdout.text()));
  expect(JSON.parse(await readFile(reportPath, "utf8"))).toEqual(
    JSON.parse(stdout.text()),
  );
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
    verdicts: { unknown: 0 },
  });
  expect(events.at(-1)).toMatchObject({
    type: "finished",
    outcome: "completed",
  });
  expect(stderr.text()).toContain(
    "Using the supplied vulnerability description",
  );
  expect(stderr.text()).toContain("Tracing source call paths");
  expect(stderr.text()).toContain("Reviewing evidence");
  expect(stderr.text()).toContain("Turn access program · standard");
  expect(stderr.text()).toContain("0 reviewed uses");
  expect(stderr.text()).toContain(`Report saved · ${reportPath}`);
  expect(stderr.text()).not.toContain("\u001b");
  if (!("checks" in report)) throw new Error("Expected a package report.");
  const check = report.checks[0]!;
  const receipts = check.claimEvidence!.receipts;
  for (const [id, row] of wireReceipts)
    expect(receipts[id]).toEqual({ ...row, sha256: id });
  expect(check.usage).toMatchObject({
    input_tokens: 12,
    output_tokens: 6,
  });
});

test("a coordinator reports its selected access program and preserves redirected JSON output", async () => {
  await using repo = await scopedTemporaryDirectory("dependency-progress-");
  execFileSync("git", ["init", "-q"], { cwd: repo.path });
  await writeFile(
    join(repo.path, "package.json"),
    JSON.stringify({ name: "fixture", version: "1.0.0" }),
  );
  execFileSync("git", ["add", "package.json"], { cwd: repo.path });
  execFileSync(
    "git",
    [
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.invalid",
      "commit",
      "-qm",
      "fixture",
    ],
    { cwd: repo.path },
  );
  const stdout = capture(false),
    stderr = capture(false);
  const eventsPath = join(repo.path, "events.jsonl");
  const status = await main(
    [
      "exploitability",
      "check",
      "npm:sample",
      "--vuln-description",
      "Supplied condition",
      "--progress-events",
      eventsPath,
      "--json",
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
        if (output?.appServer) {
          expect(output.appServer.resumableCoordinator).toBe(true);
          output.appServer.onAccessProgram?.("standard");
        }
        const packet = JSON.parse(
          (prompt ?? output?.appServer?.prompt)!.split("\n\n").at(-1)!,
        );
        output!.stdout.write(
          JSON.stringify(
            packet.claims
              ? {
                  decisions: packet.claims.map(
                    ({
                      id,
                      revision,
                      hash,
                    }: {
                      id: string;
                      revision: number;
                      hash: string;
                    }) => ({
                      id,
                      revision,
                      hash,
                      approved: true,
                      evidenceKeys: [],
                      reason: "The package is absent.",
                    }),
                  ),
                }
              : { uses: [], limitations: ["No applicable package was found."] },
          ),
        );
        return 0;
      },
    }),
  );
  expect(status, stdout.text()).toBe(0);
  expect(JSON.parse(stdout.text()).checks).toHaveLength(1);
  expect(stderr.text()).toContain("Turn access program · standard");
  const events = (await readFile(eventsPath, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  expect(events.filter((e) => e.type === "access_program")).toMatchObject([
    { program: "standard", subject: "sample" },
  ]);
});
