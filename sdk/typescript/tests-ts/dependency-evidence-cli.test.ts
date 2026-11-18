import { parse as parseToml } from "smol-toml";
import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { main, readSkillCommandOutput } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

test("a reviewed check calls only selected evidence sources and reviews the original replies", async () => {
  await using repo = await scopedTemporaryDirectory("dependency-evidence-cli-");
  const git = (...args: string[]) =>
    execFileSync("git", args, { cwd: repo.path });
  git("init", "-q");
  git(
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.invalid",
    "commit",
    "--allow-empty",
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
          default_subagent_reasoning_effort: "high",
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
  let reviewed = false;
  const stdout = capture();
  const stderr = capture();
  const status = await main(
    [
      "exploitability",
      "check",
      "npm:sample",
      "--config",
      config,
      "--codex",
      "features.multi_agent_v2.max_concurrent_threads_per_session=49",
      "--vuln-description",
      "A parser issue",
      "--json",
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
          expect(features).toMatchObject({ multi_agent_v2: false });
          expect(listed).toContain("read_dependency_evidence");
          expect(listed).not.toContain("submit_dependency_claims");
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
          expect(output?.investigationServers).toMatchObject({
            builds: server,
            dependency_investigation: { required: true },
          });
          expect(features).toMatchObject({ multi_agent_v2: true });
          expect(
            parseToml(args.find((v) => v.startsWith("agents="))!)["agents"],
          ).toMatchObject({
            max_concurrent_threads_per_session: 49,
            default_subagent_reasoning_effort: "high",
          });
          expect(listed).toContain("trace_codex_security_code");
          expect(listed).toContain("submit_dependency_assessments");
          expect(args.find((s) => s.startsWith("mcp_servers="))).toContain(
            "read_build",
          );
          await readSkillCommandOutput(
            (async function* () {
              yield JSON.stringify({
                type: "turn.completed",
                usage: {
                  input_tokens: 12,
                  cached_input_tokens: 2,
                  output_tokens: 6,
                },
              }) + "\n";
              yield JSON.stringify({
                type: "item.completed",
                item: {
                  type: "mcp_tool_call",
                  status: "completed",
                  server: "builds",
                  tool: "read_build",
                  arguments: {},
                  result,
                },
              }) + "\n";
            })(),
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
  expect(status, stderr.text() || stdout.text()).toBe(0);
  expect(reviewed).toBe(true);
  expect(JSON.parse(stdout.text()).checks[0].usage).toMatchObject({
    input_tokens: 12,
    output_tokens: 6,
  });
});
