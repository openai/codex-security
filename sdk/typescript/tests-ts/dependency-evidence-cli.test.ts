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
        const payload = JSON.parse(prompt!.split("\n\n").at(-1)!);
        if (payload.claims) {
          expect(output?.investigationServers).toEqual({});
          expect(output?.onExecEvent).toBeUndefined();
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
                  approved: true,
                  reason: "The reported gap matches the evidence.",
                }),
              ),
            }),
          );
          reviewed = true;
        } else {
          expect(output?.investigationServers).toEqual({ builds: server });
          expect(args.find((s) => s.startsWith("mcp_servers="))).toContain(
            "read_build",
          );
          await readSkillCommandOutput(
            (async function* () {
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
  expect(status, stderr.text()).toBe(0);
  expect(reviewed).toBe(true);
});
