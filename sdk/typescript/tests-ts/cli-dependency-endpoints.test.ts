import { expect, mock, test } from "bun:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { main } from "../src/cli.js";
import type { JsonObject } from "../src/config.js";
import type { DependencyProfileQuery } from "../src/dependency-profile-evidence.js";
import { dependencies } from "./cli-fixtures.js";
import { git } from "./git-fixture.js";
import { createCliTest } from "./support/cli-run.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

const advisory = {
  cve: "CVE-2024-1000",
  advisories: [
    {
      url: "https://example.invalid/advisory",
      summary: "Fixture decoder issue",
      affected: [],
    },
  ],
};
const instructions =
  "Check whether this advisory applies to the fixture API in production.";
const window = {
  start: "2026-01-01T00:00:00.000Z",
  end: "2026-01-01T00:01:00.000Z",
};
const runtime = {
  cluster: "fixture-cluster",
  service: "fixture-api",
  container: "api",
  image_name: "registry.example.invalid/fixture",
  image_tag: "build-a",
  window,
};
const source = { name: "handle", location: "index.ts", line: 1 };
const sink = { name: "decode", build_id: "decoder-build-a" };
const supplied = {
  sources: [{ id: "request", function: "handle", runtime_selectors: [source] }],
  sinks: [{ id: "decoder", function: "decode", runtime_selectors: [sink] }],
};

function profileRpc() {
  const resources = new Map<string, string>();
  const continuation = "fixture-next-page";
  const outsideReply = "only-in-full-resource";
  const call = mock(
    async (server: string, tool: string, request: JsonObject) => {
      expect([server, tool]).toEqual(["profiles", "profiles.stacks"]);
      const args = request as DependencyProfileQuery;
      const last = args.cursor === continuation;
      const page = last ? 2 : 1;
      const uri = `fixture://profiles/${page}`;
      const format = "codex-security-graph-evidence/v1";
      const text = JSON.stringify({
        format,
        frame_order: "root_first",
        metadata: {
          scope: {
            ...args.selector,
            ...args.window,
            query: args.query,
            frame_match: "ordered_exact_selectors",
          },
          coverage: {
            result_complete: false,
            backend_partial: false,
            returned_stack_count: 1,
          },
          limits: { stack_limit: 1, truncated: !last },
          pagination: {
            order: "stack_key_ascending",
            cursor: args.cursor ?? null,
            next_cursor: last ? null : continuation,
            snapshot_pinned: false,
            query_exhausted: last,
          },
          status: "found_stacks",
        },
        observations: [
          {
            id: `stack-${page}`,
            kind: "sampled_stack",
            scope: {
              cluster: runtime.cluster,
              service: runtime.service,
              container: runtime.container,
              observed_image: {
                name: runtime.image_name,
                tag: runtime.image_tag,
              },
              window,
              stack_key: page.toString(16).padStart(64, "0"),
            },
            frames: [
              { kind: "function", name: outsideReply },
              {
                kind: "function",
                name: source.name,
                attributes: { location: "index.ts:1" },
              },
              {
                kind: "function",
                name: sink.name,
                attributes: { build_id: sink.build_id },
              },
            ],
          },
        ],
      });
      resources.set(uri, text);
      return {
        structuredContent: {
          graph_evidence: {
            format,
            uri,
            sha256: createHash("sha256").update(text).digest("hex"),
          },
        },
      };
    },
  );
  const read = mock(async (server: string, uri: string) => {
    expect(server).toBe("profiles");
    return { contents: [{ uri, text: resources.get(uri) }] };
  });
  return {
    call,
    read,
    continuation,
    outsideReply,
    list: async () => ({
      data: [
        {
          name: "profiles",
          tools: { "profiles.stacks": { annotations: { readOnlyHint: true } } },
        },
      ],
    }),
  };
}

test.each([
  { configuredInstructions: true, configuredEndpoints: true },
  { configuredInstructions: false, configuredEndpoints: true },
  { configuredInstructions: true, configuredEndpoints: false },
])(
  "exploitability wires scope instructions and independent endpoint boundaries for %j",
  async ({ configuredInstructions, configuredEndpoints }) => {
    await using repository = await scopedTemporaryDirectory("cve-endpoints-");
    await using settings = await scopedTemporaryDirectory("cve-config-");
    git(repository.path, "init", "--quiet");
    await writeFile(
      join(repository.path, "index.ts"),
      "export const handle = (value: string) => decode(value);\n",
    );
    const config = join(settings.path, "explicit.json");
    await writeFile(
      config,
      JSON.stringify({
        exploitability: {
          ...(configuredEndpoints && supplied),
          ...(configuredInstructions && { scope: { instructions } }),
          runtime_mcps: ["profiles"],
        },
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
    const expectedCaller = configuredInstructions
      ? instructions
      : "Assess production services, jobs";
    const rpc = profileRpc();
    const deps = dependencies({
      currentDirectory: repository.path,
      environment: { PATH: process.env["PATH"] },
      onCodex: async (_argv, output) => {
        const session = output?.appServer;
        assert(
          session?.dependencyGraph &&
            session.dependencyReport?.queue &&
            session.dependencyReport.submit,
        );
        expect(session.prompt).toContain(expectedCaller);
        const graph = session.dependencyGraph;
        const discovery = await graph.call("query_codex_security_graph", {
          endpoints: {},
        });
        const boundary = configuredEndpoints ? "supplied" : "discover";
        expect(discovery).toMatchObject({
          endpoints: {
            boundary: { source: boundary, sink: boundary },
            page: { total: configuredEndpoints ? 2 : 0 },
            ...(configuredInstructions && { scope_instructions: instructions }),
          },
        });
        expect(discovery["endpoints"]).not.toHaveProperty("runtime_scope");
        if (configuredEndpoints) {
          expect(discovery).toMatchObject({
            endpoints: {
              page: {
                items: [
                  { id: "request", role: "source", origin: "supplied" },
                  { id: "decoder", role: "sink", origin: "supplied" },
                ],
              },
            },
          });
          const { window, ...selector } = runtime;
          const profileInput = {
            endpoints: { sources: ["request"], sinks: ["decoder"] },
            selector,
            window,
            limit: 1,
            measure: true,
          };
          const collected = await graph.call(
            "collect_dependency_profiles",
            profileInput,
            rpc,
          );
          expect(collected).toMatchObject({
            uncovered: [],
            slices: [
              { outcome: "found_stacks", pageChainComplete: true },
              { outcome: "found_stacks", pageChainComplete: true },
            ],
          });
          expect(JSON.stringify(collected)).not.toContain(rpc.outsideReply);
          expect(collected).not.toHaveProperty("graph_evidence");
          const wireRequest = {
            selector: { ...selector, frames: ["decode"] },
            window,
            limit: 1,
            measure: true,
            query: {
              kind: "pair",
              sources: [source],
              sinks: [sink],
              rules: [],
              evidence: [],
              taint_dependencies: [],
            },
          };
          expect(rpc.call.mock.calls.map(([, , args]) => args)).toEqual([
            wireRequest,
            { ...wireRequest, cursor: rpc.continuation },
          ]);
          expect(rpc.read.mock.calls).toEqual([
            ["profiles", "fixture://profiles/1"],
            ["profiles", "fixture://profiles/2"],
          ]);
          expect(
            await graph.call("query_codex_security_graph", {
              search: rpc.outsideReply,
            }),
          ).toMatchObject({
            witnesses_found: 2,
            witnesses: expect.arrayContaining([
              expect.objectContaining({
                native_id: "stack-1",
                scope: expect.objectContaining({
                  service: runtime.service,
                  observed_image: {
                    name: runtime.image_name,
                    tag: runtime.image_tag,
                  },
                }),
              }),
              expect.objectContaining({ native_id: "stack-2" }),
            ]),
          });
          await expect(
            graph.call(
              "collect_dependency_profiles",
              {
                ...profileInput,
                selector: { ...selector, frames: ["other-decoder"] },
              },
              rpc,
            ),
          ).rejects.toThrow();
          expect(rpc.call).toHaveBeenCalledTimes(2);
        }
        const queued = await session.dependencyReport.queue({
          items: [
            {
              id: "candidate",
              kind: "use",
              candidateIds: [],
              use: {
                location: "index.ts:1",
                component: "fixture-decoder",
                version: null,
                verdict: "unknown",
                deployment: "unknown",
                reason: "The selected decoder version is unbound.",
                evidence: [
                  { path: "index.ts", startLine: 1, endLine: 1, supports: [] },
                ],
                observations: [],
              },
            },
          ],
        });
        if (!queued.queued) throw new Error(queued.feedback);
        const submitted = await session.dependencyReport.submit({
          reviewItems: queued.items,
          candidateGeneration: 0,
          limitations: ["The selected decoder version is unbound."],
        });
        expect(submitted.accepted, submitted.feedback).toBe(true);
        return 0;
      },
    });
    deps.lookupDependencyAdvisory = async () => advisory;
    deps.reviewDependencyReport = mock(async (prompt) => {
      const packet = JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1));
      expect(packet.callerScope).toContain(expectedCaller);
      expect(Boolean(packet.callerScopeIsDefault)).toBe(
        !configuredInstructions,
      );
      return JSON.stringify({
        items: packet.items.map(
          (item: {
            id: string;
            revision: number;
            hash: string;
            excerptIds: string[];
          }) => ({
            id: item.id,
            revision: item.revision,
            hash: item.hash,
            accepted: true,
            reason: "The cited source does not identify the decoder version.",
            citedVersion: null,
            evidenceIds: item.excerptIds,
          }),
        ),
      });
    });
    const cli = createCliTest(main);
    expect(
      await cli.runCli(
        ["exploitability", "check", advisory.cve, "--json", "--config", config],
        deps,
      ),
      cli.stderr.text(),
    ).toBe(0);
    expect(deps.reviewDependencyReport).toHaveBeenCalledTimes(1);
    expect(JSON.parse(cli.stdout.text()).assumptions[0]).toContain(
      expectedCaller,
    );
  },
);
