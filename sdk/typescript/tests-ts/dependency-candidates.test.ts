import { expect, test } from "bun:test";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createDependencyCandidates } from "../src/dependency-candidates.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

const trace = "trace_codex_security_code";
const query = "query_codex_security_graph";

test("retains structural call, flow, and dependency locations across trace and graph queries", async () => {
  await using repo = await scopedTemporaryDirectory("dependency-candidates-");
  const path = "worker.ts";
  const manifest = "package.json";
  const otherManifest = "nested/package.json";
  await mkdir(join(repo.path, "nested"));
  await writeFile(
    join(repo.path, path),
    "// render\nrender();\nrender(data);\n",
  );
  for (const file of [manifest, otherManifest])
    await writeFile(
      join(repo.path, file),
      '{"dependencies":{"renderer":"1"}}\n',
    );

  const registry = await createDependencyCandidates(repo.path);
  const discovered = await registry.observeGraph(trace, {
    trace: [
      {
        relation: "candidate_call",
        calleeText: "render",
        evidence: [{ source: path, lines: [2] }],
      },
      {
        relation: "candidate_flow",
        sourceText: "data",
        calleeText: "render",
        evidence: [{ source: path, lines: [3] }],
      },
      { relation: "depends_on", evidence: [{ source: manifest, lines: [1] }] },
      { relation: "references", evidence: [{ source: path, lines: [1] }] },
    ],
    textMatches: [{ source: path, text: "render", lines: [1, 2, 3] }],
  });
  expect(discovered.map(({ path, line }) => [path, line])).toEqual([
    [path, 2],
    [path, 3],
    [manifest, 1],
  ]);

  const queried = await registry.observeGraph(query, {
    paths: [
      { relation: "candidate_call", source: "./worker.ts", line: 2 },
      { relation: "candidate_flow", source: path, line: 2 },
      { relation: "candidate_flow", source: path, line: 3 },
    ],
    evidence: [manifest, otherManifest].map((source) => ({
      relation: "depends_on",
      source,
      line: 1,
    })),
  });
  for (const { id, path, line } of discovered)
    expect(queried.find((candidate) => candidate.id === id)).toMatchObject({
      path,
      line,
    });
  expect(queried.find(({ path }) => path === otherManifest)).toMatchObject({
    line: 1,
  });
  expect(new Set(queried.map(({ id }) => id)).size).toBe(4);
  expect(registry.snapshot().generation).toBe(4);

  // Ignore catalog mappings and search leads even at a previously admitted line.
  expect(
    await registry.observeGraph(query, {
      textMatches: [{ source: path, text: "render", lines: [1, 2] }],
      references: [{ path, line: 2 }],
      paths: [{ source: path, line: 1 }],
      evidence: [{ relation: "uses", source: manifest, line: 1 }],
      service_resolution: { paths: [path] },
    }),
  ).toEqual([]);
  expect(registry.snapshot().generation).toBe(4);
});

test("structural evidence must resolve to a verified repository location", async () => {
  await using repo = await scopedTemporaryDirectory("dependency-checkout-");
  await using other = await scopedTemporaryDirectory("dependency-outside-");
  const source = "worker.ts";
  const line = "render();";
  await writeFile(join(repo.path, source), line + "\n");
  await writeFile(join(other.path, source), line + "\n");
  const registry = await createDependencyCandidates(repo.path);
  const observed = await registry.observeGraph(trace, {
    trace: [
      {
        relation: "candidate_call",
        evidence: [
          { source, lines: [0, 1, 2] },
          { source: "missing.ts", lines: [1] },
          { source: join(other.path, source), lines: [1] },
        ],
      },
    ],
  });
  expect(observed).toEqual([
    expect.objectContaining({
      path: source,
      line: 1,
      sourceBytes: Buffer.byteLength(line),
      sourceSha256: expect.stringMatching(/^[a-f0-9]{64}$/u),
    }),
  ]);
});
