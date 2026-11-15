import { afterEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import type { JsonObject } from "../src/config.js";
import { evidenceHash } from "../src/dependency-evidence-store.js";
import { createDependencyInvestigationTools } from "../src/dependency-investigation-tools.js";
import {
  createDependencyProfileEvidence,
  type DependencyProfileQuery,
} from "../src/dependency-profile-evidence.js";

const directories: string[] = [];

async function testDirectory() {
  const directory = await mkdtemp(join(tmpdir(), "dependency-evidence-test-"));
  directories.push(directory);
  return directory;
}

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

const commitRequest = {
  kind: "github",
  owner: "example",
  repository: "decoder",
  commit: "a".repeat(40),
  path: "src/decoder.c",
};

test("captures pinned bytes once and binds exact source ranges for review", async () => {
  const directory = await testDirectory();
  const source = "\uFEFFfirst\r\nsecond\n";
  const captures: JsonObject[] = [];
  const fetches: string[] = [];
  const options = {
    directory,
    repository: directory,
    recordSourceExcerpt(excerpt: JsonObject) {
      captures.push(excerpt);
      return "source-receipt";
    },
    source: {
      fetcher: async (input, init) => {
        fetches.push(String(input));
        expect(init).toMatchObject({ credentials: "omit", redirect: "error" });
        return new Response(Buffer.from(source));
      },
    },
  } satisfies Parameters<typeof createDependencyInvestigationTools>[0];
  const tools = createDependencyInvestigationTools(options);
  expect(tools.tools.map(({ name }) => name)).toEqual([
    "fetch_dependency_source",
    "read_dependency_source",
  ]);
  const [first, second] = (await Promise.all([
    tools.call("fetch_dependency_source", commitRequest),
    tools.call("fetch_dependency_source", commitRequest),
  ])) as [JsonObject, JsonObject];
  expect(first).toEqual(second);
  expect(first).toMatchObject({ sha256: evidenceHash(source) });
  expect(first).not.toHaveProperty("source");
  expect(fetches).toEqual([
    `https://raw.githubusercontent.com/example/decoder/${commitRequest.commit}/src/decoder.c`,
  ]);

  const reopened = createDependencyInvestigationTools(options);
  expect(await reopened.call("fetch_dependency_source", commitRequest)).toEqual(
    first,
  );
  expect(fetches).toHaveLength(1);
  const { sourceId } = first;
  const excerpt = { sourceId, startLine: 1, endLine: 1 };
  expect(await reopened.call("read_dependency_source", excerpt)).toMatchObject({
    ...excerpt,
    text: "\uFEFFfirst\r\n",
    receiptId: "source-receipt",
  });
  expect(captures).toEqual([
    expect.objectContaining({ text: "\uFEFFfirst\r\n" }),
  ]);
  await expect(
    reopened.call("read_dependency_source", { ...excerpt, endLine: 3 }),
  ).rejects.toThrow("Invalid source range");
  await expect(
    tools.call("fetch_dependency_source", {
      ...commitRequest,
      path: "../secret",
    }),
  ).rejects.toThrow();
  await expect(
    tools.call("fetch_dependency_source", { ...commitRequest, commit: "main" }),
  ).rejects.toThrow();

  const filename = join(directory, "sources", `${sourceId}.json`);
  const saved = JSON.parse(await readFile(filename, "utf8"));
  saved.url = "https://example.com/different-source";
  await writeFile(filename, JSON.stringify(saved));
  await expect(
    reopened.call("read_dependency_source", excerpt),
  ).rejects.toThrow("Saved source evidence changed");
});

test("captures and locates primary advisory text before independent review", async () => {
  const directory = await testDirectory();
  const html = [
    "<html>",
    "<main>",
    '<div class="markdown-body">',
    "The decoder requires a crafted input stream.",
    "The fix rejects invalid transitions.",
    "</div></main></html>",
    "",
  ].join("\n");
  const captures: JsonObject[] = [];
  const fetches: string[] = [];
  const request = {
    kind: "github_advisory",
    owner: "example",
    repository: "decoder",
    advisoryId: "GHSA-2222-3333-4444",
  };
  const tools = createDependencyInvestigationTools({
    directory,
    repository: directory,
    recordSourceExcerpt(excerpt) {
      captures.push(excerpt);
      return "primary-source-receipt";
    },
    source: {
      async fetcher(url, init) {
        fetches.push(url);
        expect(init).toMatchObject({ credentials: "omit", redirect: "error" });
        return new Response(html);
      },
    },
    advisory: {
      record: { id: "CVE-2099-1234" },
      evidence: [
        { id: "index", origin: "public index", excerpt: "Index description" },
      ],
      async review(prompt) {
        const packet = JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1));
        const primary = packet.evidence.find(
          (item: { id: string }) => item.id === "primary-source-receipt",
        );
        expect(JSON.parse(primary.origin)).toMatchObject({
          request,
          url: "https://github.com/example/decoder/security/advisories/GHSA-2222-3333-4444",
          sha256: evidenceHash(html),
          startLine: 4,
          endLine: 5,
        });
        expect(primary.excerpt).toBe(
          "The decoder requires a crafted input stream.\nThe fix rejects invalid transitions.\n",
        );
        expect(primary.excerpt).not.toContain("<html>");
        return JSON.stringify({
          decision: "resolved",
          reason: "Captured primary text establishes the trigger.",
          interpretations: [
            {
              component: "decoder",
              affectedVersions: "<2",
              operations: ["decode"],
              conditions: ["crafted input"],
              exclusions: [],
              evidenceIds: ["primary-source-receipt"],
            },
          ],
        });
      },
    },
  });
  expect(
    tools.tools.find(({ name }) => name === "read_dependency_source")
      ?.inputSchema["type"],
  ).toBe("object");
  const captured = await tools.call("fetch_dependency_source", request);
  const { sourceId } = captured;
  if (typeof sourceId !== "string")
    throw new Error("Missing captured source ID");
  expect(captured).not.toHaveProperty("source");
  expect(captured).not.toHaveProperty("text");
  expect(await tools.call("fetch_dependency_source", request)).toEqual(
    captured,
  );
  expect(fetches).toEqual([
    "https://github.com/example/decoder/security/advisories/GHSA-2222-3333-4444",
  ]);
  expect(
    await tools.call("read_dependency_source", {
      sourceId,
      search: "markdown-body",
    }),
  ).toEqual({ sourceId, matchingLines: [3], totalLines: 6 });
  expect(
    await tools.call("read_dependency_source", {
      sourceId,
      search: "absent symbol",
    }),
  ).toMatchObject({ matchingLines: [] });
  expect(captures).toHaveLength(0);
  const receipt = await tools.call("read_dependency_source", {
    sourceId,
    startLine: 4,
    endLine: 5,
  });
  expect(receipt).toMatchObject({
    receiptId: "primary-source-receipt",
    sha256: evidenceHash(html),
  });
  expect(captures).toHaveLength(1);
  expect(
    await tools.call("review_dependency_advisory", {
      question: "Which trigger applies?",
      interpretations: ["crafted stream", "all input"],
      evidenceIds: ["index", "primary-source-receipt"],
    }),
  ).toMatchObject({ decision: "resolved", searchOperations: ["decode"] });
  await expect(
    tools.call("fetch_dependency_source", { ...request, repository: ".." }),
  ).rejects.toThrow("Expected a GitHub repository name");
  await expect(
    tools.call("fetch_dependency_source", {
      ...request,
      advisoryId: "GHSA-2222-3333-4444/../other",
    }),
  ).rejects.toThrow();
  expect(fetches).toHaveLength(1);
});

test("reports the underlying TLS error when capturing a public advisory", async () => {
  const directory = await testDirectory();
  const tools = createDependencyInvestigationTools({
    directory,
    repository: directory,
    recordSourceExcerpt() {
      throw new Error("A failed download must not produce a receipt");
    },
    source: {
      fetcher: async () => {
        throw new TypeError("fetch failed", {
          cause: new Error("unable to verify the first certificate"),
        });
      },
    },
  });
  await expect(
    tools.call("fetch_dependency_source", {
      kind: "github_advisory",
      owner: "example",
      repository: "decoder",
      advisoryId: "GHSA-2222-3333-4444",
    }),
  ).rejects.toThrow(
    "Source lookup failed for https://github.com/example/decoder/security/advisories/GHSA-2222-3333-4444: fetch failed: unable to verify the first certificate",
  );
});

test("verifies npm tarball integrity before reading the release file", async () => {
  const directory = await testDirectory();
  const source = "export const format = 'text';\n";
  const fixture = spawnSync("python3", [
    "-I",
    "-B",
    "-c",
    [
      "import io, sys, tarfile",
      "with tarfile.open(fileobj=sys.stdout.buffer, mode='w|') as archive:",
      "    data = sys.argv[1].encode()",
      "    member = tarfile.TarInfo('package/index.js')",
      "    member.size = len(data)",
      "    archive.addfile(member, io.BytesIO(data))",
    ].join("\n"),
    source,
  ]);
  expect(fixture.status).toBe(0);
  const archive = gzipSync(fixture.stdout);
  const archiveIntegrity = `sha256-${Buffer.from(evidenceHash(archive), "hex").toString("base64")}`;
  const packageRequest = {
    kind: "npm",
    name: "example-codec",
    version: "1.2.3",
    path: "index.js",
  };
  const tarball =
    "https://registry.npmjs.org/example-codec/-/example-codec-1.2.3.tgz";
  const metadata = {
    ...packageRequest,
    dist: { integrity: archiveIntegrity, tarball },
  };
  const reviewedOrigins: unknown[] = [];
  const make = (path: string, release: unknown) =>
    createDependencyInvestigationTools({
      directory: join(directory, path),
      repository: directory,
      recordSourceExcerpt: () => "receipt",
      source: {
        python: "python3",
        fetcher: async (input) => {
          if (String(input) === tarball)
            return new Response(new Uint8Array(archive));
          expect(String(input)).toBe(
            "https://registry.npmjs.org/example-codec/1.2.3",
          );
          return Response.json(release);
        },
      },
      advisory: {
        record: { overview: "The release format is disputed." },
        evidence: [],
        async review(prompt) {
          const packet = JSON.parse(prompt.split("\n").at(-1)!);
          reviewedOrigins.push(JSON.parse(packet.evidence[0].origin));
          return JSON.stringify({
            decision: "resolved",
            reason: "The captured release member declares the format.",
            interpretations: [
              {
                component: "example-codec",
                affectedVersions: "1.2.3",
                operations: ["read"],
                conditions: [],
                exclusions: [],
                evidenceIds: ["receipt"],
              },
            ],
          });
        },
      },
    });
  const tools = make("valid", metadata);
  const captured = (await tools.call(
    "fetch_dependency_source",
    packageRequest,
  )) as JsonObject;
  expect(captured).toMatchObject({
    archiveIntegrity,
    sha256: evidenceHash(source),
    url: tarball,
  });
  expect(
    await tools.call("read_dependency_source", {
      sourceId: captured["sourceId"],
      startLine: 1,
      endLine: 1,
    }),
  ).toMatchObject({ text: source });
  await tools.call("review_dependency_advisory", {
    question: "Which format does this exact release member declare?",
    interpretations: ["text", "binary"],
    evidenceIds: ["receipt"],
  });
  expect(reviewedOrigins).toEqual([
    {
      request: packageRequest,
      url: tarball,
      archiveIntegrity,
      sha256: evidenceHash(source),
      startLine: 1,
      endLine: 1,
    },
  ]);

  await expect(
    make("bad-origin", {
      ...metadata,
      dist: {
        integrity: archiveIntegrity,
        tarball: "https://example.com/unexpected.tgz",
      },
    }).call("fetch_dependency_source", packageRequest),
  ).rejects.toThrow("must come from the npm registry");
  await expect(
    make("bad-digest", {
      ...metadata,
      dist: {
        integrity: `sha256-${Buffer.alloc(32).toString("base64")}`,
        tarball,
      },
    }).call("fetch_dependency_source", packageRequest),
  ).rejects.toThrow("integrity digest");
});

const time = (hour: string) => `2026-01-01T${hour}:00:00.000Z`;
const window = (start: string, end: string) => ({
  start: time(start),
  end: time(end),
});
const selector = { cluster: "test", service: "decoder", frames: ["decode"] };
const profileQuery = (start: string, end: string) => ({
  selector,
  window: window(start, end),
  limit: 10,
});

function providerFixture() {
  type Scenario = {
    tags?: string[];
    truncated?: boolean;
    wrongScope?: boolean;
    fail?: boolean;
  };
  const state = {
    scenario: {} as Scenario,
    blocked: false,
    calls: [] as DependencyProfileQuery[],
  };
  const resources = new Map<string, string>();
  const options = {
    providerKey: "fixture/profile/v1",
    authorize() {
      if (state.blocked) throw new Error("Scope unavailable");
    },
    async lookup(query: DependencyProfileQuery) {
      state.calls.push(query);
      const { tags = [], truncated = false, wrongScope, fail } = state.scenario;
      if (fail) throw new Error("Backend offline");
      const { cluster, service } = query.selector;
      const format = "codex-security-graph-evidence/v1";
      const resource = JSON.stringify({
        format,
        frame_order: "root_first",
        metadata: {
          scope: {
            ...query.selector,
            ...query.window,
            service: wrongScope ? "some-other-service" : service,
            frame_match: "any_exact_name",
          },
          coverage: {
            result_complete: !truncated,
            backend_partial: false,
            returned_stack_count: tags.length,
          },
          limits: { stack_limit: query.limit, truncated },
        },
        observations: tags.map((tag, index) => ({
          id: `stack-${index}`,
          kind: "sampled_stack",
          scope: {
            cluster,
            service,
            window: query.window,
            container: "web",
            observed_image: { name: "app", tag },
          },
          frames: [
            { kind: "function", name: "handler" },
            { kind: "function", name: "decode" },
          ],
        })),
      });
      const sha256 = evidenceHash(resource);
      const uri = `profile-fixture://${sha256}`;
      resources.set(uri, resource);
      return { graph_evidence: { format, uri, sha256 } };
    },
    async readResource(uri: string) {
      return resources.get(uri)!;
    },
    recordCollection({ collectionId }: { collectionId: string }) {
      return `receipt-${collectionId}`;
    },
  };
  return { options, state };
}

test("reuses completed slices and fetches only uncovered intervals", async () => {
  const directory = await testDirectory();
  const { options, state } = providerFixture();
  state.scenario = { tags: ["a", "b"] };
  const first = createDependencyProfileEvidence({ directory, ...options });
  const result = await first.collect(profileQuery("01", "02"));
  const collectionId = result.slices[0]?.collectionId!;
  expect(
    first.witnesses({ collectionId, firstRow: 2, lastRow: 2 }),
  ).toMatchObject([
    {
      row: 2,
      scope: { observed_image: { tag: "b" } },
      frames: [{ name: "handler" }, { name: "decode" }],
    },
  ]);

  const reopened = createDependencyProfileEvidence({ directory, ...options });
  state.scenario = { tags: [] };
  const coverage = await reopened.collect(profileQuery("00", "03"));
  expect(state.calls.map(({ window }) => window)).toEqual([
    window("01", "02"),
    window("00", "01"),
    window("02", "03"),
  ]);
  expect(coverage.uncovered).toEqual([]);
  expect(coverage.slices).toMatchObject([
    { outcome: "no_samples", cached: false },
    { outcome: "found_stacks", cached: true, collectionId, stackCount: 2 },
    { outcome: "no_samples", cached: false },
  ]);
  const assessment = reopened.assess({
    findings: [
      { id: "one", assessed: [{ collectionId, firstRow: 2, lastRow: 2 }] },
    ],
  });
  expect(assessment.findings).toEqual([
    {
      id: "one",
      observedImages: [
        {
          cluster: "test",
          service: "decoder",
          container: "web",
          image: { name: "app", tag: "b" },
        },
      ],
    },
  ]);
  expect(assessment.unassessed).toEqual([
    { collectionId, firstRow: 1, lastRow: 1 },
  ]);
  expect(() =>
    reopened.assess({
      findings: [
        { id: "one", assessed: [{ collectionId, firstRow: 2, lastRow: 3 }] },
      ],
    }),
  ).toThrow("outside its collection");

  // An aggregate for a wider window cannot be clipped to answer a shorter query.
  await reopened.collect({
    ...profileQuery("01", "02"),
    window: {
      start: "2026-01-01T01:15:00.000Z",
      end: "2026-01-01T01:30:00.000Z",
    },
  });
  expect(state.calls).toHaveLength(4);
  state.blocked = true;
  await expect(reopened.collect(profileQuery("01", "02"))).rejects.toThrow(
    "Scope unavailable",
  );
  expect(state.calls).toHaveLength(4);
});

test("distinguishes incomplete, failed, wrong-scope, and empty profile reads", async () => {
  const directory = await testDirectory();
  const { options, state } = providerFixture();
  const tools = createDependencyInvestigationTools({
    directory,
    repository: directory,
    profiles: options,
    source: { fetcher: fetch },
    recordSourceExcerpt: () => "receipt",
  });
  const query = profileQuery("00", "01");
  state.scenario = { tags: ["one"], truncated: true };
  expect(
    await tools.call("collect_dependency_profiles", query, options),
  ).toMatchObject({
    uncovered: [query.window],
    slices: [{ outcome: "incomplete", truncated: true }],
  });
  state.scenario = { wrongScope: true };
  expect(await tools.call("collect_dependency_profiles", query)).toMatchObject({
    uncovered: [query.window],
    slices: [
      { outcome: "failed", error: expect.stringContaining("does not match") },
    ],
  });
  state.scenario = { fail: true };
  expect(await tools.call("collect_dependency_profiles", query)).toMatchObject({
    uncovered: [query.window],
    slices: [
      { outcome: "failed", error: expect.stringContaining("Backend offline") },
    ],
  });
  state.scenario = {};
  expect(await tools.call("collect_dependency_profiles", query)).toMatchObject({
    uncovered: [],
    slices: [{ outcome: "no_samples" }],
  });
  expect(state.calls).toHaveLength(4);
});

test("adjudicates only with captured evidence and retains both search targets when unresolved", async () => {
  const directory = await testDirectory();
  const record = { overview: "The affected branch is disputed." };
  let evidenceId = "captured-fix";
  const tools = createDependencyInvestigationTools({
    directory,
    repository: directory,
    recordSourceExcerpt: () => "captured-fix",
    source: { fetcher: async () => new Response("guard(input);\n") },
    advisory: {
      record,
      evidence: [
        {
          id: "advisory-1",
          origin: "upstream advisory",
          excerpt: "The decoder is affected.",
        },
      ],
      async review(prompt) {
        expect(prompt).toContain("guard(input);");
        expect(prompt).toContain("The decoder is affected.");
        const interpretation = {
          component: "decoder",
          affectedVersions: "1.x",
          conditions: [],
          exclusions: [],
        };
        return JSON.stringify({
          decision: "unresolved",
          reason: "The fix does not identify every dispatch path.",
          interpretations: [
            {
              ...interpretation,
              operations: ["decode"],
              evidenceIds: ["advisory-1"],
            },
            {
              ...interpretation,
              operations: ["decode", "decodeStream"],
              evidenceIds: [evidenceId],
            },
          ],
        });
      },
    },
  });
  const capture = (await tools.call(
    "fetch_dependency_source",
    commitRequest,
  )) as JsonObject;
  await tools.call("read_dependency_source", {
    sourceId: capture["sourceId"],
    startLine: 1,
    endLine: 1,
  });
  const input = {
    question: "Does the affected operation include the streaming entrypoint?",
    interpretations: ["one entrypoint", "both entrypoints"],
    evidenceIds: ["advisory-1", "captured-fix"],
  };
  expect(await tools.call("review_dependency_advisory", input)).toMatchObject({
    decision: "unresolved",
    searchOperations: ["decode", "decodeStream"],
  });
  await expect(
    tools.call("review_dependency_advisory", {
      ...input,
      evidenceIds: ["missing"],
    }),
  ).rejects.toThrow("Unknown advisory evidence");
  evidenceId = "forged";
  await expect(tools.call("review_dependency_advisory", input)).rejects.toThrow(
    "captured evidence",
  );
});
