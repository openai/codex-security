import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  prepareStackPacket,
  readStackPacket,
  sampledStacksSchema,
  stackFramesRootFirst,
  stackPacketJsonSchema,
  stackPacketWorkItems,
  stackSinkMatches,
  type StackPacket,
} from "../src/dependency-stack-packet.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

const prepareFixture = fileURLToPath(
  new URL(
    "../../../evals/dependency-reachability/fixtures/stack-workflow/prepare.mjs",
    import.meta.url,
  ),
);
function fixture(directory: string, variant = "fixed") {
  const base = join(directory, variant);
  execFileSync(process.execPath, [prepareFixture, base, variant], {
    stdio: "pipe",
  });
  return {
    cve: "CVE-2099-0001",
    repository: join(base, "target"),
    sourcesPath: join(base, "sources.json"),
    sinksPath: join(base, "sinks.json"),
    stacksPath: join(base, "stacks.json"),
    inputsDir: join(directory, variant + "-inputs"),
    toolRevision: "fixture-tool-revision",
  };
}

test("freezes the exact input bytes and reopens the same observation at the selected Git revision", async () => {
  await using temp = await scopedTemporaryDirectory("stack-packet-");
  const options = fixture(temp.path);
  const original = await readFile(options.stacksPath);
  const packet = await prepareStackPacket(options);
  expect(packet.manifest.files.stacks).toEqual({
    byteLength: original.length,
    sha256: createHash("sha256").update(original).digest("hex"),
  });
  expect(await readFile(join(options.inputsDir, "stacks.json"))).toEqual(
    original,
  );
  expect(await readStackPacket(options.inputsDir, options.repository)).toEqual(
    packet,
  );
  const [item] = stackPacketWorkItems(packet);
  expect(item!.id).toBe("decode/deployment/sample");
  expect(
    stackFramesRootFirst(item!.observation!).map(({ rawIndex, frame }) => [
      rawIndex,
      frame.name,
      frame.offset,
    ]),
  ).toEqual([
    [1, "handle", undefined],
    [0, "decode", "9007199254740993"],
  ]);

  const other = await prepareStackPacket({
    ...options,
    inputsDir: join(temp.path, "second"),
  });
  expect(other.manifest.inputDigest).toBe(packet.manifest.inputDigest);
  expect(other.manifest.runId).not.toBe(packet.manifest.runId);
  expect(other.manifest.attemptId).not.toBe(packet.manifest.attemptId);
  const retry = await prepareStackPacket({
    ...options,
    runId: packet.manifest.runId,
    inputsDir: join(temp.path, "retry"),
  });
  expect(retry.manifest.runId).toBe(packet.manifest.runId);
  expect(retry.manifest.attemptId).not.toBe(packet.manifest.attemptId);
  expect(retry.manifest.inputDigest).toBe(packet.manifest.inputDigest);
});

test("rejects a changed document, different target or inconsistent manifest when reopening", async () => {
  await using temp = await scopedTemporaryDirectory("stack-integrity-");
  const options = fixture(temp.path);
  const packet = await prepareStackPacket(options);
  const wrong = fixture(temp.path, "unbound");
  await expect(
    readStackPacket(options.inputsDir, wrong.repository),
  ).rejects.toThrow("Target checkout HEAD");
  const manifestPath = join(options.inputsDir, "manifest.json");
  await chmod(manifestPath, 0o600);
  await writeFile(
    manifestPath,
    JSON.stringify({
      ...packet.manifest,
      target: { ...packet.manifest.target, repository: "different/example" },
    }),
  );
  await expect(
    readStackPacket(options.inputsDir, options.repository),
  ).rejects.toThrow("Manifest does not match");
  await writeFile(manifestPath, JSON.stringify(packet.manifest));
  const sources = join(options.inputsDir, "sources.json");
  await chmod(sources, 0o600);
  await writeFile(sources, (await readFile(sources, "utf8")) + "\n");
  await expect(
    readStackPacket(options.inputsDir, options.repository),
  ).rejects.toThrow("SHA-256 mismatch for sources.json");
});

test("preserves sink-only, partial and missing coverage without merging repeated stack hashes", async () => {
  await using temp = await scopedTemporaryDirectory("stack-coverage-");
  const options = fixture(temp.path);
  const stacks = JSON.parse(
    await readFile(options.stacksPath, "utf8"),
  ) as StackPacket["stacks"];
  const query = stacks.queries[0]!;
  query.selectors.sources = [];
  query.selectors.sinks = [{ name: "actualProbe" }];
  query.provenance = { source: "recorded-query", revision: "4" };
  const group = query.groups[0]!;
  const sample = group.observations[0]!;
  const { sourceIndex: _, ...sinkOnly } = sample;
  group.observations = [sinkOnly];
  query.groups.push(
    {
      ...group,
      id: "partial",
      truncated: true,
      observations: [
        {
          ...sinkOnly,
          sinkIndex: null,
          sinkIds: [],
          framesTruncated: true,
          frames: [],
        },
      ],
    },
    { ...group, id: "not/sampled", status: "no_match", observations: [] },
    {
      ...group,
      id: "not~captured",
      status: "no_coverage",
      truncated: null,
      observations: [],
    },
  );
  await writeFile(
    options.sourcesPath,
    JSON.stringify({ format: "codex-security.stack-sources/v1", sources: [] }),
  );
  await writeFile(options.stacksPath, JSON.stringify(stacks));
  const items = stackPacketWorkItems(await prepareStackPacket(options));
  expect(items[0]!.selectors.sinks).toEqual([{ name: "actualProbe" }]);
  expect(items[0]!.queryProvenance).toEqual(query.provenance);
  expect(
    items.map((i) => [i.id, i.status, i.truncated, i.observation?.stackHash]),
  ).toEqual([
    ["decode/deployment/sample", "observed", false, "sample-17"],
    ["decode/partial/sample", "observed", true, "sample-17"],
    ["decode/not~1sampled", "no_match", false, undefined],
    ["decode/not~0captured", "no_coverage", null, undefined],
  ]);
  group.observations = [{ ...sinkOnly, sourceIndex: 0 }];
  expect(() => sampledStacksSchema.parse(stacks)).toThrow("leaf-first source");
  group.observations = [
    {
      ...sinkOnly,
      frames: [
        { name: "decode", type: "native", offset: Number.MAX_SAFE_INTEGER + 1 },
      ],
    },
  ];
  expect(() => sampledStacksSchema.parse(stacks)).toThrow();
});

test("preserves the requested workload and flags incompatible representative service, digest and tags", async () => {
  await using temp = await scopedTemporaryDirectory("stack-scope-");
  const packet = await prepareStackPacket(fixture(temp.path));
  const query = packet.stacks.queries[0]!;
  const group = query.groups[0]!;
  const sample = group.observations[0]!;
  query.scope.image_tags = ["stable", "canary"];
  group.scope = { cluster: "west", image_tag: "stable" };
  sample.scope = { cluster: "west", container: "handler", image_tag: "stable" };
  const [refinement] = stackPacketWorkItems(packet);
  expect(refinement!.scopeConflicts).toEqual([]);
  expect(refinement!.scope.container).toBe("handler");
  sample.scope = {
    service: "other-service",
    image_digest: "sha256:" + "b".repeat(64),
    image_tag: "canary",
  };
  const [conflict] = stackPacketWorkItems(packet);
  expect(conflict!.queryScope).toEqual(query.scope);
  expect(conflict!.groupScope).toEqual(group.scope);
  expect(conflict!.queryScope.service).toBe("decoder");
  expect(conflict!.scope.service).toBe("other-service");
  expect(
    conflict!.scopeConflicts.map((reason) => reason.split(":")[0]),
  ).toEqual(["service", "image_digest", "image_tag"]);
  group.scope = { image_tags: ["canary", "unrequested"] };
  sample.scope = {};
  expect(stackPacketWorkItems(packet)[0]!.scopeConflicts).toHaveLength(1);
});

test("keeps the queried sink and mapped catalog frame distinct and rejects unsupported mappings", async () => {
  await using temp = await scopedTemporaryDirectory("stack-matches-");
  const options = fixture(temp.path);
  const stacks = JSON.parse(
    await readFile(options.stacksPath, "utf8"),
  ) as StackPacket["stacks"];
  const sample = stacks.queries[0]!.groups[0]!.observations[0]!;
  sample.frames.unshift({ name: "decodeImplementation", type: "javascript" });
  sample.sourceIndex = 2;
  sample.sinkIndex = 1;
  delete sample.sinkIds;
  sample.sinkMatches = [{ sinkId: "decoder", rawIndex: 0 }];
  await writeFile(options.stacksPath, JSON.stringify(stacks));
  const [item] = stackPacketWorkItems(await prepareStackPacket(options));
  expect(item!.observation!.sinkIndex).toBe(1);
  expect(stackSinkMatches(item!.observation!)).toEqual([
    { sinkId: "decoder", rawIndex: 0 },
  ]);
  sample.sinkIds = ["decoder"];
  expect(() => sampledStacksSchema.parse(stacks)).toThrow("indices disagree");
  delete sample.sinkIds;
  sample.sinkMatches[0]!.rawIndex = 3;
  expect(() => sampledStacksSchema.parse(stacks)).toThrow(
    "outside the captured frames",
  );
  sample.sinkMatches = [{ sinkId: "missing", rawIndex: 0 }];
  await writeFile(options.stacksPath, JSON.stringify(stacks));
  await expect(
    prepareStackPacket({ ...options, inputsDir: join(temp.path, "new") }),
  ).rejects.toThrow("Unknown catalog sink");
});

test("publishes the runtime packet JSON schema", async () => {
  const schema = await readFile(
    new URL(
      "../schemas/dependency-stack-inputs-v1.schema.json",
      import.meta.url,
    ),
    "utf8",
  );
  expect(JSON.parse(schema)).toEqual(stackPacketJsonSchema());
});
