import { expect, onTestFinished, test } from "bun:test";
import { hash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { JsonObject } from "../src/config.js";
import { DependencyAttemptStore } from "../src/dependency/attempt-store.js";
import { createDependencySourceTools } from "../src/dependency/analyzers/repository/source-evidence.js";
import { git } from "./git-fixture.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

function attemptStore() {
  const store = new DependencyAttemptStore(":memory:");
  onTestFinished(() => store.close());
  return store;
}

type Options = Parameters<typeof createDependencySourceTools>[0];
function sourceTools(options: Options) {
  const tools = createDependencySourceTools(options);
  return {
    fetch: tools.find((t) => t.name === "fetch_dependency_source")!.run,
    read: tools.find((t) => t.name === "read_dependency_source")!.run,
  };
}

test("captures a pinned public source or advisory once and binds only actual line ranges to receipts", async () => {
  await using temp = await scopedTemporaryDirectory("dependency-source-");
  const source = "\uFEFFfirst\r\nsecond\n";
  const captures: JsonObject[] = [];
  const calls: string[] = [];
  const options: Options = {
    store: attemptStore(),
    repository: temp.path,
    async fetcher(url, init) {
      calls.push(url);
      expect(init).toMatchObject({ credentials: "omit", redirect: "error" });
      return new Response(Buffer.from(source));
    },
    recordExcerpt(excerpt) {
      captures.push(excerpt);
      return "test-receipt";
    },
  };
  const tools = sourceTools(options);
  const request = {
    kind: "github",
    owner: "example",
    repository: "decoder",
    commit: "a".repeat(40),
    path: "src/file with spaces.c",
  };
  const [first, second] = await Promise.all([
    tools.fetch(request),
    tools.fetch(request),
  ]);
  expect(first).toEqual(second);
  expect(first).toMatchObject({ sha256: hash("sha256", source) });
  expect(first).not.toHaveProperty("source");
  const reopened = sourceTools(options);
  expect(await reopened.fetch(request)).toEqual(first);
  expect(calls).toEqual([
    `https://raw.githubusercontent.com/example/decoder/${request.commit}/src/file%20with%20spaces.c`,
  ]);
  const sourceId = first["sourceId"];
  expect(await reopened.read({ sourceId, search: "second" })).toMatchObject({
    matchingLines: [2],
  });
  expect(captures).toHaveLength(0);
  expect(
    await reopened.read({ sourceId, startLine: 1, endLine: 9 }),
  ).toMatchObject({
    startLine: 1,
    endLine: 2,
    text: source,
    receiptId: "test-receipt",
  });
  expect(captures).toHaveLength(1);
  expect(captures[0]).toMatchObject({
    request,
    sourceId,
    text: source,
    endLine: 2,
  });
  await expect(
    reopened.read({ sourceId, startLine: 3, endLine: 4 }),
  ).rejects.toThrow();
  for (const invalid of [
    { ...request, path: "../private" },
    { ...request, repository: ".." },
    { ...request, owner: "example/other" },
    { ...request, commit: "main" },
    { kind: "npm", name: "decoder", version: "1.2.3", path: "index.js" },
  ])
    await expect(tools.fetch(invalid)).rejects.toThrow();
  expect(calls).toHaveLength(1);
  const partial = sourceTools({
    ...options,
    fetcher: async () => new Response("incomplete", { status: 206 }),
  });
  await expect(partial.fetch({ ...request, path: "partial" })).rejects.toThrow(
    "HTTP 206",
  );
  const saved = options.store.get<JsonObject>(
    "source-artifact",
    String(sourceId),
  );
  options.store.set("source-artifact", String(sourceId), {
    ...saved,
    source: "changed",
  });
  await expect(reopened.read({ sourceId, search: "changed" })).rejects.toThrow(
    "Saved source evidence changed",
  );
  const advisory = await reopened.fetch({
    kind: "github_advisory",
    owner: "example",
    repository: "decoder",
    advisoryId: "GHSA-2222-3333-4444",
  });
  expect(
    await reopened.read({
      sourceId: advisory["sourceId"],
      startLine: 2,
      endLine: 2,
    }),
  ).toMatchObject({
    text: "second\n",
    url: "https://github.com/example/decoder/security/advisories/GHSA-2222-3333-4444",
  });
});

test("reads a historical Git tree without following later worktree changes or using the network", async () => {
  await using repo = await scopedTemporaryDirectory("dependency-checkout-");
  git(repo.path, "init", "-q");
  await writeFile(
    join(repo.path, "decoder.js"),
    "export const safe = false;\n",
  );
  git(repo.path, "-c", "core.autocrlf=false", "add", "decoder.js");
  git(repo.path, "commit", "-qm", "Original source");
  const commit = git(repo.path, "rev-parse", "HEAD");
  const blob = git(repo.path, "rev-parse", "HEAD:decoder.js");
  await writeFile(join(repo.path, "decoder.js"), "export const safe = true;\n");
  git(repo.path, "commit", "-qam", "Updated source");
  const current = git(repo.path, "rev-parse", "HEAD");
  const tools = sourceTools({
    store: attemptStore(),
    repository: repo.path,
    async fetcher() {
      throw new Error("Unexpected remote request");
    },
    recordExcerpt: () => "historical-receipt",
  });
  const request = { kind: "git", commit, path: "decoder.js" };
  const { sourceId } = await tools.fetch(request);
  expect(
    await tools.read({ sourceId, startLine: 1, endLine: 1 }),
  ).toMatchObject({
    request,
    git: { blob },
    text: "export const safe = false;\n",
    receiptId: "historical-receipt",
  });
  expect(git(repo.path, "rev-parse", "HEAD")).toBe(current);
});
