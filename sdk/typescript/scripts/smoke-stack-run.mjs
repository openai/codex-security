import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

/** An installed shell client can parse every investigation operation on stdout. */
export async function smokeStackRun({
  installedRoot,
  launcher,
  consumer,
  run,
}) {
  const root = join(consumer, "investigation");
  const repository = join(root, "target");
  await mkdir(repository, { recursive: true });
  const git = (...args) =>
    run(
      "git",
      [
        "-c",
        "user.name=Example",
        "-c",
        "user.email=example@example.invalid",
        "-c",
        "commit.gpgSign=false",
        ...args,
      ],
      { cwd: repository, capture: true },
    ).trim();
  git("init", "--quiet");
  await writeFile(join(repository, "app.js"), "export const value = 1;\n");
  git("add", "app.js");
  git("commit", "--quiet", "-m", "Add application");
  const cve = "CVE-2099-0001";
  const target = { repository: "example/app", sha: git("rev-parse", "HEAD") };
  const documents = {
    sources: { format: "codex-security.stack-sources/v1", sources: [] },
    sinks: {
      format: "codex-security.stack-sinks/v1",
      cve,
      advisory: {
        url: "https://example.invalid/advisory",
        summary: "Sample decoding error.",
      },
      sinks: [
        {
          id: "decode",
          function: "decode",
          package: "example-decoder",
          versionScheme: "semver",
          affectedVersions: ["<1.0.0"],
          preconditions: [],
        },
      ],
    },
    stacks: {
      format: "codex-security.sampled-stacks/v1",
      target,
      origin: { source: "example" },
      frameOrder: "leaf_first",
      queries: [
        {
          id: "q",
          scope: {
            window: {
              start: "2025-01-01T00:00:00Z",
              end: "2025-01-02T00:00:00Z",
            },
          },
          selectors: { sources: [], sinks: ["decode"] },
          groups: [
            { id: "g", status: "no_match", truncated: false, observations: [] },
          ],
        },
      ],
    },
  };
  for (const [name, value] of Object.entries(documents))
    await writeFile(join(root, name + ".json"), JSON.stringify(value));
  const { prepareStackPacket } = await import(
    pathToFileURL(join(installedRoot, "dist", "stack-packet.js")).href
  );
  const inputsDir = join(root, "packet");
  await prepareStackPacket({
    cve,
    repository,
    inputsDir,
    toolRevision: "fixture",
    sourcesPath: join(root, "sources.json"),
    sinksPath: join(root, "sinks.json"),
    stacksPath: join(root, "stacks.json"),
  });
  const state = join(root, "attempt.sqlite");
  const env = {
    ...process.env,
    CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY: "1",
  };
  function invoke(verb, args, input) {
    return run(
      process.execPath,
      [
        launcher,
        "exploitability",
        "run",
        verb,
        "--state",
        state,
        ...args,
        ...(input === undefined ? [] : ["--json-stdin"]),
      ],
      { cwd: root, env, capture: true, input: JSON.stringify(input) },
    );
  }
  const command = (verb, input, args = []) =>
    JSON.parse(invoke(verb, args, input));
  assert.equal(
    command("init", undefined, ["--inputs", inputsDir, "--repo", repository])
      .target.sha,
    target.sha,
  );
  assert.equal(command("tools").commands.length, 10);
  const { workItem, rootFirstRawIndices } = command("next");
  assert.deepEqual(rootFirstRawIndices, []);
  const evidence = [{ path: "app.js", startLine: 1, endLine: 1 }];
  assert.ok(
    command("record-evidence", {
      scope: "sample",
      question: "What exists?",
      claim: "The application defines a constant.",
      evidence,
    }).id,
  );
  const { claims } = command("record-claims", {
    claims: [
      { id: "sample", scope: "app", payload: "Source inspected.", evidence },
    ],
  });
  assert.equal(
    command("query-claims", { ids: ["sample"] }).claims[0].hash,
    claims[0].hash,
  );
  const { verdict } = command("record-assessments", {
    items: [
      {
        workItemId: workItem.id,
        verdict: "unknown",
        reason: "No observation.",
        remainingQuestions: ["Which caller ran?"],
        supportingClaims: claims,
      },
    ],
  });
  assert.equal(verdict, "unknown");
  const { receiptId } = command("record-evidence", {
    kind: "runtime",
    server: "example",
    tool: "sample",
    result: { ...documents.stacks.queries[0], id: "follow-up" },
  });
  const { workItemIds } = command("record-observations", { receiptId });
  const followUp = command("next").workItem;
  assert.deepEqual(workItemIds, [followUp.id]);
  command("record-assessments", {
    items: [
      {
        workItemId: followUp.id,
        verdict: "unknown",
        reason: "The follow-up found no matches.",
        remainingQuestions: ["Which caller ran?"],
      },
    ],
  });
  assert.equal(command("summarize-coverage").assessed, 2);
  assert.equal(command("finalize").verdict, "unknown");
  assert.match(
    invoke("summarize-coverage", ["--format", "yaml"]),
    /assessed: 2/u,
  );
}
