import { expect, test } from "bun:test";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Readable } from "node:stream";
import { main } from "../src/cli.js";
import { prepareStackPacket } from "../src/stack-packet.js";
import { stackPacketWorkItems } from "../src/dependency-stack-packet.js";
import type { DependencyClaimReference } from "../src/dependency-stack-claims.js";
import {
  executeStackRun,
  readFinalStackReport,
} from "../src/dependency-stack-run.js";
import { dependencies } from "./cli-fixtures.js";
import { git } from "./git-fixture.js";
import { createCliTest } from "./support/cli-run.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

const cve = "CVE-2099-0001";
const condition = "Caller controls the decoder input.";
async function sample(
  root: string,
  bindSource: boolean,
  separateImage?: "same" | "other",
) {
  const repo = join(root, "target");
  await mkdir(repo);
  git(repo, "init", "--quiet");
  await writeFile(
    join(repo, "app.js"),
    "export function request(bytes) {\n  return decode(bytes);\n}\n",
  );
  git(repo, "add", "app.js");
  git(
    repo,
    "-c",
    "commit.gpgSign=false",
    "commit",
    "--quiet",
    "-m",
    "Add sample caller",
  );
  const sha = git(repo, "rev-parse", "HEAD");
  const source = {
    id: "input",
    function: "request",
  };
  const sink = {
    id: "decode",
    function: "decode",
    package: "sample-codec",
    versionScheme: "semver",
    affectedVersions: ["<2.0.0"],
    preconditions: [condition],
  };
  const observation = {
    id: "call",
    stackHash: "sample",
    framesTruncated: false,
    sourceIndex: 1,
    sinkIndex: 0,
    sinkIds: [sink.id],
    bindings: [
      {
        package: sink.package,
        version: "1.0.0",
        imageDigest: "sha256:" + "a".repeat(64),
        provenance: "sample process",
        ...(bindSource && { sourceSha: sha }),
      },
      ...(separateImage
        ? [
            {
              package: "sample-app",
              version: "1.0.0",
              provenance: "sample application",
              sourceSha: sha,
              imageDigest:
                "sha256:" + (separateImage === "same" ? "a" : "b").repeat(64),
            },
          ]
        : []),
    ],
    frames: [
      { name: "decode", type: "javascript", offset: "9007199254740993" },
      { name: "request", type: "javascript", location: "app.js", line: 2 },
    ],
  };
  const documents = {
    sources: { format: "codex-security.stack-sources/v1", sources: [source] },
    sinks: {
      format: "codex-security.stack-sinks/v1",
      cve,
      advisory: {
        url: "https://example.invalid/advisories/decoder",
        summary: "Sample decoder accepts an invalid length.",
      },
      sinks: [sink],
    },
    stacks: {
      format: "codex-security.sampled-stacks/v1",
      target: { repository: "example/decoder", sha },
      origin: { source: "test" },
      frameOrder: "leaf_first",
      queries: [
        {
          id: "request",
          scope: {
            service: "decoder",
            window: {
              start: "2026-01-01T00:00:00Z",
              end: "2026-01-02T00:00:00Z",
            },
          },
          selectors: {
            sources: [source.function],
            sinks: [sink.function],
          },
          groups: [
            {
              id: "example",
              status: "observed",
              truncated: false,
              observations: [observation],
            },
          ],
        },
      ],
    },
  };
  for (const [role, doc] of Object.entries(documents))
    await writeFile(join(root, role + ".json"), JSON.stringify(doc));
  return {
    repo,
    sourcesPath: join(root, "sources.json"),
    sinksPath: join(root, "sinks.json"),
    stacksPath: join(root, "stacks.json"),
  };
}

for (const [label, bindSource, separateImage, expectedPositive] of [
  ["source and version in one binding", true, undefined, true],
  ["source not recorded", false, undefined, false],
  ["source and version in the same image", false, "same", true],
  ["source and version in different images", false, "other", false],
] as const) {
  test("stack verdict with " + label, async () => {
    await using dir = await scopedTemporaryDirectory("stack-proof-");
    const files = await sample(dir.path, bindSource, separateImage);
    const inputs = join(dir.path, "packet"),
      state = join(dir.path, "attempt.sqlite");
    await prepareStackPacket({
      cve,
      ...files,
      repository: files.repo,
      inputsDir: inputs,
      toolRevision: "test",
    });
    await executeStackRun("init", { state, repo: files.repo, inputs });
    const call = (command: string, input?: unknown) =>
      executeStackRun(command, { state, input });
    const { workItem, receiptId } = (await call("next")) as {
      workItem: { id: string };
      receiptId: string;
    };
    expect(
      await call("read-stacks", { workItemId: workItem.id }),
    ).toMatchObject({
      rootFirstRawIndices: [1, 0],
      observation: { frames: [{ offset: "9007199254740993" }, {}] },
    });
    const evidence = { path: "app.js", startLine: 1, endLine: 2 };
    const write = {
      operationId: "proof",
      claims: [
        {
          id: "caller",
          scope: "sample caller",
          payload: "The caller supplies bytes to decode.",
          evidence: [evidence],
          receiptSelections: (separateImage ? [0, 1] : [0]).map((index) => ({
            receiptId,
            textBlock: null,
            record: ["observation", "bindings", index],
          })),
        },
      ],
    };
    const { claims } = (await call("record-claims", write)) as {
      claims: DependencyClaimReference[];
    };
    expect(await call("record-claims", write)).toEqual({ claims });
    expect(await call("query-claims", { ids: ["caller"] })).toMatchObject({
      claims: [{ ...claims[0], state: "recorded" }],
    });
    const row = {
      workItemId: workItem.id,
      reason: "The caller supplies the decoder input.",
      verdict: "exploitable",
      supportingClaims: claims,
      attackerControlClaim: claims[0],
      use: {
        location: "decoder",
        component: "sample-codec",
        version: "1.0.0",
        deployment: "confirmed",
        verdict: "exploitable",
        reason: "The captured build accepts the input.",
        evidence: [
          {
            ...evidence,
            supports: ["affected_copy", "affected_use", "running", "access"],
          },
        ],
        proof: {
          sink: { function: "decode", callSite: { path: "app.js", line: 2 } },
          conditions: [
            {
              label: condition,
              status: "met",
              explanation: "The parameter is passed to decode.",
              citations: [{ path: "app.js", line: 2 }],
            },
          ],
        },
      },
    };
    if (!expectedPositive) {
      await expect(
        call("record-assessments", { items: [row] }),
      ).rejects.toThrow(/build-to-source binding/);
      await expect(call("finalize")).rejects.toThrow();
      return;
    }
    await call("record-assessments", { items: [row] });
    const report = await call("finalize");
    expect(report).toMatchObject({
      verdict: "exploitable",
      reviewPolicy: "single_agent",
      coverage: { total: 1, assessed: 1 },
    });
    expect(report).toEqual(await readFinalStackReport(state));
    await expect(
      call("record-evidence", {
        scope: "caller",
        question: "Who supplies bytes?",
        claim: "Caller supplied bytes.",
        evidence: [evidence],
      }),
    ).rejects.toThrow(/finalized/);
    await chmod(join(inputs, "stacks.json"), 0o600);
    await writeFile(
      join(inputs, "stacks.json"),
      (await readFile(join(inputs, "stacks.json"), "utf8")) + "\n",
    );
    await expect(call("next")).rejects.toThrow();
  });
}

test("the gated check gives one investigator a usable child CLI and publishes its verified report", async () => {
  await using dir = await scopedTemporaryDirectory("stack-cli-");
  const files = await sample(dir.path, false);
  const gate = "CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY";
  let calls = 0;
  const d = dependencies({
    currentDirectory: files.repo,
    async onCodex(argv, out, _env, prompt) {
      calls++;
      expect(argv[0]).toBe("exec");
      expect(argv.some((arg) => arg.includes(gate))).toBe(true);
      const { state, command } = JSON.parse(
        prompt!.split("\n").find((line) => line.startsWith('{"command":'))!,
      );
      expect(command.slice(-2)).toEqual(["exploitability", "run"]);
      async function child(verb: string, input?: unknown) {
        const io = createCliTest(main);
        const deps = dependencies({ currentDirectory: files.repo });
        deps.environment[gate] = "1";
        if (input !== undefined)
          deps.recordsInput = Readable.from([JSON.stringify(input)]);
        const code = await io.runCli(
          [
            "exploitability",
            "run",
            verb,
            "--state",
            state,
            ...(input !== undefined ? ["--json-stdin"] : []),
          ],
          deps,
        );
        expect(code, io.stderr.text()).toBe(0);
        return JSON.parse(io.stdout.text());
      }
      const { workItem } = await child("next");
      await child("record-assessments", {
        items: [
          {
            workItemId: workItem.id,
            verdict: "unknown",
            reason: "Source identity is missing.",
            remainingQuestions: ["Which source commit ran?"],
          },
        ],
      });
      await child("finalize");
      out!.stdout.write("Investigation complete.\n");
      return 0;
    },
  });
  d.environment[gate] = "1";
  const io = createCliTest(main);
  const code = await io.runCli(
    [
      "exploitability",
      "check",
      cve,
      "--sources",
      files.sourcesPath,
      "--sinks",
      files.sinksPath,
      "--stacks",
      files.stacksPath,
      "--json",
    ],
    d,
  );
  expect(code, io.stderr.text()).toBe(0);
  expect(calls).toBe(1);
  expect(JSON.parse(io.stdout.text())).toMatchObject({
    verdict: "unknown",
    coverage: { assessed: 1 },
  });
});

test("an explicitly dated observation outside the requested window stays an unresolved scope conflict", async () => {
  await using dir = await scopedTemporaryDirectory("stack-window-");
  const files = await sample(dir.path, true);
  const original = JSON.parse(await readFile(files.stacksPath, "utf8"));
  original.queries[0].groups[0].observations[0].observedAt =
    "2026-01-02T00:00:00.000001Z";
  await writeFile(files.stacksPath, JSON.stringify(original));
  const inputs = join(dir.path, "inputs"),
    state = join(dir.path, "run.sqlite");
  const packet = await prepareStackPacket({
    cve,
    ...files,
    repository: files.repo,
    inputsDir: inputs,
    toolRevision: "test",
  });
  const [work] = stackPacketWorkItems(packet);
  expect(work!.scopeConflicts.join(" ")).toContain("outside the query window");
  await executeStackRun("init", { state, repo: files.repo, inputs });
  await expect(
    executeStackRun("record-assessments", {
      state,
      input: {
        items: [
          {
            workItemId: work!.id,
            verdict: "exploitable",
            reason: "Observed caller.",
          },
        ],
      },
    }),
  ).rejects.toThrow(/Conflicting capture scope/);
  await executeStackRun("record-assessments", {
    state,
    input: {
      items: [
        {
          workItemId: work!.id,
          verdict: "unknown",
          reason: "Observation fell outside the requested time.",
          remainingQuestions: ["Did this caller run in the requested window?"],
        },
      ],
    },
  });
  expect(await executeStackRun("finalize", { state })).toMatchObject({
    verdict: "unknown",
    coverage: { scopeConflicts: [work!.id] },
  });
});

test("claim identity and finalized reports retain every own key in opaque JSON evidence", async () => {
  await using dir = await scopedTemporaryDirectory("stack-json-");
  const files = await sample(dir.path, true);
  const inputs = join(dir.path, "inputs"),
    state = join(dir.path, "attempt.sqlite");
  await prepareStackPacket({
    cve,
    ...files,
    repository: files.repo,
    inputsDir: inputs,
    toolRevision: "test",
  });
  await executeStackRun("init", { state, repo: files.repo, inputs });
  const command = (name: string, input?: unknown) =>
    executeStackRun(name, { state, input });
  const { workItem, receiptId } = (await command("next")) as {
    workItem: { id: string };
    receiptId: string;
  };
  const payload = JSON.parse('{"sample":{"__proto__":{"enabled":true}}}');
  const record = (value: unknown) =>
    command("record-claims", {
      claims: [
        {
          id: "input",
          scope: "sample",
          payload: value,
          receiptIds: [receiptId],
        },
      ],
    });
  const { claims } = (await record(payload)) as {
    claims: DependencyClaimReference[];
  };
  await expect(record({ sample: {} })).rejects.toThrow();
  await command("record-assessments", {
    items: [
      {
        workItemId: workItem.id,
        verdict: "unknown",
        reason: "Missing input provenance.",
        remainingQuestions: ["Who controls the input?"],
        supportingClaims: claims,
      },
    ],
  });
  const result = (await command("finalize")) as {
    claims: { payload: unknown }[];
  };
  expect(JSON.stringify(result.claims[0]!.payload)).toEqual(
    JSON.stringify(payload),
  );
});

test("packet preparation and reopen preserve opaque endpoint and query metadata", async () => {
  await using dir = await scopedTemporaryDirectory("stack-metadata-");
  const files = await sample(dir.path, true);
  const labels = JSON.parse(
    '{"__proto__":{"enabled":true},"options":[null,false,{"weight":2}]}',
  );
  for (const [kind, path] of [
    ["sources", files.sourcesPath],
    ["sinks", files.sinksPath],
  ] as const) {
    const doc = JSON.parse(await readFile(path, "utf8"));
    doc[kind][0] = { ...doc[kind][0], ...labels };
    await writeFile(path, JSON.stringify(doc));
  }
  const capture = JSON.parse(await readFile(files.stacksPath, "utf8"));
  capture.queries[0].selectors = {
    sources: [labels, "example input"],
    sinks: [{ match: labels }, 17],
  };
  await writeFile(files.stacksPath, JSON.stringify(capture));
  const inputs = join(dir.path, "packet"),
    state = join(dir.path, "run.sqlite");
  const packet = await prepareStackPacket({
    cve,
    ...files,
    repository: files.repo,
    inputsDir: inputs,
    toolRevision: "test",
  });
  const ready = await executeStackRun("init", {
    state,
    inputs,
    repo: files.repo,
  });
  expect(ready).toMatchObject({ inputDigest: packet.manifest.inputDigest });
  expect(await readFile(join(inputs, "stacks.json"))).toEqual(
    await readFile(files.stacksPath),
  );
  const next = (await executeStackRun("next", { state })) as {
    workItem: { selectors: unknown };
    sources: unknown[];
    sinks: unknown[];
  };
  expect(JSON.stringify(next.workItem.selectors)).toBe(
    JSON.stringify(capture.queries[0].selectors),
  );
  const source = JSON.parse(await readFile(files.sourcesPath, "utf8")),
    sink = JSON.parse(await readFile(files.sinksPath, "utf8"));
  expect(JSON.stringify(next.sources)).toBe(JSON.stringify(source.sources));
  expect(JSON.stringify(next.sinks)).toBe(JSON.stringify(sink.sinks));
});
