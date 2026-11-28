import { expect, test } from "bun:test";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Readable } from "node:stream";
import { main } from "../src/cli.js";
import { DependencyAttemptStore } from "../src/exploitability/attempt-store.js";
import {
  executeStackRun,
  readFinalStackReport,
} from "../src/exploitability/analyzers/stacks/run.js";
import type { DependencyClaimReference } from "../src/exploitability/analyzers/stacks/claims.js";
import {
  prepareStackPacket,
  readStackPacket,
} from "../src/exploitability/analyzers/stacks/packet.js";
import { git } from "./git-fixture.js";
import { dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

const cve = "CVE-2099-0001";
const advisory = {
  url: "https://example.invalid/advisory",
  summary: "Decoder input error.",
};
const sink = {
  id: "decode",
  function: "decode",
  package: "example-decoder",
  versionScheme: "semver",
  affectedVersions: ["<2.0.0"],
  preconditions: ["Caller controls the decoder input."],
};
const window = { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" };

async function fixture(root: string) {
  const repo = join(root, "target");
  await mkdir(repo);
  git(repo, "init", "--quiet");
  await writeFile(
    join(repo, "app.js"),
    "export function request(bytes) { return decode(bytes); }\n",
  );
  git(repo, "add", "app.js");
  git(
    repo,
    "-c",
    "commit.gpgSign=false",
    "commit",
    "--quiet",
    "-m",
    "Add example caller",
  );
  const state = join(root, "run.sqlite");
  const run = (command: string, input?: unknown) =>
    executeStackRun(command, { state, input });
  const recordQuery = (result: unknown) =>
    run("record-evidence", {
      kind: "runtime",
      server: "fixture",
      tool: "stack-query",
      result,
    }) as Promise<{ receiptId: string }>;
  function assessUnknown(
    workItemId: string,
    claims: DependencyClaimReference[],
  ) {
    const question = "Who controls the input?";
    return run("record-assessments", {
      items: [
        {
          workItemId,
          verdict: "unknown",
          reason: "The input source is unknown.",
          supportingClaims: claims,
          remainingQuestions: [question],
          questionChecks: [
            {
              question,
              checked: "Read the captured decoder frame.",
              missingEvidence: "The decoder argument and who supplied it.",
              claims,
            },
          ],
        },
      ],
    });
  }
  return {
    repo,
    sha: git(repo, "rev-parse", "HEAD"),
    state,
    run,
    recordQuery,
    assessUnknown,
  };
}

test("the gated CLI accepts an interactive init and runtime evidence without a packet", async () => {
  await using dir = await scopedTemporaryDirectory("incremental-stack-cli-");
  const { repo, state } = await fixture(dir.path);
  async function invoke(args: string[], input?: unknown) {
    const io = createCliTest(main);
    const deps = dependencies({ currentDirectory: repo });
    deps.environment["CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY"] = "1";
    if (input !== undefined)
      deps.recordsInput = Readable.from([JSON.stringify(input)]);
    const code = await io.runCli(["exploitability", "run", ...args], deps);
    expect(code, io.stderr.text()).toBe(0);
    return JSON.parse(io.stdout.text());
  }
  expect(
    await invoke(["init", "--repo", repo, "--state", state]),
  ).toMatchObject({ target: { sha: expect.any(String) } });
  const observed = await invoke(
    ["record-observations", "--state", state, "--json-stdin"],
    capture("debugger"),
  );
  expect(observed.workItemIds).toEqual(["captures/0/stacks/0"]);
  expect(
    await invoke(["init", "--repo", repo, "--state", state, "--json-stdin"], {
      cve,
      advisory,
      sinks: [sink],
    }),
  ).toMatchObject({ cve });
  expect(await invoke(["next", "--state", state])).toMatchObject({
    workItem: {
      id: observed.workItemIds[0],
      sinkMatches: [{ sinkId: sink.id, rawIndex: 0 }],
    },
  });
  const evidence = await invoke(
    ["record-evidence", "--state", state, "--json-stdin"],
    {
      kind: "runtime",
      server: "fixture",
      tool: "inventory",
      result: { version: "1.0.0" },
    },
  );
  expect(evidence.receiptId).toMatch(/^runtime-/);
  const { commands } = await invoke(["tools", "--state", state]);
  const names = commands.map((item: { name: string }) => item.name);
  expect(names).toContain("record-evidence");
  expect(names).toContain("record-observations");
  expect(names).not.toContain("read-stacks");
});

function capture(origin: string) {
  return {
    format: "codex-security.stacks/v2",
    captures: [
      {
        origin,
        query: {
          selectors: { function: "decode" },
          window,
          coverage: "complete",
        },
        stacks: [
          {
            labels: { service: "decoder" },
            frames: [
              {
                name: "decode",
                package: {
                  name: sink.package,
                  version: "1.0.0",
                  provenance: "example runtime",
                },
              },
              { name: "request", location: "app.js", line: 1 },
            ],
          },
        ],
      },
    ],
  };
}

async function packet(root: string, repo: string) {
  const documents = {
    sinks: {
      format: "codex-security.stack-sinks/v2",
      cve,
      advisory,
      sinks: [sink],
    },
    stacks: capture("captured"),
  };
  for (const [role, value] of Object.entries(documents))
    await writeFile(join(root, role + ".json"), JSON.stringify(value));
  const inputs = join(root, "packet");
  await prepareStackPacket({
    cve,
    repository: repo,
    inputsDir: inputs,
    toolRevision: "fixture",
    sinksPath: join(root, "sinks.json"),
    stacksPath: join(root, "stacks.json"),
  });
  return inputs;
}

test("interactive runs import runtime evidence, append work, and resume a finalized report", async () => {
  await using dir = await scopedTemporaryDirectory(
    "incremental-stack-interactive-",
  );
  const { repo, sha, state, run, recordQuery, assessUnknown } = await fixture(
    dir.path,
  );
  const initialized = (await executeStackRun("init", { state, repo })) as {
    inputDigest: string;
  };
  await executeStackRun("init", {
    state,
    repo,
    input: {
      cve,
      advisory,
      sources: [],
      sinks: [sink],
      repository: "example/decoder",
    },
  });
  const firstQuery = capture("first");
  const runtime = await recordQuery(firstQuery);
  const write = {
    operationId: "first-query",
    receiptId: runtime.receiptId,
  };
  const appended = await run("record-observations", write);
  const recorded = (await run("record-claims", {
    claims: [
      {
        id: "runtime-version",
        scope: "decoder",
        payload: "The running version is 1.0.0.",
        receiptSelections: [
          {
            receiptId: runtime.receiptId,
            textBlock: null,
            record: [
              "captures",
              0,
              "stacks",
              0,
              "frames",
              0,
              "package",
              "version",
            ],
          },
        ],
        receiptIds: [runtime.receiptId],
      },
    ],
  })) as { claims: DependencyClaimReference[] };
  expect(await run("record-observations", write)).toEqual(appended);
  await expect(
    run("record-observations", { ...write, receiptId: "changed" }),
  ).rejects.toThrow(/different request/i);
  expect(await run("summarize-coverage")).toMatchObject({
    total: 1,
    assessed: 0,
  });
  const first = (await run("next")) as {
    workItem: { id: string };
    target: { sha: string };
    sinks: unknown[];
  };
  expect(first.target.sha).toBe(sha);
  expect(first.sinks).toContainEqual(sink);
  await assessUnknown(first.workItem.id, recorded.claims);
  const secondRuntime = await recordQuery(capture("second"));
  await run("record-observations", { receiptId: secondRuntime.receiptId });
  expect(await run("summarize-coverage")).toMatchObject({
    total: 2,
    assessed: 1,
  });
  await expect(run("finalize")).rejects.toThrow(/disposition|outstanding/i);
  const second = (await run("next")) as {
    workItem: { id: string };
    receiptId: string;
  };
  const { claims: secondClaims } = (await run("record-claims", {
    claims: [
      {
        id: "second-captured-call",
        scope: "decoder",
        payload: "The second capture lists the call frames.",
        receiptIds: [second.receiptId],
      },
    ],
  })) as typeof recorded;
  await assessUnknown(second.workItem.id, secondClaims);
  const final = (await run("finalize")) as Awaited<
    ReturnType<typeof readFinalStackReport>
  >;
  expect(final).toMatchObject({
    verdict: "unknown",
    coverage: { total: 2, assessed: 2 },
  });
  expect(final.inputDigest).toBe(initialized.inputDigest);
  expect(final.effectiveInputDigest).toMatch(/^[a-f0-9]{64}$/);
  expect(final.effectiveInputDigest).not.toBe(final.inputDigest);
  expect(final.claims[0]!.receipts[0]!.result).toEqual(
    JSON.parse(JSON.stringify(firstQuery)),
  );
  expect(final.claims[0]!.receipts[1]!.result).toBe("1.0.0");
  expect(await readFinalStackReport(state)).toEqual(final);
  expect(await run("finalize")).toEqual(final);
  const expectedInputs = await packet(dir.path, repo);
  await expect(
    readFinalStackReport(state, {
      packet: await readStackPacket(expectedInputs, repo),
      repository: repo,
    }),
  ).rejects.toThrow(/expected input packet/i);
  await expect(
    run("record-observations", {
      operationId: "after-finalization",
      receiptId: secondRuntime.receiptId,
    }),
  ).rejects.toThrow(/finalized/i);
});

test("packet-bound verification rejects added work while direct finalize retains it", async () => {
  await using dir = await scopedTemporaryDirectory("incremental-stack-bound-");
  const { repo, state, run, recordQuery, assessUnknown } = await fixture(
    dir.path,
  );
  const inputs = await packet(dir.path, repo);
  const expected = await readStackPacket(inputs, repo);
  await executeStackRun("init", { state, inputs, repo });
  const imported = await recordQuery(capture("added"));
  await run("record-observations", { receiptId: imported.receiptId });
  for (let index = 0; index < 2; index++) {
    const current = (await run("next")) as {
      workItem: { id: string };
      receiptId: string;
    };
    const { claims } = (await run("record-claims", {
      claims: [
        {
          id: "captured-call-" + index,
          scope: "decoder",
          payload: "The capture lists the decoder call.",
          receiptIds: [current.receiptId],
        },
      ],
    })) as { claims: DependencyClaimReference[] };
    await assessUnknown(current.workItem.id, claims);
  }
  const final = (await run("finalize")) as Awaited<
    ReturnType<typeof readFinalStackReport>
  >;
  expect(await readFinalStackReport(state)).toEqual(final);
  await expect(
    readFinalStackReport(state, { packet: expected, repository: repo }),
  ).rejects.toThrow(/outside the expected input packet/i);
});

test.each(["direct", "imported"])("%s capture provenance", async (kind) => {
  await using dir = await scopedTemporaryDirectory(
    "incremental-stack-capture-",
  );
  const { repo, state, run, recordQuery, assessUnknown } = await fixture(
    dir.path,
  );
  await executeStackRun("init", {
    state,
    repo,
    input: { cve, advisory, sinks: [sink] },
  });
  const original = capture("supplemental");
  const runtime = kind === "imported" ? await recordQuery(original) : null;
  await run(
    "record-observations",
    runtime ? { receiptId: runtime.receiptId } : original,
  );
  const current = (await run("next")) as {
    workItem: { id: string };
    receiptId: string;
  };
  const recorded = (await run("record-claims", {
    claims: [
      {
        id: "captured-frame",
        scope: "decoder",
        payload: "The captured stack contains decode.",
        receiptSelections: [
          {
            receiptId: current.receiptId,
            textBlock: null,
            record: ["stack", "frames", 0],
          },
        ],
      },
    ],
  })) as { claims: DependencyClaimReference[] };
  await assessUnknown(current.workItem.id, recorded.claims);
  const final = (await run("finalize")) as Awaited<
    ReturnType<typeof readFinalStackReport>
  >;
  const receipts = final.claims[0]!.receipts;
  expect(receipts[0]).toMatchObject({
    receiptId: current.receiptId,
    origin: { arguments: { sourceReceiptId: runtime?.receiptId ?? null } },
    result: { name: "decode" },
  });
  if (runtime) {
    expect(
      receipts.find(({ receiptId }) => receiptId === runtime.receiptId)!.result,
    ).toEqual(JSON.parse(JSON.stringify(original)));
  } else {
    expect(receipts).toHaveLength(1);
  }
  expect(await readFinalStackReport(state)).toEqual(final);
  if (runtime) {
    const store = new DependencyAttemptStore(state, { create: false });
    try {
      store.delete("runtime-receipt", runtime.receiptId);
    } finally {
      store.close();
    }
    await expect(readFinalStackReport(state)).rejects.toThrow(
      /unknown runtime receipt/i,
    );
  }
});

test("a receipt cannot be reused to introduce fabricated frames", async () => {
  await using dir = await scopedTemporaryDirectory(
    "incremental-stack-integrity-",
  );
  const { repo, state, run, recordQuery } = await fixture(dir.path);
  await executeStackRun("init", {
    state,
    repo,
    input: { cve, advisory, sinks: [sink] },
  });
  const original = capture("original");
  const runtime = await recordQuery(original);
  await expect(
    run("record-observations", { receiptId: "missing" }),
  ).rejects.toThrow(/receipt/i);
  const altered = structuredClone(original);
  altered.captures[0]!.stacks[0]!.frames[0]!.name = "fabricated";
  await expect(
    run("record-observations", { receiptId: runtime.receiptId, ...altered }),
  ).rejects.toThrow();
  expect(await run("next")).toMatchObject({ workItem: null });
});
