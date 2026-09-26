import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Codex } from "@openai/codex-sdk";
import { build } from "esbuild";
import { runControlledCodeMode } from "./controlled-code-mode.mjs";
import {
  createReducerPagingFixture,
  gradeReducerPagingResult,
} from "./deep-reducer-paging-fixture.mjs";

const evalDirectory = path.dirname(fileURLToPath(import.meta.url));

/** Run one reducer through real code-mode IPC and the production artifact tools. */
export async function runReducerPagingEval({
  root,
  mode = "deterministic",
  model,
}) {
  assert.ok(mode === "deterministic" || mode === "model");
  const fixture = await createReducerPagingFixture(root);
  const tracePath = path.join(root, "tool-trace.jsonl");
  const serverConfigPath = path.join(root, "server-config.json");
  const serverPath = path.join(root, "artifact-server.cjs");
  const promptModulePath = path.join(root, "prompt.mjs");
  await writeFile(tracePath, "");
  await writeFile(
    serverConfigPath,
    JSON.stringify({ context: fixture.context, tracePath }),
  );
  await Promise.all([
    build({
      entryPoints: [path.join(evalDirectory, "deep-reducer-paging-server.mjs")],
      outfile: serverPath,
      bundle: true,
      platform: "node",
      format: "cjs",
      loader: { ".md": "text" },
    }),
    build({
      entryPoints: [path.join(evalDirectory, "../src/deep-scan/templates.ts")],
      outfile: promptModulePath,
      bundle: true,
      platform: "node",
      format: "esm",
      loader: { ".md": "text" },
    }),
  ]);
  const { renderDedupPrompt } = await import(
    pathToFileURL(promptModulePath).href
  );
  const prompt = renderDedupPrompt({
    reducerLabel: "paging-eval",
    discoveries: fixture.context.deepReducer.claimedWorkers,
  });
  const mcpServers = {
    cs_artifacts: {
      command: process.execPath,
      args: [serverPath, serverConfigPath],
      required: true,
    },
  };
  let transport;
  let usage;
  if (mode === "deterministic") {
    transport = await runControlledCodeMode({
      code: controlledReducerCode,
      mcpServers,
      workingDirectory: fixture.context.repoRoot,
      prompt,
    });
    assert.equal(transport.outcome.code, 0, transport.stderr);
    assert.deepEqual(transport.serverErrors, []);
    const output = JSON.stringify(transport.toolOutputs);
    assert.match(
      output,
      /code-mode delegate response exceeds the IPC frame limit: code-mode IPC frame length [0-9]+ exceeds 67108864 bytes/,
      "the real transport must reject the legacy payload",
    );
    assert.match(output, /reductionRecorded/);
  } else {
    const codex = new Codex({
      config: {
        mcp_servers: mcpServers,
        features: {
          code_mode: { enabled: true },
          code_mode_host: { enabled: true, disable_in_process_fallback: true },
        },
      },
    });
    const thread = codex.startThread({
      ...(model ? { model } : {}),
      workingDirectory: fixture.context.repoRoot,
      skipGitRepoCheck: true,
      approvalPolicy: "never",
      sandboxMode: "read-only",
    });
    const result = await thread.run(prompt);
    usage = result.usage;
    await writeFile(
      path.join(root, "model-response.txt"),
      result.finalResponse,
    );
  }
  const trace = (await readFile(tracePath, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  const report = {
    mode,
    ...(model ? { model } : {}),
    ...fixture.measurements,
    ...gradeReducerPagingTrace(trace, fixture.measurements.ipcFrameLimitBytes),
    ...(transport ? { realIpcErrorObserved: true } : {}),
    ...(await gradeReducerPagingResult(fixture)),
    ...(usage ? { usage } : {}),
  };
  await writeFile(
    path.join(root, "report.json"),
    JSON.stringify(report, null, 2),
  );
  return report;
}

/** Grade the captured I/O independently of model wording or another model run. */
export function gradeReducerPagingTrace(trace, ipcFrameLimitBytes) {
  const reads = trace.filter(
    (event) =>
      event.event === "request" &&
      event.tool === "get_codex_security_deep_reducer_inputs",
  );
  const readsById = new Map(reads.map((event) => [event.id, event]));
  const injected = trace.filter((event) => event.injected);
  assert.equal(injected.length, 1);
  assert.ok(injected[0].bytes > ipcFrameLimitBytes);
  const failed = reads.find((event) => event.id === injected[0].id);
  const retried = reads.find((event) => event.id > failed.id);
  assert.ok(retried, "the reducer must recover from the oversized response");
  assert.ok(
    retried.input.maxBytes < failed.input.maxBytes,
    "recovery must change the failed request's byte budget",
  );
  assert.equal(retried.input.cursor ?? "0", failed.input.cursor ?? "0");
  assert.equal(retried.input.findingRef, failed.input.findingRef);
  const pages = trace.filter(
    (event) =>
      event.event === "response" && !event.injected && readsById.has(event.id),
  );
  for (const page of pages) {
    const request = readsById.get(page.id);
    assert.ok(page.bytes <= request.input.maxBytes);
  }
  assert.ok(pages.some((page) => page.nextCursor !== undefined));
  const submissions = trace.filter(
    (event) =>
      event.event === "request" &&
      event.tool === "record_codex_security_deep_reduction",
  );
  const submissionIds = new Set(submissions.map((event) => event.id));
  const recorded = trace.filter(
    (event) => event.event === "response" && submissionIds.has(event.id),
  );
  assert.equal(
    recorded.length,
    1,
    "the reducer must successfully record its result exactly once",
  );
  const beforeRecording = trace.slice(
    0,
    trace.findIndex(
      (event) => event.event === "request" && event.id === recorded[0].id,
    ),
  );
  const pageEdges = new Map();
  for (const page of beforeRecording) {
    const request = readsById.get(page.id);
    if (
      page.event !== "response" ||
      page.injected ||
      !request ||
      request.input.findingRef !== undefined
    )
      continue;
    const cursor = request.input.cursor ?? "0";
    const edges = pageEdges.get(cursor) ?? new Set();
    edges.add(page.nextCursor);
    pageEdges.set(cursor, edges);
  }
  const reached = new Set(["0"]);
  let inputsComplete = false;
  for (const cursor of reached) {
    for (const next of pageEdges.get(cursor) ?? []) {
      if (next === undefined) inputsComplete = true;
      else reached.add(next);
    }
  }
  assert.equal(
    inputsComplete,
    true,
    "read every assigned-input page before recording",
  );
  return {
    actualOversizedResponseBytes: injected[0].bytes,
    firstBudget: failed.input.maxBytes,
    recoveryBudget: retried.input.maxBytes,
    successfulPages: pages.length,
    assignedInputsFullyRead: inputsComplete,
    referenceReads: reads.filter((event) => event.input.findingRef).length,
  };
}

// The controlled provider drives the real tools. It does not simulate their
// results, the frame limit, or recording. The model mode uses only the shipped
// reducer prompt and must discover and carry out recovery itself.
const controlledReducerCode = `// @exec: {"yield_time_ms": 60000}
let maxBytes = 1024 * 1024;
async function readDocument(findingRef) {
  let cursor;
  const fragments = [];
  do {
    const input = {maxBytes, ...(cursor === undefined ? {} : {cursor}),
      ...(findingRef === undefined ? {} : {findingRef})};
    let response;
    try {
      response = await tools.mcp__cs_artifacts__get_codex_security_deep_reducer_inputs(input);
    } catch (error) {
      text(String(error));
      maxBytes = Math.floor(maxBytes / 2);
      response = await tools.mcp__cs_artifacts__get_codex_security_deep_reducer_inputs({...input, maxBytes});
    }
    if (response.isError) throw new Error(response.content[0].text);
    const page = JSON.parse(response.content[0].text);
    fragments.push(page.json);
    cursor = page.nextCursor;
  } while (cursor !== undefined);
  return JSON.parse(fragments.join(''));
}
const inputs = await readDocument();
const original = await readDocument('source:' + inputs.previous.findings[0].provenance.sourceFindingIds[0]);
const prior = await readDocument('previous:0');
if (original.identity.anchor !== prior.identity.anchor) throw new Error('Wrong reference resolved');
const findings = [...inputs.discoveries.flatMap(entry => entry.result.findings), ...inputs.previous.findings];
for (const finding of findings) {
  // The large summary explicitly marks repeated transport padding, not evidence.
  if (finding.summary.startsWith('BEGIN ISSUE:')) {
    finding.summary = finding.summary.split('\\n', 1)[0] + '\\n' + finding.summary.slice(finding.summary.lastIndexOf('END ISSUE:'));
  }
}
const result = await tools.mcp__cs_artifacts__record_codex_security_deep_reduction({
  scanId: inputs.previous.scanId, findings
});
if (result.isError) throw new Error(result.content[0].text);
text({reductionRecorded: true});
`;

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const reports = path.join(evalDirectory, "../reports");
  await mkdir(reports, { recursive: true });
  const root = await mkdtemp(path.join(reports, "deep-reducer-paging-"));
  console.log(`Eval artifacts: ${root}`);
  const report = await runReducerPagingEval({
    root,
    mode: process.argv[2] ?? "deterministic",
    model: process.argv[3],
  });
  console.log(JSON.stringify(report, null, 2));
}
