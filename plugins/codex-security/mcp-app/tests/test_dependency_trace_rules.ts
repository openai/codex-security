import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { writeFile, chmod, readFile } from "node:fs/promises";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import { buildServer, applicationRoot } from "./build-server.ts";
import { traceInputSchema } from "../src/dependency-trace/schema.ts";
import { createDependencyTracer } from "../src/dependency-trace/trace.ts";
import { localProvider } from "../src/dependency-trace/provider.ts";
import { EvidenceGraph } from "../src/dependency-trace/graph.ts";
import {
  boundTraceResponse,
  traceResponse,
} from "../src/dependency-trace/response.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";

const basic = (pattern: string, id = "model.arbitrary.operation") => ({
  id,
  languages: ["python"],
  message: "Candidate",
  severity: "INFO",
  pattern,
});
const input = (files: string[], rules?: Record<string, unknown>[]) =>
  traceInputSchema.parse({
    package: "sample",
    symbol: "decode",
    files,
    ...(rules === undefined ? {} : { rules }),
    source_only: true,
    max_hops: 0,
    time_budget_ms: 60000,
  });
async function setup(t: TestContext, files: Record<string, string>) {
  try {
    await promisify(execFile)("opengrep", ["--version"]);
  } catch {
    t.skip("opengrep required");
    return;
  }
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-custom-rules-");
  for (const [name, text] of Object.entries(files))
    await writeFile(join(root, name), text);
  const provider = localProvider(root);
  const tracer = createDependencyTracer(root, provider, 2);
  t.after(() => tracer.close());
  return { root, provider, tracer };
}
const evidence = (
  result: Awaited<
    ReturnType<ReturnType<typeof createDependencyTracer>["trace"]>
  >,
) => result.scopes.flatMap(({ evidence }) => evidence);

test("native custom rule IDs select precise calls and preserve the executed configuration", async (t) => {
  const s = await setup(t, {
    "calls.py":
      "decode(data, mode='safe')\ndecode(data, mode='unsafe')\nunrelated(data)\n",
  });
  if (!s) return;
  const rules = [basic("decode($X, mode='unsafe')")];
  const result = await s.tracer.trace(input(["calls.py"], rules));
  assert.equal(result.complete, true);
  assert.deepEqual(
    evidence(result).map(({ line }) => line),
    [2],
  );
  const step = evidence(result)[0].step;
  assert.match(step.nativeRuleId ?? "", /model\.arbitrary\.operation$/);
  assert.ok(step.ruleExecutionId);
  const raw = traceResponse(result);
  assert.equal(raw.ruleExecutions!.length, 1);
  assert.deepEqual(raw.ruleExecutions![0].config, { rules });
  const projected = boundTraceResponse(raw);
  assert.equal(JSON.stringify(projected).includes('"pattern"'), false);
  assert.equal(
    JSON.stringify(projected).includes(raw.ruleExecutions![0].configSha256),
    true,
  );
});

test("native match spans survive grouped replies and stored same-line graph facts", async (t) => {
  const prefix = "# café\n";
  const calls = [
    'decoder.decode(data, mode="safe")',
    'decoder.decode(data, mode="other")',
  ];
  const source = prefix + calls.join("; ") + "\n";
  const bytes = Buffer.from(source);
  const s = await setup(t, { "calls.py": source });
  if (!s) return;
  const rules = [
    {
      id: "focused-receiver",
      languages: ["python"],
      message: "Receiver-only range",
      severity: "INFO",
      patterns: [
        { pattern: "$RECEIVER.decode(...)" },
        { "focus-metavariable": "$RECEIVER" },
      ],
    },
    basic("$RECEIVER.decode(...)", "whole-call"),
  ];
  const request = input(["calls.py"], rules);
  const result = await s.tracer.trace(request);
  assert.equal(result.complete, true, result.limits.join(", "));
  const matches = evidence(result).map(({ match }) => match!);
  assert.equal(matches.length, 4);
  const expected = calls.flatMap((call) => {
    const offset = bytes.indexOf(call);
    return [
      { rule: "focused-receiver", text: "decoder" },
      { rule: "whole-call", text: call },
    ].map(({ rule, text }) => ({
      rule,
      text,
      start: { line: 2, col: offset - Buffer.byteLength(prefix) + 1, offset },
      end: {
        line: 2,
        col: offset - Buffer.byteLength(prefix) + text.length + 1,
        offset: offset + Buffer.byteLength(text),
      },
    }));
  });
  for (const { rule, text, start, end } of expected) {
    const match = matches.find(
      (item) =>
        item.nativeRuleId?.endsWith(rule) && item.start.offset === start.offset,
    );
    assert.ok(match);
    assert.deepEqual(match.start, start);
    assert.deepEqual(match.end, end);
    assert.equal(
      bytes.subarray(match.start.offset, match.end.offset).toString(),
      text,
    );
    assert.ok(match.ruleExecutionId);
  }
  const repeated = { ...result, scopes: [...result.scopes, ...result.scopes] };
  const reply = boundTraceResponse(traceResponse(repeated));
  assert.equal(reply.trace.length, 1, "semantic call rows remain grouped");
  assert.deepEqual(reply.trace[0].evidence[0].lines, [2]);
  assert.deepEqual(reply.trace[0].evidence[0].matches, matches);
  assert.equal(reply.trace[0].relation, "candidate_call");

  const graph = new EvidenceGraph();
  graph.addTrace(repeated, false);
  const stored = graph.query("calls.py");
  assert.ok("paths" in stored);
  assert.equal(
    stored.paths.length,
    4,
    "distinct native ranges are retained, repeated results are deduplicated",
  );
  assert.deepEqual(
    stored.paths.map(({ match }) => match),
    matches,
  );
  assert.deepEqual(
    evidence(await s.tracer.trace(request)).map(({ match }) => match),
    matches,
    "cached scopes retain the original native ranges",
  );
});

test("native config changes invalidate file and batch caches even with the same rule ID", async (t) => {
  const s = await setup(t, { "calls.py": "decode(first)\nother(second)\n" });
  if (!s) return;
  const rules = [basic("decode(...)", "same-id")];
  let reads = 0;
  const run = s.provider.run.bind(s.provider);
  s.provider.run = (scope, signal) => {
    reads++;
    return run(scope, signal);
  };
  const first = await s.tracer.trace(input(["calls.py"], rules));
  const firstExecution = traceResponse(first).ruleExecutions![0];
  await s.tracer.trace(input(["calls.py"], rules));
  assert.equal(reads, 1);
  rules[0].pattern = "other(...)";
  const changed = await s.tracer.trace(input(["calls.py"], rules));
  assert.equal(reads, 2);
  assert.deepEqual(
    evidence(changed).map(({ line }) => line),
    [2],
  );
  assert.notEqual(
    traceResponse(changed).ruleExecutions![0].configSha256,
    firstExecution.configSha256,
  );
  assert.equal(firstExecution.config.rules[0].pattern, "decode(...)");
  const scope = {
    kind: "file" as const,
    package: "sample",
    symbol: "decode",
    path: "calls.py",
    rules,
  };
  const before = await s.provider.fingerprint!(
    scope,
    new AbortController().signal,
  );
  rules[0].pattern = "decode(...)";
  assert.notEqual(
    await s.provider.fingerprint!(scope, new AbortController().signal),
    before,
  );
});

test("native malformed patterns and unsupported languages remain incomplete", async (t) => {
  const s = await setup(t, { "calls.py": "decode(data)\n" });
  if (!s) return;
  for (const rule of [
    basic("decode("),
    { ...basic("decode(...)"), languages: ["not-a-native-language"] },
    {
      id: "mutually-exclusive",
      languages: ["python"],
      message: "Candidate",
      severity: "INFO",
      "pattern-either": [{ pattern: "decode(...)" }],
      patterns: [{ pattern: "decode(...)" }],
    },
  ]) {
    const result = await s.tracer.trace(input(["calls.py"], [rule]));
    assert.equal(result.complete, false);
    assert.equal(evidence(result).length, 0);
    assert.ok(result.scopes.some(({ reason }) => reason));
    if (rule.id === "mutually-exclusive") {
      const reason = result.scopes.map(({ reason }) => reason).join("\n");
      assert.match(reason, /pattern-either/);
      assert.match(reason, /patterns/);
      assert.match(reason, /mutually exclusive|only one|one of/i);
    }
    assert.equal(traceResponse(result).ruleExecutions!.length, 1);
    assert.ok(
      traceResponse(result).coverage.partial.every(
        (scope) => !("rules" in scope) && "ruleConfigSha256" in scope,
      ),
    );
    assert.equal(
      JSON.stringify(boundTraceResponse(traceResponse(result))).includes(
        '"pattern"',
      ),
      false,
    );
  }
});

test("native supplied rules keep mixed languages separate and support explicit Rust files", async (t) => {
  const s = await setup(t, {
    "calls.py": "decode(data)\n",
    "calls.js": "decode(data);\n",
    "calls.rs": "fn main() { decode(data); }\n",
  });
  if (!s) return;
  const rules = [
    basic("decode(...)"),
    { ...basic("decode(...)", "js-custom"), languages: ["javascript"] },
    { ...basic("decode(...)", "rust-custom"), languages: ["rust"] },
  ];
  const result = await s.tracer.trace(
    input(["calls.py", "calls.js", "calls.rs"], rules),
  );
  assert.equal(result.complete, true);
  assert.deepEqual(
    new Set(evidence(result).map(({ source }) => source)),
    new Set(["calls.py", "calls.js", "calls.rs"]),
  );
  assert.equal(result.scopes.length, 3);
});

test("native explicit unresolved rules retain text leads in the graph without execution edges", async (t) => {
  const s = await setup(t, {
    "embedded.py": "script = \"frame.save(buffer, format='PNG')\"\n",
  });
  if (!s) return;
  const rules = [
    {
      id: "embedded-candidate",
      languages: ["generic"],
      message: "Follow embedded source",
      severity: "INFO",
      "pattern-regex": "frame\\.save\\([^\\n]+",
      metadata: { evidence_kind: "unresolved_lead" },
    },
  ];
  const result = await s.tracer.trace(input(["embedded.py"], rules));
  assert.equal(result.complete, true);
  assert.deepEqual(evidence(result), []);
  const response = traceResponse(result);
  assert.equal(response.textMatches.length, 1);
  assert.match(response.textMatches[0].text, /frame.save/);
  assert.equal(response.textMatches[0].lines[0], 1);
  const graph = new EvidenceGraph();
  graph.addTrace(result, false);
  assert.equal(
    (graph.query() as { code_paths_found: number }).code_paths_found,
    0,
  );
  const detail = graph.query("embedded.py") as {
    evidence: { relation: string; sourceText: string }[];
  };
  assert.ok(
    detail.evidence.some(
      ({ relation, sourceText }) =>
        relation === "unresolved_lead" && sourceText.includes("frame.save"),
    ),
  );
});

test("native taint rules enable intrafile mode without source_symbol", async (t) => {
  const s = await setup(t, { "flow.py": "value = source()\nsink(value)\n" });
  if (!s) return;
  const rule = {
    id: "custom-taint",
    languages: ["python"],
    message: "Candidate flow",
    severity: "INFO",
    mode: "taint",
    "pattern-sources": [{ pattern: "source()" }],
    "pattern-sinks": [{ pattern: "sink(...)" }],
  };
  const result = await s.tracer.trace(input(["flow.py"], [rule]));
  assert.equal(result.complete, true);
  assert.equal(evidence(result).length, 1);
  assert.equal(traceResponse(result).ruleExecutions![0].taintIntrafile, true);
});

test("native focus-metavariable supplies the actual candidate range and caller", async (t) => {
  const s = await setup(t, {
    "wrapper.py": "def wrapper(data):\n    decode(data)\n",
  });
  if (!s) return;
  const rule = {
    id: "focused-custom",
    languages: ["python"],
    message: "Candidate",
    severity: "INFO",
    patterns: [
      { pattern: "$CALL" },
      { "pattern-inside": "def $CALLER(...):\n  ..." },
      {
        "metavariable-pattern": {
          metavariable: "$CALL",
          pattern: "decode(...)",
        },
      },
      { "focus-metavariable": "$CALL" },
    ],
  };
  const rangeRule = {
    ...rule,
    id: "focused-range",
    metadata: { evidence_kind: "unresolved_lead" },
  };
  const result = await s.tracer.trace(input(["wrapper.py"], [rule, rangeRule]));
  assert.equal(
    traceResponse(result).textMatches[0].text,
    "decode(data)",
    "native primary focus covers the complete invocation",
  );
  const call = evidence(result)[0];
  assert.equal(call.line, 2);
  assert.equal(call.step.from.name, "wrapper");
  assert.equal(result.complete, false);
  assert.deepEqual(result.limits, ["hop limit"]);
  const followed = await s.tracer.trace({
    ...input(["wrapper.py"], [rule]),
    max_hops: 1,
  });
  assert.equal(followed.complete, false);
  assert.ok(
    followed.scopes.some(({ reason }) =>
      /model-authored rules/.test(reason ?? ""),
    ),
  );
  assert.ok(
    followed.scopes.some(
      ({ scope, hops }) =>
        scope.kind === "file" &&
        scope.symbol === "wrapper" &&
        scope.rules === undefined &&
        hops === 1,
    ),
  );
});

test("missing model rules never invoke OpenGrep, including version probes", async (t) => {
  if (process.platform === "win32") return t.skip("POSIX executable fixture");
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-mandatory-rules-");
  const tools = await dirs.create("trusted-rule-tool-");
  await writeFile(join(root, "calls.py"), "decode(data)\n");
  await writeFile(
    join(root, "package.json"),
    '{"dependencies":{"sample":"1.0.0"}}',
  );
  const marker = join(tools, "invocations.jsonl");
  const executable = join(tools, "opengrep");
  await writeFile(
    executable,
    `#!${process.execPath}\nrequire('node:fs').appendFileSync(${JSON.stringify(marker)}, JSON.stringify(process.argv)+'\\n');if(process.argv.includes('--version'))process.stdout.write('1.33.1\\n');else if(JSON.parse(require('node:fs').readFileSync('rules.json','utf8')).rules[0].id==='output-limit'){process.stdout.write('x'.repeat(3*1024*1024));}else if(JSON.parse(require('node:fs').readFileSync('rules.json','utf8')).rules[0].id==='partial-analysis'){process.stderr.write('deciding-exit-zero-stderr');process.stdout.write(JSON.stringify({results:[],errors:[{type:'PartialParsing',message:'deciding-exit-zero-context',nested:{detail:'all-error-fields-retained'}}],paths:{scanned:['input-0.py']}}));}else{process.stderr.write('native-syntax-error:'+ 'x'.repeat(2200));process.stdout.write(JSON.stringify({results:[],errors:[{type:'SyntheticSchemaError',message:'deciding-stdout-only-context',nested:{detail:'all-error-fields-retained'}}]}));process.exit(2);}\n`,
  );
  await chmod(executable, 0o700);
  const previous = process.env.PATH;
  process.env.PATH = tools;
  t.after(() => {
    if (previous === undefined) delete process.env.PATH;
    else process.env.PATH = previous;
  });
  const provider = localProvider(root);
  const signal = new AbortController().signal;
  const file = {
    kind: "file" as const,
    package: "sample",
    symbol: "decode",
    path: "calls.py",
  };
  const batch = { ...file, kind: "source_batch" as const, files: ["calls.py"] };
  for (const scope of [
    file,
    batch,
    { ...file, rules: [] },
    { ...batch, rules: [] },
  ]) {
    assert.equal(await provider.fingerprint!(scope, signal), undefined);
    const result = await provider.run(scope, signal);
    assert.equal(result.complete, false);
    assert.match(result.reason ?? "", /model-authored rules/);
  }
  const tracer = createDependencyTracer(root, provider, 2);
  t.after(() => tracer.close());
  const result = await tracer.trace(input(["calls.py"]));
  assert.equal(result.complete, false);
  assert.match(result.scopes[0].reason ?? "", /model-authored rules/);
  const manifest = await provider.run(
    { ...file, symbol: undefined, path: "package.json" },
    signal,
  );
  assert.equal(manifest.complete, true);
  assert.ok(
    manifest.evidence.some(({ step }) => step.relation === "depends_on"),
  );
  await assert.rejects(readFile(marker), { code: "ENOENT" });
  const rejected = await provider.run(
    { ...file, rules: [basic("decode(...)")] },
    signal,
  );
  assert.equal(rejected.complete, false);
  assert.ok(
    rejected.reason!.includes("native-syntax-error:" + "x".repeat(2200)),
    "native syntax diagnostics remain complete",
  );
  assert.match(rejected.reason ?? "", /deciding-stdout-only-context/);
  assert.match(rejected.reason ?? "", /all-error-fields-retained/);
  const partial = await provider.run(
    { ...file, rules: [basic("decode(...)", "partial-analysis")] },
    signal,
  );
  assert.equal(partial.complete, false);
  assert.match(partial.reason ?? "", /deciding-exit-zero-context/);
  assert.match(partial.reason ?? "", /deciding-exit-zero-stderr/);
  assert.match(partial.reason ?? "", /all-error-fields-retained/);

  const overflowing = await provider.run(
    { ...file, rules: [basic("decode(...)", "output-limit")] },
    signal,
  );
  assert.equal(overflowing.complete, false);
  assert.match(overflowing.reason ?? "", /output|byte/i);
  assert.equal(
    overflowing.ruleExecution!.config.rules[0].id,
    "output-limit",
    "a completed native attempt retains configuration even when output is too large",
  );
});

test("distinct supplied IDs at one call retain distinct graph proof references", async (t) => {
  const s = await setup(t, { "calls.py": "decode(data)\n" });
  if (!s) return;
  const result = await s.tracer.trace(
    input(
      ["calls.py"],
      [basic("decode(...)", "first-id"), basic("decode(...)", "second-id")],
    ),
  );
  assert.equal(result.complete, true);
  assert.equal(evidence(result).length, 2);
  assert.equal(
    new Set(evidence(result).map(({ step }) => step.nativeRuleId)).size,
    2,
  );
  const graph = new EvidenceGraph();
  graph.addTrace(result, false);
  assert.equal(
    (graph.query() as { code_paths_found: number }).code_paths_found,
    2,
  );
  assert.equal(traceResponse(result).ruleExecutions!.length, 1);
});

test("normal graph session accepts rules and retains full host proof before projection", async (t) => {
  const s = await setup(t, { "calls.py": "decode(data)\nother(data)\n" });
  if (!s) return;
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const runtime = await dirs.create("trace-custom-session-");
  const bundle = join(runtime, "session.cjs");
  await buildServer(bundle, {
    entryPoints: [join(applicationRoot, "src/dependency-trace/session.ts")],
  });
  const { createDependencyGraphSession } = (
    await import(pathToFileURL(bundle).href)
  ).default;
  const session = await createDependencyGraphSession(s.root, false, {
    fullTraceReply: true,
  });
  t.after(() => session.close());
  const rules = [basic("decode(...)", "session-rule")];
  const raw = await session.call(
    "trace_codex_security_code",
    input(["calls.py"], rules),
  );
  assert.deepEqual(raw.ruleExecutions[0].config, { rules });
  assert.equal(raw.trace.length, 1);
  const bounded = session.boundTraceResponse(raw);
  assert.equal(JSON.stringify(bounded).includes('"pattern"'), false);
  const summary = await session.call("query_codex_security_graph", {});
  assert.equal(summary.code_paths_found, 1);
  assert.equal(summary.ruleExecutions.length, 1);
  assert.deepEqual(summary.ruleExecutions[0].ruleIds, ["session-rule"]);
  assert.equal(summary.ruleExecutions[0].config, undefined);
});
