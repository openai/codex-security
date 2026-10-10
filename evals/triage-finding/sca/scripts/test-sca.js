"use strict";

const { test, mock } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");
const { createRequire } = require("node:module");
const { pathToFileURL } = require("node:url");
const { execFileSync } = require("node:child_process");
const {
  CORPUS,
  EXPECTED,
  FIXTURE_ROOT,
  parseOutcome,
  normalizePromptfooResult,
  summarize,
  summarizeExport,
  matchRetention,
} = require("./sca-result.js");
const { generateTests } = require("./generate-tests.js");
const {
  stageRuntime,
  stageProviderConfig,
  main,
} = require("./run-promptfoo.js");
const runtimeVars = require("../../scripts/runtime-vars.mts").default;
const assertion = require("../assertions/sca-evidence.js");
const { afterEach } = require("../assertions/sca-metrics.js");
const { buildBaselines } = require("./baselines.js");

function resultFor(testCase, verdict = EXPECTED[testCase.gold_label]) {
  const component = testCase.input.component;
  return {
    schema_version: "triage-finding/v0",
    repository: { path: `/synthetic/${testCase.case_id}`, revision: null },
    findings: [
      {
        triage_item_id: `triage-${testCase.case_id}`,
        input_id: testCase.input.input_id,
        source_type: "advisory",
        title: "Synthetic application assessment",
        normalized_input: {
          vulnerable_component: `${component.name} ${component.version}`,
          claimed_source:
            "Request fields from the synthetic application contract",
          claimed_sink: "Fictional dependency API",
          claimed_control: "The literal option or missing deployment setting",
          affected_version_or_path: `${component.version} in ${component.source}`,
          preconditions: testCase.input.preconditions,
          impact: "Fictional advisory impact",
          references: testCase.input.advisory_ids,
        },
        verdict,
        confidence: verdict === "needs_review" ? "low" : "high",
        affected_locations: [
          {
            label: "Application option",
            path: "src/application.mjs",
            lines: "4",
            detail: "The source option controls advisory applicability.",
          },
        ],
        reachable_path: ["User-controlled request enters handle"],
        boundary_assessment: {
          product_surface: "Fictional fixture endpoint",
          source_trust: "untrusted",
          boundary_crossed:
            verdict === "needs_review" ? null : verdict === "confirmed",
          policy_basis: "APPLICATION.md",
        },
        exploitability_stack_rank: {
          rank_queue: verdict === "not_actionable" ? null : verdict,
          rank: verdict === "not_actionable" ? null : 1,
          rationale: "Synthetic case only",
          drivers: [],
        },
        evidence: testCase.required_evidence.map(
          (entry) =>
            `${entry.path}:${entry.line} selects \`${entry.fragment}\`.`,
        ),
        counterevidence: [],
        proof_gaps:
          verdict === "needs_review" ? ["Deployed setting is missing."] : [],
        recommended_next_step: "Review the static dependency assessment.",
        fix_finding_handoff:
          verdict === "confirmed"
            ? "Review a dependency update and ordinary project checks."
            : null,
      },
    ],
  };
}

function rowFor(testCase, verdict) {
  return {
    vars: { case_id: testCase.case_id },
    response: { output: JSON.stringify(resultFor(testCase, verdict)) },
  };
}

test("corpus contains four fictional families and all three labels without claiming human outcomes", () => {
  assert.equal(CORPUS.kind, "synthetic_smoke");
  assert.equal(CORPUS.human_adjudicated_cases, 0);
  assert.equal(CORPUS.cases.length, 12);
  assert.equal(new Set(CORPUS.cases.map((item) => item.case_id)).size, 12);
  assert.equal(
    new Set(CORPUS.cases.map((item) => item.advisory_family)).size,
    4,
  );
  for (const label of ["affected", "not_affected", "unresolved"])
    assert.equal(
      CORPUS.cases.filter((item) => item.gold_label === label).length,
      4,
    );
});

test("scanner and inspectable-usage baselines preserve all matches without inventing applicability labels", () => {
  const baselines = buildBaselines();
  assert.equal(baselines.cases.length, 12);
  for (const entry of baselines.cases) {
    assert.equal(entry.scanner_only.application_assessment, null);
    assert.equal(
      entry.scanner_with_usage_evidence.application_assessment,
      null,
    );
    assert.deepEqual(
      entry.scanner_only.advisory_ids,
      entry.scanner_with_usage_evidence.advisory_ids,
    );
    assert.equal(entry.scanner_with_usage_evidence.source_evidence[0].line, 1);
    assert.equal(JSON.stringify(entry).includes("gold_label"), false);
  }
});

for (const fixture of CORPUS.cases) {
  test(`${fixture.case_id}: frozen source/advisory digests and schema-valid expected assessment`, () => {
    for (const [relative, expected] of Object.entries(fixture.sha256)) {
      const bytes = fs.readFileSync(
        path.join(FIXTURE_ROOT, fixture.case_id, relative),
      );
      assert.equal(
        crypto.createHash("sha256").update(bytes).digest("hex"),
        expected,
        relative,
      );
    }
    const output = resultFor(fixture);
    assert.deepEqual(parseOutcome(output, fixture).evidenceFailures, []);
    assert.equal(
      assertion(output, { vars: { case_id: fixture.case_id } }).pass,
      true,
    );
    const captured = JSON.parse(
      fs.readFileSync(
        path.join(FIXTURE_ROOT, fixture.case_id, "osv.json"),
        "utf8",
      ),
    );
    assert.equal(
      captured.results[0].packages[0].package.name,
      fixture.input.component.name,
    );
    assert.equal(
      captured.results[0].packages[0].package.version,
      fixture.input.component.version,
    );
    assert.deepEqual(
      captured.results[0].packages[0].vulnerabilities[0],
      fixture.input.advisories[0],
    );
  });
}

test("wrong source, package, resolved version and advisory cannot pass evidence checks", () => {
  const fixture = CORPUS.cases[0];
  const result = resultFor(fixture);
  result.findings[0].normalized_input = {
    ...result.findings[0].normalized_input,
    vulnerable_component: `${fixture.input.component.name}-extra 11.4.0`,
    affected_version_or_path: "11.4.0 in nested/package-lock.json",
    references: ["SCA-FIXTURE-001-extra"],
  };
  assert.equal(parseOutcome(result, fixture).evidenceFailures.length, 4);
});

test("a citation must quote the correct source span, not merely mention a filename", () => {
  const fixture = CORPUS.cases[0];
  for (const text of [
    "src/application.mjs says maxDepth: null",
    "src/application.mjs:1 selects `maxDepth: null`",
    "src/application.mjs:4 selects `maxDepth: true`",
    "src/application.mjs:1-900 selects `maxDepth: null`",
    "other/application.mjs:4 selects `maxDepth: null`",
  ]) {
    const result = resultFor(fixture);
    result.findings[0].evidence = [text];
    assert.match(
      parseOutcome(result, fixture).evidenceFailures.join(" "),
      /supported citation/,
    );
  }
});

test("needs_review must identify a proof gap", () => {
  const fixture = CORPUS.cases[2];
  const result = resultFor(fixture);
  result.findings[0].proof_gaps = [];
  assert.match(
    parseOutcome(result, fixture).evidenceFailures.join(" "),
    /proof gap/,
  );
});

test("missing, duplicate, or changed match IDs and malformed schema become invalid output", () => {
  const fixture = CORPUS.cases[0];
  for (const mutate of [
    (result) => {
      result.findings = [];
    },
    (result) => {
      result.findings.push(result.findings[0]);
    },
    (result) => {
      result.findings[0].input_id = "wrong-match";
    },
    (result) => {
      result.findings[0].source_type = "freeform";
    },
    (result) => {
      delete result.findings[0].evidence;
    },
    (result) => {
      result.findings[0].unexpected = true;
    },
  ]) {
    const result = resultFor(fixture);
    mutate(result);
    const outcome = normalizePromptfooResult({
      vars: { case_id: fixture.case_id },
      response: { output: result },
    });
    assert.equal(outcome.status, "invalid_output");
    assert.equal(outcome.verdict, null);
  }
});

test("provider errors remain model errors rather than unresolved or negative labels", () => {
  const outcome = normalizePromptfooResult({
    vars: { case_id: CORPUS.cases[0].case_id },
    response: { error: "Synthetic provider failure" },
  });
  assert.equal(outcome.status, "model_error");
  assert.equal(outcome.verdict, null);
  assert.equal(outcome.error, "Synthetic provider failure");
  assert.equal(summarize([outcome]).affectedConfirmationRecall, 0);
});

test("three-class confusion, recall, dismissals, coverage and uncertainty use all attempted cases", () => {
  const row = (caseIndex, verdict) =>
    normalizePromptfooResult(rowFor(CORPUS.cases[caseIndex], verdict));
  const outcomes = [
    row(0, "confirmed"),
    row(0, "needs_review"),
    { ...row(0), status: "invalid_output", verdict: null },
    row(0, "not_actionable"),
    row(1, "not_actionable"),
    row(2, "confirmed"),
    row(2, "needs_review"),
    { ...row(1), status: "model_error", verdict: null },
  ];
  const report = summarize(outcomes);
  assert.equal(report.attempted, 8);
  assert.equal(report.uniqueCases, 3);
  assert.equal(report.confirmationPrecision, 0.5);
  assert.equal(report.affectedConfirmationRecall, 0.25);
  assert.equal(report.incorrectDismissalRate, 0.25);
  assert.equal(report.dismissalPrecision, 0.5);
  assert.equal(report.uncertaintyHandling, 0.5);
  assert.equal(report.decisionCoverage, 0.5);
  assert.equal(report.decisionAccuracy, 0.5);
  assert.equal(report.unjustifiedDecisionsOnUnresolved, 1);
  assert.equal(report.confusionMatrix.affected.invalid_output, 1);
  assert.equal(report.confusionMatrix.not_affected.model_error, 1);
});

test("undefined metrics and unreviewed evidence are null, not invented perfect scores", () => {
  const report = summarize([]);
  assert.equal(report.confirmationPrecision, null);
  assert.equal(report.decisionCoverage, null);
  assert.equal(report.reviewerSupportedEvidenceRate, null);
  const one = summarize([normalizePromptfooResult(rowFor(CORPUS.cases[0]))]);
  assert.equal(one.mechanicalCitationPassRate, 1);
  assert.equal(one.reviewerSupportedEvidenceRate, null);
  assert.equal(one.costCoverage, 0);
});

test("cost and latency report actual available measurements", () => {
  const rows = [10, 30, 50, null].map((latency, index) =>
    normalizePromptfooResult({
      ...rowFor(CORPUS.cases[0]),
      latencyMs: latency,
      cost: index < 2 ? 0.1 : null,
    }),
  );
  const report = summarize(rows);
  assert.equal(report.medianLatencyMs, 30);
  assert.equal(report.reportedCostUsd, 0.2);
  assert.equal(report.costCoverage, 0.5);
});

test("scanner retention tracks source, resolved version and every original alias independently of assessments", () => {
  const first = CORPUS.cases[0].input;
  const second = {
    ...first,
    component: { ...first.component, source: "nested/package-lock.json" },
  };
  const third = {
    ...first,
    component: { ...first.component, version: "1.3.0" },
  };
  assert.equal(
    matchRetention([first, second, third], [first, second, third]).rate,
    1,
  );
  assert.equal(matchRetention([first, second, third], [first]).rate, 1 / 3);
  assert.equal(
    matchRetention(
      [first],
      [{ ...first, advisory_ids: [first.advisory_ids[0]] }],
    ).rate,
    0.5,
  );
  assert.equal(matchRetention([], []).rate, null);
  assert.equal(
    matchRetention(
      [second],
      [
        {
          ...second,
          component: {
            ...second.component,
            source: "nested\\package-lock.json",
          },
        },
      ],
    ).rate,
    process.platform === "win32" ? 1 : 0,
  );
});

test("exports retain separate arms and errors; unrecognized cases do not silently disappear", () => {
  const rows = ["baseline", "wrapper"].map((label) => ({
    ...rowFor(CORPUS.cases[0]),
    prompt: { label },
    provider: { id: "synthetic-provider" },
  }));
  const report = summarizeExport({ results: { results: rows } });
  assert.equal(Object.keys(report.arms).length, 2);
  assert.equal(report.human_adjudicated_cases, 0);
  assert.throws(
    () => summarizeExport({ results: [{ vars: { case_id: "unknown" } }] }),
    /Unknown SCA case/,
  );
});

test("Promptfoo metrics include execution failures even when normal assertions do not run", () => {
  const updated = afterEach({
    test: { vars: { case_id: CORPUS.cases[0].case_id } },
    result: { response: { error: "Synthetic failure" } },
  });
  assert.equal(updated.result.namedScores.attempted, 1);
  assert.equal(updated.result.namedScores.execution_errors, 1);
  assert.equal(updated.result.namedScores.affected_cases, 1);
  assert.equal(updated.result.namedScores.correctly_confirmed, 0);
});

test("model staging uses the checkout skill and label-free cases without the gold corpus or scoring scripts", () => {
  const runtime = stageRuntime();
  const previous = process.env.SCA_EVAL_RUNTIME_ROOT;
  try {
    process.env.SCA_EVAL_RUNTIME_ROOT = runtime;
    const tests = generateTests();
    assert.equal(tests.length, 12);
    assert.equal(
      fs.existsSync(
        path.join(
          runtimeVars({}).triage_runtime_root,
          "skills/triage-finding/SKILL.md",
        ),
      ),
      true,
    );
    assert.equal(
      fs.existsSync(
        path.join(
          runtimeVars({}).triage_runtime_root,
          "scripts/launch_codex_security_mcp",
        ),
      ),
      true,
    );
    assert.equal(fs.existsSync(path.join(runtime, "plugins")), false);
    assert.equal(fs.existsSync(path.join(runtime, "evals")), false);
    assert.equal(fs.existsSync(path.join(runtime, "cases/corpus.json")), false);
    for (const item of tests) {
      assert.deepEqual(Object.keys(item.vars).sort(), [
        "case_id",
        "input_id",
        "target_repo",
      ]);
      const resolved = runtimeVars(item.vars);
      assert.equal(resolved.target_repo, item.vars.target_repo);
      assert.equal(
        resolved.triage_node_path,
        fs.realpathSync(process.execPath),
      );
      const staged = fs.readdirSync(item.vars.target_repo);
      assert.equal(staged.includes("corpus.json"), false);
      assert.equal(staged.includes("input.json"), true);
    }
  } finally {
    if (previous === undefined) delete process.env.SCA_EVAL_RUNTIME_ROOT;
    else process.env.SCA_EVAL_RUNTIME_ROOT = previous;
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("disables literal inherited integration names while retaining the persistent Codex home", async () => {
  const previousNodeOptions = process.env.NODE_OPTIONS;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "sca-provider-"));
  const runtime = path.join(root, "runtime");
  const codexHome = path.join(root, "saved-login");
  fs.mkdirSync(runtime);
  fs.mkdirSync(codexHome);
  const serverNames = ["synthetic-files", "synthetic.http"];
  const savedConfig = [
    'web_search = "live"',
    ...serverNames.map(
      (name) =>
        `[mcp_servers.${JSON.stringify(name)}]\ncommand = "synthetic-unused"`,
    ),
  ].join("\n");
  fs.writeFileSync(path.join(codexHome, "config.toml"), savedConfig);
  const receipt = path.join(codexHome, "invocation.json");
  const childReceipt = path.join(runtime, "child.json");
  const codexScript = path.join(root, "codex.cjs");
  fs.writeFileSync(
    codexScript,
    `const fs = require("node:fs");
     if (process.argv.includes("exec")) {
       fs.writeFileSync(${JSON.stringify(childReceipt)}, JSON.stringify({
         args: process.argv.slice(2), nodeOptions: process.env.NODE_OPTIONS,
         codexHome: process.env.CODEX_HOME, mcpNodePath: process.env.CODEX_MCP_NODE_PATH,
       }));
       for (const event of [
         { type: "thread.started", thread_id: "synthetic-thread" },
         { type: "item.completed", item: { id: "message", type: "agent_message", text: "synthetic response" } },
         { type: "turn.completed", usage: { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1 } }
       ]) console.log(JSON.stringify(event));
       process.exit(0);
     }
     fs.writeFileSync(${JSON.stringify(receipt)}, JSON.stringify({
       args: process.argv.slice(2), codexHome: process.env.CODEX_HOME,
     }));
     console.log(JSON.stringify(${JSON.stringify(serverNames.map((name) => ({ name })))}));`,
  );
  try {
    process.env.NODE_OPTIONS = "--no-warnings";
    const providerPath = stageProviderConfig(runtime, codexHome, codexScript);
    const provider = JSON.parse(fs.readFileSync(providerPath, "utf8"));
    assert.equal(provider.config.cli_config.mcp_servers, undefined);
    assert.deepEqual(JSON.parse(fs.readFileSync(receipt, "utf8")), {
      args: [
        "-C",
        runtimeVars({}).triage_runtime_root,
        "-c",
        "features.plugins=false",
        "-c",
        "features.apps=false",
        "mcp",
        "list",
        "--json",
      ],
      codexHome,
    });
    assert.equal(
      provider.config.cli_env.CODEX_HOME,
      "{{env.SCA_EVAL_CODEX_HOME}}",
    );
    assert.equal(
      provider.config.codex_path_override,
      runtimeVars({}).triage_node_path,
    );
    assert.equal(
      provider.config.cli_env.CODEX_MCP_NODE_PATH,
      runtimeVars({}).triage_node_path,
    );
    assert.equal(provider.config.working_dir, "{{triage_runtime_root}}");
    assert.deepEqual(provider.config.additional_directories, [
      "{{env.SCA_EVAL_RUNTIME_ROOT}}",
      "{{env.SCA_EVAL_CODEX_RUNTIME_ROOT}}",
      "{{triage_node_root}}",
    ]);
    assert.equal(provider.config.cli_config.features.apps, false);
    assert.equal(provider.config.cli_config.web_search, "disabled");
    assert.equal(
      fs.readFileSync(path.join(codexHome, "config.toml"), "utf8"),
      savedConfig,
    );
    assert.deepEqual(fs.readdirSync(codexHome), [
      "config.toml",
      "invocation.json",
    ]);

    const sdkRequire = createRequire(
      path.resolve(__dirname, "../../../../sdk/typescript/package.json"),
    );
    const { Codex } = await import(
      pathToFileURL(
        path.resolve(
          __dirname,
          "../../../../sdk/typescript/node_modules/@openai/codex-sdk/dist/index.js",
        ),
      ).href
    );
    const turn = await new Codex({
      codexPathOverride: provider.config.codex_path_override,
      config: provider.config.cli_config,
      env: {
        ...process.env,
        CODEX_HOME: codexHome,
        CODEX_MCP_NODE_PATH: provider.config.cli_env.CODEX_MCP_NODE_PATH,
        NODE_OPTIONS: provider.config.cli_env.NODE_OPTIONS,
      },
    })
      .startThread({
        workingDirectory: runtimeVars({}).triage_runtime_root,
        skipGitRepoCheck: true,
      })
      .run("synthetic configuration probe");
    assert.equal(turn.finalResponse, "synthetic response");
    const child = JSON.parse(fs.readFileSync(childReceipt, "utf8"));
    assert.equal(child.nodeOptions, "--no-warnings");
    assert.equal(child.codexHome, codexHome);
    assert.equal(child.mcpNodePath, runtimeVars({}).triage_node_path);
    const argv = child.args;
    assert.equal(argv[2], "exec");
    const configArgs = argv.flatMap((arg, index) =>
      arg === "--config" ? [arg, argv[index + 1]] : [],
    );
    const effective = JSON.parse(
      execFileSync(
        process.execPath,
        [
          sdkRequire.resolve("@openai/codex/bin/codex.js"),
          "-C",
          runtime,
          ...configArgs,
          "mcp",
          "list",
          "--json",
        ],
        { env: { ...process.env, CODEX_HOME: codexHome }, encoding: "utf8" },
      ),
    );
    assert.deepEqual(
      effective.map(({ name, enabled }) => ({ name, enabled })),
      serverNames.map((name) => ({ name, enabled: false })),
    );
    const nativeRuntime = path.join(root, "native-runtime");
    fs.mkdirSync(nativeRuntime);
    const nativeProvider = JSON.parse(
      fs.readFileSync(
        stageProviderConfig(
          nativeRuntime,
          codexHome,
          sdkRequire.resolve("@openai/codex/bin/codex.js"),
        ),
        "utf8",
      ),
    );
    assert.match(
      execFileSync(
        nativeProvider.config.codex_path_override,
        ["exec", "--help"],
        {
          cwd: nativeRuntime,
          env: {
            ...process.env,
            CODEX_HOME: codexHome,
            NODE_OPTIONS: nativeProvider.config.cli_env.NODE_OPTIONS,
          },
          encoding: "utf8",
        },
      ),
      /Usage: codex exec/,
    );
    assert.equal(
      fs.readFileSync(path.join(codexHome, "config.toml"), "utf8"),
      savedConfig,
    );
  } finally {
    if (previousNodeOptions === undefined) delete process.env.NODE_OPTIONS;
    else process.env.NODE_OPTIONS = previousNodeOptions;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("runs the package-selected Promptfoo entrypoint with the selected Node and cleans only staged cases", () => {
  const childProcess = require("node:child_process");
  const evalRoot = path.resolve(__dirname, "../..");
  const promptfooPackage = path.join(
    evalRoot,
    "node_modules/promptfoo/package.json",
  );
  const bin = { promptfoo: "bin/synthetic-promptfoo.cjs" };
  const evalSdkPackage = path.join(
    evalRoot,
    "node_modules/@openai/codex-sdk/package.json",
  );
  const installedSdkPackage = fs.realpathSync(
    path.resolve(
      __dirname,
      "../../../../sdk/typescript/node_modules/@openai/codex-sdk/package.json",
    ),
  );
  // Deterministic CI installs the SDK; model-eval dependencies are separate.
  const readFile = fs.readFileSync;
  const realpath = fs.realpathSync;
  const packageRead = mock.method(fs, "readFileSync", (file, ...args) =>
    file === promptfooPackage
      ? JSON.stringify({ bin })
      : readFile(file, ...args),
  );
  const packagePath = mock.method(fs, "realpathSync", (file, ...args) =>
    file === evalSdkPackage ? installedSdkPackage : realpath(file, ...args),
  );
  const args = ["validate", "config", "-c", "./sca/promptfooconfig.yaml"];
  let staged;
  const calls = [];
  const spy = mock.method(
    childProcess,
    "execFileSync",
    (command, argv, options) => {
      calls.push({ command, argv });
      assert.equal(command, runtimeVars({}).triage_node_path);
      if (argv.includes("list")) return "[]";
      assert.deepEqual(argv, [
        path.resolve(path.dirname(promptfooPackage), bin.promptfoo),
        ...args,
      ]);
      assert.equal(options.cwd, evalRoot);
      staged = options.env.SCA_EVAL_RUNTIME_ROOT;
      assert.equal(fs.existsSync(path.join(staged, "cases")), true);
      assert.equal(fs.existsSync(path.join(staged, "evals")), false);
      const provider = JSON.parse(
        fs.readFileSync(options.env.SCA_EVAL_PROVIDER_CONFIG, "utf8"),
      );
      assert.equal(provider.config.cli_env.CODEX_MCP_NODE_PATH, command);
      assert.equal(
        options.env.SCA_EVAL_CODEX_HOME,
        process.env.CODEX_HOME || path.join(os.homedir(), ".codex"),
      );
      return "";
    },
  );
  try {
    main(args);
    assert.equal(calls.length, 2);
    assert.equal(fs.existsSync(staged), false);
    assert.equal(fs.existsSync(runtimeVars({}).triage_runtime_root), true);
  } finally {
    spy.mock.restore();
    packagePath.mock.restore();
    packageRead.mock.restore();
    if (staged) fs.rmSync(staged, { recursive: true, force: true });
  }
});

test("does not stage an unrestricted provider when MCP discovery fails", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "sca-provider-failure-"));
  const codexScript = path.join(root, "codex.cjs");
  fs.writeFileSync(codexScript, "process.exit(1);");
  try {
    assert.throws(() => stageProviderConfig(root, root, codexScript));
    assert.equal(fs.existsSync(path.join(root, "provider.json")), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

module.exports = { resultFor };

test(
  "scanner retention preserves distinct literal POSIX source paths",
  { skip: process.platform === "win32" },
  () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "sca-retention-"));
    try {
      const sources = ["a\\b/package-lock.json", "a/b/package-lock.json"];
      for (const source of sources) {
        fs.mkdirSync(path.dirname(path.join(root, source)), {
          recursive: true,
        });
        fs.writeFileSync(path.join(root, source), "{}");
      }
      assert.notEqual(
        fs.realpathSync(path.join(root, sources[0])),
        fs.realpathSync(path.join(root, sources[1])),
      );
      const first = CORPUS.cases[0].input;
      const matches = sources.map((source) => ({
        ...first,
        component: { ...first.component, source },
      }));
      const result = matchRetention(matches, [matches[0]]);
      assert.equal(result.rate, 0.5);
      assert.equal(result.missing.length, first.advisory_ids.length);
      assert.equal(result.missing[0][0], sources[1]);
      assert.equal(matchRetention(matches, matches).rate, 1);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  },
);
