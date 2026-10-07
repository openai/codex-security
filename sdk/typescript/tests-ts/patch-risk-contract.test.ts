import { spawnSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { runCommand } from "./support/shell.js";
import { windowsHelperFixture } from "./windows-helper-command.js";
import { removeTemporaryDirectory } from "./support/temporary-directories.js";
import {
  hasWindowsLoopbackShare,
  windowsLoopbackPath,
} from "./windows-helper-location.js";

interface Assessment {
  [key: string]: unknown;
  schemaVersion: number;
  patch: {
    repository: string;
    sourceType: string;
    base: string;
    head: string;
    changedFiles: string[];
    sha256: string;
  };
  recommendation: string;
  workflowLabel: string;
  impact: { rating: string; rationale: string };
  regressionLikelihood: { rating: string; rationale: string };
  regressionProtection: {
    rating: string;
    rationale: string;
    exactHeadChecksPassed: boolean;
  };
  recoverability: { rating: string; rationale: string };
  confidence: { rating: string; rationale: string };
  applicability: { status: string; rationale: string };
  statusQuoRisk: { rating: string; rationale: string };
  autoMergeExclusions: string[];
  affectedRuntimeRoots: string[];
  materialBoundaries: Array<{
    id: string;
    invariant: string;
    runtimeRoot: string;
    counterexample: string;
    legitimateControl: string;
    result: string;
  }>;
  validation: Array<{
    name: string;
    status: string;
    protects: string;
  }>;
  unknowns: Array<{
    summary: string;
    decisionCritical: boolean;
  }>;
  evidencePlan: Array<{
    question: string;
    action: string;
    outcomes: Record<string, string>;
  }>;
}

const schemaPath = join(
  PLUGIN_ROOT,
  "schemas",
  "patch-risk-assessment.schema.json",
);
const node = Bun.which("node")!;
const helper = join(PLUGIN_ROOT, "mcp", "helpers.mjs");
const powershellDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    powershellDirectories.splice(0).map(removeTemporaryDirectory),
  );
});

function assessment(): Assessment {
  return {
    schemaVersion: 1,
    patch: {
      repository: "example/project",
      sourceType: "pull_request_diff",
      base: "a".repeat(40),
      head: "b".repeat(40),
      changedFiles: ["src/request.ts"],
      sha256: "c".repeat(64),
    },
    recommendation: "merge",
    workflowLabel: "human_review_required",
    impact: { rating: "moderate", rationale: "A bounded caller can fail." },
    regressionLikelihood: {
      rating: "low",
      rationale: "The changed path and its caller are covered.",
    },
    regressionProtection: {
      rating: "strong",
      rationale: "Focused and integration checks passed at the exact head.",
      exactHeadChecksPassed: true,
    },
    recoverability: { rating: "easy", rationale: "A revert is isolated." },
    confidence: { rating: "high", rationale: "Runtime callers are known." },
    applicability: {
      status: "confirmed",
      rationale: "The path is deployed.",
    },
    statusQuoRisk: {
      rating: "moderate",
      rationale: "The defect remains.",
    },
    autoMergeExclusions: [],
    affectedRuntimeRoots: ["service.request"],
    materialBoundaries: [
      {
        id: "request-contract",
        invariant:
          "Supported requests retain their existing response contract.",
        runtimeRoot: "service.request",
        counterexample: "A supported request takes the changed branch.",
        legitimateControl: "A supported request takes the unchanged branch.",
        result: "supported",
      },
    ],
    validation: [
      {
        name: "focused request tests",
        status: "passed",
        protects: "Changed behavior through the production caller.",
      },
    ],
    unknowns: [],
    evidencePlan: [],
  };
}

function validateText(input: string | Buffer, cwd = PLUGIN_ROOT, args = ["-"]) {
  return spawnSync(node, [helper, "validate-patch-risk-assessment", ...args], {
    cwd,
    encoding: "utf8",
    input,
    env: { ...process.env, PATH: "", PYTHON: join(cwd, "unavailable-python") },
    maxBuffer: Infinity,
  });
}

function validate(payload: Assessment) {
  return validateText(JSON.stringify(payload));
}

describe("patch risk assessment contract", () => {
  test("loads the installed helper without Python from another working directory", async () => {
    const outside = await mkdtemp(join(tmpdir(), "patch-risk-contract-"));
    try {
      const result = validateText(JSON.stringify(assessment()), outside);
      expect(result.status, result.stderr).toBe(0);
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });

  test("publishes a valid draft 2020-12 schema", async () => {
    const schema = JSON.parse(await readFile(schemaPath, "utf8"));
    const validateSchema = new Ajv2020({
      strict: false,
      validateFormats: false,
    }).compile(schema);

    expect(schema.$schema).toBe("https://json-schema.org/draft/2020-12/schema");
    expect(
      validateSchema(assessment()),
      JSON.stringify(validateSchema.errors),
    ).toBe(true);

    const rawWorktree = assessment();
    rawWorktree.patch.sourceType = "raw_worktree";
    expect(validateSchema(rawWorktree)).toBe(false);
  });

  test("enforces the published patch-risk schema", () => {
    const valid = validate(assessment());
    expect(valid.status, valid.stderr).toBe(0);

    const duplicateChangedFiles = assessment();
    duplicateChangedFiles.patch.changedFiles = [
      "src/request.ts",
      "src/request.ts",
    ];
    expect(validate(duplicateChangedFiles).status).not.toBe(0);

    const emptyRationale = assessment();
    emptyRationale.impact.rationale = "";
    expect(validate(emptyRationale).status).not.toBe(0);

    const duplicateItems = assessment();
    duplicateItems.autoMergeExclusions = ["migration", "migration"];
    expect(validate(duplicateItems).status).not.toBe(0);

    const tooManyEvidenceSteps = assessment();
    tooManyEvidenceSteps.evidencePlan = Array.from(
      { length: 4 },
      (_, index) => ({
        question: `Question ${index}`,
        action: "Inspect the corresponding evidence.",
        outcomes: { supported: "merge", contradicted: "revise" },
      }),
    );
    const tooManySteps = validate(tooManyEvidenceSteps);
    expect(tooManySteps.status).toBe(1);
    expect(tooManySteps.stderr).toContain("evidencePlan");

    const incompleteOutcomes = assessment();
    incompleteOutcomes.evidencePlan = [
      {
        question: "Is the boundary protected?",
        action: "Inspect the corresponding evidence.",
        outcomes: { supported: "merge" },
      },
    ];
    const tooFewOutcomes = validate(incompleteOutcomes);
    expect(tooFewOutcomes.status).toBe(1);
    expect(tooFewOutcomes.stderr).toContain("outcomes");

    const emptyOutcome = assessment();
    emptyOutcome.evidencePlan = [
      {
        question: "Is the boundary protected?",
        action: "Inspect the corresponding evidence.",
        outcomes: { supported: "", contradicted: "revise" },
      },
    ];
    const invalidOutcome = validate(emptyOutcome);
    expect(invalidOutcome.status).toBe(1);
    expect(invalidOutcome.stderr).toContain("outcomes/supported");
  });

  test("enforces the published schema without Python", async () => {
    const schema = JSON.parse(await readFile(schemaPath, "utf8"));
    const validateSchema = new Ajv2020({
      strict: false,
      validateFormats: false,
    }).compile(schema);
    const invalidAssessments: Assessment[] = [];

    const missingRequired = assessment();
    delete (missingRequired as Record<string, unknown>)["patch"];
    invalidAssessments.push(missingRequired);

    const additionalProperty = assessment();
    additionalProperty["unexpected"] = true;
    invalidAssessments.push(additionalProperty);

    const invalidPattern = assessment();
    invalidPattern.patch.sha256 = "g".repeat(64);
    invalidAssessments.push(invalidPattern);

    const trailingNewlineDigest = assessment();
    trailingNewlineDigest.patch.sha256 = `${"c".repeat(64)}\n`;
    invalidAssessments.push(trailingNewlineDigest);

    const emptyValidation = assessment();
    emptyValidation.validation = [];
    invalidAssessments.push(emptyValidation);

    const duplicateItems = assessment();
    duplicateItems["autoMergeExclusions"] = ["migration", "migration"];
    invalidAssessments.push(duplicateItems);

    const emptyString = assessment();
    emptyString.impact.rationale = "";
    invalidAssessments.push(emptyString);

    for (const payload of invalidAssessments) {
      expect(validateSchema(payload)).toBe(false);
      expect(validate(payload).status).not.toBe(0);
    }
  });

  test("accepts a supported human-review merge without Python", () => {
    const result = validate(assessment());
    expect(result.status, result.stderr).toBe(0);
  });

  test("compares JSON numeric constants by value", () => {
    const serialized = JSON.stringify(assessment()).replace(
      '"schemaVersion":1',
      '"schemaVersion":1.0',
    );

    const result = validateText(serialized);
    expect(result.status, result.stderr).toBe(0);
  });

  test("enforces strict auto-merge gates", () => {
    const payload = assessment();
    payload.workflowLabel = "auto_merge_candidate";

    const rejected = validate(payload);
    expect(rejected.status).not.toBe(0);

    payload.impact.rating = "low";
    const accepted = validate(payload);
    expect(accepted.status, accepted.stderr).toBe(0);
  });

  test("requires a bounded evidence plan for an evidence hold", () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.unknowns = [
      {
        summary: "The rollout target is unavailable.",
        decisionCritical: true,
      },
    ];

    expect(validate(payload).status).not.toBe(0);

    payload.evidencePlan = [
      {
        question: "Does the changed configuration own the rollout target?",
        action: "Inspect the checked-in deployment mapping.",
        outcomes: {
          supported: "merge",
          contradicted: "no_op",
          unavailable: "hold_for_evidence",
        },
      },
    ];
    const accepted = validate(payload);
    expect(accepted.status, accepted.stderr).toBe(0);

    payload.evidencePlan[0]!.outcomes = JSON.parse(
      '{"__proto__":"merge","contradicted":"revise"}',
    );
    expect(validate(payload).status).toBe(0);
    payload.evidencePlan[0]!.outcomes["__proto__"] = "unsupported";
    const invalidOutcome = validate(payload);
    expect(invalidOutcome.status).toBe(1);
    expect(invalidOutcome.stderr).toContain("outcomes");
  });

  test("requires an established non-applicable no-op", () => {
    const payload = assessment();
    payload.recommendation = "no_op";
    payload.workflowLabel = "no_op";

    expect(validate(payload).status).not.toBe(0);

    payload.applicability = {
      status: "superseded",
      rationale: "A narrower patch already landed.",
    };
    const accepted = validate(payload);
    expect(accepted.status, accepted.stderr).toBe(0);
  });

  test("requires affirmative failure evidence for a block", () => {
    const payload = assessment();
    payload.recommendation = "block";
    payload.workflowLabel = "block";

    expect(validate(payload).status).not.toBe(0);

    payload.materialBoundaries[0]!.result = "contradicted";
    const accepted = validate(payload);
    expect(accepted.status, accepted.stderr).toBe(0);
  });

  test("requires affirmative failure evidence for a revision", () => {
    const payload = assessment();
    payload.recommendation = "revise";
    payload.workflowLabel = "revise";

    expect(validate(payload).status).not.toBe(0);

    payload.validation[0]!.status = "failed";
    const accepted = validate(payload);
    expect(accepted.status, accepted.stderr).toBe(0);
  });

  test("keeps failed validation and established defects out of merge and hold", () => {
    const merge = assessment();
    merge.validation[0]!.status = "failed";
    expect(validate(merge).status).not.toBe(0);

    const hold = assessment();
    hold.recommendation = "hold_for_evidence";
    hold.workflowLabel = "hold_for_evidence";
    hold.materialBoundaries[0]!.result = "contradicted";
    hold.unknowns = [
      {
        summary: "A separate rollout detail is unavailable.",
        decisionCritical: true,
      },
    ];
    hold.evidencePlan = [
      {
        question: "Which rollout target is selected?",
        action: "Inspect the checked-in deployment mapping.",
        outcomes: { found: "revise", unavailable: "hold_for_evidence" },
      },
    ];
    expect(validate(hold).status).not.toBe(0);
  });

  test("requires no-op for an established non-applicable disposition", () => {
    const payload = assessment();
    payload.recommendation = "block";
    payload.workflowLabel = "block";
    payload.applicability.status = "wrong_owner";
    payload.materialBoundaries[0]!.result = "contradicted";

    expect(validate(payload).status).not.toBe(0);
  });

  test("preserves the ordered auto-merge gates", () => {
    const cases: Array<[string, (value: Assessment) => void]> = [
      [
        "impact.rating",
        (value) => {
          value.impact.rating = "moderate";
        },
      ],
      [
        "regressionLikelihood.rating",
        (value) => {
          value.regressionLikelihood.rating = "high";
        },
      ],
      [
        "regressionProtection.rating",
        (value) => {
          value.regressionProtection.rating = "partial";
        },
      ],
      [
        "regressionProtection.exactHeadChecksPassed",
        (value) => {
          value.regressionProtection.exactHeadChecksPassed = false;
        },
      ],
      [
        "recoverability.rating",
        (value) => {
          value.recoverability.rating = "managed";
        },
      ],
      [
        "confidence.rating",
        (value) => {
          value.confidence.rating = "moderate";
        },
      ],
      [
        "applicability.status",
        (value) => {
          value.applicability.status = "unknown";
        },
      ],
      [
        "affectedRuntimeRoots",
        (value) => {
          value.affectedRuntimeRoots = [];
        },
      ],
      [
        "statusQuoRisk.rating",
        (value) => {
          value.statusQuoRisk.rating = "unknown";
        },
      ],
      [
        "autoMergeExclusions",
        (value) => {
          value.autoMergeExclusions = ["public_contract"];
        },
      ],
      [
        "unknowns",
        (value) => {
          value.unknowns = [
            { summary: "A non-critical detail.", decisionCritical: false },
          ];
        },
      ],
      [
        "validation",
        (value) => {
          value.validation[0]!.status = "skipped";
        },
      ],
    ];
    const payload = assessment();
    payload.workflowLabel = "auto_merge_candidate";
    payload.impact.rating = "low";
    expect(validate(payload).status).toBe(0);
    for (const [field, mutate] of cases) {
      const changed = structuredClone(payload);
      mutate(changed);
      const result = validate(changed);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(
        `auto_merge_candidate gate failed: ${field}`,
      );
      mutate(payload);
    }
    expect(validate(payload).stderr.trim().split("\n")).toEqual([
      "merge requires confirmed applicability",
      ...cases.map(([field]) => `auto_merge_candidate gate failed: ${field}`),
    ]);
  });

  test("keeps all merge errors in their established order", () => {
    const payload = assessment();
    payload.workflowLabel = "block";
    payload.applicability.status = "wrong_owner";
    payload.unknowns = [
      { summary: "The owner is unknown.", decisionCritical: true },
    ];
    payload.materialBoundaries[0]!.result = "unresolved";
    payload.validation[0]!.status = "failed";
    payload.evidencePlan = [
      {
        question: "Who owns this?",
        action: "Inspect the mapping.",
        outcomes: { owned: "revise", unowned: "no_op" },
      },
    ];
    const result = validate(payload);
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr.trim().split("\n")).toEqual([
      "merge requires an auto-merge or human-review workflow label",
      "merge requires confirmed applicability",
      "merge cannot retain a decision-critical unknown",
      "merge requires every material boundary to be supported",
      "merge cannot retain a failed validation",
      "merge cannot retain an evidence plan",
      "only hold_for_evidence may include an evidence plan",
      "an established non-applicable disposition requires no_op",
    ]);
    delete (payload as Record<string, unknown>)["patch"];
    const missingPatch = validate(payload);
    expect(missingPatch.status).toBe(1);
    expect(missingPatch.stderr).toContain("patch-risk-assessment.schema");
  });

  test("requires matching non-merge labels and a settled no-op disposition", () => {
    const payload = assessment();
    payload.recommendation = "revise";
    payload.validation[0]!.status = "failed";
    expect(validate(payload).stderr).toBe(
      "non-merge workflow label must match the recommendation\n",
    );
    payload.workflowLabel = "revise";
    expect(validate(payload).status).toBe(0);
    for (const status of [
      "no_live_effect",
      "wrong_owner",
      "duplicate",
      "superseded",
    ]) {
      const noOp = assessment();
      noOp.recommendation = noOp.workflowLabel = "no_op";
      noOp.applicability.status = status;
      expect(validate(noOp).status).toBe(0);
      noOp.unknowns = [
        { summary: "Coverage is unresolved.", decisionCritical: true },
      ];
      expect(validate(noOp).stderr).toBe(
        "no_op cannot retain a decision-critical unknown\n",
      );
    }
  });

  test("keeps each established failure out of an evidence hold", () => {
    const failures: Array<(value: Assessment) => void> = [
      (value) => {
        value.regressionLikelihood.rating = "critical";
      },
      (value) => {
        value.materialBoundaries[0]!.result = "contradicted";
      },
      (value) => {
        value.validation[0]!.status = "failed";
      },
    ];
    for (const fail of failures) {
      const payload = assessment();
      payload.recommendation = payload.workflowLabel = "hold_for_evidence";
      payload.unknowns = [
        { summary: "A rollout detail.", decisionCritical: true },
      ];
      payload.evidencePlan = [
        {
          question: "Which rollout?",
          action: "Inspect deployment.",
          outcomes: { owned: "merge", unowned: "no_op" },
        },
      ];
      fail(payload);
      expect(validate(payload).stderr).toBe(
        "hold_for_evidence cannot defer an established defect\n",
      );
      payload.evidencePlan = [];
      for (const recommendation of ["revise", "block"]) {
        payload.recommendation = payload.workflowLabel = recommendation;
        expect(validate(payload).status).toBe(0);
      }
    }
  });

  test("requires numeric schema version 1", () => {
    const serialized = JSON.stringify(assessment());
    for (const token of ["1", "1.0", "1e0"]) {
      const result = validateText(
        serialized.replace('"schemaVersion":1', `"schemaVersion":${token}`),
      );
      expect(result.status, result.stderr).toBe(0);
    }
    for (const token of [
      "true",
      "false",
      '"1"',
      "0",
      "null",
      "9007199254740993",
    ]) {
      const result = validateText(
        serialized.replace('"schemaVersion":1', `"schemaVersion":${token}`),
      );
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("schemaVersion");
    }
  });

  test("accepts large assessments and rejects truncated JSON", async () => {
    const complete = assessment();
    complete.impact.rationale = '"'.repeat(5_000_000);
    const truncated =
      '{"impact":{"rationale":"' + '\\"'.repeat(5_000_000) + "\\";
    for (const [input, status] of [
      [truncated, 1],
      [JSON.stringify(complete), 0],
    ] as const) {
      const result = await runCommand(
        node,
        [helper, "validate-patch-risk-assessment", "-"],
        {
          input,
          timeout: 5000,
        },
      );
      expect(result.signal, result.error?.message).toBeNull();
      expect(result.status, result.stderr).toBe(status);
      if (status === 1)
        expect(result.stderr).toContain("cannot read assessment:");
      else expect(result.stderr).toBe("");
    }
  });

  test.each([
    [
      "top-level",
      '"recommendation":"merge"',
      '"recommendation":"block","recommendation":"merge"',
      "recommendation",
    ],
    [
      "nested validation",
      '"status":"passed"',
      '"status":"failed","status":"passed"',
      "status",
    ],
    [
      "escaped key",
      '"status":"passed"',
      '"status":"failed","\\u0073tatus":"passed"',
      "status",
    ],
    [
      "prototype member",
      '"schemaVersion":1',
      '"__proto__":{},"__proto__":{},"schemaVersion":1',
      "__proto__",
    ],
  ])("rejects %s duplicate object keys", (_label, original, duplicate, key) => {
    const result = validateText(
      JSON.stringify(assessment()).replace(original, duplicate),
    );
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`duplicate JSON object key: ${key}`);
  });

  test.each([
    ["ordinary", 'field "quoted"', 'field "quoted"'],
    ["escape", "field\u001b[2J", "field\\u001b[2J"],
    ["C1", "field\u009b2J", "field\\u009b2J"],
    ["bidirectional", "field\u202e", "field\\u202e"],
  ])(
    "preserves duplicate-key diagnostic text with escaped controls: %s",
    (_label, key, display) => {
      const encoded = JSON.stringify(key);
      const result = validateText(`{${encoded}:1,${encoded}:2}`);
      expect(result.status).toBe(1);
      expect(result.stderr).toBe(`duplicate JSON object key: ${display}\n`);
    },
  );

  test("allows repeated names in separate objects and key-like string contents", () => {
    const payload = assessment();
    payload.impact.rationale = '{"status":"failed","status":"passed"} \\"';
    const result = validate(payload);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("");
  });

  test("rejects malformed JSON with a useful diagnostic", () => {
    for (const text of [
      "\ufeff{}",
      '{"x":1,}',
      '{"x" "\\q"}',
      '[0 "\\q"]',
      '{"x":"\\uZZZZ"}',
      '{"x":"\\q"}',
      '"\\q',
      '"\\u123',
      '"truncated\\',
      '{"x":"line\n"}',
      '{"x":"😀\\q"}',
      "{} false",
      '{"schemaVersion":NaN}',
      '{"schemaVersion":Infinity}',
    ]) {
      const result = validateText(text);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("cannot read assessment:");
    }
    const array = validateText("[]");
    expect(array.status).toBe(1);
    expect(array.stderr).toContain("assessment must be a JSON object");
  });

  test("escapes terminal controls echoed by JSON syntax errors", () => {
    for (const [control, escaped] of [
      ["\u001b", "\\u001b"],
      ["\u202e", "\\u202e"],
      ["\u{e0001}", "\\u{e0001}"],
    ] as const) {
      const result = validateText(`${control}[2J`);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("cannot read assessment:");
      expect(result.stderr).not.toContain(control);
      expect(result.stderr).toContain(escaped);
    }
  });

  test("reads file and stdin inputs without rewriting the assessment", async () => {
    const outside = await mkdtemp(join(tmpdir(), "patch-risk-files-"));
    try {
      const original =
        JSON.stringify(assessment(), null, 2).replaceAll("\n", "\r\n") + "\r\n";
      for (const name of ["assessment with spaces.json", "-1", "- item", "-"]) {
        const path = join(outside, name);
        await writeFile(path, original);
        const result = validateText("not stdin", outside, [
          name.startsWith("-") ? `./${name}` : name,
        ]);
        expect(result.status, result.stderr).toBe(0);
        expect(result.stdout).toBe("");
        expect(result.stderr).toBe("");
        expect(await readFile(path, "utf8")).toBe(original);
        expect(validateText("", outside, ["--", name]).status).toBe(
          name === "-" ? 1 : 0,
        );
      }
      const file = join(outside, "assessment with spaces.json");
      if (process.platform !== "win32") {
        for (const suffix of ["/.", "///", "/./."])
          expect(validateText("", outside, [file + suffix]).status).toBe(0);
        await mkdir(join(outside, "child", "nested"), { recursive: true });
        await symlink("child/nested", join(outside, "link"));
        await writeFile(join(outside, "child", "assessment.json"), original);
        await writeFile(join(outside, "assessment.json"), "wrong sibling");
        expect(
          validateText("", outside, ["link/../assessment.json/."]).status,
        ).toBe(0);
      }
      expect(validateText(original, outside).status).toBe(0);
      if (process.platform !== "win32") {
        const launched = spawnSync(
          join(PLUGIN_ROOT, "scripts", "launch_codex_security_mcp"),
          ["--helper", "validate-patch-risk-assessment", "-"],
          {
            cwd: outside,
            input: original,
            encoding: "utf8",
            env: { ...process.env, CODEX_MCP_NODE_PATH: node },
          },
        );
        expect(launched.status, launched.stderr).toBe(0);
        expect(launched.stdout).toBe("");
        expect(launched.stderr).toBe("");
      }
      const invalid = join(outside, "invalid.json");
      const malformed = '{\r\n"x":1\r\n"y":2}';
      await writeFile(invalid, malformed);
      expect(validateText(malformed).stderr).toContain(
        "cannot read assessment:",
      );
      expect(validateText("", outside, [invalid]).stderr).toContain(
        "cannot read assessment:",
      );
      await writeFile(invalid, Buffer.from([0xff]));
      expect(validateText("", outside, [invalid]).status).toBe(1);
      expect(validateText("", outside, ["missing.json"]).stderr).toContain(
        "cannot read assessment:",
      );
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });

  test("escapes terminal controls in assessment file-read error paths", async () => {
    const outside = await mkdtemp(join(tmpdir(), "patch-risk-read-error-"));
    try {
      for (const [control, escaped] of [
        ["\u001b", "\\u001b"],
        ["\u202e", "\\u202e"],
        ["\u{e0001}", "\\u{e0001}"],
      ] as const) {
        const file = join(outside, `missing-${control}[2J.json`);
        const result = validateText("", outside, [file]);
        expect(result.status).toBe(1);
        expect(result.stdout).toBe("");
        expect(result.stderr).toContain(`missing-${escaped}[2J.json`);
        expect(result.stderr).not.toContain(control);
      }
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });

  for (const location of ["absolute", "relative", "unc"] as const)
    test.skipIf(
      process.platform !== "win32" ||
        (location === "unc" && !hasWindowsLoopbackShare),
    )(
      `executes the documented PowerShell command with ${location} literal assessment and plugin paths`,
      async () => {
        const outside = await mkdtemp(join(tmpdir(), "patch-risk-powershell-"));
        powershellDirectories.push(outside);
        const launcher = windowsHelperFixture(outside);
        const file = join(
          outside,
          "review-%USERNAME% !EXPAND! \u96ea's",
          "assessment.json",
        );
        const expandedFile = file.replace("%USERNAME%", "expanded-user");
        for (const path of [file, expandedFile])
          await mkdir(dirname(path), { recursive: true });
        const original = JSON.stringify(assessment()).replace(
          "example/project",
          "example/caf\u00e9-\u96ea",
        );
        await writeFile(expandedFile, original);
        const caller = join(outside, "caller");
        await mkdir(caller);
        const workingDirectory =
          location === "unc" ? windowsLoopbackPath(caller) : caller;
        const argument = (path: string) =>
          location === "absolute" ? path : relative(caller, path);
        for (const powershell of launcher.powershells) {
          for (const input of [
            "invalid",
            "valid",
            "stdin",
            "pipeline",
            "missing",
          ]) {
            await writeFile(file, input === "invalid" ? "{}" : original);
            if (input === "missing") await rm(file);
            const result = await launcher.run(
              powershell,
              "skills/assess-patch-risk/SKILL.md",
              {
                "<plugin-root>": argument(launcher.plugin),
                "<assessment.json>":
                  input === "stdin" || input === "pipeline"
                    ? "-"
                    : argument(file),
              },
              input === "pipeline" ? "" : original,
              workingDirectory,
              input === "pipeline" ? original : undefined,
            );
            const diagnostics = `${location} ${input}\n${result.diagnostics}`;
            expect(result.stdout, diagnostics).not.toContain(
              "expanded-plugin-used",
            );
            expect(result.status, diagnostics).toBe(
              input === "invalid" || input === "missing" ? 1 : 0,
            );
            if (location !== "unc") expect(result.stdout, diagnostics).toBe("");
            if (input === "invalid")
              expect(result.stderr, diagnostics).toContain(
                "patch-risk-assessment.schema",
              );
            else if (input === "missing")
              expect(result.stderr, diagnostics).toContain("Convert-Path");
            else if (location !== "unc")
              expect(result.stderr, diagnostics).toBe("");
            if (input === "missing")
              await expect(readFile(file), diagnostics).rejects.toMatchObject({
                code: "ENOENT",
              });
            else
              await expect(readFile(file, "utf8"), diagnostics).resolves.toBe(
                input === "invalid" ? "{}" : original,
              );
          }
        }
      },
    );

  test.skipIf(process.platform === "win32")(
    "keeps stdin surrogate escapes distinct from replacement characters",
    () => {
      const serialized = JSON.stringify(assessment()).replace(
        '"changedFiles":["src/request.ts"]',
        '"changedFiles":["RAW","\\ufffd"]',
      );
      const [before, after] = serialized.split("RAW");
      const result = validateText(
        Buffer.concat([
          Buffer.from(before!),
          Buffer.from([0xff]),
          Buffer.from(after!),
        ]),
      );
      expect(result.status, result.stderr).toBe(0);
    },
  );

  test("supports documented help, positional arguments, and parser exit statuses", () => {
    for (const args of [["-h"], ["--help"]]) {
      const result = validateText("", PLUGIN_ROOT, args);
      expect(result.status).toBe(0);
      expect(result.stdout).toContain("Validate a patch-risk assessment.");
    }
    for (const args of [
      [],
      ["--"],
      ["--bad"],
      ["one", "two"],
      ["--help=bad"],
      ["-h=bad"],
    ]) {
      expect(validateText("", PLUGIN_ROOT, args).status).toBe(2);
    }
    expect(validateText("", PLUGIN_ROOT, ["--", "-h"]).status).toBe(1);
  });
});
