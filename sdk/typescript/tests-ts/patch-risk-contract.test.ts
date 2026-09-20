import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

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

  test("enforces the patch-risk schema through the shared validator", () => {
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
    expect(validate(tooManyEvidenceSteps).stderr).toBe(
      "patch-risk-assessment.schema.evidencePlan: array has too many items\n",
    );

    const incompleteOutcomes = assessment();
    incompleteOutcomes.evidencePlan = [
      {
        question: "Is the boundary protected?",
        action: "Inspect the corresponding evidence.",
        outcomes: { supported: "merge" },
      },
    ];
    expect(validate(incompleteOutcomes).stderr).toBe(
      "patch-risk-assessment.schema.evidencePlan[0].outcomes: object has too few properties\n",
    );

    const emptyOutcome = assessment();
    emptyOutcome.evidencePlan = [
      {
        question: "Is the boundary protected?",
        action: "Inspect the corresponding evidence.",
        outcomes: { supported: "", contradicted: "revise" },
      },
    ];
    expect(validate(emptyOutcome).stderr).toBe(
      "patch-risk-assessment.schema.evidencePlan[0].outcomes.supported: unsupported value ''\n",
    );
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

  test("rejects duplicate JSON object keys", () => {
    const serialized = JSON.stringify(assessment()).replace(
      '"recommendation":"merge"',
      '"recommendation":"block","recommendation":"merge"',
    );

    const rejected = validateText(serialized);
    expect(rejected.status).not.toBe(0);
    expect(rejected.stderr).toContain(
      "duplicate JSON object key: recommendation",
    );
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
    expect(validate(payload).stderr).toBe(
      "patch-risk-assessment.schema.patch: missing required schema property\n",
    );
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

  test("distinguishes booleans, exact integers, and floating-point values", () => {
    const serialized = JSON.stringify(assessment());
    for (const token of ["1", "1.0", "1e0", "1.00000000000000000000001"]) {
      const result = validateText(
        serialized.replace('"schemaVersion":1', `"schemaVersion":${token}`),
      );
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toBe("");
      expect(result.stderr).toBe("");
    }
    for (const token of [
      "true",
      "false",
      "0",
      "-0.0",
      "NaN",
      "Infinity",
      "-Infinity",
      "1e9999",
      "9007199254740993",
    ]) {
      const result = validateText(
        serialized.replace('"schemaVersion":1', `"schemaVersion":${token}`),
      );
      expect(result.status).toBe(1);
      expect(result.stderr).toBe(
        "patch-risk-assessment.schema.schemaVersion: expected 1\n",
      );
    }
    for (const [items, message] of [
      ["1,1.0", "unsupported value 1"],
      ["true,1", "unsupported value True"],
      [
        "9007199254740992,9007199254740993.0",
        "unsupported value 9007199254740992",
      ],
      [
        "9007199254740993,9007199254740993.0",
        "unsupported value 9007199254740993",
      ],
      ['{"x":1,"y":2},{"y":2.0,"x":1.0}', "unsupported value"],
      ["NaN,NaN", "unsupported value nan"],
    ]) {
      const result = validateText(
        serialized.replace(
          '"autoMergeExclusions":[]',
          `"autoMergeExclusions":[${items}]`,
        ),
      );
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(message!);
    }
  });

  test("rejects malformed JSON and preserves duplicate and property order", () => {
    for (const [text, message] of [
      ["\ufeff{}", "cannot read assessment: Unexpected UTF-8 BOM"],
      ['{"x":1,}', "Expecting property name enclosed in double quotes"],
      ['{"x":"\\uZZZZ"}', "cannot read assessment:"],
      ['{"x":"\\q"}', "cannot read assessment:"],
      ['"\\q', "cannot read assessment:"],
      ['"\\u123', "cannot read assessment:"],
      ['{"x":"line\n"}', "cannot read assessment:"],
      ["{} false", "Extra data"],
      ["[]", "assessment must be a JSON object"],
      ['{"x":0,"x":1,"nested":{"y":0,"y":1}}', "duplicate JSON object key: y"],
      ['{"x":0,"\\u0078":1}', "duplicate JSON object key: x"],
      ['{"__proto__":0,"__proto__":1}', "duplicate JSON object key: __proto__"],
    ]) {
      const result = validateText(text!);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(message!);
    }
    const serialized = JSON.stringify(assessment());
    const reordered = `{"unexpected":0,"1":0,${serialized.slice(1)}`;
    expect(validateText(reordered).stderr).toBe(
      "patch-risk-assessment.schema.unexpected: unexpected schema property\n",
    );
    expect(validateText(`{"\\ud800":0,${serialized.slice(1)}`).stderr).toBe(
      "patch-risk-assessment.schema.\\ud800: unexpected schema property\n",
    );
    const control = assessment();
    control.patch.sourceType = "can't\u00a0merge\n";
    expect(validate(control).stderr).toBe(
      'patch-risk-assessment.schema.patch.sourceType: unsupported value "can\'t\\xa0merge\\n"\n',
    );
    control.patch.repository = "\ud800";
    control.patch.sourceType = "patch_file";
    expect(validate(control).status).toBe(0);
    for (const value of [`${"c".repeat(64)}\n`, `${"c".repeat(64)}\r\n`]) {
      control.patch.sha256 = value;
      expect(validate(control).stderr).toContain(
        "string does not match schema pattern",
      );
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
          name === "-" ? "./-" : name,
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
      if (process.platform !== "win32")
        expect(validateText("", outside, [`${file}/.`]).status).toBe(0);
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
        "line 3 column 1 (char 10)",
      );
      expect(validateText("", outside, [invalid]).stderr).toContain(
        "line 3 column 1 (char 8)",
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

  test("preserves help, positional arguments, and parser exit statuses", () => {
    for (const args of [
      ["-h"],
      ["--h"],
      ["--he"],
      ["-hfoo"],
      ["--bad", "--help"],
    ]) {
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
    expect(validateText("", PLUGIN_ROOT, ["-.5"]).status).toBe(1);
  });
});
