import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { parse } from "../../sdk/typescript/node_modules/smol-toml/dist/index.js";
import {
  createFixture,
  expectedFindings,
  sourceEvidence,
} from "./fixtures.mts";
import type {
  CodeEvidence,
  SourceLocation,
  Finding,
  Result,
} from "./grade.mts";
import type { EvalCodex } from "./harness.mts";
import type { ThreadOptions } from "../../sdk/typescript/node_modules/@openai/codex-sdk/dist/index.js";
import { gradeResult } from "./grade.mts";
import {
  codexSettings,
  prepareEval,
  runPreparedEval,
  threadSettings,
} from "./harness.mts";
import { DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID } from "./runtime.mts";

interface TestFinding extends Finding {
  title?: string;
  taxonomy: { category: string; cwe: string[] };
  locations: SourceLocation[];
  codeEvidence: CodeEvidence[];
}
interface TestResult extends Result {
  findings: TestFinding[];
  coverage: {
    surfaces: Record<string, unknown>[];
    explicitExclusions: { pattern: string; reason: string }[];
    deferred: unknown[];
    openQuestions: string[];
  };
  resolved_questions?: TestFinding[];
}
const fixture = createFixture();

function retainedResult(source = fixture): TestResult {
  return {
    findings: expectedFindings(source),
    coverage: {
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
      openQuestions: [],
    },
  };
}

test("counts every retained secret location, including unused and integration source", () => {
  const report = gradeResult(retainedResult(), fixture);
  assert.equal(report.passed, true);
  assert.equal(report.recall, 1);
  assert.deepEqual(
    report.cases.map((entry) => entry.id),
    [
      "active-source",
      "unused-source",
      "integration-source",
      "dotenv-url",
      "account-config",
      "private-key",
      "provider-token",
      "runtime-disclosure",
    ],
  );
});

test("delegating API token literals preserves the contextual password and independent response leak", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "external-token-scanner-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const prepared = await prepareEval(root, { externalTokenScanner: true });
  const delegated = prepared.fixture;
  const policy = (
    await readFile(join(prepared.repo, "SECURITY.md"), "utf8")
  ).trim();
  assert.ok(prepared.prompt.includes(policy));
  for (const value of delegated.secretValues)
    assert.equal(prepared.prompt.includes(value), false);

  // Grade findings for all eight cases against the exact source being scanned.
  const all = retainedResult({ ...delegated, positives: fixture.positives });
  const duplicate = gradeResult(all, delegated);
  assert.equal(duplicate.passed, false);
  assert.deepEqual(
    duplicate.falsePositives.map((entry) => entry.unexpectedLocations),
    [["config/release.env"]],
  );
  all.findings.splice(duplicate.falsePositives[0].index, 1);
  const report = gradeResult(all, delegated);
  assert.equal(report.passed, true);
  assert.deepEqual(
    report.cases.map(({ id }) => id),
    fixture.positives
      .filter(({ id }) => id !== "provider-token")
      .map(({ id }) => id),
  );
});

test("runtime disclosure needs its own finding even when token alerts are delegated", () => {
  for (const data of [fixture, createFixture(true)]) {
    const result = retainedResult(data);
    const index = data.positives.findIndex(
      ({ id }) => id === "runtime-disclosure",
    );
    const finding = result.findings[index];
    finding.taxonomy = { category: "missing-authorization", cwe: ["CWE-862"] };
    assert.equal(gradeResult(result, data).passed, true);
    finding.taxonomy = {
      category: "Sensitive credentials in public responses",
      cwe: ["CWE-200"],
    };
    assert.equal(gradeResult(result, data).passed, true);
    finding.taxonomy = { category: "hardcoded-credentials", cwe: ["CWE-200"] };
    assert.equal(gradeResult(result, data).cases[index].found, false);
    finding.taxonomy = { category: "credential-exposure", cwe: ["CWE-798"] };
    assert.equal(gradeResult(result, data).cases[index].found, false);
    result.findings.splice(index, 1);
    assert.equal(gradeResult(result, data).passed, false);
  }
});

test("a source credential finding cannot cover the independent public endpoint", () => {
  for (const data of [fixture, createFixture(true)]) {
    const result = retainedResult(data);
    const password =
      result.findings[
        data.positives.findIndex(({ id }) => id === "dotenv-url")
      ];
    const runtimeIndex = data.positives.findIndex(
      ({ id }) => id === "runtime-disclosure",
    );
    const [runtime] = result.findings.splice(runtimeIndex, 1);
    password.taxonomy = {
      category: "credential exposure",
      cwe: ["CWE-200", "CWE-798"],
    };
    password.locations.push(...runtime.locations);
    password.codeEvidence.push(...runtime.codeEvidence);
    const merged = gradeResult(result, data);
    assert.equal(merged.cases[runtimeIndex].found, false);
    assert.equal(merged.passed, false);

    // A separate endpoint finding can cite the password location as context.
    password.locations.pop();
    password.codeEvidence.pop();
    runtime.taxonomy = { category: "credential exposure", cwe: ["CWE-200"] };
    runtime.locations.push({ ...password.locations[0], role: "supporting" });
    result.findings.push(runtime);
    assert.equal(gradeResult(result, data).passed, true);
  }
});

test("resolved, deferred, and intermediate findings do not satisfy final recall", () => {
  const result = retainedResult();
  result.coverage.deferred = result.findings;
  result.resolved_questions = result.findings;
  result.findings = [];
  const report = gradeResult(result, fixture);
  assert.equal(report.passed, false);
  assert.equal(report.recall, 0);
});

test("grades the unchecked status on each source credential separately from discovery", () => {
  const result = retainedResult();
  const source = result.findings[0];
  delete source.validation;
  source.codeEvidence[0].explanation = "Validity unchecked";
  result.coverage.openQuestions.push("Validity unchecked");
  const leak = result.findings.at(-1)!;
  delete leak.validation;
  const missing = gradeResult(result, fixture);
  assert.equal(missing.discoveryPassed, true);
  assert.equal(missing.passed, false);
  assert.deepEqual(missing.validityCopy, {
    withStatus: 6,
    retainedCredentialFindings: 7,
  });
  source.summary = "Validity unchecked. The bearer is embedded in the client.";
  const complete = gradeResult(result, fixture);
  assert.equal(complete.passed, true);
  assert.equal(complete.validityCopy.withStatus, 7);
  delete source.summary;
  source.validation = { limitations: ["Validity unchecked."] };
  assert.equal(gradeResult(result, fixture).passed, true);
});

for (const [name, mutate] of [
  [
    "wrong source line",
    (finding: TestFinding) => {
      finding.locations[0].startLine = 1;
    },
  ],
  [
    "wrong source path",
    (finding: TestFinding) => {
      finding.locations[0].path = "src/absent.py";
    },
  ],
  [
    "unrelated CWE",
    (finding: TestFinding) => {
      finding.taxonomy.cwe = ["CWE-89"];
    },
  ],
  [
    "unrelated category",
    (finding: TestFinding) => {
      finding.taxonomy.category = "sql-injection";
    },
  ],
  [
    "line range outside source",
    (finding: TestFinding) => {
      finding.locations[0].endLine = 100000;
    },
  ],
] as const) {
  test(`rejects ${name}`, () => {
    const result = retainedResult();
    mutate(result.findings[0]);
    const report = gradeResult(result, fixture);
    assert.equal(report.passed, false);
    assert.equal(report.cases[0].found, false);
  });
}

for (const category of [
  "not-a-secret",
  "noncredential",
  "NOT_A_SECRET",
  "non_credentials",
  "not a credential",
  "NON SECRET",
  "not-a-secret-exposure",
  "non-credential-finding",
  "not-a-private-key",
  "non-hardcoded-credential",
  "non-sensitive-data-exposure",
  "no sensitive information disclosure",
  "not-a-password-exposure",
  "non-token-exposure",
  "non-api-key-exposure",
  "no-secret-exposure",
  "secret-free",
  "without-credentials",
]) {
  test(`rejects negated category ${category}`, () => {
    const result = retainedResult();
    result.findings[0].taxonomy.category = category;
    const report = gradeResult(result, fixture);
    assert.equal(report.passed, false);
    assert.equal(report.cases[0].found, false);
  });
}

test("rejects unrelated categories containing credential-term substrings", () => {
  for (const category of ["tokenization-error", "secretary-data"]) {
    for (const cwe of ["CWE-798", "CWE-200"]) {
      const result = retainedResult();
      result.findings[0].taxonomy = { category, cwe: [cwe] };
      const report = gradeResult(result, fixture);
      assert.equal(report.passed, false, `${category}:${cwe}`);
      assert.equal(report.cases[0].found, false, `${category}:${cwe}`);
    }
  }
});

test("accepts plural and identifier-style credential categories", () => {
  for (const category of [
    "tokens-exposed",
    "secrets_in_source",
    "privateKeysInSource",
    "hardcodedCredentials",
    "credentialExposure",
  ]) {
    const result = retainedResult();
    result.findings[0].taxonomy.category = category;
    assert.equal(gradeResult(result, fixture).passed, true, category);
  }
});

test("accepts credential exposure with non-secret context in the category", () => {
  const result = retainedResult();
  for (const category of [
    "credential exposure with non-secret context",
    "credential exposure with no-secret context",
    "credential exposure with secret-free context",
    "credential exposure with context without credentials",
  ]) {
    result.findings[0].taxonomy.category = category;
    assert.equal(gradeResult(result, fixture).passed, true, category);
  }
});

test("public status access corroborates only the independently identified runtime disclosure", () => {
  const result = retainedResult();
  const runtime = result.findings.at(-1)!;
  const context = {
    path: "README.md",
    startLine: fixture.statusAccessLine,
    role: "Documented public access",
  };
  runtime.locations.push(context);
  assert.equal(gradeResult(result, fixture).passed, true);
  const originalEvidence = runtime.codeEvidence;
  runtime.codeEvidence = [
    sourceEvidence(fixture, context.path, context.startLine),
  ];
  assert.deepEqual(
    gradeResult(result, fixture).evidenceFailures[0].missingCaseEvidence,
    ["runtime-disclosure"],
  );
  runtime.codeEvidence = originalEvidence;
  runtime.locations.pop();
  result.findings[0].locations.push(context);
  assert.equal(gradeResult(result, fixture).falsePositiveCount, 1);
  result.findings[0].locations.pop();
  for (const location of [
    { ...context, startLine: 1 },
    { ...context, startLine: 1, endLine: context.startLine },
  ]) {
    runtime.locations.push(location);
    assert.equal(gradeResult(result, fixture).falsePositiveCount, 1);
    runtime.locations.pop();
  }
  runtime.locations = [context];
  assert.equal(gradeResult(result, fixture).cases.at(-1)!.found, false);
  assert.equal(gradeResult(result, fixture).falsePositiveCount, 1);
});

test("recognizes the embedded signing key at its declaration with CWE-321", () => {
  const result = retainedResult();
  const index = fixture.positives.findIndex(({ id }) => id === "private-key");
  const key = fixture.positives[index];
  const finding = result.findings[index];
  for (const category of [
    "Embedded cryptographic signing key",
    "Cryptographic key disclosure",
    "Signing-key exposure",
  ]) {
    finding.taxonomy = { category, cwe: ["CWE-321"] };
    assert.equal(gradeResult(result, fixture).passed, true);
  }
  for (const category of [
    "public signing key",
    "not a signing key",
    "SQL injection",
  ]) {
    finding.taxonomy.category = category;
    assert.equal(gradeResult(result, fixture).cases[index].found, false);
  }
  finding.taxonomy.category = "Signing key exposure";
  finding.taxonomy.cwe = ["CWE-200"];
  assert.equal(gradeResult(result, fixture).cases[index].found, false);
  finding.taxonomy.cwe = ["CWE-321"];
  for (const [path, line] of [
    ["config/public.pem", 1],
    [key.path, key.consumerLine!],
  ] as const) {
    finding.locations = [{ path, startLine: line, role: "root_control" }];
    assert.equal(gradeResult(result, fixture).cases[index].found, false);
  }
});

test("accepts a secret's valid source range and sensitive-data category", () => {
  const result = retainedResult();
  result.findings[0].locations[0].endLine = fixture.positives[0].line + 1;
  result.findings[0].taxonomy.category = "sensitive-data-exposure";
  assert.equal(gradeResult(result, fixture).passed, true);
});

test("sensitive information disclosure requires a credential-specific CWE for source literals", () => {
  const result = retainedResult();
  for (const cwe of ["CWE-798", "CWE-200", "CWE-540"]) {
    result.findings[0].taxonomy = {
      category: "Sensitive information disclosure",
      cwe: [cwe],
    };
    assert.equal(gradeResult(result, fixture).passed, cwe === "CWE-798", cwe);
  }
});

test("response-specific categories identify the runtime leak with CWE-201", () => {
  const result = retainedResult();
  const index = fixture.positives.findIndex(
    (expected) => expected.id === "runtime-disclosure",
  );
  const runtime = result.findings[index];
  for (const category of [
    "Sensitive information in response",
    "Insertion of Sensitive Information Into Sent Data",
    "sensitive-information-in-response",
  ]) {
    runtime.taxonomy = { category, cwe: ["CWE-201"] };
    assert.equal(gradeResult(result, fixture).passed, true, category);
    runtime.taxonomy.cwe = ["CWE-200"];
    assert.equal(gradeResult(result, fixture).passed, false, category);
  }
  runtime.taxonomy = { category: "Response", cwe: ["CWE-201"] };
  assert.equal(gradeResult(result, fixture).passed, false);
  runtime.taxonomy.category = "Sensitive information in response";
  result.findings[0].taxonomy.category = runtime.taxonomy.category;
  assert.equal(gradeResult(result, fixture).cases[0].found, false);
});

test("runtime taxonomy distinguishes denied leaks from missing protections", () => {
  const result = retainedResult();
  const index = fixture.positives.findIndex(
    (expected) => expected.id === "runtime-disclosure",
  );
  for (const [category, cwe, found] of [
    ["not a data leak", "CWE-200", false],
    ["not an exposure", "CWE-200", false],
    ["not exposed", "CWE-200", false],
    ["non_disclosure", "CWE-200", false],
    ["deny information disclosure", "CWE-200", false],
    ["no sensitive data leakage", "CWE-200", false],
    ["data-leak-free", "CWE-200", false],
    ["information disclosure with no secret in source", "CWE-200", true],
    ["missing authentication", "CWE-306", true],
    ["no authentication", "CWE-306", true],
    ["insufficient access control", "CWE-862", true],
    ["Insufficiently Protected Credentials", "CWE-522", true],
    ["insufficientlyProtectedCredentials", "CWE-522", true],
    ["Insufficiently Protected Credentials", "CWE-200", false],
    ["hardcoded credentials", "CWE-522", false],
    ["credential management", "CWE-522", false],
  ] as const) {
    result.findings[index].taxonomy = { category, cwe: [cwe] };
    const report = gradeResult(result, fixture);
    assert.equal(report.cases[index].found, found, `${category} (${cwe})`);
    assert.equal(report.passed, found, `${category} (${cwe})`);
  }
});

for (const category of [
  "password-in-configuration",
  "token-exposure",
  "api-key-exposure",
]) {
  test(`accepts credential category ${category}`, () => {
    const result = retainedResult();
    result.findings[0].taxonomy.category = category;
    assert.equal(gradeResult(result, fixture).passed, true);
  });
}

test("accepts equivalent CWE spelling without weakening generic disclosure categories", () => {
  for (const [cwe, generic] of [
    ["cwe-798", false],
    ["CWE-0798", false],
    [" CWE-798 ", false],
    [" cwe-00200 ", true],
    ["CWE-0540", true],
  ] as const) {
    const result = retainedResult();
    result.findings[0].taxonomy.cwe = ["CWE-798", cwe];
    assert.equal(gradeResult(result, fixture).passed, true, cwe);
    if (generic) {
      result.findings[0].taxonomy.category = "sensitive-data-exposure";
      assert.equal(gradeResult(result, fixture).passed, false, cwe);
    }
  }
});

test("rejects unrelated or malformed CWE identifiers after normalization", () => {
  for (const cwe of [
    " cwe-0089 ",
    "CWE-798-extra",
    "CWE-798.0",
    "798",
    "CWE-321",
  ]) {
    for (const withValidCwe of [false, true]) {
      const result = retainedResult();
      result.findings[0].taxonomy.cwe = withValidCwe ? ["CWE-798", cwe] : [cwe];
      const report = gradeResult(result, fixture);
      assert.equal(report.passed, false, cwe);
      assert.equal(report.cases[0].found, withValidCwe, cwe);
      assert.equal(report.falsePositiveCount, 1, cwe);
    }
  }
});

test("matches path casing only on Windows while preserving citation checks", () => {
  const descriptor = Object.getOwnPropertyDescriptor(process, "platform");
  try {
    for (const platform of ["linux", "win32"]) {
      Object.defineProperty(process, "platform", { value: platform });
      const result = retainedResult();
      const finding = result.findings[0];
      finding.locations.push(
        { path: "src/client.py", startLine: 7, role: "sink" },
        { path: "README.md", startLine: 1, role: "supporting" },
      );
      finding.codeEvidence.push(sourceEvidence(fixture, "README.md", 1));
      for (const citation of [...finding.locations, ...finding.codeEvidence])
        citation.path =
          ".\\" + citation.path.toUpperCase().replaceAll("/", "\\");
      assert.equal(gradeResult(result, fixture).passed, platform === "win32");
      if (platform === "win32") {
        finding.locations[1].endLine = 999;
        assert.equal(gradeResult(result, fixture).passed, false);
        delete finding.locations[1].endLine;
        finding.locations[0].path = "SRC\\RUNTIME_CONFIG.PY";
        const report = gradeResult(result, fixture);
        assert.equal(report.passed, false);
        assert.equal(report.cases[0].found, false);
        assert.equal(report.falsePositiveCount, 1);
      }
    }
  } finally {
    Object.defineProperty(process, "platform", descriptor!);
  }
});

for (const cwe of ["CWE-256", "CWE-259", "CWE-260"]) {
  test(`accepts ${cwe} for the password in the database configuration`, () => {
    const result = retainedResult();
    const databaseIndex = fixture.positives.findIndex(
      (entry) => entry.id === "dotenv-url",
    );
    result.findings[databaseIndex].taxonomy.cwe = [cwe];
    result.findings[databaseIndex].taxonomy.category =
      "password-in-configuration";
    assert.equal(gradeResult(result, fixture).passed, true);
  });
}

for (const cwe of ["CWE-312", "CWE-313"]) {
  test(`accepts ${cwe} for credentials stored in source and configuration files`, () => {
    const result = retainedResult();
    for (const { taxonomy } of result.findings) {
      if (taxonomy.category === "hardcoded-credentials") taxonomy.cwe = [cwe];
    }
    assert.equal(gradeResult(result, fixture).passed, true);

    result.findings[0].taxonomy.category = "sql-injection";
    const report = gradeResult(result, fixture);
    assert.equal(report.passed, false);
    assert.equal(report.cases[0].found, false);
  });
}

test("accepts cryptographic-key categories only for a matching CWE-321 exposure", () => {
  const index = fixture.positives.findIndex(({ id }) => id === "private-key");
  for (const [category, cwe, passes] of [
    ["Embedded cryptographic key", "CWE-321", true],
    ["cryptographic_keys", "CWE-321", true],
    ["Embedded public cryptographic key", "CWE-321", false],
    ["Not an embedded cryptographic key", "CWE-321", false],
    ["Weak cryptographic key", "CWE-321", false],
    ["Embedded cryptographic key", "CWE-200", false],
    ["Embedded cryptographic key", "CWE-798", false],
  ] as const) {
    const result = retainedResult();
    result.findings[index].taxonomy = { category, cwe: [cwe] };
    assert.equal(gradeResult(result, fixture).passed, passes, category);
  }
});

test("keeps password and cryptographic-key CWEs specific to those exposures", () => {
  for (const [index, expected] of fixture.positives.entries()) {
    for (const [cwe, applicableId] of [
      ["CWE-256", "dotenv-url"],
      ["CWE-259", "dotenv-url"],
      ["CWE-260", "dotenv-url"],
      ["CWE-321", "private-key"],
    ] as const) {
      if (expected.id === applicableId) continue;
      const result = retainedResult();
      result.findings[index].taxonomy.cwe = [cwe];
      const report = gradeResult(result, fixture);
      assert.equal(report.passed, false, `${expected.id}:${cwe}`);
      assert.equal(report.cases[index].found, false, `${expected.id}:${cwe}`);
    }
  }
});

for (const cwe of ["CWE-200", "CWE-540"]) {
  test(`accepts ${cwe} for specifically categorized credential exposure`, () => {
    const result = retainedResult();
    for (const { taxonomy } of result.findings) {
      if (taxonomy.category === "hardcoded-credentials") taxonomy.cwe = [cwe];
    }
    assert.equal(gradeResult(result, fixture).passed, true);

    result.findings[0].taxonomy.category = "sensitive-data-exposure";
    const report = gradeResult(result, fixture);
    assert.equal(report.passed, false);
    assert.equal(report.cases[0].found, false);
  });
}

for (const negativeIndex of fixture.negatives.keys()) {
  test(`rejects a finding against negative control ${negativeIndex}`, () => {
    const result = retainedResult();
    result.findings.push({
      taxonomy: { category: "hardcoded-credentials", cwe: ["CWE-798"] },
      locations: [
        {
          path: fixture.negatives[negativeIndex],
          startLine: 1,
          role: "root_control",
        },
      ],
    } as TestFinding);
    const report = gradeResult(result, fixture);
    assert.equal(report.recall, 1);
    assert.equal(report.falsePositiveCount, 1);
    assert.equal(report.passed, false);
  });
}

test("a provider-format placeholder and an access key ID alone cannot satisfy credential recall", () => {
  for (const data of [fixture, createFixture(true)]) {
    for (const [path, marker] of [
      ["examples/settings.env.example", "GITLAB_TOKEN=glpat-"],
      ["src/constants.py", "AWS_ACCESS_KEY_ID"],
    ]) {
      const line =
        data.files[path]
          .split("\n")
          .findIndex((text) => text.includes(marker)) + 1;
      assert.ok(line > 0);
      const result = retainedResult(data);
      result.findings.push({
        taxonomy: { category: "token-exposure", cwe: ["CWE-798"] },
        locations: [{ path, startLine: line, role: "root_control" }],
        codeEvidence: [sourceEvidence(data, path, line)],
      });
      assert.equal(gradeResult(result, data).falsePositiveCount, 1);
    }
  }
});

for (const role of [
  "supporting",
  "support",
  "context",
  "consumer",
  "expected_control",
]) {
  test(`benign ${role} context does not become a false positive`, () => {
    for (const path of [
      fixture.negatives[0],
      `./${fixture.negatives[0]}`,
      `.\\${fixture.negatives[0].replaceAll("/", "\\")}`,
    ]) {
      const result = retainedResult();
      result.findings[0].locations.push({
        path,
        startLine: 1,
        endLine: null,
        role,
      });
      assert.equal(gradeResult(result, fixture).passed, true);
      result.findings[0].locations.at(-1)!.endLine = 4;
      assert.equal(gradeResult(result, fixture).passed, true);
    }
  });

  test(`rejects invalid ${role} source citations`, () => {
    for (const location of [
      { path: "src/absent.py", startLine: 999 },
      { path: "src/runtime_config.py", startLine: 0 },
      { path: "src/runtime_config.py", startLine: -1, endLine: 1 },
      { path: "src/runtime_config.py", startLine: 999 },
      { path: "src/runtime_config.py", startLine: 3, endLine: 1 },
      { path: "src/runtime_config.py", startLine: 1, endLine: 999 },
    ]) {
      const result = retainedResult();
      result.findings[0].locations.push({ ...location, role });
      const report = gradeResult(result, fixture);
      assert.equal(report.recall, 1);
      assert.equal(report.falsePositiveCount, 1);
      assert.equal(report.passed, false);
    }
  });
}

for (const [name, location] of [
  ["unrelated source file", { path: "README.md", startLine: 1 }],
  ["invented source file", { path: "src/absent.py", startLine: 1 }],
  ["wrong line in a positive file", { path: "src/retired.py", startLine: 1 }],
  ["negative control", { path: "src/runtime_config.py", startLine: 1 }],
] as const) {
  test(`rejects an additional non-supporting location at ${name}`, () => {
    const result = retainedResult();
    result.findings[0].locations.push({ ...location, role: "root_control" });
    const report = gradeResult(result, fixture);
    assert.equal(report.recall, 1);
    assert.equal(report.falsePositiveCount, 1);
    assert.equal(report.passed, false);
  });
}

for (const role of ["root_control", "sink"]) {
  test(`rejects a ${role} citation classified only by a different finding`, () => {
    const result = retainedResult();
    const finding = result.findings[0];
    finding.taxonomy.cwe = ["CWE-522"];
    const key = fixture.positives.find(
      (expected) => expected.id === "private-key",
    )!;
    const location = {
      path: key.path,
      startLine: role === "sink" ? key.consumerLine! : key.line,
      role: "supporting",
    };
    finding.locations.push(location);
    assert.equal(gradeResult(result, fixture).passed, true);

    location.role = role;
    const report = gradeResult(result, fixture);
    assert.equal(report.recall, 1);
    assert.equal(report.falsePositiveCount, 1);
    assert.deepEqual(report.errors, [
      "false positives or incorrect taxonomy/locations",
    ]);
  });
}

test("correct finding locations cannot hide missing or unrelated code evidence", () => {
  for (const evidence of [
    undefined,
    [],
    [sourceEvidence(fixture, "src/client.py", 1)],
    [sourceEvidence(fixture, "src/runtime_config.py", 3)],
    [{ ...sourceEvidence(fixture, "src/client.py", 3), code: " \n" }],
  ]) {
    const result = retainedResult();
    result.findings[0].codeEvidence = evidence as CodeEvidence[];
    const report = gradeResult(result, fixture);
    assert.equal(report.recall, 1);
    assert.equal(report.passed, false);
    assert.deepEqual(report.errors, ["missing or invalid code evidence"]);
  }
});

test("rejects fabricated source text at otherwise valid evidence locations", () => {
  for (const code of [
    "invented source",
    sourceEvidence(fixture, "src/client.py", 1).code,
    sourceEvidence(fixture, "src/client.py", 3).code.replace(
      "SERVICE_TOKEN",
      "OTHER_TOKEN",
    ),
  ]) {
    const result = retainedResult();
    result.findings[0].codeEvidence[0].code = code;
    const report = gradeResult(result, fixture);
    assert.equal(report.recall, 1);
    assert.equal(report.falsePositiveCount, 0);
    assert.deepEqual(report.evidenceFailures, [
      {
        index: 0,
        incorrectSnippets: [{ path: "src/client.py", startLine: 3 }],
        missingCaseEvidence: [],
      },
    ]);
    assert.deepEqual(report.errors, ["missing or invalid code evidence"]);
  }

  const result = retainedResult();
  result.findings[0].codeEvidence.push({
    ...sourceEvidence(fixture, "README.md", 1),
    code: "invented supporting context",
  });
  assert.deepEqual(gradeResult(result, fixture).errors, [
    "missing or invalid code evidence",
  ]);
});

test("rejects invented and out-of-bounds citations alongside valid evidence", () => {
  for (const citation of [
    { path: "src/absent.py", startLine: 1 },
    { path: "src/client.py", startLine: 0 },
    { path: "src/client.py", startLine: 999 },
    { path: "src/client.py", startLine: 7, code: "first line\nsecond line" },
  ]) {
    const result = retainedResult();
    result.findings[0].codeEvidence.push({
      ...sourceEvidence(fixture, "src/client.py", 3),
      ...citation,
    });
    assert.deepEqual(gradeResult(result, fixture).errors, [
      "missing or invalid code evidence",
    ]);
  }
});

test("accepts multiline exposure and consumer excerpts with supporting context", () => {
  for (const [startLine, endLine] of [
    [1, 3],
    [4, 7],
  ] as const) {
    const result = retainedResult();
    result.findings[0].codeEvidence = [
      sourceEvidence(fixture, "src/client.py", startLine, endLine),
      sourceEvidence(fixture, "src/runtime_config.py", 3),
    ];
    result.findings[0].codeEvidence[0].code =
      result.findings[0].codeEvidence[0].code!.replaceAll("\n", "\r\n") +
      "\r\n";
    assert.equal(gradeResult(result, fixture).passed, true);
  }
});

test("consumer evidence and sinks must cover credential use, not function framing", () => {
  for (const [id, line] of [
    ["active-source", 5],
    ["active-source", 6],
    ["integration-source", 5],
    ["integration-source", 6],
    ["private-key", 5],
    ["private-key", 7],
  ] as const) {
    const index = fixture.positives.findIndex((expected) => expected.id === id);
    const expected = fixture.positives[index];
    const result = retainedResult();
    result.findings[index].codeEvidence = [
      sourceEvidence(fixture, expected.path, line),
    ];
    assert.deepEqual(
      gradeResult(result, fixture).errors,
      ["missing or invalid code evidence"],
      `${id}:${line}`,
    );

    const invalidSink = retainedResult();
    invalidSink.findings[index].locations.push({
      path: expected.path,
      startLine: line,
      role: "sink",
    });
    assert.equal(
      gradeResult(invalidSink, fixture).falsePositiveCount,
      1,
      `${id}:${line}`,
    );
  }
});

test("accepts actual credential-use lines and excerpts containing them", () => {
  for (const [index, expected] of fixture.positives.entries()) {
    if (expected.consumerLine === null) continue;
    for (const [startLine, endLine] of [
      [expected.consumerLine, expected.consumerLine],
      [5, expected.lineCount],
    ] as const) {
      const result = retainedResult();
      result.findings[index].codeEvidence = [
        sourceEvidence(fixture, expected.path, startLine, endLine),
      ];
      result.findings[index].locations.push({
        path: expected.path,
        startLine,
        endLine,
        role: "sink",
      });
      assert.equal(gradeResult(result, fixture).passed, true, expected.id);
    }
  }
});

test("multiple expected exposures can share a finding", () => {
  const result = retainedResult();
  const unused = result.findings.splice(1, 1)[0];
  result.findings[0].locations.push(...unused.locations);
  const incomplete = gradeResult(result, fixture);
  assert.deepEqual(incomplete.errors, ["missing or invalid code evidence"]);
  assert.deepEqual(incomplete.evidenceFailures, [
    { index: 0, incorrectSnippets: [], missingCaseEvidence: ["unused-source"] },
  ]);
  result.findings[0].codeEvidence.push(...unused.codeEvidence);
  assert.equal(gradeResult(result, fixture).passed, true);
});

test("grouped exposures retain their applicable CWE classifications", () => {
  const result = retainedResult();
  const indices = ["dotenv-url", "private-key"].map((id) =>
    fixture.positives.findIndex((expected) => expected.id === id),
  );
  const grouped = indices.map((index) => result.findings[index]);
  const finding = {
    ...grouped[0],
    taxonomy: {
      category: "hardcoded-credentials",
      cwe: ["CWE-256", "CWE-321"],
    },
    locations: grouped.flatMap((entry) => entry.locations),
    codeEvidence: grouped.flatMap((entry) => entry.codeEvidence),
  };
  result.findings = result.findings.filter(
    (_, index) => !indices.includes(index),
  );
  result.findings.push(finding);
  assert.equal(gradeResult(result, fixture).passed, true);

  finding.taxonomy.cwe.push("CWE-89");
  const report = gradeResult(result, fixture);
  assert.equal(report.recall, 1);
  assert.equal(report.falsePositiveCount, 1);
  assert.equal(report.passed, false);
});

for (const role of ["supporting", "expected_control"]) {
  test(`${role} citations cannot satisfy an independently missed exposure`, () => {
    const result = retainedResult();
    const unused = result.findings.splice(1, 1)[0];
    result.findings[0].locations.push({
      ...unused.locations[0],
      role,
    });
    const report = gradeResult(result, fixture);
    assert.equal(report.cases[1].found, false);
    assert.equal(report.passed, false);
  });
}

test("accepts a credential-use location only alongside its matched exposure", () => {
  const result = retainedResult();
  for (const [index, expected] of fixture.positives.entries()) {
    if (expected.consumerLine === null) continue;
    const use: SourceLocation = {
      path: expected.path,
      startLine: expected.consumerLine,
      endLine: expected.lineCount,
    };
    if (expected.id === "private-key") use.role = "Signing operation";
    result.findings[index].locations.push(use);
    const onlyConsumer = retainedResult();
    onlyConsumer.findings[index].locations = [use];
    assert.equal(gradeResult(onlyConsumer, fixture).cases[index].found, false);
  }
  assert.equal(gradeResult(result, fixture).passed, true);

  for (const [path, startLine, role] of [
    ["README.md", 1, "sink"],
    ["src/absent.py", 5, "sink"],
    ["src/client.py", 1, "credential-use sink"],
    ["src/client.py", 6, "Authentication use"],
  ] as const) {
    const invalid = retainedResult();
    invalid.findings[0].locations.push({ path, startLine, role });
    assert.equal(gradeResult(invalid, fixture).falsePositiveCount, 1);
  }
});

for (const [name, separator] of [
  ["POSIX", "/"],
  ["Windows", "\\"],
] as const) {
  test(`accepts ${name} source and credential-use paths with relative prefixes`, () => {
    for (const prefix of ["", "./", "././", ".\\", ".\\./", "./.\\"]) {
      const result = retainedResult();
      for (const [index, expected] of fixture.positives.entries()) {
        const path = `${prefix}${expected.path.replaceAll("/", separator)}`;
        result.findings[index].locations[0].path = path;
        result.findings[index].codeEvidence[0].path = path;
        if (expected.consumerLine !== null) {
          result.findings[index].locations.push({
            path,
            startLine: expected.consumerLine,
            endLine: expected.lineCount,
            role: "sink",
          });
        }
      }
      assert.equal(gradeResult(result, fixture).passed, true, prefix);
    }
  });
}

test("path normalization does not make unrelated or unsafe source locations valid", () => {
  for (const path of [
    "./src/absent.py",
    "./src/../src/client.py",
    "/src/client.py",
    ".\\src\\absent.py",
    ".\\src\\..\\src\\client.py",
    "\\src\\client.py",
    "C:\\src\\client.py",
  ]) {
    const result = retainedResult();
    result.findings[0].locations[0].path = path;
    const report = gradeResult(result, fixture);
    assert.equal(report.cases[0].found, false, path);
    assert.equal(report.falsePositiveCount, 1, path);
    assert.equal(report.passed, false, path);
  }
});

test("accepts the private-key body and rejects reversed source ranges", () => {
  const result = retainedResult();
  const keyIndex = fixture.positives.findIndex(
    (entry) => entry.id === "private-key",
  );
  result.findings[keyIndex].locations[0].startLine++;
  assert.equal(gradeResult(result, fixture).passed, true);
  result.findings[keyIndex].locations[0].endLine =
    fixture.positives[keyIndex].line;
  assert.equal(gradeResult(result, fixture).passed, false);
});

for (const footerLocation of [true, false]) {
  test(`rejects footer-only private-key evidence with ${footerLocation ? "footer" : "declaration"} location`, () => {
    const result = retainedResult();
    const keyIndex = fixture.positives.findIndex(
      (entry) => entry.id === "private-key",
    );
    const path = fixture.positives[keyIndex].path;
    const footerLine =
      fixture.files[path]
        .split("\n")
        .findIndex((line) => line.includes("-----END PRIVATE KEY-----")) + 1;
    const finding = result.findings[keyIndex];
    if (footerLocation) finding.locations[0].startLine = footerLine;
    finding.codeEvidence = [sourceEvidence(fixture, path, footerLine)];
    const report = gradeResult(result, fixture);
    assert.equal(report.passed, false);
    assert.equal(report.cases[keyIndex].found, !footerLocation);
    if (!footerLocation)
      assert.deepEqual(report.errors, ["missing or invalid code evidence"]);
  });
}

test("accepts public-key context alongside credential evidence", () => {
  const result = retainedResult();
  result.findings[0].codeEvidence.push(
    sourceEvidence(fixture, "src/signing.mjs", 2, 4),
    sourceEvidence(fixture, "config/public.pem", 1, 3),
  );
  assert.equal(gradeResult(result, fixture).passed, true);
});

test("scope notes neither fail correct findings nor compensate for missing findings", () => {
  const result = retainedResult();
  Object.assign(result.coverage, {
    completeness: "partial",
    explicitExclusions: [
      { pattern: ".", reason: "Review focused on reported exposures." },
    ],
    deferred: [{ reason: "Runtime confirmation was unavailable." }],
    surfaces: [{ label: "Runtime", disposition: "needs_follow_up" }],
    openQuestions: ["Have the embedded credentials expired?"],
  });
  assert.equal(gradeResult(result, fixture).passed, true);
  result.findings.pop();
  assert.equal(gradeResult(result, fixture).passed, false);
});

test("supplies the policy inventory for the entire synthetic repository", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "source-audit-policy-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const directory = join(root, "repository", "config");
  await mkdir(directory, { recursive: true });
  await writeFile(
    join(directory, "SECURITY.md"),
    "Review local configuration.",
  );

  const prepared = await prepareEval(root);
  assert.ok(prepared.prompt.includes('["config/SECURITY.md"]'));
});

test("stages and hashes the selected workflow's audit briefs", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "source-audit-comparison-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const brief = "validate-scan-findings.md";
  const workflow = join(root, "workflow");
  await mkdir(workflow);
  const corePromptPath = join(workflow, "core-scan.md");
  await writeFile(corePromptPath, `Validate with [this brief](${brief}).`);

  const standalone = await prepareEval(join(root, "standalone"), {
    corePromptPath,
  });
  const bundled = await readFile(
    new URL(
      `../../plugins/codex-security/references/${brief}`,
      import.meta.url,
    ),
    "utf8",
  );
  assert.equal(
    await readFile(join(standalone.runtime, "references", brief), "utf8"),
    bundled,
  );

  await writeFile(
    join(workflow, brief),
    "Validation instructions under comparison.",
  );
  const fixedReference = "threat-model.md";
  await writeFile(join(workflow, fixedReference), "Alternate threat model.");
  const selected = await prepareEval(join(root, "selected"), {
    corePromptPath,
  });
  assert.equal(
    await readFile(join(selected.runtime, "references", brief), "utf8"),
    "Validation instructions under comparison.",
  );
  assert.equal(selected.promptSha256, standalone.promptSha256);
  assert.equal(
    selected.referenceSha256[fixedReference],
    standalone.referenceSha256[fixedReference],
  );
  assert.notEqual(
    selected.referenceSha256[brief],
    standalone.referenceSha256[brief],
  );
  assert.ok(!("baseline-auditor.md" in selected.referenceSha256));
});

test("stages production prompt unchanged and no labels; grades only the final SDK response", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "source-audit-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const prepared = await prepareEval(root);
  const production = await readFile(
    new URL(
      "../../plugins/codex-security/references/core-scan.md",
      import.meta.url,
    ),
    "utf8",
  );
  assert.equal(
    await readFile(join(prepared.runtime, "references/core-scan.md"), "utf8"),
    production,
  );
  assert.ok(prepared.prompt.endsWith(production));
  for (const brief of ["baseline-auditor.md", "focused-investigator.md"]) {
    const source = new URL(
      `../../plugins/codex-security/references/${brief}`,
      import.meta.url,
    );
    assert.deepEqual(
      await readFile(join(prepared.runtime, "references", brief)),
      await readFile(source),
    );
  }
  const staged = (
    await readdir(prepared.repo, { recursive: true, withFileTypes: true })
  )
    .filter((entry) => entry.isFile())
    .map((entry) =>
      join(entry.parentPath, entry.name)
        .slice(prepared.repo.length + 1)
        .replaceAll("\\", "/"),
    );
  assert.deepEqual(staged.sort(), Object.keys(prepared.fixture.files).sort());
  for (const expected of prepared.fixture.positives)
    assert.equal(prepared.prompt.includes(expected.id), false);
  for (const value of prepared.fixture.secretValues)
    assert.equal(prepared.prompt.includes(value), false);

  let settings: ThreadOptions | undefined;
  const fakeCodex: EvalCodex = {
    startThread(options) {
      settings = options;
      return {
        async runStreamed(prompt, options) {
          assert.equal(prompt, prepared.prompt);
          assert.ok(
            (options.outputSchema as { properties: { findings: unknown } })
              .properties.findings,
          );
          return {
            events: (async function* () {
              for (const result of [
                retainedResult(prepared.fixture),
                { findings: [], coverage: {} },
              ]) {
                yield {
                  type: "item.completed",
                  item: { type: "agent_message", text: JSON.stringify(result) },
                };
              }
              yield {
                type: "turn.completed",
                usage: { input_tokens: 1, output_tokens: 1 },
              };
            })(),
          };
        },
      };
    },
  };
  const { report } = await runPreparedEval(prepared, fakeCodex);
  assert.equal(report.recall, 0);
  assert.equal(settings!.sandboxMode, undefined);
  assert.deepEqual(settings!.additionalDirectories, [prepared.runtime]);
  assert.equal(settings!.workingDirectory, prepared.repo);
});

test("named read-only profile excludes gold and credentials without a legacy sandbox override", () => {
  const codexPath = "/tmp/native-package[local]/bin/codex";
  const home = "/tmp/eval-home[private]";
  const settings = codexSettings(home, codexPath, {
    PATH: "/usr/bin",
    DATABASE_URL: "synthetic-private-dsn",
    CODEX_API_KEY: "synthetic-model-auth",
    CODEX_HOME: "/tmp/ambient-home",
    CODEX_SQLITE_HOME: "/tmp/ambient-state",
    CODEX_CLI_PATH: "/tmp/ambient-codex",
  });
  const config = structuredClone(
    parse(settings.configOverrides.join("\n")),
  ) as {
    default_permissions: string;
    features: Record<string, boolean>;
    allow_login_shell: boolean;
    windows: { sandbox: string };
    shell_environment_policy: Record<string, unknown>;
    permissions: Record<
      string,
      { filesystem: unknown; network: Record<string, unknown> }
    >;
  };
  assert.deepEqual(settings.env, {
    PATH: "/usr/bin",
    CODEX_API_KEY: "synthetic-model-auth",
    CODEX_HOME: home,
    CODEX_SQLITE_HOME: home,
    CODEX_CLI_PATH: codexPath,
  });
  assert.equal(settings.codexPathOverride, codexPath);
  assert.equal(
    config.default_permissions,
    DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID,
  );
  assert.equal(config.features.plugins, false);
  assert.equal(config.features.apps, false);
  assert.equal(config.features.memories, false);
  assert.equal(config.features.shell_snapshot, false);
  assert.equal(config.allow_login_shell, false);
  assert.equal(config.windows.sandbox, "elevated");
  assert.deepEqual(config.shell_environment_policy, {
    inherit: "core",
    ignore_default_excludes: false,
  });
  assert.deepEqual(
    config.permissions[DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID].filesystem,
    {
      ":minimal": "read",
      ":workspace_roots": "read",
      [dirname(dirname(codexPath))]: { ".": "read" },
      [resolve(home)]: { ".": "deny" },
    },
  );
  assert.deepEqual(
    config.permissions[DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID].network,
    { enabled: false },
  );
  assert.equal(
    threadSettings({ repo: "/tmp/repo", runtime: "/tmp/runtime" }).sandboxMode,
    undefined,
  );
});

test("grades current worker review state", () => {
  const result = retainedResult();
  const { coverage, ...draft } = result;
  assert.equal(
    gradeResult({ ...draft, reviewState: coverage }, fixture).passed,
    true,
  );
});
