import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { parse } from "../../sdk/typescript/node_modules/smol-toml/dist/index.js";
import { createFixture } from "./fixtures.mjs";
import { gradeResult } from "./grade.mjs";
import {
  codexSettings,
  prepareEval,
  runPreparedEval,
  threadSettings,
} from "./harness.mjs";
import { DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID } from "./runtime.mjs";

function sourceEvidence(fixture, path, startLine, endLine = startLine) {
  const source = fixture.files[path]
    .split("\n")
    .slice(startLine - 1, endLine)
    .join("\n");
  return {
    id: `${path}:${startLine}`,
    label: "Source context",
    path,
    startLine,
    code: source,
    explanation: "Source-backed credential declaration.",
  };
}

function retainedResult(fixture) {
  return {
    findings: fixture.positives.map((expected) => ({
      title: "Embedded credential",
      taxonomy: { category: "hardcoded-credentials", cwe: [expected.cwes[0]] },
      locations: [
        { path: expected.path, startLine: expected.line, role: "root_control" },
      ],
      codeEvidence: [
        sourceEvidence(fixture, expected.path, expected.line, expected.endLine),
      ],
    })),
    coverage: {
      completeness: "complete",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
      openQuestions: [],
    },
  };
}

test("counts every retained secret location, including unused and integration source", () => {
  const fixture = createFixture();
  const report = gradeResult(retainedResult(fixture), fixture);
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
    ],
  );
});

test("resolved, deferred, and intermediate findings do not satisfy final recall", () => {
  const fixture = createFixture();
  const result = retainedResult(fixture);
  result.coverage.deferred = result.findings;
  result.resolved_questions = result.findings;
  result.findings = [];
  const report = gradeResult(result, fixture);
  assert.equal(report.passed, false);
  assert.equal(report.recall, 0);
});

for (const [name, mutate] of [
  [
    "wrong source line",
    (finding) => {
      finding.locations[0].startLine = 1;
    },
  ],
  [
    "wrong source path",
    (finding) => {
      finding.locations[0].path = "src/absent.py";
    },
  ],
  [
    "unrelated CWE",
    (finding) => {
      finding.taxonomy.cwe = ["CWE-89"];
    },
  ],
  [
    "unrelated category",
    (finding) => {
      finding.taxonomy.category = "sql-injection";
    },
  ],
  [
    "line range outside source",
    (finding) => {
      finding.locations[0].endLine = 100000;
    },
  ],
]) {
  test(`rejects ${name}`, () => {
    const fixture = createFixture();
    const result = retainedResult(fixture);
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
  "not-a-password-exposure",
  "non-token-exposure",
  "non-api-key-exposure",
  "no-secret-exposure",
  "secret-free",
  "without-credentials",
]) {
  test(`rejects negated category ${category}`, () => {
    const fixture = createFixture();
    const result = retainedResult(fixture);
    result.findings[0].taxonomy.category = category;
    const report = gradeResult(result, fixture);
    assert.equal(report.passed, false);
    assert.equal(report.cases[0].found, false);
  });
}

test("rejects unrelated categories containing credential-term substrings", () => {
  const fixture = createFixture();
  for (const category of ["tokenization-error", "secretary-data"]) {
    for (const cwe of ["CWE-798", "CWE-200"]) {
      const result = retainedResult(fixture);
      result.findings[0].taxonomy = { category, cwe: [cwe] };
      const report = gradeResult(result, fixture);
      assert.equal(report.passed, false, `${category}:${cwe}`);
      assert.equal(report.cases[0].found, false, `${category}:${cwe}`);
    }
  }
});

test("accepts plural and identifier-style credential categories", () => {
  const fixture = createFixture();
  for (const category of [
    "tokens-exposed",
    "secrets_in_source",
    "privateKeysInSource",
    "hardcodedCredentials",
    "credentialExposure",
  ]) {
    const result = retainedResult(fixture);
    result.findings[0].taxonomy.category = category;
    assert.equal(gradeResult(result, fixture).passed, true, category);
  }
});

test("accepts credential exposure with non-secret context in the category", () => {
  const fixture = createFixture();
  const result = retainedResult(fixture);
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

test("accepts a secret's valid source range and sensitive-data category", () => {
  const fixture = createFixture();
  const result = retainedResult(fixture);
  result.findings[0].locations[0].endLine = fixture.positives[0].line + 1;
  result.findings[0].taxonomy.category = "sensitive-data-exposure";
  assert.equal(gradeResult(result, fixture).passed, true);
});

for (const category of [
  "password-in-configuration",
  "token-exposure",
  "api-key-exposure",
]) {
  test(`accepts credential category ${category}`, () => {
    const fixture = createFixture();
    const result = retainedResult(fixture);
    result.findings[0].taxonomy.category = category;
    assert.equal(gradeResult(result, fixture).passed, true);
  });
}

test("accepts equivalent CWE spelling without weakening generic disclosure categories", () => {
  const fixture = createFixture();
  for (const [cwe, generic] of [
    ["cwe-798", false],
    ["CWE-0798", false],
    [" CWE-798 ", false],
    [" cwe-00200 ", true],
    ["CWE-0540", true],
  ]) {
    const result = retainedResult(fixture);
    result.findings[0].taxonomy.cwe = ["CWE-798", cwe];
    assert.equal(gradeResult(result, fixture).passed, true, cwe);
    if (generic) {
      result.findings[0].taxonomy.category = "sensitive-data-exposure";
      assert.equal(gradeResult(result, fixture).passed, false, cwe);
    }
  }
});

test("rejects unrelated or malformed CWE identifiers after normalization", () => {
  const fixture = createFixture();
  for (const cwe of [
    " cwe-0089 ",
    "CWE-798-extra",
    "CWE-798.0",
    "798",
    "CWE-321",
  ]) {
    for (const withValidCwe of [false, true]) {
      const result = retainedResult(fixture);
      result.findings[0].taxonomy.cwe = withValidCwe ? ["CWE-798", cwe] : [cwe];
      const report = gradeResult(result, fixture);
      assert.equal(report.passed, false, cwe);
      assert.equal(report.cases[0].found, withValidCwe, cwe);
      assert.equal(report.falsePositiveCount, 1, cwe);
    }
  }
});

test("matches path casing only on Windows while preserving citation checks", () => {
  const fixture = createFixture();
  const descriptor = Object.getOwnPropertyDescriptor(process, "platform");
  try {
    for (const platform of ["linux", "win32"]) {
      Object.defineProperty(process, "platform", { value: platform });
      const result = retainedResult(fixture);
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
    Object.defineProperty(process, "platform", descriptor);
  }
});

for (const cwe of ["CWE-256", "CWE-259", "CWE-260"]) {
  test(`accepts ${cwe} for the password in the database configuration`, () => {
    const fixture = createFixture();
    const result = retainedResult(fixture);
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
    const fixture = createFixture();
    const result = retainedResult(fixture);
    for (const finding of result.findings) finding.taxonomy.cwe = [cwe];
    assert.equal(gradeResult(result, fixture).passed, true);

    result.findings[0].taxonomy.category = "sql-injection";
    const report = gradeResult(result, fixture);
    assert.equal(report.passed, false);
    assert.equal(report.cases[0].found, false);
  });
}

test("keeps password and cryptographic-key CWEs specific to those exposures", () => {
  const fixture = createFixture();
  for (const [index, expected] of fixture.positives.entries()) {
    for (const [cwe, applicableId] of [
      ["CWE-256", "dotenv-url"],
      ["CWE-259", "dotenv-url"],
      ["CWE-260", "dotenv-url"],
      ["CWE-321", "private-key"],
    ]) {
      if (expected.id === applicableId) continue;
      const result = retainedResult(fixture);
      result.findings[index].taxonomy.cwe = [cwe];
      const report = gradeResult(result, fixture);
      assert.equal(report.passed, false, `${expected.id}:${cwe}`);
      assert.equal(report.cases[index].found, false, `${expected.id}:${cwe}`);
    }
  }
});

for (const cwe of ["CWE-200", "CWE-540"]) {
  test(`accepts ${cwe} for specifically categorized credential exposure`, () => {
    const fixture = createFixture();
    const result = retainedResult(fixture);
    for (const finding of result.findings) finding.taxonomy.cwe = [cwe];
    assert.equal(gradeResult(result, fixture).passed, true);

    result.findings[0].taxonomy.category = "sensitive-data-exposure";
    const report = gradeResult(result, fixture);
    assert.equal(report.passed, false);
    assert.equal(report.cases[0].found, false);
  });
}

for (const negativeIndex of [0, 1, 2, 3]) {
  test(`rejects a finding against negative control ${negativeIndex}`, () => {
    const fixture = createFixture();
    const result = retainedResult(fixture);
    result.findings.push({
      taxonomy: { category: "hardcoded-credentials", cwe: ["CWE-798"] },
      locations: [
        {
          path: fixture.negatives[negativeIndex],
          startLine: 1,
          role: "root_control",
        },
      ],
    });
    const report = gradeResult(result, fixture);
    assert.equal(report.recall, 1);
    assert.equal(report.falsePositiveCount, 1);
    assert.equal(report.passed, false);
  });
}

for (const role of [
  "supporting",
  "support",
  "context",
  "consumer",
  "expected_control",
]) {
  test(`benign ${role} context does not become a false positive`, () => {
    const fixture = createFixture();
    for (const path of [
      fixture.negatives[0],
      `./${fixture.negatives[0]}`,
      `.\\${fixture.negatives[0].replaceAll("/", "\\")}`,
    ]) {
      const result = retainedResult(fixture);
      result.findings[0].locations.push({
        path,
        startLine: 1,
        endLine: null,
        role,
      });
      assert.equal(gradeResult(result, fixture).passed, true);
      result.findings[0].locations.at(-1).endLine = 4;
      assert.equal(gradeResult(result, fixture).passed, true);
    }
  });

  test(`rejects invalid ${role} source citations`, () => {
    const fixture = createFixture();
    for (const location of [
      { path: "src/absent.py", startLine: 999 },
      { path: "src/runtime_config.py", startLine: 0 },
      { path: "src/runtime_config.py", startLine: -1, endLine: 1 },
      { path: "src/runtime_config.py", startLine: 999 },
      { path: "src/runtime_config.py", startLine: 3, endLine: 1 },
      { path: "src/runtime_config.py", startLine: 1, endLine: 999 },
    ]) {
      const result = retainedResult(fixture);
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
]) {
  test(`rejects an additional non-supporting location at ${name}`, () => {
    const fixture = createFixture();
    const result = retainedResult(fixture);
    result.findings[0].locations.push({ ...location, role: "root_control" });
    const report = gradeResult(result, fixture);
    assert.equal(report.recall, 1);
    assert.equal(report.falsePositiveCount, 1);
    assert.equal(report.passed, false);
  });
}

for (const role of ["root_control", "sink"]) {
  test(`rejects a ${role} citation classified only by a different finding`, () => {
    const fixture = createFixture();
    const result = retainedResult(fixture);
    const finding = result.findings[0];
    finding.taxonomy.cwe = ["CWE-522"];
    const key = fixture.positives.find(
      (expected) => expected.id === "private-key",
    );
    const location = {
      path: key.path,
      startLine: role === "sink" ? key.consumerLine : key.line,
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
  const fixture = createFixture();
  for (const evidence of [
    undefined,
    [],
    [sourceEvidence(fixture, "src/client.py", 1)],
    [sourceEvidence(fixture, "src/runtime_config.py", 3)],
    [{ ...sourceEvidence(fixture, "src/client.py", 3), code: " \n" }],
  ]) {
    const result = retainedResult(fixture);
    result.findings[0].codeEvidence = evidence;
    const report = gradeResult(result, fixture);
    assert.equal(report.recall, 1);
    assert.equal(report.passed, false);
    assert.deepEqual(report.errors, ["missing or invalid code evidence"]);
  }
});

test("rejects fabricated source text at otherwise valid evidence locations", () => {
  const fixture = createFixture();
  for (const code of [
    "invented source",
    sourceEvidence(fixture, "src/client.py", 1).code,
    sourceEvidence(fixture, "src/client.py", 3).code.replace(
      "SERVICE_TOKEN",
      "OTHER_TOKEN",
    ),
  ]) {
    const result = retainedResult(fixture);
    result.findings[0].codeEvidence[0].code = code;
    const report = gradeResult(result, fixture);
    assert.equal(report.recall, 1);
    assert.equal(report.falsePositiveCount, 0);
    assert.deepEqual(report.errors, ["missing or invalid code evidence"]);
  }

  const result = retainedResult(fixture);
  result.findings[0].codeEvidence.push({
    ...sourceEvidence(fixture, "README.md", 1),
    code: "invented supporting context",
  });
  assert.deepEqual(gradeResult(result, fixture).errors, [
    "missing or invalid code evidence",
  ]);
});

test("rejects invented and out-of-bounds citations alongside valid evidence", () => {
  const fixture = createFixture();
  for (const citation of [
    { path: "src/absent.py", startLine: 1 },
    { path: "src/client.py", startLine: 0 },
    { path: "src/client.py", startLine: 999 },
    { path: "src/client.py", startLine: 7, code: "first line\nsecond line" },
  ]) {
    const result = retainedResult(fixture);
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
  const fixture = createFixture();
  for (const [startLine, endLine] of [
    [1, 3],
    [4, 7],
  ]) {
    const result = retainedResult(fixture);
    result.findings[0].codeEvidence = [
      sourceEvidence(fixture, "src/client.py", startLine, endLine),
      sourceEvidence(fixture, "src/runtime_config.py", 3),
    ];
    result.findings[0].codeEvidence[0].code =
      result.findings[0].codeEvidence[0].code.replaceAll("\n", "\r\n") + "\r\n";
    assert.equal(gradeResult(result, fixture).passed, true);
  }
});

test("consumer evidence and sinks must cover credential use, not function framing", () => {
  const fixture = createFixture();
  for (const [id, line] of [
    ["active-source", 5],
    ["active-source", 6],
    ["integration-source", 5],
    ["integration-source", 6],
    ["private-key", 5],
    ["private-key", 7],
  ]) {
    const index = fixture.positives.findIndex((expected) => expected.id === id);
    const expected = fixture.positives[index];
    const result = retainedResult(fixture);
    result.findings[index].codeEvidence = [
      sourceEvidence(fixture, expected.path, line),
    ];
    assert.deepEqual(
      gradeResult(result, fixture).errors,
      ["missing or invalid code evidence"],
      `${id}:${line}`,
    );

    const invalidSink = retainedResult(fixture);
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
  const fixture = createFixture();
  for (const [index, expected] of fixture.positives.entries()) {
    if (expected.consumerLine === null) continue;
    for (const [startLine, endLine] of [
      [expected.consumerLine, expected.consumerLine],
      [5, expected.lineCount],
    ]) {
      const result = retainedResult(fixture);
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
  const fixture = createFixture();
  const result = retainedResult(fixture);
  const unused = result.findings.splice(1, 1)[0];
  result.findings[0].locations.push(...unused.locations);
  assert.deepEqual(gradeResult(result, fixture).errors, [
    "missing or invalid code evidence",
  ]);
  result.findings[0].codeEvidence.push(...unused.codeEvidence);
  assert.equal(gradeResult(result, fixture).passed, true);
});

test("grouped exposures retain their applicable CWE classifications", () => {
  const fixture = createFixture();
  const result = retainedResult(fixture);
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
    const fixture = createFixture();
    const result = retainedResult(fixture);
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

test("accepts real credential-use sinks without treating them as separate exposures", () => {
  const fixture = createFixture();
  const result = retainedResult(fixture);
  for (const [index, expected] of fixture.positives.entries()) {
    if (expected.consumerLine === null) continue;
    const sink = {
      path: expected.path,
      startLine: expected.consumerLine,
      endLine: expected.lineCount,
      role: "sink",
    };
    result.findings[index].locations.push(sink);
    const onlyConsumer = retainedResult(fixture);
    onlyConsumer.findings[index].locations = [sink];
    assert.equal(gradeResult(onlyConsumer, fixture).cases[index].found, false);
  }
  assert.equal(gradeResult(result, fixture).passed, true);

  for (const location of [
    { path: "README.md", startLine: 1 },
    { path: "src/absent.py", startLine: 5 },
    { path: "src/client.py", startLine: 1 },
  ]) {
    const invalid = retainedResult(fixture);
    invalid.findings[0].locations.push({ ...location, role: "sink" });
    assert.equal(gradeResult(invalid, fixture).falsePositiveCount, 1);
  }
});

for (const [name, separator] of [
  ["POSIX", "/"],
  ["Windows", "\\"],
]) {
  test(`accepts ${name} source and credential-use paths with relative prefixes`, () => {
    const fixture = createFixture();
    for (const prefix of ["", "./", "././", ".\\", ".\\./", "./.\\"]) {
      const result = retainedResult(fixture);
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
  const fixture = createFixture();
  for (const path of [
    "./src/absent.py",
    "./src/../src/client.py",
    "/src/client.py",
    ".\\src\\absent.py",
    ".\\src\\..\\src\\client.py",
    "\\src\\client.py",
    "C:\\src\\client.py",
  ]) {
    const result = retainedResult(fixture);
    result.findings[0].locations[0].path = path;
    const report = gradeResult(result, fixture);
    assert.equal(report.cases[0].found, false, path);
    assert.equal(report.falsePositiveCount, 1, path);
    assert.equal(report.passed, false, path);
  }
});

test("accepts the private-key body and rejects reversed source ranges", () => {
  const fixture = createFixture();
  const result = retainedResult(fixture);
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
    const fixture = createFixture();
    const result = retainedResult(fixture);
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
  const fixture = createFixture();
  const result = retainedResult(fixture);
  result.findings[0].codeEvidence.push(
    sourceEvidence(fixture, "src/signing.mjs", 2, 4),
    sourceEvidence(fixture, "config/public.pem", 1, 3),
  );
  assert.equal(gradeResult(result, fixture).passed, true);
});

test("incomplete coverage cannot pass even with all positive findings", () => {
  const fixture = createFixture();
  const result = retainedResult(fixture);
  result.coverage.completeness = "partial";
  assert.equal(gradeResult(result, fixture).passed, false);
});

for (const [name, mutate] of [
  [
    "deferred work",
    (coverage) => {
      coverage.deferred.push({
        reason: "source review remains unfinished",
        paths: ["README.md"],
      });
    },
  ],
  [
    "surface needing follow-up",
    (coverage) => {
      coverage.surfaces.push({
        label: "configuration",
        disposition: "needs_follow_up",
        notes: "source review remains unfinished",
      });
    },
  ],
]) {
  test(`complete coverage cannot pass with ${name}`, () => {
    const fixture = createFixture();
    const result = retainedResult(fixture);
    mutate(result.coverage);
    const report = gradeResult(result, fixture);
    assert.equal(report.recall, 1);
    assert.equal(report.passed, false);
    assert.deepEqual(report.errors, ["incomplete coverage"]);
  });
}

test("complete coverage permits reviewed surfaces and nonblocking questions", () => {
  const fixture = createFixture();
  const result = retainedResult(fixture);
  result.coverage.surfaces.push({
    label: "configuration",
    disposition: "reported",
    notes: "source review complete",
  });
  result.coverage.openQuestions.push("Have the embedded credentials expired?");
  assert.equal(gradeResult(result, fixture).passed, true);
});

for (const pattern of [
  "src/client.py",
  "src/runtime_config.py",
  "./README.md",
  "**/test_*.py",
  "config/.*",
  "src",
  "config/",
  ".",
  "/tmp/generated-repo/src/client.py",
  "/tmp/generated-repo/**/*.py",
  "/tmp/generated-repo/config/",
  "/",
]) {
  test(`complete coverage cannot exclude fixture path ${pattern}`, () => {
    const fixture = createFixture();
    const result = retainedResult(fixture);
    result.coverage.explicitExclusions.push({
      pattern,
      reason: "Not reviewed",
    });
    const report = gradeResult(result, fixture, "/tmp/generated-repo");
    assert.equal(report.recall, 1);
    assert.equal(report.passed, false);
    assert.deepEqual(report.errors, ["incomplete coverage"]);
  });
}

test("complete coverage permits exclusions outside the generated fixture", () => {
  const fixture = createFixture();
  const result = retainedResult(fixture);
  result.coverage.explicitExclusions.push(
    { pattern: "node_modules/**", reason: "No dependencies in fixture" },
    { pattern: "https://delivery.example.test/**", reason: "Offline review" },
    { pattern: "/tmp/external/**", reason: "Outside fixture" },
    {
      pattern: "/tmp/generated-repository/src/client.py",
      reason: "Different repository",
    },
  );
  assert.equal(
    gradeResult(result, fixture, "/tmp/generated-repo").passed,
    true,
  );
});

for (const repo of [
  String.raw`C:\Temp\repository`,
  "C:/Temp/repository",
  String.raw`\\server\share\repository`,
  "//server/share/repository",
]) {
  test(`coverage matches Windows exclusions for ${repo}`, () => {
    const fixture = createFixture();
    const slashRepo = repo.replaceAll("\\", "/");
    for (const pattern of [
      `${slashRepo}/src/client.py`,
      `${slashRepo}/src/client.py`.replaceAll("/", "\\"),
      `${slashRepo}/**/*.py`,
      `${slashRepo}/SRC/**/*.PY`,
      "SRC/**/*.PY",
      `${slashRepo}/config/`,
      String.raw`src\client.py`,
    ]) {
      const result = retainedResult(fixture);
      result.coverage.explicitExclusions.push({
        pattern,
        reason: "Not reviewed",
      });
      const report = gradeResult(result, fixture, repo);
      assert.equal(report.recall, 1);
      assert.equal(report.passed, false, pattern);
      assert.deepEqual(report.errors, ["incomplete coverage"]);
    }
    const external = retainedResult(fixture);
    external.coverage.explicitExclusions.push(
      {
        pattern: `${slashRepo}-external/src/client.py`,
        reason: "Outside fixture",
      },
      {
        pattern: String.raw`D:\Other\repository\**`,
        reason: "Different drive",
      },
    );
    assert.equal(gradeResult(external, fixture, repo).passed, true);
  });
}

test("POSIX exclusion globs remain case-sensitive", () => {
  const fixture = createFixture();
  const result = retainedResult(fixture);
  result.coverage.explicitExclusions.push({
    pattern: "SRC/**/*.PY",
    reason: "Outside fixture",
  });
  assert.equal(gradeResult(result, fixture, "/tmp/repository").passed, true);
});

test("Windows drive casing does not hide an in-scope exclusion", () => {
  const fixture = createFixture();
  const result = retainedResult(fixture);
  result.coverage.explicitExclusions.push({
    pattern: "c:/Temp/repository/src/client.py",
    reason: "Not reviewed",
  });
  const report = gradeResult(result, fixture, String.raw`C:\Temp\repository`);
  assert.equal(report.passed, false);
  assert.deepEqual(report.errors, ["incomplete coverage"]);
});

for (const [repo, prefix, ancestor] of [
  ["/tmp/repository[fixture]", "/tmp/repository[fixture]", "/"],
  [
    String.raw`C:\Temp\repository[fixture]`,
    "c:/Temp/repository[fixture]",
    "c:/",
  ],
  [
    String.raw`\\server\share\repository[fixture]`,
    "//server/share/repository[fixture]",
    "//server/share/",
  ],
  [
    "/tmp/user[fixture]/repository",
    "/tmp/user[fixture]/repository",
    "/tmp/user[fixture]",
  ],
  [
    String.raw`C:\Temp\user[fixture]\repository`,
    "c:/Temp/user[fixture]/repository",
    "c:/Temp/user[fixture]",
  ],
  [
    String.raw`\\server\share\user[fixture]\repository`,
    "//server/share/user[fixture]/repository",
    "//server/share/user[fixture]",
  ],
]) {
  test(`absolute exclusions treat the repository prefix literally for ${repo}`, () => {
    const fixture = createFixture();
    for (const pattern of [
      `${prefix}/src/client.py`,
      `${prefix}/**/*.py`,
      `${prefix}/config/`,
      prefix,
      ancestor,
    ]) {
      const result = retainedResult(fixture);
      result.coverage.explicitExclusions.push({
        pattern,
        reason: "Not reviewed",
      });
      const report = gradeResult(result, fixture, repo);
      assert.equal(report.passed, false, pattern);
      assert.deepEqual(report.errors, ["incomplete coverage"]);
    }
    for (const pattern of [
      `${prefix}-external/src/client.py`,
      `${prefix.replace("[fixture]", "fixture")}/**/*.py`,
    ]) {
      const result = retainedResult(fixture);
      result.coverage.explicitExclusions.push({
        pattern,
        reason: "Different repository",
      });
      assert.equal(gradeResult(result, fixture, repo).passed, true, pattern);
    }
  });
}

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

  let settings;
  const fakeCodex = {
    startThread(options) {
      settings = options;
      return {
        async runStreamed(prompt, options) {
          assert.equal(prompt, prepared.prompt);
          assert.ok(options.outputSchema.properties.findings);
          return {
            events: (async function* () {
              yield {
                type: "item.completed",
                item: {
                  type: "agent_message",
                  text: JSON.stringify(retainedResult(prepared.fixture)),
                },
              };
              yield {
                type: "item.completed",
                item: {
                  type: "agent_message",
                  text: JSON.stringify({
                    findings: [],
                    coverage: { completeness: "complete" },
                  }),
                },
              };
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
  assert.equal(settings.sandboxMode, undefined);
  assert.deepEqual(settings.additionalDirectories, [prepared.runtime]);
  assert.equal(settings.workingDirectory, prepared.repo);
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
  const config = parse(settings.configOverrides.join("\n"));
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
  assert.deepEqual(
    { ...config.shell_environment_policy },
    {
      inherit: "core",
      ignore_default_excludes: false,
    },
  );
  assert.deepEqual(
    JSON.parse(
      JSON.stringify(
        config.permissions[DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID].filesystem,
      ),
    ),
    {
      ":minimal": "read",
      ":workspace_roots": "read",
      [dirname(dirname(codexPath))]: { ".": "read" },
      [resolve(home)]: { ".": "deny" },
    },
  );
  assert.deepEqual(
    { ...config.permissions[DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID].network },
    { enabled: false },
  );
  assert.equal(
    threadSettings({ repo: "/tmp/repo", runtime: "/tmp/runtime" }).sandboxMode,
    undefined,
  );
});
