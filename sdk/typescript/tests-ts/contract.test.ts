import { createHash } from "node:crypto";
import {
  chmod,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  truncate,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { ContractValidationError, loadContract } from "../src/index.js";
import type { NormalizedTarget, ScanExpectation } from "../src/index.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const EXAMPLE = join(PLUGIN_ROOT, "examples", "completed-scan");
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function copyExample(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "codex-security-contract-"));
  temporaryDirectories.push(root);
  const scanDir = join(root, "scan");
  await cp(EXAMPLE, scanDir, { recursive: true });
  if (process.platform !== "win32") await chmod(scanDir, 0o700);
  return scanDir;
}

async function readJson(path: string): Promise<Record<string, any>> {
  return JSON.parse(await readFile(path, "utf8"));
}

async function writeJson(path: string, payload: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(payload, null, 2)}\n`);
}

async function reseal(scanDir: string): Promise<void> {
  const manifestPath = join(scanDir, "scan-manifest.json");
  const manifest = await readJson(manifestPath);
  for (const artifact of manifest["scan"]["artifacts"]) {
    const path = join(scanDir, artifact["path"]);
    try {
      artifact["sha256"] = createHash("sha256")
        .update(await readFile(path))
        .digest("hex");
    } catch {}
  }
  await writeJson(manifestPath, manifest);
}

function setFindingIdentity(
  manifest: Record<string, any>,
  finding: Record<string, any>,
): void {
  const fingerprint = `codex-security/v1:sha256:${createHash("sha256")
    .update(
      [
        "codex-security/v1",
        manifest["scan"]["target"]["targetId"],
        finding["ruleId"],
        finding["identity"]["anchor"],
        finding["identity"]["instance"] ?? "",
      ].join("\0"),
    )
    .digest("hex")}`;
  finding["fingerprints"] = {
    algorithm: "codex-security/v1",
    primary: fingerprint,
  };
  finding["findingId"] = `csf_${createHash("sha256")
    .update(fingerprint)
    .digest("hex")
    .slice(0, 24)}`;
  finding["occurrenceId"] = `occ_${createHash("sha256")
    .update([manifest["scan"]["id"], fingerprint].join("\0"))
    .digest("hex")
    .slice(0, 24)}`;
}

function expectation(
  target: NormalizedTarget,
  mode: "standard" | "deep" = "standard",
): ScanExpectation {
  return {
    repository: dirname(target.paths[0] ?? "/tmp"),
    repositoryRevision: "deadbeef",
    target,
    mode,
    pluginVersion: "0.1.0",
  };
}

describe("canonical scan contract", () => {
  test("loads the unchanged plugin example with typed canonical names", async () => {
    const scanDir = await copyExample();
    const contract = await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT });
    expect(contract.manifest.documentType).toBe("codex-security.scan-manifest");
    expect(contract.manifest.scan.target.targetId).toBe(
      "target_sha256_example",
    );
    expect(contract.findings.findings[0]?.severity.level).toBe("high");
    expect(contract.coverage.mode).toBe("repository");
    expect(contract.findings.scanId).toBe(contract.manifest.scan.id);
  });

  test("honors cancellation during contract validation", async () => {
    const scanDir = await copyExample();
    const controller = new AbortController();
    controller.abort(new DOMException("canceled", "AbortError"));
    await expect(
      loadContract(scanDir, {
        pluginRoot: PLUGIN_ROOT,
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ name: "AbortError" });
  });

  test.skipIf(process.platform === "win32")(
    "rejects a scan directory that is no longer private to the current user",
    async () => {
      const scanDir = await copyExample();
      await chmod(scanDir, 0o755);
      await expect(
        loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
      ).rejects.toThrow("must not be accessible to other users");
    },
  );

  test.skipIf(process.platform === "win32")(
    "rejects a private scan beneath an insecure shared ancestor",
    async () => {
      const scanDir = await copyExample();
      const parent = dirname(scanDir);
      await chmod(parent, 0o777);

      try {
        await expect(
          loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
        ).rejects.toThrow("sticky bit");
      } finally {
        await chmod(parent, 0o700);
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "accepts a scan directory beneath a symlinked parent",
    async () => {
      const root = await mkdtemp(
        join(tmpdir(), "codex-security-contract-link-"),
      );
      temporaryDirectories.push(root);
      const parent = join(root, "actual-parent");
      const linkedParent = join(root, "linked-parent");
      await mkdir(parent, { mode: 0o700 });
      const scanDir = join(parent, "scan");
      await cp(EXAMPLE, scanDir, { recursive: true });
      if (process.platform !== "win32") await chmod(scanDir, 0o700);
      await symlink(parent, linkedParent);

      await expect(
        loadContract(join(linkedParent, "scan"), { pluginRoot: PLUGIN_ROOT }),
      ).resolves.toBeDefined();
    },
  );

  test("rejects oversized contract documents before parsing them", async () => {
    for (const [filename, maximum] of [
      ["scan-manifest.json", 16 * 1024 * 1024],
      ["findings.json", 128 * 1024 * 1024],
      ["coverage.json", 32 * 1024 * 1024],
    ] as const) {
      const scanDir = await copyExample();
      await truncate(join(scanDir, filename), maximum + 1);

      await expect(
        loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
      ).rejects.toThrow(
        `${filename}: JSON document exceeds the ${maximum}-byte limit`,
      );
    }
  });

  test("rejects oversized contract schemas before parsing them", async () => {
    const pluginRoot = await mkdtemp(
      join(tmpdir(), "codex-security-schema-large-"),
    );
    temporaryDirectories.push(pluginRoot);
    await cp(join(PLUGIN_ROOT, "schemas"), join(pluginRoot, "schemas"), {
      recursive: true,
    });
    const maximum = 4 * 1024 * 1024;
    await truncate(
      join(pluginRoot, "schemas", "scan-manifest.schema.json"),
      maximum + 1,
    );

    await expect(
      loadContract(await copyExample(), { pluginRoot }),
    ).rejects.toThrow(
      `scan-manifest.schema.json: JSON document exceeds the ${maximum}-byte limit`,
    );
  });

  test("rejects deeply nested JSON before overflowing the call stack", async () => {
    const scanDir = await copyExample();
    const depth = 258;
    await writeFile(
      join(scanDir, "findings.json"),
      `{"overflow":${"[".repeat(depth)}0${"]".repeat(depth)}}`,
    );

    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).rejects.toThrow("JSON document exceeds the 256-level nesting limit");
  });

  test("does not expose attacker-controlled keys in validation errors", async () => {
    const scanDir = await copyExample();
    const marker = "PRIVATE_JSON_KEY";
    await writeFile(
      join(scanDir, "findings.json"),
      JSON.stringify({ [marker]: 9007199254740992 }),
    );

    let thrown: unknown;
    try {
      await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(ContractValidationError);
    expect((thrown as Error).message).toContain("unsafe integer-valued");
    expect((thrown as Error).message).not.toContain(marker);
  });

  test("rejects unsafe or overly complex configured schemas", async () => {
    for (const [schema, expected] of [
      [{ $ref: "#" }, "unsupported JSON Schema keyword"],
      [
        { type: "string", pattern: "^(a+)+$" },
        "unsupported JSON Schema pattern",
      ],
      [
        {
          allOf: Array.from({ length: 129 }, () => ({ type: "object" })),
        },
        "128-edge applicator limit",
      ],
    ] as const) {
      const pluginRoot = await mkdtemp(
        join(tmpdir(), "codex-security-schema-invalid-"),
      );
      temporaryDirectories.push(pluginRoot);
      await mkdir(join(pluginRoot, "schemas"));
      await writeJson(
        join(pluginRoot, "schemas", "scan-manifest.schema.json"),
        schema,
      );

      await expect(
        loadContract(await copyExample(), { pluginRoot }),
      ).rejects.toThrow(expected);
    }
  });

  test("does not expose attacker-controlled schema compilation errors", async () => {
    const pluginRoot = await mkdtemp(
      join(tmpdir(), "codex-security-schema-compile-"),
    );
    temporaryDirectories.push(pluginRoot);
    await mkdir(join(pluginRoot, "schemas"));
    const marker = "PRIVATE_SCHEMA_KEY";
    await writeJson(join(pluginRoot, "schemas", "scan-manifest.schema.json"), {
      type: "object",
      properties: {
        [marker]: { type: "not-a-valid-json-schema-type" },
      },
    });

    let thrown: unknown;
    try {
      await loadContract(await copyExample(), { pluginRoot });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(ContractValidationError);
    expect((thrown as Error).message).toBe(
      "scan-manifest.schema.json: invalid JSON Schema.",
    );
    expect((thrown as Error).message).not.toContain(marker);
    expect((thrown as Error).cause).toBeUndefined();
  });

  test("rejects changed sealed artifacts and duplicate paths", async () => {
    const scanDir = await copyExample();
    const findingsPath = join(scanDir, "findings.json");
    const findings = await readJson(findingsPath);
    findings["findings"][0]["title"] = "tampered";
    await writeJson(findingsPath, findings);
    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).rejects.toThrow("sealed artifact changed");

    const second = await copyExample();
    const manifestPath = join(second, "scan-manifest.json");
    const manifest = await readJson(manifestPath);
    manifest["scan"]["artifacts"].push({ ...manifest["scan"]["artifacts"][0] });
    await writeJson(manifestPath, manifest);
    await expect(
      loadContract(second, { pluginRoot: PLUGIN_ROOT }),
    ).rejects.toThrow("schema validation failed");
  });

  test("rejects unsafe Windows and traversal artifact paths", async () => {
    for (const unsafe of ["D:/escape", "../escape", "artifacts\\escape"]) {
      const scanDir = await copyExample();
      const path = join(scanDir, "scan-manifest.json");
      const manifest = await readJson(path);
      manifest["scan"]["artifacts"].push({
        path: unsafe,
        sha256: "0".repeat(64),
        mediaType: "text/plain",
      });
      await writeJson(path, manifest);
      await expect(
        loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
      ).rejects.toThrow(ContractValidationError);
    }
  });

  test("rejects calendar-invalid RFC 3339 timestamps", async () => {
    const scanDir = await copyExample();
    const manifestPath = join(scanDir, "scan-manifest.json");
    const manifest = await readJson(manifestPath);
    manifest["scan"]["completedAt"] = "2026-02-30T18:00:00Z";
    manifest["scan"]["sealedAt"] = "2026-02-30T18:00:00Z";
    await writeJson(manifestPath, manifest);
    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).rejects.toThrow("date-time");

    manifest["scan"]["completedAt"] = "0000-01-01T00:00:00Z";
    manifest["scan"]["sealedAt"] = "0000-01-01T00:00:00Z";
    await writeJson(manifestPath, manifest);
    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).rejects.toThrow("date-time");
  });

  test("accepts lowercase RFC 3339 separators", async () => {
    const scanDir = await copyExample();
    const manifestPath = join(scanDir, "scan-manifest.json");
    const manifest = await readJson(manifestPath);
    manifest["scan"]["completedAt"] = "2026-05-31t18:09:00z";
    manifest["scan"]["sealedAt"] = "2026-05-31t18:09:00z";
    await writeJson(manifestPath, manifest);
    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).resolves.toBeDefined();
  });

  test("requires completed and sealed timestamps to match exactly", async () => {
    const scanDir = await copyExample();
    const manifestPath = join(scanDir, "scan-manifest.json");
    const manifest = await readJson(manifestPath);
    manifest["scan"]["completedAt"] = "2026-01-01T00:00:01.000400Z";
    manifest["scan"]["sealedAt"] = "2026-01-01T00:00:01.000400Z";
    await writeJson(manifestPath, manifest);
    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).resolves.toBeDefined();

    manifest["scan"]["sealedAt"] = "2026-01-01T01:00:01.000400+01:00";
    await writeJson(manifestPath, manifest);
    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).rejects.toThrow("Manifest sealedAt must match completedAt.");
  });

  test("rejects invalid UTF-8 in JSON documents", async () => {
    const scanDir = await copyExample();
    const findingsPath = join(scanDir, "findings.json");
    const findings = await readFile(findingsPath);
    const contentOffset = findings.indexOf("findingId");
    expect(contentOffset).toBeGreaterThanOrEqual(0);
    findings[contentOffset] = 0xff;
    await writeFile(findingsPath, findings);

    const manifestPath = join(scanDir, "scan-manifest.json");
    const manifest = await readJson(manifestPath);
    const artifact = manifest["scan"]["artifacts"].find(
      (candidate: Record<string, unknown>) =>
        candidate["path"] === "findings.json",
    );
    artifact["sha256"] = createHash("sha256").update(findings).digest("hex");
    await writeJson(manifestPath, manifest);

    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).rejects.toThrow("unreadable JSON document");
  });

  test("rejects schema-valid but canonically invalid contract data", async () => {
    const cases: Array<
      [
        string,
        (
          manifest: Record<string, any>,
          findings: Record<string, any>,
          coverage: Record<string, any>,
        ) => void,
        string,
      ]
    > = [
      [
        "unsafe location",
        (_manifest, findings) => {
          findings["findings"][0]["locations"][0]["path"] = "../outside.ts";
        },
        "safe repository-relative POSIX path",
      ],
      [
        "ill-formed Unicode location",
        (_manifest, findings) => {
          findings["findings"][0]["locations"][0]["path"] =
            "src/bad-\ud800-name.ts";
        },
        "well-formed Unicode",
      ],
      [
        "unsafe scope",
        (manifest, _findings, coverage) => {
          manifest["scan"]["scope"]["includePaths"] = ["../outside"];
          coverage["includePaths"] = ["../outside"];
        },
        "safe repository-relative POSIX path",
      ],
      [
        "ill-formed Unicode scope",
        (manifest, _findings, coverage) => {
          manifest["scan"]["scope"]["includePaths"] = ["src/bad-\ud800-name"];
          coverage["includePaths"] = ["src/bad-\ud800-name"];
        },
        "well-formed Unicode",
      ],
      [
        "ill-formed Unicode artifact",
        (manifest) => {
          manifest["scan"]["artifacts"].push({
            path: "artifacts/bad-\ud800-name.txt",
            sha256: "0".repeat(64),
            mediaType: "text/plain",
          });
        },
        "well-formed Unicode",
      ],
      [
        "ill-formed Unicode receipt",
        (_manifest, _findings, coverage) => {
          coverage["surfaces"][0]["receiptRefs"] = [
            "artifacts/bad-\ud800-name.txt",
          ];
        },
        "well-formed Unicode",
      ],
      [
        "wrong identities",
        (_manifest, findings) => {
          findings["findings"][0]["findingId"] = `csf_${"0".repeat(24)}`;
          findings["findings"][0]["occurrenceId"] = `occ_${"1".repeat(24)}`;
          findings["findings"][0]["fingerprints"] = {
            algorithm: "codex-security/v1",
            primary: `codex-security/v1:sha256:${"2".repeat(64)}`,
          };
        },
        "derived fingerprint identity",
      ],
      [
        "opaque remote",
        (manifest) => {
          manifest["scan"]["target"]["remote"] = "ssh:opaque";
        },
        "canonical absolute URL",
      ],
      [
        "relative remote",
        (manifest) => {
          manifest["scan"]["target"]["remote"] = "relative/repository";
        },
        "canonical absolute URL",
      ],
      [
        "scheme-without-authority remote",
        (manifest) => {
          manifest["scan"]["target"]["remote"] = "https:example.com/repo";
        },
        "canonical absolute URL",
      ],
      [
        "single-slash remote",
        (manifest) => {
          manifest["scan"]["target"]["remote"] = "https:/example.com/repo";
        },
        "canonical absolute URL",
      ],
      [
        "backslash authority remote",
        (manifest) => {
          manifest["scan"]["target"]["remote"] =
            "https://example.com\\@evil.test/repo";
        },
        "scan.target.remote",
      ],
    ];

    for (const [_name, mutate, expected] of cases) {
      const scanDir = await copyExample();
      const manifestPath = join(scanDir, "scan-manifest.json");
      const findingsPath = join(scanDir, "findings.json");
      const coveragePath = join(scanDir, "coverage.json");
      const manifest = await readJson(manifestPath);
      const findings = await readJson(findingsPath);
      const coverage = await readJson(coveragePath);
      mutate(manifest, findings, coverage);
      await writeJson(findingsPath, findings);
      await writeJson(coveragePath, coverage);
      await writeJson(manifestPath, manifest);
      await reseal(scanDir);
      await expect(
        loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
      ).rejects.toThrow(expected);
    }
  });

  test("accepts distinct finding siblings and Unicode target identities", async () => {
    const scanDir = await copyExample();
    const manifestPath = join(scanDir, "scan-manifest.json");
    const findingsPath = join(scanDir, "findings.json");
    const manifest = await readJson(manifestPath);
    const findings = await readJson(findingsPath);
    manifest["scan"]["target"]["targetId"] = "target_仓库_😀";
    const first = findings["findings"][0];
    const second = structuredClone(first);
    first["identity"]["instance"] = "first-sink";
    second["identity"]["instance"] = "second-sink";
    setFindingIdentity(manifest, first);
    setFindingIdentity(manifest, second);
    findings["findings"].push(second);
    await writeJson(manifestPath, manifest);
    await writeJson(findingsPath, findings);
    await reseal(scanDir);

    const loaded = await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT });
    expect(loaded.findings.findings).toHaveLength(2);
    expect(loaded.findings.findings[0]?.findingId).not.toBe(
      loaded.findings.findings[1]?.findingId,
    );
  });

  test("rejects unsafe and non-finite JSON numbers before contract typing", async () => {
    for (const [field, expected] of [
      ["startLine", "unsafe integer-valued JSON numbers"],
      ["endLine", "unsafe integer-valued JSON numbers"],
      ["evidenceStartLine", "unsafe integer-valued JSON numbers"],
      ["evidenceEndLine", "unsafe integer-valued JSON numbers"],
      ["overflow", "non-finite JSON numbers"],
    ] as const) {
      const scanDir = await copyExample();
      const findingsPath = join(scanDir, "findings.json");
      const findings = await readJson(findingsPath);
      const finding = findings["findings"][0];
      if (field === "evidenceStartLine" || field === "evidenceEndLine") {
        finding["codeEvidence"] = [
          {
            id: "source",
            label: "Source",
            path: "src/extract.py",
            startLine: 41,
            endLine: 44,
            code: "extract()",
            explanation: "Source evidence",
          },
        ];
      }
      if (field === "overflow") {
        finding["extensions"] = { overflow: 0 };
      }
      await writeJson(findingsPath, findings);
      let text = await readFile(findingsPath, "utf8");
      const replacement = field === "overflow" ? "1e400" : "9007199254740993";
      const needle =
        field === "startLine"
          ? '"startLine": 41'
          : field === "endLine"
            ? '"endLine": 44'
            : field === "evidenceStartLine"
              ? '"startLine": 41'
              : field === "evidenceEndLine"
                ? '"endLine": 44'
                : '"overflow": 0';
      if (field === "evidenceStartLine" || field === "evidenceEndLine") {
        const last = text.lastIndexOf(needle);
        text = `${text.slice(0, last)}${needle.replace(/: \d+$/, `: ${replacement}`)}${text.slice(last + needle.length)}`;
      } else {
        text = text.replace(
          needle,
          needle.replace(/: \d+$/, `: ${replacement}`),
        );
      }
      await writeFile(findingsPath, text);
      await reseal(scanDir);
      await expect(
        loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
      ).rejects.toThrow(expected);
    }
  });

  test.skipIf(process.platform === "win32")(
    "rejects missing or symlinked derived writeup and hardening files",
    async () => {
      for (const kind of ["writeup", "hardening"] as const) {
        for (const symlinked of [false, true]) {
          const scanDir = await copyExample();
          const manifestPath = join(scanDir, "scan-manifest.json");
          const findingsPath = join(scanDir, "findings.json");
          const manifest = await readJson(manifestPath);
          const findings = await readJson(findingsPath);
          const relativePath =
            kind === "writeup"
              ? "findings/report/report.md"
              : "hardening/hardening.md";
          if (kind === "writeup") {
            findings["findings"][0]["writeup"] = { reportPath: relativePath };
          } else {
            manifest["scan"]["hardening"] = { portfolioPath: relativePath };
          }
          await writeJson(manifestPath, manifest);
          await writeJson(findingsPath, findings);
          await reseal(scanDir);
          if (symlinked) {
            const external = join(scanDir, "external.md");
            const referenced = join(scanDir, relativePath);
            await writeFile(external, "external\n");
            await mkdir(dirname(referenced), { recursive: true });
            await symlink(external, referenced);
          }
          await expect(
            loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
          ).rejects.toThrow(
            kind === "writeup"
              ? "writeup.reportPath"
              : "hardening.portfolioPath",
          );
        }
      }
    },
  );

  test("accepts regular derived artifacts and a schema-valid scope summary", async () => {
    const scanDir = await copyExample();
    const manifestPath = join(scanDir, "scan-manifest.json");
    const findingsPath = join(scanDir, "findings.json");
    const manifest = await readJson(manifestPath);
    const findings = await readJson(findingsPath);
    manifest["scan"]["scope"]["summary"] = "\u0085";
    manifest["scan"]["hardening"] = {
      portfolioPath: "hardening/hardening.md",
    };
    findings["findings"][0]["writeup"] = {
      reportPath: "findings/report/report.md",
    };
    await mkdir(join(scanDir, "hardening"));
    await mkdir(join(scanDir, "findings", "report"), { recursive: true });
    await writeFile(join(scanDir, "hardening", "hardening.md"), "hardening\n");
    await writeFile(
      join(scanDir, "findings", "report", "report.md"),
      "report\n",
    );
    await writeJson(manifestPath, manifest);
    await writeJson(findingsPath, findings);
    await reseal(scanDir);
    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).resolves.toBeDefined();
  });

  test.each([
    "accepts whitespace in schema-only minLength contract fields",
    "accepts representative schema-only minLength fields in each contract document",
  ])("%s", async (description) => {
    const cases: Array<
      [
        string,
        (
          manifest: Record<string, any>,
          findings: Record<string, any>,
          coverage: Record<string, any>,
        ) => void,
      ]
    > = [
      [
        "scope list",
        (manifest) => {
          manifest["scan"]["scope"]["artifactsReviewed"] = [" "];
        },
      ],
      [
        "threat summary",
        (manifest) => {
          manifest["scan"]["threatModel"] = { summary: " " };
        },
      ],
      [
        "threat list",
        (manifest) => {
          manifest["scan"]["threatModel"] = { summary: "ok", assets: [" "] };
        },
      ],
      [
        "severity vector",
        (_manifest, findings) => {
          findings["findings"][0]["severity"]["vector"] = " ";
        },
      ],
      [
        "location role",
        (_manifest, findings) => {
          findings["findings"][0]["locations"][0]["role"] = " ";
        },
      ],
      [
        "evidence label",
        (_manifest, findings) => {
          findings["findings"][0]["codeEvidence"] = [
            {
              id: "source",
              label: " ",
              path: "src/x.ts",
              startLine: 41,
              code: "x()",
              explanation: "ok",
            },
          ];
        },
      ],
      [
        "evidence path",
        (_manifest, findings) => {
          findings["findings"][0]["codeEvidence"] = [
            {
              id: "source",
              label: "ok",
              path: " ",
              startLine: 41,
              code: "x()",
              explanation: "ok",
            },
          ];
        },
      ],
      [
        "root summary",
        (_manifest, findings) => {
          findings["findings"][0]["rootCause"] = { summary: " " };
        },
      ],
      [
        "root code",
        (_manifest, findings) => {
          findings["findings"][0]["rootCause"] = { summary: "ok", code: " " };
        },
      ],
      [
        "remediation test",
        (_manifest, findings) => {
          findings["findings"][0]["remediationTests"] = [" "];
        },
      ],
      [
        "extensions candidate",
        (_manifest, findings) => {
          findings["findings"][0]["extensions"] = { candidateId: " " };
        },
      ],
      [
        "surface notes",
        (_manifest, _findings, coverage) => {
          coverage["surfaces"][0]["notes"] = " ";
        },
      ],
      [
        "surface risk",
        (_manifest, _findings, coverage) => {
          coverage["surfaces"][0]["riskArea"] = " ";
        },
      ],
      [
        "explicit exclusion",
        (_manifest, _findings, coverage) => {
          coverage["explicitExclusions"] = [{ pattern: " ", reason: "ok" }];
        },
      ],
      [
        "deferred",
        (_manifest, _findings, coverage) => {
          coverage["completeness"] = "partial";
          coverage["deferred"] = [{ id: " ", reason: "ok" }];
        },
      ],
      [
        "open question",
        (_manifest, _findings, coverage) => {
          coverage["openQuestions"] = [{ question: " " }];
        },
      ],
    ];
    const selectedCases =
      description ===
      "accepts representative schema-only minLength fields in each contract document"
        ? cases.filter(([name]) =>
            ["scope list", "severity vector", "surface notes"].includes(name),
          )
        : cases;
    for (const [_name, mutate] of selectedCases) {
      const scanDir = await copyExample();
      const manifestPath = join(scanDir, "scan-manifest.json");
      const findingsPath = join(scanDir, "findings.json");
      const coveragePath = join(scanDir, "coverage.json");
      const manifest = await readJson(manifestPath);
      const findings = await readJson(findingsPath);
      const coverage = await readJson(coveragePath);
      mutate(manifest, findings, coverage);
      await writeJson(manifestPath, manifest);
      await writeJson(findingsPath, findings);
      await writeJson(coveragePath, coverage);
      await reseal(scanDir);
      await expect(
        loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
      ).resolves.toBeDefined();
    }
  });

  test("accepts Git-backed scans when the SDK cannot resolve a revision", async () => {
    const scanDir = await copyExample();

    await expect(
      loadContract(scanDir, {
        pluginRoot: PLUGIN_ROOT,
        expectation: {
          ...expectation({ kind: "repository", paths: [] }),
          repositoryRevision: null,
        },
      }),
    ).resolves.toBeDefined();
  });

  test("accepts directory scans without requiring a Git repository", async () => {
    const scanDir = await copyExample();
    const manifestPath = join(scanDir, "scan-manifest.json");
    const coveragePath = join(scanDir, "coverage.json");
    const manifest = await readJson(manifestPath);
    const coverage = await readJson(coveragePath);
    manifest["scan"]["target"]["kind"] = "directory_snapshot";
    delete manifest["scan"]["target"]["revision"];
    delete manifest["scan"]["target"]["remote"];
    coverage["inventoryStrategy"] = "directory";
    await writeJson(manifestPath, manifest);
    await writeJson(coveragePath, coverage);
    await reseal(scanDir);

    for (const repositoryRevision of [null, "deadbeef"]) {
      await expect(
        loadContract(scanDir, {
          pluginRoot: PLUGIN_ROOT,
          expectation: {
            ...expectation({ kind: "repository", paths: [] }),
            repositoryRevision,
          },
        }),
      ).resolves.toBeDefined();
    }
  });

  test("rejects Git-backed scans for a different revision", async () => {
    const scanDir = await copyExample();

    await expect(
      loadContract(scanDir, {
        pluginRoot: PLUGIN_ROOT,
        expectation: {
          ...expectation({ kind: "repository", paths: [] }),
          repositoryRevision: "different-revision",
        },
      }),
    ).rejects.toThrow("Scan target revision does not match the repository.");
  });

  test("rejects diff targets for repository scans", async () => {
    const scanDir = await copyExample();
    const manifestPath = join(scanDir, "scan-manifest.json");
    const manifest = await readJson(manifestPath);
    manifest["scan"]["target"]["kind"] = "git_diff";
    await writeJson(manifestPath, manifest);
    await reseal(scanDir);

    await expect(
      loadContract(scanDir, {
        pluginRoot: PLUGIN_ROOT,
        expectation: {
          ...expectation({ kind: "repository", paths: [] }),
          repositoryRevision: null,
        },
      }),
    ).rejects.toThrow("Repository scan manifest target must not be git_diff.");
  });

  test("binds requested path scope, mode, and plugin version", async () => {
    const scanDir = await copyExample();
    const coveragePath = join(scanDir, "coverage.json");
    const coverage = await readJson(coveragePath);
    coverage["mode"] = "scoped_path";
    await writeJson(coveragePath, coverage);
    await reseal(scanDir);

    const target: NormalizedTarget = { kind: "paths", paths: ["src"] };
    await expect(
      loadContract(scanDir, {
        pluginRoot: PLUGIN_ROOT,
        expectation: expectation(target),
      }),
    ).resolves.toBeDefined();
    await expect(
      loadContract(scanDir, {
        pluginRoot: PLUGIN_ROOT,
        expectation: expectation({ kind: "paths", paths: ["packages/auth"] }),
      }),
    ).rejects.toThrow("include paths");
    await expect(
      loadContract(scanDir, {
        pluginRoot: PLUGIN_ROOT,
        expectation: { ...expectation(target), pluginVersion: "9.9.9" },
      }),
    ).rejects.toThrow("producer version");
  });
});
