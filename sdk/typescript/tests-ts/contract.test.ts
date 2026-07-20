import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
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
    "accepts a scan directory beneath a symlinked parent",
    async () => {
      const root = await mkdtemp(
        join(tmpdir(), "codex-security-contract-link-"),
      );
      temporaryDirectories.push(root);
      const parent = join(root, "actual-parent");
      const linkedParent = join(root, "linked-parent");
      await mkdir(parent);
      await cp(EXAMPLE, join(parent, "scan"), { recursive: true });
      await symlink(parent, linkedParent);

      await expect(
        loadContract(join(linkedParent, "scan"), { pluginRoot: PLUGIN_ROOT }),
      ).resolves.toBeDefined();
    },
  );

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
    ).rejects.toThrow("duplicate artifact path");
  });

  test.skipIf(process.platform === "win32")(
    "rejects non-regular contract schemas without blocking",
    async () => {
      const pluginRoot = await mkdtemp(
        join(tmpdir(), "codex-security-schema-fifo-"),
      );
      temporaryDirectories.push(pluginRoot);
      await mkdir(join(pluginRoot, "schemas"));
      await cp(join(PLUGIN_ROOT, "schemas"), join(pluginRoot, "schemas"), {
        recursive: true,
      });
      const schema = join(pluginRoot, "schemas", "scan-manifest.schema.json");
      await rm(schema);
      execFileSync("mkfifo", [schema]);

      await expect(
        loadContract(await copyExample(), { pluginRoot }),
      ).rejects.toThrow("unreadable JSON document");
    },
  );

  test("binds sealed JSON hashes to the exact parsed bytes", async () => {
    const scanDir = await copyExample();
    const findingsPath = join(scanDir, "findings.json");
    const replacement = join(scanDir, "findings-b.json");
    const findings = await readJson(findingsPath);
    findings["findings"][0]["title"] = "sealed replacement";
    const replacementBytes = `${JSON.stringify(findings, null, 2)}\n`;
    await writeFile(replacement, replacementBytes);
    const manifestPath = join(scanDir, "scan-manifest.json");
    const manifest = await readJson(manifestPath);
    const artifact = manifest["scan"]["artifacts"].find(
      (candidate: Record<string, unknown>) =>
        candidate["path"] === "findings.json",
    );
    artifact["sha256"] = createHash("sha256")
      .update(replacementBytes)
      .digest("hex");
    await writeJson(manifestPath, manifest);

    const script = `
      import { mock } from "bun:test";
      import { renameSync } from "node:fs";
      import * as original from "node:fs/promises";
      import { join } from "node:path";
      const [scanDir, pluginRoot, contract] = process.argv.slice(1);
      const schema = join(pluginRoot, "schemas", "scan-manifest.schema.json");
      const findings = join(scanDir, "findings.json");
      const replacement = join(scanDir, "findings-b.json");
      const actualOpen = original.open;
      let swapped = false;
      mock.module("node:fs/promises", () => ({
        ...original,
        open: async (path, ...args) => {
          if (path === schema && !swapped) {
            swapped = true;
            renameSync(replacement, findings);
          }
          return await actualOpen(path, ...args);
        },
      }));
      const { loadContract } = await import(contract);
      try {
        await loadContract(scanDir, { pluginRoot });
        console.log("ACCEPTED", swapped);
        process.exitCode = 2;
      } catch (error) {
        console.log("REJECTED", swapped, error instanceof Error ? error.message : String(error));
      }
    `;
    const result = spawnSync(
      process.execPath,
      [
        "-e",
        script,
        scanDir,
        PLUGIN_ROOT,
        fileURLToPath(new URL("../src/contract.ts", import.meta.url)),
      ],
      { encoding: "utf8" },
    );
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("REJECTED true");
    expect(result.stdout).toContain("sealed artifact changed");
  });

  test.skipIf(process.platform === "win32")(
    "rejects a sealed artifact retargeted after its path check",
    async () => {
      const scanDir = await copyExample();
      const artifacts = join(scanDir, "artifacts");
      await mkdir(artifacts);
      const artifactPath = join(artifacts, "extra.txt");
      const external = join(scanDir, "external.txt");
      await writeFile(artifactPath, "local\n");
      await writeFile(external, "external\n");
      const manifestPath = join(scanDir, "scan-manifest.json");
      const manifest = await readJson(manifestPath);
      manifest["scan"]["artifacts"].push({
        path: "artifacts/extra.txt",
        sha256: createHash("sha256").update("external\n").digest("hex"),
        mediaType: "text/plain",
      });
      await writeJson(manifestPath, manifest);

      const script = `
        import { mock } from "bun:test";
        import { renameSync, symlinkSync } from "node:fs";
        import * as original from "node:fs/promises";
        import { join } from "node:path";
        const [scanDir, pluginRoot, contract] = process.argv.slice(1);
        const artifact = join(scanDir, "artifacts", "extra.txt");
        const external = join(scanDir, "external.txt");
        const actualRealpath = original.realpath;
        let swapped = false;
        mock.module("node:fs/promises", () => ({
          ...original,
          realpath: async (path, ...args) => {
            const canonical = await actualRealpath(path, ...args);
            if (path === artifact && !swapped) {
              queueMicrotask(() => {
                renameSync(artifact, artifact + ".checked");
                symlinkSync(external, artifact);
                swapped = true;
              });
            }
            return canonical;
          },
        }));
        const { loadContract } = await import(contract);
        try {
          await loadContract(scanDir, { pluginRoot });
          console.log("ACCEPTED", swapped);
          process.exitCode = 2;
        } catch (error) {
          console.log("REJECTED", swapped, error instanceof Error ? error.message : String(error));
        }
      `;
      const result = spawnSync(
        process.execPath,
        [
          "-e",
          script,
          scanDir,
          PLUGIN_ROOT,
          fileURLToPath(new URL("../src/contract.ts", import.meta.url)),
        ],
        { encoding: "utf8" },
      );
      expect(result.status).toBe(0);
      expect(result.stdout).toContain("REJECTED true");
      expect(result.stdout).toContain("checked regular file");
    },
  );

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

  test("compares completed and sealed timestamps as instants", async () => {
    const scanDir = await copyExample();
    const manifestPath = join(scanDir, "scan-manifest.json");
    const manifest = await readJson(manifestPath);
    manifest["scan"]["completedAt"] = "2026-01-01T00:00:01.000400Z";
    manifest["scan"]["sealedAt"] = "2026-01-01T01:00:01.000400+01:00";
    await writeJson(manifestPath, manifest);
    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).resolves.toBeDefined();

    manifest["scan"]["sealedAt"] = "2026-01-01T00:00:01.000500Z";
    await writeJson(manifestPath, manifest);
    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).rejects.toThrow("Manifest sealedAt must match completedAt.");

    manifest["scan"]["completedAt"] = "6047-06-21T22:22:12.0620137891-16:32";
    manifest["scan"]["sealedAt"] = "6047-06-22T14:54:12.062013Z";
    await writeJson(manifestPath, manifest);
    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).resolves.toBeDefined();

    manifest["scan"]["sealedAt"] = "6047-06-22T14:54:12.062014Z";
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

  test("validates permissive finding detail schemas before typing", async () => {
    const scanDir = await copyExample();
    const findingsPath = join(scanDir, "findings.json");
    const findings = await readJson(findingsPath);
    findings["findings"][0]["validation"] = {
      summary: null,
      method: null,
      evidence: null,
      counterEvidence: null,
    };
    findings["findings"][0]["attackPath"] = {
      dataflow: null,
      reachability: null,
    };
    await writeJson(findingsPath, findings);
    await reseal(scanDir);
    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).resolves.toBeDefined();

    findings["findings"][0]["validation"] = { summary: 42 };
    await writeJson(findingsPath, findings);
    await reseal(scanDir);

    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).rejects.toThrow("validation.summary");
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
        "end before start",
        (_manifest, findings) => {
          findings["findings"][0]["locations"][0]["startLine"] = 41;
          findings["findings"][0]["locations"][0]["endLine"] = 1;
        },
        "endLine",
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
        "duplicate surface",
        (_manifest, _findings, coverage) => {
          coverage["surfaces"].push({ ...coverage["surfaces"][0] });
        },
        "duplicate surface id",
      ],
      [
        "score without system",
        (_manifest, findings) => {
          delete findings["findings"][0]["severity"]["scoringSystem"];
        },
        "scoringSystem",
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
      [
        "blank title",
        (_manifest, findings) => {
          findings["findings"][0]["title"] = "   ";
        },
        "expected a non-empty string",
      ],
      [
        "Python-whitespace title",
        (_manifest, findings) => {
          findings["findings"][0]["title"] = "\u0085\u001c\u001f";
        },
        "expected a non-empty string",
      ],
      [
        "Python-whitespace producer",
        (manifest) => {
          manifest["scan"]["producer"]["name"] = "\u0085\u001c\u001f";
        },
        "expected a non-empty string",
      ],
      [
        "ill-formed Unicode target identity",
        (manifest, findings) => {
          manifest["scan"]["target"]["targetId"] = "target_\ud800";
          setFindingIdentity(manifest, findings["findings"][0]);
        },
        "well-formed Unicode",
      ],
      [
        "ill-formed Unicode scan identity",
        (manifest, findings, coverage) => {
          manifest["scan"]["id"] = "scan_\ud800";
          findings["scanId"] = manifest["scan"]["id"];
          coverage["scanId"] = manifest["scan"]["id"];
          setFindingIdentity(manifest, findings["findings"][0]);
        },
        "well-formed Unicode",
      ],
      [
        "blank scoring system",
        (_manifest, findings) => {
          findings["findings"][0]["severity"]["scoringSystem"] = "   ";
        },
        "scoringSystem",
      ],
      [
        "duplicate code evidence",
        (_manifest, findings) => {
          const evidence = {
            id: "source",
            label: "Source",
            path: "../allowed-by-python.ts",
            startLine: 2,
            endLine: 1,
            code: "source()",
            explanation: "Source evidence",
          };
          findings["findings"][0]["codeEvidence"] = [evidence, { ...evidence }];
        },
        "duplicate code-evidence id",
      ],
      [
        "unknown root-cause evidence",
        (_manifest, findings) => {
          findings["findings"][0]["rootCause"] = {
            summary: "Root cause",
            evidenceRefs: ["missing"],
          };
        },
        "unknown code-evidence ids",
      ],
      [
        "unknown validation evidence",
        (_manifest, findings) => {
          findings["findings"][0]["validation"] = {
            evidenceRefs: ["missing"],
          };
        },
        "unknown code-evidence ids",
      ],
      [
        "unknown attack-path evidence",
        (_manifest, findings) => {
          findings["findings"][0]["attackPath"] = {
            evidenceRefs: ["missing"],
          };
        },
        "unknown code-evidence ids",
      ],
      [
        "duplicate logical finding",
        (_manifest, findings) => {
          findings["findings"].push(structuredClone(findings["findings"][0]));
        },
        "duplicate occurrence identity",
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

  test("accepts whitespace in schema-only minLength contract fields", async () => {
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
    for (const [_name, mutate] of cases) {
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

  test.skipIf(process.platform === "win32")(
    "binds the initially validated scan-directory inode",
    async () => {
      const scanDir = await copyExample();
      const replacement = join(dirname(scanDir), "replacement");
      await cp(scanDir, replacement, { recursive: true });
      const replacementFindings = join(replacement, "findings.json");
      const findings = await readJson(replacementFindings);
      findings["findings"][0]["title"] = "VALID REPLACEMENT";
      await writeJson(replacementFindings, findings);
      await reseal(replacement);
      const script = `
        import { mock } from "bun:test";
        import { renameSync } from "node:fs";
        import * as original from "node:fs/promises";
        const [scan, replacement, pluginRoot, contract] = process.argv.slice(1);
        const actualLstat = original.lstat;
        let rootLstats = 0;
        let swapped = false;
        mock.module("node:fs/promises", () => ({
          ...original,
          lstat: async (path, ...args) => {
            const metadata = await actualLstat(path, ...args);
            if (path === scan && ++rootLstats === 3 && !swapped) {
              renameSync(scan, scan + ".original");
              renameSync(replacement, scan);
              swapped = true;
            }
            return metadata;
          },
        }));
        const { loadContract } = await import(contract);
        try {
          await loadContract(scan, { pluginRoot });
          console.log("ACCEPTED", swapped, rootLstats);
          process.exitCode = 2;
        } catch (error) {
          console.log("REJECTED", swapped, rootLstats, error instanceof Error ? error.message : String(error));
        }
      `;
      const result = spawnSync(
        process.execPath,
        [
          "-e",
          script,
          scanDir,
          replacement,
          PLUGIN_ROOT,
          fileURLToPath(new URL("../src/contract.ts", import.meta.url)),
        ],
        { encoding: "utf8" },
      );
      expect(result.status).toBe(0);
      expect(result.stdout).toContain("REJECTED true");
    },
  );

  test.skipIf(process.platform === "win32")(
    "rejects a scan directory swapped between canonical document reads",
    async () => {
      const scanDir = await copyExample();
      const root = dirname(scanDir);
      const replacement = join(root, "replacement");
      await cp(scanDir, replacement, { recursive: true });
      const replacementFindings = join(replacement, "findings.json");
      const findings = await readJson(replacementFindings);
      findings["findings"][0]["title"] = "Replacement findings";
      await writeJson(replacementFindings, findings);
      const manifestPath = join(scanDir, "scan-manifest.json");
      const manifest = await readJson(manifestPath);
      for (const artifact of manifest["scan"]["artifacts"]) {
        artifact["sha256"] = createHash("sha256")
          .update(await readFile(join(replacement, artifact["path"])))
          .digest("hex");
      }
      await writeJson(manifestPath, manifest);
      const script = `
        import { mock } from "bun:test";
        import { renameSync } from "node:fs";
        import * as original from "node:fs/promises";
        import { join } from "node:path";
        const [scan, replacement, pluginRoot, contract] = process.argv.slice(1);
        const manifest = join(scan, "scan-manifest.json");
        const actualOpen = original.open;
        const actualLstat = original.lstat;
        let readManifest = false;
        let swapped = false;
        mock.module("node:fs/promises", () => ({
          ...original,
          open: async (path, ...args) => {
            const file = await actualOpen(path, ...args);
            if (path === manifest) {
              const read = file.readFile.bind(file);
              file.readFile = async (...readArgs) => {
                const bytes = await read(...readArgs);
                readManifest = true;
                return bytes;
              };
            }
            return file;
          },
          lstat: async (path, ...args) => {
            if (readManifest && !swapped && path === scan) {
              renameSync(scan, scan + ".original");
              renameSync(replacement, scan);
              swapped = true;
            }
            return await actualLstat(path, ...args);
          },
        }));
        const { loadContract } = await import(contract);
        try {
          await loadContract(scan, { pluginRoot });
          console.log("ACCEPTED", swapped);
          process.exitCode = 2;
        } catch (error) {
          console.log("REJECTED", swapped, error instanceof Error ? error.message : String(error));
        }
      `;
      const result = spawnSync(
        process.execPath,
        [
          "-e",
          script,
          scanDir,
          replacement,
          PLUGIN_ROOT,
          fileURLToPath(new URL("../src/contract.ts", import.meta.url)),
        ],
        { encoding: "utf8" },
      );
      expect(result.status).toBe(0);
      expect(result.stdout).toContain("REJECTED true");
    },
  );

  test("rejects invalid canonical fields with permissive plugin schemas", async () => {
    const pluginRoot = await mkdtemp(
      join(tmpdir(), "codex-security-permissive-schema-"),
    );
    temporaryDirectories.push(pluginRoot);
    const schemas = join(pluginRoot, "schemas");
    await mkdir(schemas);
    for (const name of [
      "scan-manifest.schema.json",
      "findings.schema.json",
      "coverage.schema.json",
    ]) {
      await writeJson(join(schemas, name), { type: "object" });
    }

    const scanDir = await copyExample();
    const findingsPath = join(scanDir, "findings.json");
    const coveragePath = join(scanDir, "coverage.json");
    const findings = await readJson(findingsPath);
    findings["findings"][0]["severity"]["level"] = "urgent";
    await writeJson(findingsPath, findings);
    await reseal(scanDir);
    await expect(loadContract(scanDir, { pluginRoot })).rejects.toThrow(
      "severity.level",
    );

    findings["findings"][0]["severity"]["level"] = "high";
    await writeJson(findingsPath, findings);
    const coverage = await readJson(coveragePath);
    coverage["inventoryStrategy"] = "anything";
    await writeJson(coveragePath, coverage);
    await reseal(scanDir);
    await expect(loadContract(scanDir, { pluginRoot })).rejects.toThrow(
      "inventoryStrategy",
    );

    coverage["inventoryStrategy"] = "repository";
    await writeJson(coveragePath, coverage);
    findings["findings"][0]["severity"]["score"] = 8.1;
    findings["findings"][0]["severity"]["scoringSystem"] = 7;
    await writeJson(findingsPath, findings);
    await reseal(scanDir);
    await expect(loadContract(scanDir, { pluginRoot })).rejects.toThrow(
      ContractValidationError,
    );
    await expect(loadContract(scanDir, { pluginRoot })).rejects.toThrow(
      "scoringSystem",
    );

    for (const [removePaths, expected] of [
      [
        ["findings.json", "coverage.json"],
        "expected generated artifact records",
      ],
      [["findings.json"], "missing required artifact: findings.json"],
      [["coverage.json"], "missing required artifact: coverage.json"],
    ] as const) {
      const artifactScan = await copyExample();
      const manifestPath = join(artifactScan, "scan-manifest.json");
      const manifest = await readJson(manifestPath);
      const removed = new Set<string>(removePaths);
      manifest["scan"]["artifacts"] = manifest["scan"]["artifacts"].filter(
        (artifact: Record<string, any>) => !removed.has(artifact["path"]),
      );
      await writeJson(manifestPath, manifest);
      await expect(loadContract(artifactScan, { pluginRoot })).rejects.toThrow(
        expected,
      );
    }

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
        "revision target without revision",
        (manifest) => {
          manifest["scan"]["target"]["kind"] = "git_revision";
          delete manifest["scan"]["target"]["revision"];
        },
        "target.revision",
      ],
      [
        "snapshot target without digest",
        (manifest) => {
          manifest["scan"]["target"]["kind"] = "directory_snapshot";
          delete manifest["scan"]["target"]["snapshotDigest"];
        },
        "target.snapshotDigest",
      ],
      [
        "invalid snapshot format",
        (manifest) => {
          manifest["scan"]["target"]["snapshotDigest"] = "not-a-snapshot";
        },
        "target.snapshotDigest",
      ],
      [
        "permissive scheme-without-authority remote",
        (manifest) => {
          manifest["scan"]["target"]["remote"] = "https:example.com/repo";
        },
        "canonical absolute URL",
      ],
      [
        "permissive single-slash remote",
        (manifest) => {
          manifest["scan"]["target"]["remote"] = "https:/example.com/repo";
        },
        "canonical absolute URL",
      ],
      [
        "permissive backslash authority remote",
        (manifest) => {
          manifest["scan"]["target"]["remote"] =
            "https://example.com\\@evil.test/repo";
        },
        "canonical absolute URL",
      ],
      [
        "invalid rule slug",
        (manifest, findings) => {
          const finding = findings["findings"][0];
          finding["ruleId"] = "UpperCase Rule";
          setFindingIdentity(manifest, finding);
        },
        "ruleId",
      ],
      [
        "invalid anchor slug",
        (manifest, findings) => {
          const finding = findings["findings"][0];
          finding["identity"]["anchor"] = "UpperCase Anchor";
          setFindingIdentity(manifest, finding);
        },
        "identity.anchor",
      ],
      [
        "invalid instance slug",
        (manifest, findings) => {
          const finding = findings["findings"][0];
          finding["identity"]["instance"] = "UpperCase Instance";
          setFindingIdentity(manifest, finding);
        },
        "identity.instance",
      ],
      [
        "scoring system without score",
        (_manifest, findings) => {
          const severity = findings["findings"][0]["severity"];
          delete severity["score"];
          severity["scoringSystem"] = 7;
        },
        "severity.scoringSystem",
      ],
      [
        "invalid severity vector",
        (_manifest, findings) => {
          findings["findings"][0]["severity"]["vector"] = 7;
        },
        "severity.vector",
      ],
      [
        "invalid severity rationale",
        (_manifest, findings) => {
          findings["findings"][0]["severity"]["rationale"] = 7;
        },
        "severity.rationale",
      ],
      [
        "invalid severity change conditions",
        (_manifest, findings) => {
          findings["findings"][0]["severity"]["changeConditions"] = 7;
        },
        "severity.changeConditions",
      ],
      [
        "invalid writeup",
        (_manifest, findings) => {
          findings["findings"][0]["writeup"] = 7;
        },
        "writeup",
      ],
      [
        "invalid report path",
        (_manifest, findings) => {
          findings["findings"][0]["writeup"] = { reportPath: "report.md" };
        },
        "writeup.reportPath",
      ],
      [
        "invalid remediation tests",
        (_manifest, findings) => {
          findings["findings"][0]["remediationTests"] = 7;
        },
        "remediationTests",
      ],
      [
        "invalid preventive controls",
        (_manifest, findings) => {
          findings["findings"][0]["preventiveControls"] = 7;
        },
        "preventiveControls",
      ],
      [
        "invalid validation",
        (_manifest, findings) => {
          findings["findings"][0]["validation"] = 7;
        },
        "validation",
      ],
      [
        "invalid attack path",
        (_manifest, findings) => {
          findings["findings"][0]["attackPath"] = 7;
        },
        "attackPath",
      ],
      [
        "non-array code evidence",
        (_manifest, findings) => {
          findings["findings"][0]["codeEvidence"] = {};
        },
        "codeEvidence",
      ],
      [
        "invalid code-evidence row",
        (_manifest, findings) => {
          findings["findings"][0]["codeEvidence"] = [{ id: "source" }];
        },
        "codeEvidence[0].label",
      ],
      [
        "non-object extensions",
        (_manifest, findings) => {
          findings["findings"][0]["extensions"] = [];
        },
        "extensions",
      ],
      [
        "invalid location role",
        (_manifest, findings) => {
          findings["findings"][0]["locations"][0]["role"] = 7;
        },
        "locations[0].role",
      ],
      [
        "invalid root cause",
        (_manifest, findings) => {
          findings["findings"][0]["rootCause"] = 7;
        },
        "rootCause",
      ],
      [
        "invalid explicit exclusion",
        (_manifest, _findings, coverage) => {
          coverage["explicitExclusions"] = [7];
        },
        "explicitExclusions[0]",
      ],
      [
        "invalid deferred item",
        (_manifest, _findings, coverage) => {
          coverage["deferred"] = [7];
        },
        "deferred[0]",
      ],
      [
        "invalid open questions",
        (_manifest, _findings, coverage) => {
          coverage["openQuestions"] = 7;
        },
        "openQuestions",
      ],
      [
        "invalid open-question row",
        (_manifest, _findings, coverage) => {
          coverage["openQuestions"] = [{}];
        },
        "openQuestions[0].question",
      ],
      [
        "invalid surface notes",
        (_manifest, _findings, coverage) => {
          coverage["surfaces"][0]["notes"] = 7;
        },
        "surfaces[0].notes",
      ],
      [
        "invalid surface risk area",
        (_manifest, _findings, coverage) => {
          coverage["surfaces"][0]["riskArea"] = 7;
        },
        "surfaces[0].riskArea",
      ],
      [
        "invalid threat model",
        (manifest) => {
          manifest["scan"]["threatModel"] = 7;
        },
        "threatModel",
      ],
      [
        "invalid threat-model assets",
        (manifest) => {
          manifest["scan"]["threatModel"] = { summary: "Threats", assets: 7 };
        },
        "threatModel.assets",
      ],
      [
        "invalid hardening",
        (manifest) => {
          manifest["scan"]["hardening"] = { portfolioPath: "report.md" };
        },
        "hardening.portfolioPath",
      ],
      [
        "invalid scope summary",
        (manifest) => {
          manifest["scan"]["scope"]["summary"] = 7;
        },
        "scope.summary",
      ],
      [
        "invalid reviewed artifacts",
        (manifest) => {
          manifest["scan"]["scope"]["artifactsReviewed"] = 7;
        },
        "scope.artifactsReviewed",
      ],
    ];
    for (const [_name, mutate, expected] of cases) {
      const invalidScan = await copyExample();
      const manifestPath = join(invalidScan, "scan-manifest.json");
      const findingsPath = join(invalidScan, "findings.json");
      const coveragePath = join(invalidScan, "coverage.json");
      const manifest = await readJson(manifestPath);
      const findings = await readJson(findingsPath);
      const coverage = await readJson(coveragePath);
      mutate(manifest, findings, coverage);
      await writeJson(manifestPath, manifest);
      await writeJson(findingsPath, findings);
      await writeJson(coveragePath, coverage);
      await reseal(invalidScan);
      await expect(loadContract(invalidScan, { pluginRoot })).rejects.toThrow(
        expected,
      );
    }
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
