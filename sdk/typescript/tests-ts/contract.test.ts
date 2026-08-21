import { createHash } from "node:crypto";
import type { Stats } from "node:fs";
import {
  chmod,
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  type FileHandle,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import fc from "fast-check";
import { ContractValidationError, loadContract } from "../src/index.js";
import { sameCheckedFileDevice } from "../src/contract.js";
import type { NormalizedTarget, ScanExpectation } from "../src/index.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { propertyOptions } from "./support/property.js";

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
  test("rejects byte changes to any sealed binary artifact", async () => {
    const scanDir = await copyExample();
    const artifactPath = join(scanDir, "artifacts", "synthetic.bin");
    const manifestPath = join(scanDir, "scan-manifest.json");
    const manifest = await readJson(manifestPath);
    await mkdir(dirname(artifactPath), { recursive: true });

    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 256 }),
        fc.nat(),
        fc.integer({ min: 1, max: 255 }),
        async (bytes, offset, difference) => {
          await writeFile(artifactPath, bytes);
          await writeJson(manifestPath, {
            ...manifest,
            scan: {
              ...manifest["scan"],
              artifacts: [
                ...manifest["scan"]["artifacts"],
                {
                  path: "artifacts/synthetic.bin",
                  sha256: createHash("sha256").update(bytes).digest("hex"),
                  mediaType: "application/octet-stream",
                },
              ],
            },
          });
          await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT });
          const changed = Uint8Array.from(bytes);
          changed[offset % bytes.length]! ^= difference;
          await writeFile(artifactPath, changed);
          await expect(
            loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
          ).rejects.toBeInstanceOf(ContractValidationError);
        },
      ),
      {
        ...propertyOptions,
        numRuns: Number(process.env["CODEX_SECURITY_PROPERTY_RUNS"] ?? "20"),
      },
    );
  });

  test("rejects non-relative artifact paths before accepting a seal", async () => {
    const scanDir = await copyExample();
    const manifestPath = join(scanDir, "scan-manifest.json");
    const manifest = await readJson(manifestPath);
    const prefixes = ["../", "/", "C:/", "artifacts/../", "artifacts\\"];
    await mkdir(join(scanDir, "artifacts"), { recursive: true });
    await fc.assert(
      fc.asyncProperty(
        fc.stringMatching(/^[a-z]{1,16}$/u),
        fc.constantFrom(...prefixes),
        async (name, prefix) => {
          const filename = `artifact-${name}`;
          const bytes = Buffer.from(name);
          const artifact = {
            path: `artifacts/${filename}`,
            sha256: createHash("sha256").update(bytes).digest("hex"),
            mediaType: "application/octet-stream",
          };
          const scan = {
            ...manifest["scan"],
            artifacts: [...manifest["scan"]["artifacts"], artifact],
          };
          await writeFile(join(scanDir, "artifacts", filename), bytes);
          await writeJson(manifestPath, { ...manifest, scan });
          await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT });

          artifact.path = `${prefix}${filename}`;
          await writeJson(manifestPath, { ...manifest, scan });
          const rejected = loadContract(scanDir, { pluginRoot: PLUGIN_ROOT });
          await expect(rejected).rejects.toBeInstanceOf(
            ContractValidationError,
          );
          await expect(rejected).rejects.toThrow(
            /safe scan-relative POSIX path|schema validation failed \(pattern/u,
          );
        },
      ),
      {
        ...propertyOptions,
        numRuns: Number(process.env["CODEX_SECURITY_PROPERTY_RUNS"] ?? "20"),
        examples: [
          ...prefixes.map((prefix): [string, string] => ["synthetic", prefix]),
          ["con", "C:/"],
        ],
      },
    );
  });

  test("ships a completed example that passes tracking preflight", () => {
    const result = Bun.spawnSync(
      [
        Bun.which("python3") ?? "python",
        "-I",
        "-B",
        join(PLUGIN_ROOT, "scripts", "validate_tracking_source.py"),
        EXAMPLE,
      ],
      { stdout: "pipe", stderr: "pipe" },
    );
    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
  });

  test("compares exact Windows volume serials without rounding file identity", async () => {
    const scanDir = await copyExample();
    const path = join(scanDir, "scan-manifest.json");
    const metadata = await lstat(path);
    const identity = await lstat(path, { bigint: true });
    const volume = BigInt.asUintN(32, identity.dev);
    const highDevice = (1n << 60n) | volume;
    expect(highDevice).toBeGreaterThan(BigInt(Number.MAX_SAFE_INTEGER));

    let device = highDevice;
    let inode = identity.ino;
    let regular = true;
    let inspected = 0;
    let referenceDevice = highDevice;
    let referenceInode = identity.ino;
    let referenceRegular = true;
    let referenceClosed = 0;
    const file = {
      stat: async () => {
        inspected += 1;
        return {
          dev: device,
          ino: inode,
          isFile: () => regular,
        };
      },
    } as unknown as FileHandle;
    const reference = {
      stat: async () => ({
        dev: referenceDevice,
        ino: referenceInode,
        isFile: () => referenceRegular,
      }),
      close: async () => {
        referenceClosed += 1;
      },
    } as unknown as FileHandle;
    const openReference = async () => reference;
    const checked = { path, metadata, parents: [] };
    const opened = { dev: Number(highDevice), ino: metadata.ino } as Stats;

    await expect(
      sameCheckedFileDevice(file, checked, opened, "win32", openReference),
    ).resolves.toBe(true);
    expect(referenceClosed).toBe(1);

    const inconsistentNumberInode = {
      dev: metadata.dev,
      ino: metadata.ino + 1024,
    } as Stats;
    await expect(
      sameCheckedFileDevice(
        file,
        checked,
        inconsistentNumberInode,
        "win32",
        openReference,
      ),
    ).resolves.toBe(false);

    device = highDevice ^ 1n;
    await expect(
      sameCheckedFileDevice(file, checked, opened, "win32", openReference),
    ).resolves.toBe(false);
    expect(referenceClosed).toBe(2);

    referenceDevice = device;
    await expect(
      sameCheckedFileDevice(file, checked, opened, "win32", openReference),
    ).resolves.toBe(true);
    expect(referenceClosed).toBe(3);

    device = highDevice;
    referenceDevice = highDevice;
    inode = identity.ino + 1n;
    await expect(
      sameCheckedFileDevice(file, checked, opened, "win32", openReference),
    ).resolves.toBe(false);

    inode = identity.ino;
    regular = false;
    await expect(
      sameCheckedFileDevice(file, checked, opened, "win32", openReference),
    ).resolves.toBe(false);

    regular = true;
    referenceInode = identity.ino + 1n;
    await expect(
      sameCheckedFileDevice(file, checked, opened, "win32", openReference),
    ).resolves.toBe(false);

    referenceInode = identity.ino;
    referenceRegular = false;
    await expect(
      sameCheckedFileDevice(file, checked, opened, "win32", openReference),
    ).resolves.toBe(false);

    const windowsInspections = inspected;
    await expect(
      sameCheckedFileDevice(file, checked, opened, "linux", openReference),
    ).resolves.toBe(false);
    expect(inspected).toBe(windowsInspections);
  });

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

  test("preserves schema-valid sealed finding details", async () => {
    const scanDir = await copyExample();
    const findingsPath = join(scanDir, "findings.json");
    const findings = await readJson(findingsPath);
    const validation = {
      evidence: "single proof",
      counterEvidence: [],
      status: null,
      disposition: null,
      result: null,
    };
    findings["findings"][0]["validation"] = validation;
    findings["findings"][0]["code_evidence"] = null;
    await writeJson(findingsPath, findings);
    await reseal(scanDir);

    const loaded = await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT });

    expect(loaded.findings.findings[0]?.validation).toEqual(validation);
    expect(loaded.findings.findings[0]?.code_evidence).toBeNull();
    expect(await readJson(findingsPath)).toEqual(findings);
  });

  test("preserves valid details while normalizing malformed legacy siblings", async () => {
    const scanDir = await copyExample();
    const findingsPath = join(scanDir, "findings.json");
    const findings = await readJson(findingsPath);
    const validation = {
      evidence: "single proof",
      counterEvidence: [],
      status: null,
      disposition: null,
      result: null,
    };
    findings["findings"][0]["validation"] = validation;
    const codeEvidence = [{ id: " ", code: " " }];
    findings["findings"][0]["code_evidence"] = codeEvidence;
    findings["findings"][0]["attackPath"] = {
      steps: { first: "upload" },
    };
    await writeJson(findingsPath, findings);
    await reseal(scanDir);

    const loaded = await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT });

    expect(loaded.findings.findings[0]?.validation).toEqual(validation);
    expect(loaded.findings.findings[0]?.code_evidence).toEqual(codeEvidence);
    expect(loaded.findings.findings[0]?.attackPath?.steps).toBeUndefined();
    expect(await readJson(findingsPath)).toEqual(findings);
  });

  test("preserves empty union lists while normalizing malformed siblings", async () => {
    const scanDir = await copyExample();
    const findingsPath = join(scanDir, "findings.json");
    const findings = await readJson(findingsPath);
    findings["findings"][0]["validation"] = { evidence: [] };
    findings["findings"][0]["attackPath"] = {
      steps: { first: "upload" },
    };
    await writeJson(findingsPath, findings);
    await reseal(scanDir);

    const loaded = await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT });

    expect(loaded.findings.findings[0]?.validation?.evidence).toEqual([]);
    expect(loaded.findings.findings[0]?.attackPath?.steps).toBeUndefined();
    expect(await readJson(findingsPath)).toEqual(findings);
  });

  test("normalizes pre-typed sealed finding details without changing the artifact", async () => {
    const scanDir = await copyExample();
    const findingsPath = join(scanDir, "findings.json");
    const findings = await readJson(findingsPath);
    const legacyValidation = {
      evidence: { kind: "trace" },
      counterEvidence: [null, "The mitigation was checked."],
    };
    const legacyAttackPath = { steps: { first: "upload" } };
    findings["findings"][0]["validation"] = legacyValidation;
    findings["findings"][0]["attackPath"] = legacyAttackPath;
    findings["findings"][0]["root_cause"] = null;
    findings["findings"][0]["code_evidence"] = [
      { id: "legacy-source", code: "legacy_source()" },
    ];
    await writeJson(findingsPath, findings);
    await reseal(scanDir);

    const loaded = await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT });
    expect(loaded.findings.findings[0]?.code_evidence?.[0]?.id).toBe(
      "legacy-source",
    );
    const loadedFinding = loaded.findings.findings[0];
    expect(loadedFinding?.validation?.evidence).toBeUndefined();
    expect(
      loadedFinding?.validation?.counterEvidence?.map((item) =>
        item.toUpperCase(),
      ),
    ).toEqual(["THE MITIGATION WAS CHECKED."]);
    expect(loadedFinding?.attackPath?.steps).toBeUndefined();
    expect(loadedFinding?.root_cause).toBeNull();
    expect(await readJson(findingsPath)).toEqual(findings);
  });

  test("rejects malformed canonical root-cause details", async () => {
    const scanDir = await copyExample();
    const findingsPath = join(scanDir, "findings.json");
    const findings = await readJson(findingsPath);
    findings["findings"][0]["rootCause"] = { summary: [] };
    await writeJson(findingsPath, findings);
    await reseal(scanDir);

    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).rejects.toThrow("findings.json");
    expect(await readJson(findingsPath)).toEqual(findings);
  });

  test("loads an empty legacy root cause without changing the artifact", async () => {
    const scanDir = await copyExample();
    const findingsPath = join(scanDir, "findings.json");
    const findings = await readJson(findingsPath);
    findings["findings"][0]["root_cause"] = "";
    await writeJson(findingsPath, findings);
    await reseal(scanDir);

    const loaded = await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT });

    expect(loaded.findings.findings[0]?.root_cause).toBe("");
    expect(await readJson(findingsPath)).toEqual(findings);
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
      await mkdir(parent);
      const scanDir = join(parent, "scan");
      await cp(EXAMPLE, scanDir, { recursive: true });
      if (process.platform !== "win32") await chmod(scanDir, 0o700);
      await symlink(parent, linkedParent);

      await expect(
        loadContract(join(linkedParent, "scan"), { pluginRoot: PLUGIN_ROOT }),
      ).resolves.toBeDefined();
    },
  );

  test("loads contract documents larger than the previous size limit", async () => {
    const scanDir = await copyExample();
    const path = join(scanDir, "scan-manifest.json");
    const manifest = await readJson(path);
    manifest["metadata"] = "x".repeat(16 * 1024 * 1024);
    await writeJson(path, manifest);

    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).resolves.toBeDefined();
  });

  test("loads contract schemas larger than the previous size limit", async () => {
    const pluginRoot = await mkdtemp(
      join(tmpdir(), "codex-security-schema-large-"),
    );
    temporaryDirectories.push(pluginRoot);
    await cp(join(PLUGIN_ROOT, "schemas"), join(pluginRoot, "schemas"), {
      recursive: true,
    });
    const path = join(pluginRoot, "schemas", "scan-manifest.schema.json");
    const schema = await readJson(path);
    schema["description"] = "x".repeat(4 * 1024 * 1024);
    await writeJson(path, schema);

    await expect(
      loadContract(await copyExample(), { pluginRoot }),
    ).resolves.toBeDefined();
  });

  test("loads valid JSON nested beyond the previous depth limit", async () => {
    const scanDir = await copyExample();
    const path = join(scanDir, "findings.json");
    const findings = await readJson(path);
    let nested: unknown = "value";
    for (let depth = 0; depth < 258; depth += 1) nested = [nested];
    findings["findings"][0]["extensions"] = { nested };
    await writeJson(path, findings);
    await reseal(scanDir);

    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).resolves.toBeDefined();
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

  test("accepts valid schemas beyond the previous complexity limit", async () => {
    const pluginRoot = await mkdtemp(
      join(tmpdir(), "codex-security-schema-complex-"),
    );
    temporaryDirectories.push(pluginRoot);
    await cp(join(PLUGIN_ROOT, "schemas"), join(pluginRoot, "schemas"), {
      recursive: true,
    });
    const path = join(pluginRoot, "schemas", "scan-manifest.schema.json");
    const schema = await readJson(path);
    schema["allOf"] = Array.from({ length: 129 }, () => ({ type: "object" }));
    await writeJson(path, schema);

    await expect(
      loadContract(await copyExample(), { pluginRoot }),
    ).resolves.toBeDefined();
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
    for (const unsafe of [
      "D:/escape",
      "../escape",
      "artifacts\\escape",
      "artifacts/report?.json",
    ]) {
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

    for (const unsafe of [
      "artifacts/report.json.",
      "artifacts/report.json ",
      "artifacts/CON.txt",
    ]) {
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
      ).rejects.toThrow("safe scan-relative POSIX path");
    }
  });

  test("keeps bundled finalizer paths portable to Windows", () => {
    const python =
      process.env["PYTHON"] ?? Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    if (python === null) return;
    const program = [
      "import json, sys",
      "sys.path.insert(0, sys.argv[1])",
      "import finalize_scan_contract as finalizer",
      "def accepted(value):",
      "    try:",
      "        finalizer._require_portable_relative_path(value, 'artifact path')",
      "    except finalizer.ContractError:",
      "        return False",
      "    return True",
      "print(json.dumps([accepted(value) for value in ['artifacts/report.json.', 'artifacts/report.json ', 'artifacts/CON.txt', 'artifacts/report?.json', 'artifacts/report:stream']]))",
    ].join("\n");
    const result = Bun.spawnSync(
      [python, "-I", "-B", "-c", program, join(PLUGIN_ROOT, "scripts")],
      { stdout: "pipe", stderr: "pipe" },
    );

    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual([
      false,
      false,
      false,
      false,
      false,
    ]);
  });

  test("accepts Unix-valid source and scope path components", async () => {
    const scanDir = await copyExample();
    const manifestPath = join(scanDir, "scan-manifest.json");
    const findingsPath = join(scanDir, "findings.json");
    const coveragePath = join(scanDir, "coverage.json");
    const manifest = await readJson(manifestPath);
    const findings = await readJson(findingsPath);
    const coverage = await readJson(coveragePath);
    findings["findings"][0]["locations"][0]["path"] = "src/app.ts:fixture";
    manifest["scan"]["scope"]["includePaths"] = ["src/CON.py"];
    coverage["includePaths"] = ["src/CON.py"];
    await writeJson(findingsPath, findings);
    await writeJson(coveragePath, coverage);
    await writeJson(manifestPath, manifest);
    await reseal(scanDir);

    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).resolves.toBeDefined();
  });

  test("rejects trailing-dot aliases for sealed artifacts", async () => {
    const scanDir = await copyExample();
    const manifestPath = join(scanDir, "scan-manifest.json");
    const manifest = await readJson(manifestPath);
    await writeFile(
      join(scanDir, "findings.json."),
      await readFile(join(scanDir, "findings.json")),
    );
    manifest["scan"]["artifacts"].push({
      ...manifest["scan"]["artifacts"][0],
      path: "findings.json.",
    });
    await writeJson(manifestPath, manifest);

    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).rejects.toThrow("safe scan-relative POSIX path");
  });

  test("rejects case-insensitive aliases for sealed artifacts", async () => {
    const scanDir = await copyExample();
    const manifestPath = join(scanDir, "scan-manifest.json");
    const manifest = await readJson(manifestPath);
    await writeFile(
      join(scanDir, "FINDINGS.json"),
      await readFile(join(scanDir, "findings.json")),
    );
    manifest["scan"]["artifacts"].push({
      ...manifest["scan"]["artifacts"][0],
      path: "FINDINGS.json",
    });
    await writeJson(manifestPath, manifest);

    await expect(
      loadContract(scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).rejects.toThrow("duplicate artifact path");

    const python =
      process.env["PYTHON"] ?? Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    if (python === null) return;
    const result = Bun.spawnSync(
      [
        python,
        "-I",
        "-B",
        join(PLUGIN_ROOT, "scripts", "finalize_scan_contract.py"),
        "--scan-dir",
        await realpath(scanDir),
      ],
      { stdout: "pipe", stderr: "pipe" },
    );
    const stderr = new TextDecoder().decode(result.stderr);
    expect(result.exitCode, stderr).not.toBe(0);
    expect(stderr).toContain("duplicate artifact path");
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
    const manifestPath = join(scanDir, "scan-manifest.json");
    const manifest = await readJson(manifestPath);
    manifest["scan"]["scope"]["includePaths"] = ["src"];
    await writeJson(manifestPath, manifest);
    const coveragePath = join(scanDir, "coverage.json");
    const coverage = await readJson(coveragePath);
    coverage["mode"] = "scoped_path";
    coverage["inventoryStrategy"] = "scoped_path";
    coverage["includePaths"] = ["src"];
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
