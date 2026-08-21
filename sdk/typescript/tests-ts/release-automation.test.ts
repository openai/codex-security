import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "bun:test";

type ReleaseMetadata = Record<string, unknown>;

type ReleaseAutomation = {
  releaseVersion: (packageJson: ReleaseMetadata) => string;
  releaseTagVersion: (
    refType: string,
    ref: string,
    refName: string,
    packageJson: ReleaseMetadata,
  ) => string;
  compareReleaseVersions: (left: string, right: string) => -1 | 0 | 1;
  requireReleaseIncrease: (version: string, previousVersion: string) => string;
  initialPublishedVersions: (
    version: string,
    registryError: unknown,
  ) => string[];
  publishedReleaseMode: (
    version: string,
    publishedVersions: unknown,
  ) => "publish" | "recover";
  requirePublishedReleaseIncrease: (
    version: string,
    publishedVersions: unknown,
  ) => string;
  releaseHistory: (
    tag: string,
    history: {
      registryVersions: string[];
      githubReleaseTags: string[];
      reachableTags: string[];
    },
  ) => { previousTag: string | null; makeLatest: boolean };
  verifyPublishedRelease: (
    metadata: ReleaseMetadata,
    archive: Uint8Array,
    expected: { version: string; gitHead: string },
  ) => {
    version: string;
    gitHead: string;
    integrity: string;
    sha256: string;
  };
  verifyGitHubPublishedRelease: (
    metadata: ReleaseMetadata,
    archive: Uint8Array,
    expected: {
      version: string;
      gitHead: string;
      repository: string;
      runId: string;
    },
    provenance: {
      version: string;
      gitHead: string;
      repository: string;
      runId: string;
      sha512: string;
    },
  ) => {
    version: string;
    gitHead: string;
    integrity: string;
    sha256: string;
  };
  verifySignatureAudit: (
    report: ReleaseMetadata,
    archive: Uint8Array,
    expected: {
      version: string;
      gitHead: string;
      repository: string;
      runId: string;
    },
  ) => {
    version: string;
    gitHead: string;
    repository: string;
    runId: string;
    sha512: string;
  };
  verifyRecoveredSignatureAudit: (
    report: ReleaseMetadata,
    archive: Uint8Array,
    expected: {
      version: string;
      gitHead: string;
      repository: string;
    },
  ) => {
    version: string;
    gitHead: string;
    repository: string;
    runId: string;
    sha512: string;
  };
  verifyGitHubRelease: (
    release: ReleaseMetadata,
    archive: Uint8Array,
    expectedTag: string,
    assetName: string,
    downloadedArchive?: Uint8Array,
  ) => { tag: string; asset: string; digest: string };
};

const automationScript = new URL(
  "../scripts/release-automation.mjs",
  import.meta.url,
);
const {
  releaseVersion,
  releaseTagVersion,
  compareReleaseVersions,
  requireReleaseIncrease,
  initialPublishedVersions,
  publishedReleaseMode,
  requirePublishedReleaseIncrease,
  releaseHistory,
  verifyPublishedRelease,
  verifyGitHubPublishedRelease,
  verifySignatureAudit,
  verifyRecoveredSignatureAudit,
  verifyGitHubRelease,
} = (await import(automationScript.href)) as ReleaseAutomation;

const releaseCommit = "1e03c89ad22d2df5ae65b146be1483b3608572a9";
const releaseRun = "30481596229";
const releaseRepository = "openai/codex-security";
const releaseTagTimeout = process.platform === "win32" ? 20_000 : 10_000;

function releaseShell(): string {
  if (process.platform !== "win32") return "bash";
  const git = Bun.which("git");
  if (git === null) return "bash";
  const gitBash = join(dirname(dirname(git)), "bin", "bash.exe");
  return existsSync(gitBash) ? gitBash : "bash";
}

const bash = releaseShell();
const jqMock = [
  "jq() {",
  '  node -e \'const fs=require("node:fs");const filter=process.argv.at(-1);const value=JSON.parse(fs.readFileSync(0,"utf8"));if(filter==="[.object.type, .object.sha] | @tsv"){const fields=[value.object?.type,value.object?.sha];if(fields.some((field)=>typeof field!=="string"))process.exit(1);process.stdout.write(fields.join("\\t")+"\\n");}else if(filter===".status // empty"){if(value.status!=null)process.stdout.write(String(value.status)+"\\n");}else process.exit(64);\' -- "$@"',
  "}",
].join("\n");
const releaseSigningCertificate =
  "MIIHOjCCBr+gAwIBAgIUDDD6xE6tccKRAzn6GcB6Ajvw2+swCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3Rv" +
  "cmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjYwNzI5MTg1MTA1WhcNMjYwNzI5MTkw" +
  "MTA1WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkin3vstve90HTjDjvA07JK3um96wz1+wu9IbeAOgqPZW" +
  "7Ijzx++FAEBWmRp9dJiLOa3xlHM1ZEqjZc3FlbBQrqOCBd4wggXaMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAK" +
  "BggrBgEFBQcDAzAdBgNVHQ4EFgQUn/ffAFOuPTzNV/Vezq93CcIME+wwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjp" +
  "KFWixi4YZD8wbgYDVR0RAQH/BGQwYoZgaHR0cHM6Ly9naXRodWIuY29tL29wZW5haS9jb2RleC1zZWN1cml0eS8u" +
  "Z2l0aHViL3dvcmtmbG93cy9ub2RlLXJlbGVhc2UueW1sQHJlZnMvdGFncy9ucG0tdjAuMS4yMDkGCisGAQQBg78w" +
  "AQEEK2h0dHBzOi8vdG9rZW4uYWN0aW9ucy5naXRodWJ1c2VyY29udGVudC5jb20wEgYKKwYBBAGDvzABAgQEcHVz" +
  "aDA2BgorBgEEAYO/MAEDBCgxZTAzYzg5YWQyMmQyZGY1YWU2NWIxNDZiZTE0ODNiMzYwODU3MmE5MBoGCisGAQQB" +
  "g78wAQQEDG5vZGUtcmVsZWFzZTAjBgorBgEEAYO/MAEFBBVvcGVuYWkvY29kZXgtc2VjdXJpdHkwIgYKKwYBBAGD" +
  "vzABBgQUcmVmcy90YWdzL25wbS12MC4xLjIwOwYKKwYBBAGDvzABCAQtDCtodHRwczovL3Rva2VuLmFjdGlvbnMu" +
  "Z2l0aHVidXNlcmNvbnRlbnQuY29tMHAGCisGAQQBg78wAQkEYgxgaHR0cHM6Ly9naXRodWIuY29tL29wZW5haS9j" +
  "b2RleC1zZWN1cml0eS8uZ2l0aHViL3dvcmtmbG93cy9ub2RlLXJlbGVhc2UueW1sQHJlZnMvdGFncy9ucG0tdjAu" +
  "MS4yMDgGCisGAQQBg78wAQoEKgwoMWUwM2M4OWFkMjJkMmRmNWFlNjViMTQ2YmUxNDgzYjM2MDg1NzJhOTAdBgor" +
  "BgEEAYO/MAELBA8MDWdpdGh1Yi1ob3N0ZWQwOAYKKwYBBAGDvzABDAQqDChodHRwczovL2dpdGh1Yi5jb20vb3Bl" +
  "bmFpL2NvZGV4LXNlY3VyaXR5MDgGCisGAQQBg78wAQ0EKgwoMWUwM2M4OWFkMjJkMmRmNWFlNjViMTQ2YmUxNDgz" +
  "YjM2MDg1NzJhOTAkBgorBgEEAYO/MAEOBBYMFHJlZnMvdGFncy9ucG0tdjAuMS4yMBoGCisGAQQBg78wAQ8EDAwK" +
  "MTI5OTc2OTIyMDApBgorBgEEAYO/MAEQBBsMGWh0dHBzOi8vZ2l0aHViLmNvbS9vcGVuYWkwGAYKKwYBBAGDvzAB" +
  "EQQKDAgxNDk1NzA4MjBwBgorBgEEAYO/MAESBGIMYGh0dHBzOi8vZ2l0aHViLmNvbS9vcGVuYWkvY29kZXgtc2Vj" +
  "dXJpdHkvLmdpdGh1Yi93b3JrZmxvd3Mvbm9kZS1yZWxlYXNlLnltbEByZWZzL3RhZ3MvbnBtLXYwLjEuMjA4Bgor" +
  "BgEEAYO/MAETBCoMKDFlMDNjODlhZDIyZDJkZjVhZTY1YjE0NmJlMTQ4M2IzNjA4NTcyYTkwFAYKKwYBBAGDvzAB" +
  "FAQGDARwdXNoMFwGCisGAQQBg78wARUETgxMaHR0cHM6Ly9naXRodWIuY29tL29wZW5haS9jb2RleC1zZWN1cml0" +
  "eS9hY3Rpb25zL3J1bnMvMzA0ODE1OTYyMjkvYXR0ZW1wdHMvMTAWBgorBgEEAYO/MAEWBAgMBnB1YmxpYzATBgor" +
  "BgEEAYO/MAEXBAUMA25wbTA6BgorBgEEAYO/MAEYBCwMKnJlcG86b3BlbmFpL2NvZGV4LXNlY3VyaXR5OmVudmly" +
  "b25tZW50Om5wbTCBigYKKwYBBAHWeQIEAgR8BHoAeAB2AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6O" +
  "AAABn683UUoAAAQDAEcwRQIhAIByLL09iV3Tt78+V79VHOAcTGiwBe8ZQJO2YfWKr5CcAiAYJQpfxgVSyerx1dTC" +
  "SivSEzQt/ABuKvEHEFavAb+qCzAKBggqhkjOPQQDAwNpADBmAjEA09chNJjy7FhYVY6n7ioITfLzDBs9oaHuGFrD" +
  "HXYnMKbVXVlkt2fVM8WjllMQitjhAjEA2m9qBcOod9M8uMCw76eVJk3YloyAhcTDZfMTtMWaM5DpNG4v/vEZ+MIt" +
  "zIiMHK/0";
const archive = Buffer.from("verified codex security release artifact");
const integrity =
  "sha512-" + createHash("sha512").update(archive).digest("base64");
const sha512 = createHash("sha512").update(archive).digest("hex");
const digest = "sha256:" + createHash("sha256").update(archive).digest("hex");
const protectedReleaseWorkflow = readFileSync(
  new URL("../../../.github/workflows/node-release.yml", import.meta.url),
  "utf8",
);
const releaseCutWorkflow = readFileSync(
  new URL("../../../.github/workflows/node-release-cut.yml", import.meta.url),
  "utf8",
);
const githubReleaseWorkflow = readFileSync(
  new URL(
    "../../../.github/workflows/node-github-release.yml",
    import.meta.url,
  ),
  "utf8",
);
const releaseLabelsWorkflow = readFileSync(
  new URL(
    "../../../.github/workflows/node-release-labels.yml",
    import.meta.url,
  ),
  "utf8",
);

function publishedMetadata(): ReleaseMetadata {
  return {
    name: "@openai/codex-security",
    version: "0.1.2",
    gitHead: releaseCommit,
    "dist.integrity": integrity,
    "dist.attestations": {
      provenance: {
        predicateType: "https://slsa.dev/provenance/v1",
      },
    },
  };
}

function githubRelease(): ReleaseMetadata {
  return {
    tag_name: "npm-v0.1.2",
    draft: false,
    prerelease: false,
    assets: [{ name: "openai-codex-security-0.1.2.tgz", digest }],
  };
}

type SignatureAuditFixture = {
  name?: string;
  version?: string;
  registry?: string;
  invalid?: unknown[];
  missing?: unknown[];
  includeVerified?: boolean;
  includeProvenance?: boolean;
  includeBundle?: boolean;
  signingCertificate?: string | null;
  certificateLocation?: "certificate" | "chain";
  subjectName?: string;
  subjectDigest?: string;
  repository?: string;
  workflowPath?: string;
  workflowRef?: string;
  sourceCommit?: string;
  runId?: string;
  attempt?: string;
  builder?: string;
};

function signatureAudit(options: SignatureAuditFixture = {}): ReleaseMetadata {
  const version = options.version ?? "0.1.2";
  const repository = options.repository ?? releaseRepository;
  const releaseRef = options.workflowRef ?? `refs/tags/npm-v${version}`;
  const signingCertificate =
    options.signingCertificate === undefined
      ? releaseSigningCertificate
      : options.signingCertificate;
  const verificationMaterial =
    options.certificateLocation === "chain"
      ? {
          x509CertificateChain: {
            certificates: [{ rawBytes: signingCertificate }],
          },
        }
      : { certificate: { rawBytes: signingCertificate } };
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [
      {
        name:
          options.subjectName ?? `pkg:npm/%40openai/codex-security@${version}`,
        digest: { sha512: options.subjectDigest ?? sha512 },
      },
    ],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        externalParameters: {
          workflow: {
            repository: `https://github.com/${repository}`,
            ref: releaseRef,
            path: options.workflowPath ?? ".github/workflows/node-release.yml",
          },
        },
        resolvedDependencies: [
          {
            uri: `git+https://github.com/${repository}@${releaseRef}`,
            digest: { gitCommit: options.sourceCommit ?? releaseCommit },
          },
        ],
      },
      runDetails: {
        builder: {
          id:
            options.builder ??
            "https://github.com/actions/runner/github-hosted",
        },
        metadata: {
          invocationId:
            `https://github.com/${repository}/actions/runs/` +
            `${options.runId ?? releaseRun}/attempts/${options.attempt ?? "1"}`,
        },
      },
    },
  };

  return {
    invalid: options.invalid ?? [],
    missing: options.missing ?? [],
    verified:
      options.includeVerified === false
        ? []
        : [
            {
              name: options.name ?? "@openai/codex-security",
              version,
              registry: options.registry ?? "https://registry.npmjs.org/",
              attestations:
                options.includeProvenance === false
                  ? {}
                  : {
                      provenance: {
                        predicateType: "https://slsa.dev/provenance/v1",
                      },
                    },
              attestationBundles:
                options.includeBundle === false
                  ? []
                  : [
                      {
                        predicateType: "https://slsa.dev/provenance/v1",
                        bundle: {
                          verificationMaterial,
                          dsseEnvelope: {
                            payload: Buffer.from(
                              JSON.stringify(statement),
                            ).toString("base64"),
                          },
                        },
                      },
                    ],
            },
          ],
  };
}

function signingCertificateWithReplacement(
  original: string,
  replacement: string,
): string {
  const needle = Buffer.from(original);
  const substitute = Buffer.from(replacement);
  if (needle.length !== substitute.length) {
    throw new Error(
      "Signing certificate replacements must preserve DER lengths.",
    );
  }

  const certificate = Buffer.from(releaseSigningCertificate, "base64");
  let offset = certificate.indexOf(needle);
  if (offset === -1) {
    throw new Error(
      "Signing certificate does not contain the requested value.",
    );
  }

  while (offset !== -1) {
    substitute.copy(certificate, offset);
    offset = certificate.indexOf(needle, offset + substitute.length);
  }

  return certificate.toString("base64");
}

function signatureExpected() {
  return {
    version: "0.1.2",
    gitHead: releaseCommit,
    repository: releaseRepository,
    runId: releaseRun,
  };
}

function workflowStepShell(workflow: string, stepName: string): string {
  const stepMarker = `      - name: ${stepName}\n`;
  const stepStart = workflow.indexOf(stepMarker);
  if (stepStart === -1) {
    throw new Error(`Workflow step is missing: ${stepName}`);
  }

  const nextStep = workflow.indexOf("\n      - name: ", stepStart + 1);
  const step = workflow.slice(
    stepStart,
    nextStep === -1 ? undefined : nextStep,
  );
  const runMarker = "        run: |\n";
  const runStart = step.indexOf(runMarker);
  if (runStart === -1) {
    throw new Error(`Workflow step has no shell script: ${stepName}`);
  }

  return step
    .slice(runStart + runMarker.length)
    .split("\n")
    .map((line) => (line.startsWith("          ") ? line.slice(10) : line))
    .join("\n");
}

describe("stable npm release versions", () => {
  test("accepts the official stable package and version", () => {
    expect(
      releaseVersion({
        name: "@openai/codex-security",
        version: "0.1.2",
      }),
    ).toBe("0.1.2");
  });

  test("rejects another package", () => {
    expect(() =>
      releaseVersion({ name: "codex-security", version: "0.1.2" }),
    ).toThrow("Release package must be @openai/codex-security.");
  });

  test.each(["0.1.2-beta.1", "01.1.2", "0.1", "latest", ""])(
    "rejects unstable or malformed version %s",
    (version) => {
      expect(() =>
        releaseVersion({ name: "@openai/codex-security", version }),
      ).toThrow("Release package must have a stable X.Y.Z version.");
    },
  );
});

describe("protected Git release refs", () => {
  const packageJson = {
    name: "@openai/codex-security",
    version: "0.1.2",
  };

  test("accepts the exact stable Git tag and package", () => {
    expect(
      releaseTagVersion(
        "tag",
        "refs/tags/npm-v0.1.2",
        "npm-v0.1.2",
        packageJson,
      ),
    ).toBe("0.1.2");
  });

  test("rejects a release-shaped branch", () => {
    expect(() =>
      releaseTagVersion(
        "branch",
        "refs/heads/npm-v0.1.2",
        "npm-v0.1.2",
        packageJson,
      ),
    ).toThrow("npm releases must be dispatched from a real Git tag.");
  });

  test("rejects a mismatched full Git ref", () => {
    expect(() =>
      releaseTagVersion(
        "tag",
        "refs/tags/npm-v0.1.3",
        "npm-v0.1.2",
        packageJson,
      ),
    ).toThrow("npm releases must be dispatched from a real Git tag.");
  });

  test("rejects an unstable release tag", () => {
    expect(() =>
      releaseTagVersion(
        "tag",
        "refs/tags/npm-v0.1.2-beta.1",
        "npm-v0.1.2-beta.1",
        packageJson,
      ),
    ).toThrow("Release tags must identify a stable npm-vX.Y.Z version.");
  });

  test("rejects a Git tag for a different package version", () => {
    expect(() =>
      releaseTagVersion(
        "tag",
        "refs/tags/npm-v0.1.3",
        "npm-v0.1.3",
        packageJson,
      ),
    ).toThrow("npm release tag must match the stable package version.");
  });
});

describe("monotonic stable release versions", () => {
  test("compares semantic version components numerically", () => {
    expect(compareReleaseVersions("0.1.10", "0.1.9")).toBe(1);
    expect(compareReleaseVersions("1.0.0", "0.99.99")).toBe(1);
    expect(compareReleaseVersions("0.1.2", "0.1.2")).toBe(0);
    expect(compareReleaseVersions("0.1.2", "0.1.3")).toBe(-1);
  });

  test("compares components without unsafe JavaScript number rounding", () => {
    expect(
      compareReleaseVersions("9007199254740993.0.0", "9007199254740992.0.0"),
    ).toBe(1);
  });

  test("accepts a strictly increasing release", () => {
    expect(requireReleaseIncrease("0.1.3", "0.1.2")).toBe("0.1.3");
  });

  test("rejects a downgrade or repeated release", () => {
    expect(() => requireReleaseIncrease("0.1.1", "0.1.2")).toThrow(
      "Release version must be greater than the previous stable version.",
    );
    expect(() => requireReleaseIncrease("0.1.2", "0.1.2")).toThrow(
      "Release version must be greater than the previous stable version.",
    );
  });

  test("rejects malformed and prerelease versions", () => {
    expect(() => compareReleaseVersions("0.1.3-beta.1", "0.1.2")).toThrow(
      "Release versions must use stable X.Y.Z versions.",
    );
  });

  test("requires every release to exceed every published stable version", () => {
    expect(
      requirePublishedReleaseIncrease("0.1.11", [
        "0.1.9",
        "0.1.10",
        "0.1.3-beta.1",
      ]),
    ).toBe("0.1.11");
  });

  test("identifies a strictly increasing version as a new publication", () => {
    expect(publishedReleaseMode("0.1.3", ["0.1.0", "0.1.2"])).toBe("publish");
  });

  test("allows a missing npm package only for its initial stable release", () => {
    expect(
      initialPublishedVersions("0.1.0", { error: { code: "E404" } }),
    ).toEqual([]);
  });

  test.each([
    { version: "0.1.1", registryError: { error: { code: "E404" } } },
    { version: "0.1.0", registryError: { error: { code: "E403" } } },
    { version: "0.1.0", registryError: { error: { code: "ETIMEDOUT" } } },
    { version: "0.1.0", registryError: { error: null } },
    { version: "0.1.0", registryError: null },
  ])(
    "rejects unverified npm history for $version and registry response $registryError",
    ({ version, registryError }) => {
      expect(() => initialPublishedVersions(version, registryError)).toThrow(
        "Unable to verify published npm release history.",
      );
    },
  );

  test("identifies the current published version as recoverable", () => {
    expect(publishedReleaseMode("0.1.2", ["0.1.0", "0.1.2"])).toBe("recover");
  });

  test("never recovers a published version below a newer stable release", () => {
    expect(() => publishedReleaseMode("0.1.2", ["0.1.2", "0.1.3"])).toThrow(
      "Release version must be greater than every published stable version.",
    );
  });

  test("ignores prerelease versions when determining recovery", () => {
    expect(publishedReleaseMode("0.1.2", ["0.1.2", "0.1.3-beta.1"])).toBe(
      "recover",
    );
  });

  test("fails safely when recovery history is malformed", () => {
    for (const publishedVersions of [null, {}, "0.1.2"]) {
      expect(() => publishedReleaseMode("0.1.2", publishedVersions)).toThrow(
        "Published npm release versions must be an array.",
      );
    }
  });

  test("rejects a manual release below the highest published version", () => {
    expect(() =>
      requirePublishedReleaseIncrease("1.9.9", ["1.9.8", "2.0.0"]),
    ).toThrow(
      "Release version must be greater than every published stable version.",
    );
  });

  test("rejects a previously published release version", () => {
    expect(() =>
      requirePublishedReleaseIncrease("0.1.2", ["0.1.0", "0.1.2"]),
    ).toThrow(
      "Release version must be greater than every published stable version.",
    );
  });

  test("fails safely when published release history is malformed", () => {
    for (const publishedVersions of [null, {}, "0.1.2"]) {
      expect(() =>
        requirePublishedReleaseIncrease("0.1.3", publishedVersions),
      ).toThrow("Published npm release versions must be an array.");
    }
  });
});

describe("published GitHub and npm release history", () => {
  test("marks the first verified GitHub release as latest", () => {
    expect(
      releaseHistory("npm-v0.1.2", {
        registryVersions: ["0.1.0", "0.1.1", "0.1.2"],
        githubReleaseTags: [],
        reachableTags: ["npm-v0.1.1", "npm-v0.1.0"],
      }),
    ).toEqual({ previousTag: "npm-v0.1.1", makeLatest: true });
  });

  test("keeps an already-published newest GitHub release marked latest", () => {
    expect(
      releaseHistory("npm-v0.1.2", {
        registryVersions: ["0.1.1", "0.1.2"],
        githubReleaseTags: ["npm-v0.1.1", "npm-v0.1.2"],
        reachableTags: ["npm-v0.1.1", "npm-v0.1.2"],
      }),
    ).toEqual({ previousTag: "npm-v0.1.1", makeLatest: true });
  });

  test("never marks a historical backfill as latest", () => {
    expect(
      releaseHistory("npm-v0.1.2", {
        registryVersions: ["0.1.1", "0.1.2", "0.1.3"],
        githubReleaseTags: ["npm-v0.1.3"],
        reachableTags: ["npm-v0.1.1"],
      }),
    ).toEqual({ previousTag: "npm-v0.1.1", makeLatest: false });
  });

  test("never marks a backfill latest when a newer npm release lacks GitHub notes", () => {
    expect(
      releaseHistory("npm-v0.1.2", {
        registryVersions: ["0.1.1", "0.1.2", "0.1.3"],
        githubReleaseTags: [],
        reachableTags: ["npm-v0.1.1"],
      }),
    ).toEqual({ previousTag: "npm-v0.1.1", makeLatest: false });
  });

  test("starts notes from the newest actually published version", () => {
    expect(
      releaseHistory("npm-v0.1.4", {
        registryVersions: ["0.1.1", "0.1.2", "0.1.4"],
        githubReleaseTags: ["npm-v0.1.2"],
        reachableTags: ["npm-v0.1.3", "npm-v0.1.2", "npm-v0.1.1"],
      }),
    ).toEqual({ previousTag: "npm-v0.1.2", makeLatest: true });
  });

  test("compares published versions numerically rather than lexically", () => {
    expect(
      releaseHistory("npm-v0.1.11", {
        registryVersions: ["0.1.9", "0.1.10", "0.1.11"],
        githubReleaseTags: ["npm-v0.1.9", "npm-v0.1.10"],
        reachableTags: ["npm-v0.1.9", "npm-v0.1.10"],
      }),
    ).toEqual({ previousTag: "npm-v0.1.10", makeLatest: true });
  });

  test("ignores unrelated, unstable, and unreachable release tags", () => {
    expect(
      releaseHistory("npm-v0.1.2", {
        registryVersions: ["0.1.1", "0.1.2", "0.1.3-beta.1"],
        githubReleaseTags: ["container-v99.0.0", "npm-v0.1.3-beta.1"],
        reachableTags: ["container-v99.0.0", "npm-v0.1.3-beta.1", "npm-v0.1.1"],
      }),
    ).toEqual({ previousTag: "npm-v0.1.1", makeLatest: true });
  });

  test("rejects invalid release history inputs", () => {
    expect(() =>
      releaseHistory("0.1.2", {
        registryVersions: [],
        githubReleaseTags: [],
        reachableTags: [],
      }),
    ).toThrow("Release tags must identify a stable npm-vX.Y.Z version.");
  });
});

describe("published npm release verification", () => {
  test("verifies source commit, tarball integrity, and SLSA provenance", () => {
    expect(
      verifyPublishedRelease(publishedMetadata(), archive, {
        version: "0.1.2",
        gitHead: releaseCommit,
      }),
    ).toEqual({
      version: "0.1.2",
      gitHead: releaseCommit,
      integrity,
      sha256: digest.slice("sha256:".length),
    });
  });

  test("supports nested public npm metadata", () => {
    expect(
      verifyPublishedRelease(
        {
          name: "@openai/codex-security",
          version: "0.1.2",
          gitHead: releaseCommit,
          dist: {
            integrity,
            attestations: {
              provenance: {
                predicateType: "https://slsa.dev/provenance/v1",
              },
            },
          },
        },
        archive,
        { version: "0.1.2", gitHead: releaseCommit },
      ).integrity,
    ).toBe(integrity);
  });

  test("rejects a different published version", () => {
    expect(() =>
      verifyPublishedRelease(publishedMetadata(), archive, {
        version: "0.1.3",
        gitHead: releaseCommit,
      }),
    ).toThrow("Published npm package must match the release version.");
  });

  test("rejects a missing or mismatched release commit", () => {
    expect(() =>
      verifyPublishedRelease(
        { ...publishedMetadata(), gitHead: undefined },
        archive,
        { version: "0.1.2", gitHead: releaseCommit },
      ),
    ).toThrow("npm package gitHead must match release commit");
  });

  test("rejects a tarball that differs from the published npm artifact", () => {
    expect(() =>
      verifyPublishedRelease(
        publishedMetadata(),
        Buffer.from("different release artifact"),
        { version: "0.1.2", gitHead: releaseCommit },
      ),
    ).toThrow(
      "Published npm integrity must match the verified release artifact.",
    );
  });

  test("rejects missing or unexpected provenance", () => {
    expect(() =>
      verifyPublishedRelease(
        { ...publishedMetadata(), "dist.attestations": undefined },
        archive,
        { version: "0.1.2", gitHead: releaseCommit },
      ),
    ).toThrow("Published npm package must have SLSA v1 provenance.");
  });
});

describe("GitHub release publication verification", () => {
  const expected = {
    version: "0.1.2",
    gitHead: releaseCommit,
    repository: releaseRepository,
    runId: releaseRun,
  };
  const provenance = {
    ...expected,
    sha512,
  };

  test("retains strict source and artifact verification for current releases", () => {
    expect(
      verifyGitHubPublishedRelease(
        publishedMetadata(),
        archive,
        expected,
        provenance,
      ),
    ).toEqual({
      version: "0.1.2",
      gitHead: releaseCommit,
      integrity,
      sha256: digest.slice("sha256:".length),
    });
  });

  test.each(["0.1.0", "0.1.1"])(
    "recovers the missing gitHead only from verified provenance for %s",
    (version) => {
      const metadata: ReleaseMetadata = { ...publishedMetadata(), version };
      delete metadata["gitHead"];

      expect(
        verifyGitHubPublishedRelease(
          metadata,
          archive,
          { ...expected, version },
          { ...provenance, version },
        ),
      ).toEqual({
        version,
        gitHead: releaseCommit,
        integrity,
        sha256: digest.slice("sha256:".length),
      });

      expect(() =>
        verifyPublishedRelease(metadata, archive, { ...expected, version }),
      ).toThrow("npm package gitHead must match release commit");
    },
  );

  test("rejects a missing gitHead on all later npm releases", () => {
    const metadata: ReleaseMetadata = { ...publishedMetadata() };
    delete metadata["gitHead"];

    expect(() =>
      verifyGitHubPublishedRelease(metadata, archive, expected, provenance),
    ).toThrow("Only npm releases 0.1.0 and 0.1.1 may omit gitHead.");
  });

  test("rejects a mismatched historical npm gitHead", () => {
    expect(() =>
      verifyGitHubPublishedRelease(
        {
          ...publishedMetadata(),
          version: "0.1.0",
          gitHead: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
        archive,
        { ...expected, version: "0.1.0" },
        { ...provenance, version: "0.1.0" },
      ),
    ).toThrow("npm package gitHead must match release commit");
  });

  test.each([
    { version: "0.1.1" },
    { gitHead: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
    { repository: "different/codex-security" },
    { runId: "30481596228" },
    { sha512: "0".repeat(128) },
  ])("rejects signed provenance that does not match %j", (mismatch) => {
    expect(() =>
      verifyGitHubPublishedRelease(publishedMetadata(), archive, expected, {
        ...provenance,
        ...mismatch,
      }),
    ).toThrow("Verified signed npm provenance must match the GitHub release.");
  });

  test("rejects missing verified provenance", () => {
    expect(() =>
      verifyGitHubPublishedRelease(
        publishedMetadata(),
        archive,
        expected,
        undefined as unknown as typeof provenance,
      ),
    ).toThrow("Verified signed npm provenance must match the GitHub release.");
  });
});

describe("cryptographically verified npm provenance", () => {
  test("binds the verified bundle to the exact archive, source, and run", () => {
    expect(
      verifySignatureAudit(signatureAudit(), archive, signatureExpected()),
    ).toEqual({
      version: "0.1.2",
      gitHead: releaseCommit,
      repository: releaseRepository,
      runId: releaseRun,
      sha512,
    });
  });

  test("recovers a published archive using its authenticated original run", () => {
    expect(
      verifyRecoveredSignatureAudit(signatureAudit(), archive, {
        version: "0.1.2",
        gitHead: releaseCommit,
        repository: releaseRepository,
      }),
    ).toEqual({
      version: "0.1.2",
      gitHead: releaseCommit,
      repository: releaseRepository,
      runId: releaseRun,
      sha512,
    });
  });

  test.each(["", "0", "01", "not-a-number", "1/extra", "1?attempt=2"])(
    "rejects the malformed protected workflow run attempt %j",
    (attempt) => {
      expect(() =>
        verifySignatureAudit(
          signatureAudit({ attempt }),
          archive,
          signatureExpected(),
        ),
      ).toThrow(
        "Verified SLSA provenance must identify the successful release run.",
      );
      expect(() =>
        verifyRecoveredSignatureAudit(signatureAudit({ attempt }), archive, {
          version: "0.1.2",
          gitHead: releaseCommit,
          repository: releaseRepository,
        }),
      ).toThrow(
        "Verified SLSA provenance must identify the protected release run.",
      );
    },
  );

  test("rejects a recovered archive whose certificate identifies another run", () => {
    expect(() =>
      verifyRecoveredSignatureAudit(
        signatureAudit({ runId: "30481596228" }),
        archive,
        {
          version: "0.1.2",
          gitHead: releaseCommit,
          repository: releaseRepository,
        },
      ),
    ).toThrow("The Fulcio certificate must identify the exact release run.");
  });

  test("rejects a recovered archive signed for a different source commit", () => {
    expect(() =>
      verifyRecoveredSignatureAudit(signatureAudit(), archive, {
        version: "0.1.2",
        gitHead: "0000000000000000000000000000000000000000",
        repository: releaseRepository,
      }),
    ).toThrow("npm package gitHead must match release commit");
  });

  test("rejects a recovery without an authentic provenance bundle", () => {
    expect(() =>
      verifyRecoveredSignatureAudit(
        signatureAudit({ includeBundle: false }),
        archive,
        {
          version: "0.1.2",
          gitHead: releaseCommit,
          repository: releaseRepository,
        },
      ),
    ).toThrow("The verified SLSA provenance bundle is missing.");
  });

  test("accepts the real Fulcio certificate in the legacy chain format", () => {
    expect(
      verifySignatureAudit(
        signatureAudit({ certificateLocation: "chain" }),
        archive,
        signatureExpected(),
      ),
    ).toEqual({
      version: "0.1.2",
      gitHead: releaseCommit,
      repository: releaseRepository,
      runId: releaseRun,
      sha512,
    });
  });

  test("rejects missing and malformed Fulcio signing certificates", () => {
    for (const signingCertificate of [null, "not-base64"]) {
      expect(() =>
        verifySignatureAudit(
          signatureAudit({ signingCertificate }),
          archive,
          signatureExpected(),
        ),
      ).toThrow("The verified Fulcio signing certificate is invalid.");
    }
  });

  test("rejects empty and noncanonical DER signing certificates", () => {
    const invalidCertificates = [
      Buffer.from([0x30, 0x00]),
      Buffer.from([0x30, 0x02, 0x30, 0x00]),
      Buffer.from([0x30, 0x80, 0x00, 0x00]),
      Buffer.from([0x30, 0x81, 0x00]),
      Buffer.from([0x30, 0x82, 0x00, 0x01, 0x00]),
    ];

    for (const certificate of invalidCertificates) {
      expect(() =>
        verifySignatureAudit(
          signatureAudit({
            signingCertificate: certificate.toString("base64"),
          }),
          archive,
          signatureExpected(),
        ),
      ).toThrow("The verified Fulcio signing certificate is invalid.");
    }
  });

  test("rejects a certificate from another OIDC issuer", () => {
    expect(() =>
      verifySignatureAudit(
        signatureAudit({
          signingCertificate: signingCertificateWithReplacement(
            "token.actions.githubusercontent.com",
            "token.actions.githabusercontent.com",
          ),
        }),
        archive,
        signatureExpected(),
      ),
    ).toThrow(
      "The Fulcio certificate must use the GitHub Actions OIDC issuer.",
    );
  });

  test("rejects a certificate for another GitHub Actions workflow", () => {
    expect(() =>
      verifySignatureAudit(
        signatureAudit({
          signingCertificate: signingCertificateWithReplacement(
            "node-release.yml",
            "fake-release.yml",
          ),
        }),
        archive,
        signatureExpected(),
      ),
    ).toThrow(
      "The Fulcio certificate must identify the protected release workflow.",
    );
  });

  test("rejects a certificate for a different release commit", () => {
    expect(() =>
      verifySignatureAudit(
        signatureAudit({
          signingCertificate: signingCertificateWithReplacement(
            releaseCommit,
            "2e03c89ad22d2df5ae65b146be1483b3608572a9",
          ),
        }),
        archive,
        signatureExpected(),
      ),
    ).toThrow("The Fulcio certificate must identify the exact release commit.");
  });

  test("rejects a certificate for another release run", () => {
    expect(() =>
      verifySignatureAudit(
        signatureAudit({
          signingCertificate: signingCertificateWithReplacement(
            releaseRun,
            "30481596228",
          ),
        }),
        archive,
        signatureExpected(),
      ),
    ).toThrow("The Fulcio certificate must identify the exact release run.");
  });

  test("rejects a certificate outside the protected npm environment", () => {
    expect(() =>
      verifySignatureAudit(
        signatureAudit({
          signingCertificate: signingCertificateWithReplacement(
            "environment:npm",
            "environment:dev",
          ),
        }),
        archive,
        signatureExpected(),
      ),
    ).toThrow(
      "The Fulcio certificate must identify the protected npm environment.",
    );
  });

  test("rejects invalid or missing registry signatures", () => {
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ invalid: [{ name: "@openai/codex-security" }] }),
        archive,
        signatureExpected(),
      ),
    ).toThrow("npm registry signatures and attestations must verify.");
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ missing: [{ name: "@openai/codex-security" }] }),
        archive,
        signatureExpected(),
      ),
    ).toThrow("npm registry signatures and attestations must verify.");
  });

  test("requires the exact published package in the verified audit", () => {
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ includeVerified: false }),
        archive,
        signatureExpected(),
      ),
    ).toThrow(
      "The published package must have a cryptographically verified attestation.",
    );
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ name: "@openai/codex" }),
        archive,
        signatureExpected(),
      ),
    ).toThrow(
      "The published package must have a cryptographically verified attestation.",
    );
  });

  test("requires the signed public npm registry and SLSA bundle", () => {
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ registry: "https://registry.example/" }),
        archive,
        signatureExpected(),
      ),
    ).toThrow("Verified provenance must come from the public npm registry.");
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ includeProvenance: false }),
        archive,
        signatureExpected(),
      ),
    ).toThrow("The verified npm package must have SLSA v1 provenance.");
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ includeBundle: false }),
        archive,
        signatureExpected(),
      ),
    ).toThrow("The verified SLSA provenance bundle is missing.");
  });

  test("rejects malformed attestation bundle collections safely", () => {
    const report = signatureAudit();
    const [verified] = report["verified"] as ReleaseMetadata[];

    for (const attestationBundles of [null, {}, "invalid", 42, [null]]) {
      expect(() =>
        verifySignatureAudit(
          {
            ...report,
            verified: [{ ...verified, attestationBundles }],
          },
          archive,
          signatureExpected(),
        ),
      ).toThrow("The verified SLSA provenance bundle is missing.");
    }
  });

  test("rejects provenance for a different package subject or archive", () => {
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ subjectName: "pkg:npm/another-package@0.1.2" }),
        archive,
        signatureExpected(),
      ),
    ).toThrow(
      "Verified SLSA provenance must identify the exact published tarball.",
    );
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ subjectDigest: "incorrect" }),
        archive,
        signatureExpected(),
      ),
    ).toThrow(
      "Verified SLSA provenance must identify the exact published tarball.",
    );
  });

  test("rejects another repository, workflow, or release tag", () => {
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ repository: "attacker/codex-security" }),
        archive,
        signatureExpected(),
      ),
    ).toThrow(
      "Verified SLSA provenance must identify the protected release workflow.",
    );
    expect(() =>
      verifySignatureAudit(
        signatureAudit({
          workflowPath: ".github/workflows/untrusted-release.yml",
        }),
        archive,
        signatureExpected(),
      ),
    ).toThrow(
      "Verified SLSA provenance must identify the protected release workflow.",
    );
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ workflowRef: "refs/heads/npm-v0.1.2" }),
        archive,
        signatureExpected(),
      ),
    ).toThrow(
      "Verified SLSA provenance must identify the protected release workflow.",
    );
  });

  test("rejects a source commit outside the protected release", () => {
    expect(() =>
      verifySignatureAudit(
        signatureAudit({
          sourceCommit: "0000000000000000000000000000000000000000",
        }),
        archive,
        signatureExpected(),
      ),
    ).toThrow("npm package gitHead must match release commit");
  });

  test("rejects provenance from another release run or builder", () => {
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ runId: "12345" }),
        archive,
        signatureExpected(),
      ),
    ).toThrow(
      "Verified SLSA provenance must identify the successful release run.",
    );
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ builder: "https://example.com/untrusted-runner" }),
        archive,
        signatureExpected(),
      ),
    ).toThrow(
      "Verified SLSA provenance must use a GitHub-hosted release runner.",
    );
  });
});

describe("idempotent GitHub release verification", () => {
  test("accepts the already-published exact verified release asset", () => {
    expect(
      verifyGitHubRelease(
        githubRelease(),
        archive,
        "npm-v0.1.2",
        "openai-codex-security-0.1.2.tgz",
      ),
    ).toEqual({
      tag: "npm-v0.1.2",
      asset: "openai-codex-security-0.1.2.tgz",
      digest,
    });
  });

  test("verifies downloaded release bytes when GitHub omits the asset digest", () => {
    const release = githubRelease();

    expect(
      verifyGitHubRelease(
        {
          ...release,
          assets: [{ name: "openai-codex-security-0.1.2.tgz" }],
        },
        archive,
        "npm-v0.1.2",
        "openai-codex-security-0.1.2.tgz",
        archive,
      ),
    ).toEqual({
      tag: "npm-v0.1.2",
      asset: "openai-codex-security-0.1.2.tgz",
      digest,
    });
  });

  test("rejects a digestless release asset without its downloaded bytes", () => {
    expect(() =>
      verifyGitHubRelease(
        {
          ...githubRelease(),
          assets: [{ name: "openai-codex-security-0.1.2.tgz" }],
        },
        archive,
        "npm-v0.1.2",
        "openai-codex-security-0.1.2.tgz",
      ),
    ).toThrow(
      "Existing GitHub Release asset must match the verified npm artifact.",
    );
  });

  test("rejects downloaded release bytes that differ from the npm archive", () => {
    expect(() =>
      verifyGitHubRelease(
        {
          ...githubRelease(),
          assets: [{ name: "openai-codex-security-0.1.2.tgz" }],
        },
        archive,
        "npm-v0.1.2",
        "openai-codex-security-0.1.2.tgz",
        Buffer.from("different downloaded GitHub release"),
      ),
    ).toThrow(
      "Existing GitHub Release asset must match the verified npm artifact.",
    );
  });

  test("rejects a GitHub release for another tag", () => {
    expect(() =>
      verifyGitHubRelease(
        { ...githubRelease(), tag_name: "npm-v0.1.1" },
        archive,
        "npm-v0.1.2",
        "openai-codex-security-0.1.2.tgz",
      ),
    ).toThrow("Existing GitHub Release must match the release tag.");
  });

  test("rejects a draft or prerelease", () => {
    expect(() =>
      verifyGitHubRelease(
        { ...githubRelease(), draft: true },
        archive,
        "npm-v0.1.2",
        "openai-codex-security-0.1.2.tgz",
      ),
    ).toThrow("Existing GitHub Release must be published and stable.");
  });

  test("rejects a missing or different GitHub release artifact", () => {
    expect(() =>
      verifyGitHubRelease(
        {
          ...githubRelease(),
          assets: [
            {
              name: "openai-codex-security-0.1.2.tgz",
              digest: "sha256:incorrect",
            },
          ],
        },
        archive,
        "npm-v0.1.2",
        "openai-codex-security-0.1.2.tgz",
      ),
    ).toThrow(
      "Existing GitHub Release asset must match the verified npm artifact.",
    );
  });

  test("rejects malformed GitHub release assets safely", () => {
    for (const assets of [null, {}, [null]]) {
      expect(() =>
        verifyGitHubRelease(
          { ...githubRelease(), assets },
          archive,
          "npm-v0.1.2",
          "openai-codex-security-0.1.2.tgz",
        ),
      ).toThrow(
        "Existing GitHub Release asset must match the verified npm artifact.",
      );
    }
  });

  test("ignores malformed assets before the exact verified release asset", () => {
    const release = githubRelease();

    expect(
      verifyGitHubRelease(
        {
          ...release,
          assets: [null, ...(release["assets"] as ReleaseMetadata[])],
        },
        archive,
        "npm-v0.1.2",
        "openai-codex-security-0.1.2.tgz",
      ),
    ).toEqual({
      tag: "npm-v0.1.2",
      asset: "openai-codex-security-0.1.2.tgz",
      digest,
    });
  });
});

describe("GitHub release workflow safeguards", () => {
  const checkedOutVersion = releaseVersion(
    JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    ) as ReleaseMetadata,
  );
  const checkedOutTag = `npm-v${checkedOutVersion}`;

  test("rejects unsupported jq mock filters", () => {
    const result = spawnSync(
      bash,
      [
        "-c",
        `${jqMock}\nprintf '%s\\n' '{"object":{"type":"commit","sha":"abc"}}' | jq -r '.wrong | @tsv'`,
      ],
      { encoding: "utf8" },
    );

    expect(result.status).toBe(64);
  });

  test("requires a real tag for protected npm publication", () => {
    expect(protectedReleaseWorkflow).toContain("release-tag");
    expect(protectedReleaseWorkflow).toContain('"$GITHUB_REF_TYPE"');
    expect(protectedReleaseWorkflow).toContain('"$GITHUB_REF"');
  });

  test("pins both supported-minimum verification and protected signing runtimes", () => {
    expect(protectedReleaseWorkflow).toContain('node-version: "22.13.0"');
    expect(protectedReleaseWorkflow).toContain('node-version: "24.15.0"');
  });

  test("restricts release cuts to main and increasing stable versions", () => {
    expect(releaseCutWorkflow).toMatch(
      /- name: Set up Node\.js\n(?:[^\n]*\n)*?\s+node-version: "24\.15\.0"/u,
    );
    expect(releaseCutWorkflow).toContain(
      'if [[ "$GITHUB_REF" != "refs/heads/main" ]]; then',
    );
    expect(releaseCutWorkflow).toContain(
      'git merge-base --is-ancestor "$GITHUB_SHA" origin/main',
    );
    expect(releaseCutWorkflow).toContain("require-increase");
    expect(releaseCutWorkflow).toContain("require-published-increase");
    expect(releaseCutWorkflow).toContain(
      "npm view @openai/codex-security versions",
    );
  });

  test("executes the manual release cut against all published versions", () => {
    const script = workflowStepShell(
      releaseCutWorkflow,
      "Resolve the stable package version",
    );
    const mocks = [
      "git() { return 0; }",
      "npm() { printf '%s\\n' '[\"0.1.1\",\"999999999999999999999999.0.0\"]'; }",
    ].join("\n");
    const result = spawnSync(bash, ["-c", `${mocks}\n${script}`], {
      cwd: fileURLToPath(new URL("../../../", import.meta.url)),
      encoding: "utf8",
      env: {
        ...process.env,
        BEFORE_SHA: "",
        GITHUB_EVENT_NAME: "workflow_dispatch",
        GITHUB_OUTPUT: "/dev/null",
        GITHUB_REF: "refs/heads/main",
        GITHUB_SHA: releaseCommit,
      },
      timeout: 10_000,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "Release version must be greater than every published stable version.",
    );
  });

  test.each([
    {
      scenario: "a successful version-increase commit",
      event: "workflow_run",
      previousVersion: "0.1.5",
      currentVersion: "0.1.6",
      publishedVersions: ["0.1.5"],
      changed: true,
    },
    {
      scenario: "a successful fix after the version-increase commit failed CI",
      event: "workflow_run",
      previousVersion: "0.1.6",
      currentVersion: "0.1.6",
      publishedVersions: ["0.1.5"],
      changed: true,
    },
    {
      scenario: "an unchanged version that has already been published",
      event: "workflow_run",
      previousVersion: "0.1.5",
      currentVersion: "0.1.5",
      publishedVersions: ["0.1.5"],
      changed: false,
    },
    {
      scenario: "a manually dispatched unpublished version",
      event: "workflow_dispatch",
      previousVersion: "0.1.5",
      currentVersion: "0.1.6",
      publishedVersions: ["0.1.5"],
      changed: true,
    },
  ])(
    "resolves $scenario against its published npm history",
    ({
      event,
      previousVersion,
      currentVersion,
      publishedVersions,
      changed,
    }) => {
      const script = workflowStepShell(
        releaseCutWorkflow,
        "Resolve the stable package version",
      );
      const mocks = [
        "git() {",
        '  case "$1" in',
        "    fetch|merge-base) return 0 ;;",
        "    rev-parse) printf '%s\\n' \"$MOCK_PREVIOUS_SHA\" ;;",
        '    show) printf \'{"version":"%s"}\\n\' "$MOCK_PREVIOUS_VERSION" ;;',
        "    *) return 64 ;;",
        "  esac",
        "}",
        "node() {",
        '  if [[ "${2:-}" == "version" ]]; then',
        "    printf '%s\\n' \"$MOCK_RELEASE_VERSION\"",
        "    return 0",
        "  fi",
        '  command node "$@"',
        "}",
        "npm() { printf '%s\\n' \"$MOCK_PUBLISHED_VERSIONS\"; }",
      ].join("\n");
      const workspace = mkdtempSync(
        join(tmpdir(), "codex-security-release-cut-"),
      );

      try {
        const outputPath = join(workspace, "outputs");
        const result = spawnSync(bash, ["-c", `${mocks}\n${script}`], {
          cwd: fileURLToPath(new URL("../../../", import.meta.url)),
          encoding: "utf8",
          env: {
            ...process.env,
            GITHUB_EVENT_NAME: event,
            GITHUB_OUTPUT: outputPath,
            GITHUB_REF: "refs/heads/main",
            GITHUB_SHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            MOCK_PREVIOUS_SHA: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            MOCK_PREVIOUS_VERSION: previousVersion,
            MOCK_PUBLISHED_VERSIONS: JSON.stringify(publishedVersions),
            MOCK_RELEASE_VERSION: currentVersion,
            RELEASE_SHA: releaseCommit,
          },
          timeout: 10_000,
        });

        expect(result.stderr).toBe("");
        expect(result.status).toBe(0);

        const outputs = readFileSync(outputPath, "utf8");
        expect(outputs).toContain(`changed=${changed}`);
        if (changed) {
          expect(outputs).toContain(`version=${currentVersion}`);
          expect(outputs).toContain(`tag=npm-v${currentVersion}`);
        }
      } finally {
        rmSync(workspace, { recursive: true, force: true });
      }
    },
  );

  test.each([
    {
      workflow: "release cut",
      version: "0.1.0",
      errorCode: "E404",
      status: 0,
    },
    {
      workflow: "protected publisher",
      version: "0.1.0",
      errorCode: "E404",
      status: 0,
    },
    {
      workflow: "release cut",
      version: "0.1.1",
      errorCode: "E404",
      status: 1,
    },
    {
      workflow: "protected publisher",
      version: "0.1.1",
      errorCode: "E404",
      status: 1,
    },
    {
      workflow: "release cut",
      version: "0.1.0",
      errorCode: "ETIMEDOUT",
      status: 1,
    },
    {
      workflow: "protected publisher",
      version: "0.1.0",
      errorCode: "E403",
      status: 1,
    },
  ])(
    "handles $errorCode during $workflow npm-history validation for $version",
    ({ workflow, version, errorCode, status }) => {
      const cutting = workflow === "release cut";
      const script = workflowStepShell(
        cutting ? releaseCutWorkflow : protectedReleaseWorkflow,
        cutting ? "Resolve the stable package version" : "Validate release tag",
      );
      const mocks = [
        "git() { return 0; }",
        "node() {",
        '  if [[ "${2:-}" == "version" || "${2:-}" == "release-tag" ]]; then',
        "    printf '%s\\n' \"$MOCK_RELEASE_VERSION\"",
        "    return 0",
        "  fi",
        '  command node "$@"',
        "}",
        "npm() {",
        "  printf '%s\\n' \"$MOCK_REGISTRY_RESPONSE\"",
        "  return 1",
        "}",
        "sfw() {",
        "  printf '%s\\n' \"$MOCK_REGISTRY_RESPONSE\"",
        "  return 1",
        "}",
      ].join("\n");
      const result = spawnSync(bash, ["-c", `${mocks}\n${script}`], {
        cwd: fileURLToPath(new URL("../../../", import.meta.url)),
        encoding: "utf8",
        env: {
          ...process.env,
          BEFORE_SHA: "",
          GITHUB_EVENT_NAME: "workflow_dispatch",
          GITHUB_OUTPUT: "/dev/null",
          GITHUB_REF: cutting ? "refs/heads/main" : `refs/tags/npm-v${version}`,
          GITHUB_REF_NAME: `npm-v${version}`,
          GITHUB_REF_TYPE: "tag",
          GITHUB_SHA: releaseCommit,
          MOCK_REGISTRY_RESPONSE: JSON.stringify({
            error: { code: errorCode },
          }),
          MOCK_RELEASE_VERSION: version,
        },
        timeout: 10_000,
      });

      expect(result.status).toBe(status);
      if (status !== 0) {
        expect(result.stderr).toContain(
          "Unable to verify published npm release history.",
        );
      }
    },
  );

  test("creates the release tag at the successful CI commit", () => {
    const script = workflowStepShell(
      releaseCutWorkflow,
      "Create the exact merged release tag",
    );
    const mock = [
      jqMock,
      "gh() {",
      '  if [[ "$1" != "api" ]]; then return 64; fi',
      "  shift",
      '  if [[ "$1" == "--include" ]]; then',
      "    printf 'HTTP/2.0 404 Mock\\nContent-Type: application/json\\n\\n'",
      '    printf \'%s\\n\' \'{"message":"Not Found","status":"404"}\'',
      "    return 1",
      "  fi",
      '  if [[ "$1" != "--method" || "$2" != "POST" ||',
      '        "$3" != "repos/test/codex-security/git/refs" ||',
      '        "$4" != "-f" || "$5" != "ref=refs/tags/npm-v0.1.2" ||',
      '        "$6" != "-f" || "$7" != "sha=$RELEASE_SHA" ||',
      '        "$8" != "--silent" ]]; then return 65; fi',
      "  printf 'created tag at %s\\n' \"$RELEASE_SHA\"",
      "}",
    ].join("\n");
    const result = spawnSync(bash, ["-c", `${mock}\n${script}`], {
      encoding: "utf8",
      env: {
        ...process.env,
        GITHUB_REPOSITORY: "test/codex-security",
        GITHUB_SHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        RELEASE_SHA: releaseCommit,
        RELEASE_TAG: "npm-v0.1.2",
      },
      timeout: releaseTagTimeout,
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain(`created tag at ${releaseCommit}`);
  });

  test.each([
    {
      kind: "missing tag with GitHub's 404 error body",
      lookupResponse: JSON.stringify({ message: "Not Found", status: "404" }),
      lookupHttpStatus: "404",
      status: 0,
    },
    {
      kind: "forbidden tag lookup",
      lookupResponse: JSON.stringify({ message: "Forbidden", status: "403" }),
      lookupHttpStatus: "403",
      status: 1,
    },
    {
      kind: "malformed missing-tag response",
      lookupResponse: "not JSON",
      lookupHttpStatus: "404",
      status: 1,
    },
    {
      kind: "unavailable tag lookup",
      lookupResponse: "",
      lookupHttpStatus: "",
      status: 1,
    },
  ])(
    "handles $kind safely before cutting a release",
    ({ lookupResponse, lookupHttpStatus, status }) => {
      const script = workflowStepShell(
        releaseCutWorkflow,
        "Create the exact merged release tag",
      );
      const mock = [
        jqMock,
        "gh() {",
        '  if [[ "$1" != "api" ]]; then return 64; fi',
        "  shift",
        '  if [[ "$1" == "--include" &&',
        '        "$2" == "repos/test/codex-security/git/ref/tags/npm-v0.1.2" ]]; then',
        '    if [[ -n "$MOCK_LOOKUP_HTTP_STATUS" ]]; then',
        "      printf 'HTTP/2.0 %s Mock\\nContent-Type: application/json\\n\\n%s\\n' \\",
        '        "$MOCK_LOOKUP_HTTP_STATUS" "$MOCK_LOOKUP_RESPONSE"',
        "    fi",
        "    return 1",
        "  fi",
        '  if [[ "$1" != "--method" || "$2" != "POST" ||',
        '        "$3" != "repos/test/codex-security/git/refs" ||',
        '        "$4" != "-f" || "$5" != "ref=refs/tags/npm-v0.1.2" ||',
        '        "$6" != "-f" || "$7" != "sha=$GITHUB_SHA" ||',
        '        "$8" != "--silent" ]]; then return 65; fi',
        "  printf 'created exact release tag\\n'",
        "}",
      ].join("\n");
      const result = spawnSync(bash, ["-c", `${mock}\n${script}`], {
        encoding: "utf8",
        env: {
          ...process.env,
          GITHUB_REPOSITORY: "test/codex-security",
          GITHUB_SHA: releaseCommit,
          MOCK_LOOKUP_HTTP_STATUS: lookupHttpStatus,
          MOCK_LOOKUP_RESPONSE: lookupResponse,
          RELEASE_TAG: "npm-v0.1.2",
        },
        timeout: releaseTagTimeout,
      });

      expect(result.status).toBe(status);
      if (status === 0) {
        expect(result.stdout).toContain("created exact release tag");
      } else {
        expect(result.stderr).toContain(
          "Unable to query release tag npm-v0.1.2.",
        );
        expect(result.stdout).not.toContain("created exact release tag");
      }
    },
  );

  test.each([
    {
      kind: "existing lightweight tag",
      tagType: "commit",
      tagObject: releaseCommit,
      peeledCommit: "",
      status: 0,
    },
    {
      kind: "existing annotated tag",
      tagType: "tag",
      tagObject: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      peeledCommit: releaseCommit,
      status: 0,
    },
    {
      kind: "retargeted annotated tag",
      tagType: "tag",
      tagObject: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      peeledCommit: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      status: 1,
    },
  ])(
    "resolves an $kind to its exact commit before cutting a release",
    ({ tagType, tagObject, peeledCommit, status }) => {
      const script = workflowStepShell(
        releaseCutWorkflow,
        "Create the exact merged release tag",
      );
      const mock = [
        jqMock,
        "gh() {",
        '  if [[ "$1" != "api" ]]; then return 64; fi',
        "  shift",
        '  if [[ "$1" == "--include" ]]; then',
        "    shift",
        '    if [[ "$1" != "repos/test/codex-security/git/ref/tags/npm-v0.1.2" ]]; then',
        "      return 65",
        "    fi",
        "    printf 'HTTP/2.0 200 OK\\nContent-Type: application/json\\n\\n'",
        '    printf \'{"object":{"type":"%s","sha":"%s"}}\\n\' \\',
        '      "$MOCK_TAG_TYPE" "$MOCK_TAG_OBJECT"',
        "    return 0",
        "  fi",
        '  case "$1" in',
        "    repos/test/codex-security/git/tags/*)",
        "      printf '%s\\n' \"$MOCK_PEELED_COMMIT\"",
        "      ;;",
        "    *) return 65 ;;",
        "  esac",
        "}",
      ].join("\n");
      const result = spawnSync(bash, ["-c", `${mock}\n${script}`], {
        encoding: "utf8",
        env: {
          ...process.env,
          GITHUB_REPOSITORY: "test/codex-security",
          GITHUB_SHA: releaseCommit,
          MOCK_PEELED_COMMIT: peeledCommit,
          MOCK_TAG_OBJECT: tagObject,
          MOCK_TAG_TYPE: tagType,
          RELEASE_TAG: "npm-v0.1.2",
        },
        timeout: releaseTagTimeout,
      });

      expect(result.status).toBe(status);
      if (status === 0) {
        expect(result.stdout).toContain(
          `Release tag npm-v0.1.2 already points to ${releaseCommit}.`,
        );
      } else {
        expect(result.stderr).toContain(
          "Release tag npm-v0.1.2 already points to a different commit.",
        );
      }
    },
  );

  test("enforces increasing versions inside the protected npm publisher", () => {
    expect(protectedReleaseWorkflow).toContain(
      "sfw npm view @openai/codex-security versions",
    );
    expect(protectedReleaseWorkflow).toContain("release-mode");
  });

  test.each([
    {
      kind: "deleted release tag",
      tagType: "missing",
      tagObject: "",
      peeledCommit: "",
      status: 1,
    },
    {
      kind: "retargeted lightweight tag",
      tagType: "commit",
      tagObject: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      peeledCommit: "",
      status: 1,
    },
    {
      kind: "retargeted annotated tag",
      tagType: "tag",
      tagObject: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      peeledCommit: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      status: 1,
    },
    {
      kind: "verified lightweight tag",
      tagType: "commit",
      tagObject: releaseCommit,
      peeledCommit: "",
      status: 0,
    },
    {
      kind: "verified annotated tag",
      tagType: "tag",
      tagObject: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      peeledCommit: releaseCommit,
      status: 0,
    },
  ])(
    "revalidates the authoritative $kind immediately before npm publication",
    ({ tagType, tagObject, peeledCommit, status }) => {
      const script = workflowStepShell(
        protectedReleaseWorkflow,
        "Revalidate protected release tag",
      );
      const mock = [
        "gh() {",
        '  if [[ "$1" != "api" ]]; then return 64; fi',
        "  shift",
        '  case "$1" in',
        `    "repos/test/codex-security/git/ref/tags/${checkedOutTag}")`,
        '      if [[ "$MOCK_TAG_TYPE" == "missing" ]]; then return 1; fi',
        '      printf \'%s\\t%s\\n\' "$MOCK_TAG_TYPE" "$MOCK_TAG_OBJECT"',
        "      ;;",
        "    repos/test/codex-security/git/tags/*)",
        "      printf '%s\\n' \"$MOCK_PEELED_COMMIT\"",
        "      ;;",
        "    *) return 65 ;;",
        "  esac",
        "}",
      ].join("\n");
      const result = spawnSync(bash, ["-c", `${mock}\n${script}`], {
        encoding: "utf8",
        env: {
          ...process.env,
          GITHUB_REF: `refs/tags/${checkedOutTag}`,
          GITHUB_REF_NAME: checkedOutTag,
          GITHUB_REF_TYPE: "tag",
          GITHUB_REPOSITORY: "test/codex-security",
          GITHUB_SHA: releaseCommit,
          MOCK_PEELED_COMMIT: peeledCommit,
          MOCK_TAG_OBJECT: tagObject,
          MOCK_TAG_TYPE: tagType,
        },
        timeout: 10_000,
      });

      expect(result.status).toBe(status);
      if (status === 0) {
        expect(result.stdout).toContain(
          "Protected npm release tag matches the verified commit.",
        );
      } else {
        expect(result.stderr).toContain(
          "Protected npm release tag must still point to the verified commit.",
        );
      }
    },
  );

  test("rejects manually publishing a tag older than npm latest", () => {
    const script = workflowStepShell(
      protectedReleaseWorkflow,
      "Validate release tag",
    );
    const mocks = [
      "git() { return 0; }",
      "sfw() { printf '%s\\n' '[\"0.1.1\",\"999999999999999999999999.0.0\"]'; }",
    ].join("\n");
    const result = spawnSync(bash, ["-c", `${mocks}\n${script}`], {
      cwd: fileURLToPath(new URL("../../../", import.meta.url)),
      encoding: "utf8",
      env: {
        ...process.env,
        GITHUB_OUTPUT: "/dev/null",
        GITHUB_REF: `refs/tags/${checkedOutTag}`,
        GITHUB_REF_NAME: checkedOutTag,
        GITHUB_REF_TYPE: "tag",
        GITHUB_SHA: releaseCommit,
      },
      timeout: 10_000,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "Release version must be greater than every published stable version.",
    );
  });

  test("allows the exact already-published release to enter verified recovery", () => {
    const script = workflowStepShell(
      protectedReleaseWorkflow,
      "Validate release tag",
    );
    const mocks = [
      "git() { return 0; }",
      `sfw() { printf '%s\\n' '["0.1.0","${checkedOutVersion}"]'; }`,
    ].join("\n");
    const result = spawnSync(bash, ["-c", `${mocks}\n${script}`], {
      cwd: fileURLToPath(new URL("../../../", import.meta.url)),
      encoding: "utf8",
      env: {
        ...process.env,
        GITHUB_OUTPUT: "/dev/null",
        GITHUB_REF: `refs/tags/${checkedOutTag}`,
        GITHUB_REF_NAME: checkedOutTag,
        GITHUB_REF_TYPE: "tag",
        GITHUB_SHA: releaseCommit,
      },
      timeout: 10_000,
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain(
      "Recovering the already-published npm release.",
    );
  });

  test("verifies recovered packages without republishing immutable versions", () => {
    expect(protectedReleaseWorkflow).toContain(
      "Recover the published npm release archive",
    );
    expect(protectedReleaseWorkflow).toContain(
      "Verify recovered npm release provenance",
    );
    expect(protectedReleaseWorkflow).toContain("verify-recovered-provenance");
    expect(protectedReleaseWorkflow).toContain(
      "needs.verify.outputs.mode == 'publish'",
    );
  });

  test("durably queues every release-cut and protected publishing run", () => {
    expect(releaseCutWorkflow).toMatch(
      /concurrency:\s*\n\s+group: node-release-cut\s*\n\s+queue: max/u,
    );
    expect(protectedReleaseWorkflow).toMatch(
      /concurrency:\s*\n\s+group: \$\{\{ github\.workflow \}\}\s*\n\s+queue: max/u,
    );
  });

  test("dispatches GitHub releases after publishing with isolated permissions", () => {
    expect(protectedReleaseWorkflow).toContain(
      [
        "  dispatch-github-release:",
        "    if: github.repository == 'openai/codex-security'",
        "    name: dispatch GitHub release",
        "    needs: publish",
        "    runs-on: ubuntu-latest",
        "    permissions:",
        "      actions: write",
      ].join("\n"),
    );
    expect(protectedReleaseWorkflow).toMatch(
      /  publish:\n[\s\S]*?    permissions:\n      contents: read\n      id-token: write\n/u,
    );
    expect(githubReleaseWorkflow).not.toContain("workflow_run:");
    expect(githubReleaseWorkflow).not.toContain("github.event.workflow_run");
    expect(githubReleaseWorkflow).not.toContain("TRIGGER_TAG");
    expect(githubReleaseWorkflow).not.toContain("TRIGGER_RUN_ID");
  });

  test("dispatches the exact protected run and release tag from trusted main", () => {
    const script = workflowStepShell(
      protectedReleaseWorkflow,
      "Dispatch the verified GitHub release",
    );
    const mock = "gh() { printf '%s\\n' \"$@\"; }";
    const result = spawnSync(bash, ["-c", `${mock}\n${script}`], {
      encoding: "utf8",
      env: {
        ...process.env,
        GITHUB_REPOSITORY: releaseRepository,
        RELEASE_RUN_ID: releaseRun,
        RELEASE_TAG: "npm-v0.1.2",
      },
      timeout: 10_000,
    });

    expect(result.status).toBe(0);
    expect(result.stdout.trim().split("\n")).toEqual([
      "workflow",
      "run",
      "node-github-release.yml",
      "--repo",
      releaseRepository,
      "--ref",
      "main",
      "-f",
      "tag=npm-v0.1.2",
      "-f",
      `run_id=${releaseRun}`,
    ]);
  });

  test("serializes every GitHub release and historical backfill", () => {
    expect(githubReleaseWorkflow).toMatch(
      /concurrency:\s*\n\s+group: node-github-release\s*\n\s+queue: max/u,
    );
    expect(githubReleaseWorkflow).not.toContain(
      "group: node-github-release-${{",
    );
  });

  test("runs manually dispatched GitHub releases from trusted main", () => {
    expect(githubReleaseWorkflow).toContain("workflow_dispatch:");
    expect(githubReleaseWorkflow).toContain("github.ref == 'refs/heads/main'");
    expect(githubReleaseWorkflow).toMatch(
      /- name: Checkout release automation\n(?:[^\n]*\n)*?\s+ref: refs\/heads\/main/u,
    );
  });

  test("requires an actual Git tag for GitHub releases", () => {
    expect(githubReleaseWorkflow).toContain(
      '"repos/$GITHUB_REPOSITORY/git/ref/tags/$release_tag"',
    );
  });

  test.each(["queued", "in_progress"])(
    "waits for a %s protected npm release to finish before publishing notes",
    (pendingStatus) => {
      const script = workflowStepShell(
        githubReleaseWorkflow,
        "Resolve the successful protected release",
      );
      const root = mkdtempSync(join(tmpdir(), "codex-security-release-wait-"));
      const state = join(root, "release-state");
      const sleeps = join(root, "release-sleeps");
      const mocks = [
        "gh() {",
        '  if [[ "$1" != "api" ]]; then return 64; fi',
        "  shift",
        '  case "$1" in',
        '    "repos/openai/codex-security/git/ref/tags/npm-v0.1.2")',
        `      printf '%s\\t%s\\n' 'commit' '${releaseCommit}'`,
        "      ;;",
        `    "repos/openai/codex-security/actions/runs/${releaseRun}")`,
        '      if [[ -f "$MOCK_RUN_STATE" ]]; then',
        `        printf '%s\\t%s\\t%s\\t%s\\t%s\\n' 'node-release' 'completed' 'success' '${releaseCommit}' 'npm-v0.1.2'`,
        "      else",
        '        touch "$MOCK_RUN_STATE"',
        `        printf '%s\\t%s\\t%s\\t%s\\t%s\\n' 'node-release' '${pendingStatus}' 'pending' '${releaseCommit}' 'npm-v0.1.2'`,
        "      fi",
        "      ;;",
        "    *) return 65 ;;",
        "  esac",
        "}",
        `sleep() { printf '%s\\n' "$1" >> "${sleeps}"; }`,
      ].join("\n");

      try {
        const result = spawnSync(bash, ["-c", `${mocks}\n${script}`], {
          encoding: "utf8",
          env: {
            ...process.env,
            GITHUB_OUTPUT: "/dev/null",
            GITHUB_REPOSITORY: releaseRepository,
            INPUT_RUN_ID: releaseRun,
            INPUT_TAG: "npm-v0.1.2",
            MOCK_RUN_STATE: state,
          },
          timeout: 10_000,
        });

        expect(result.status).toBe(0);
        expect(readFileSync(sleeps, "utf8")).toBe("2\n");
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
    },
  );

  test("rejects a pending npm release for a different tagged commit", () => {
    const script = workflowStepShell(
      githubReleaseWorkflow,
      "Resolve the successful protected release",
    );
    const differentCommit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const mocks = [
      "gh() {",
      '  if [[ "$1" != "api" ]]; then return 64; fi',
      "  shift",
      '  case "$1" in',
      '    "repos/openai/codex-security/git/ref/tags/npm-v0.1.2")',
      `      printf '%s\\t%s\\n' 'commit' '${releaseCommit}'`,
      "      ;;",
      `    "repos/openai/codex-security/actions/runs/${releaseRun}")`,
      `      printf '%s\\t%s\\t%s\\t%s\\t%s\\n' 'node-release' 'in_progress' 'pending' '${differentCommit}' 'npm-v0.1.2'`,
      "      ;;",
      "    *) return 65 ;;",
      "  esac",
      "}",
      "sleep() { return 99; }",
    ].join("\n");
    const result = spawnSync(bash, ["-c", `${mocks}\n${script}`], {
      encoding: "utf8",
      env: {
        ...process.env,
        GITHUB_OUTPUT: "/dev/null",
        GITHUB_REPOSITORY: releaseRepository,
        INPUT_RUN_ID: releaseRun,
        INPUT_TAG: "npm-v0.1.2",
      },
      timeout: 10_000,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "The release run must successfully publish the exact tagged commit.",
    );
  });

  test("times out safely if a protected npm release never completes", () => {
    const script = workflowStepShell(
      githubReleaseWorkflow,
      "Resolve the successful protected release",
    );
    const mocks = [
      "gh() {",
      '  if [[ "$1" != "api" ]]; then return 64; fi',
      "  shift",
      '  case "$1" in',
      '    "repos/openai/codex-security/git/ref/tags/npm-v0.1.2")',
      `      printf '%s\\t%s\\n' 'commit' '${releaseCommit}'`,
      "      ;;",
      `    "repos/openai/codex-security/actions/runs/${releaseRun}")`,
      `      printf '%s\\t%s\\t%s\\t%s\\t%s\\n' 'node-release' 'in_progress' 'pending' '${releaseCommit}' 'npm-v0.1.2'`,
      "      ;;",
      "    *) return 65 ;;",
      "  esac",
      "}",
      "sleep() { :; }",
    ].join("\n");
    const result = spawnSync(bash, ["-c", `${mocks}\n${script}`], {
      encoding: "utf8",
      env: {
        ...process.env,
        GITHUB_OUTPUT: "/dev/null",
        GITHUB_REPOSITORY: releaseRepository,
        INPUT_RUN_ID: releaseRun,
        INPUT_TAG: "npm-v0.1.2",
      },
      timeout: 10_000,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      `Timed out waiting for protected npm release ${releaseRun} to complete.`,
    );
  });

  test("rejects a release-shaped branch before resolving its commit", () => {
    const script = workflowStepShell(
      githubReleaseWorkflow,
      "Resolve the successful protected release",
    );
    const mock = [
      "gh() {",
      '  if [[ "$1" != "api" ]]; then return 64; fi',
      "  shift",
      '  case "$1" in',
      '    "repos/openai/codex-security/git/ref/tags/npm-v0.1.2")',
      "      return 1",
      "      ;;",
      '    "repos/openai/codex-security/commits/npm-v0.1.2")',
      `      printf '%s\\n' '${releaseCommit}'`,
      "      ;;",
      `    "repos/openai/codex-security/actions/runs/${releaseRun}")`,
      `      printf '%s\\t%s\\t%s\\t%s\\t%s\\n' 'node-release' 'completed' 'success' '${releaseCommit}' 'npm-v0.1.2'`,
      "      ;;",
      "    *) return 65 ;;",
      "  esac",
      "}",
    ].join("\n");
    const result = spawnSync(bash, ["-c", `${mock}\n${script}`], {
      encoding: "utf8",
      env: {
        ...process.env,
        GITHUB_OUTPUT: "/dev/null",
        GITHUB_REPOSITORY: "openai/codex-security",
        INPUT_RUN_ID: releaseRun,
        INPUT_TAG: "npm-v0.1.2",
      },
      timeout: 10_000,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "GitHub releases require an existing stable npm-vX.Y.Z tag.",
    );
  });

  test.each([
    { kind: "lightweight", tagType: "commit", objectSha: releaseCommit },
    {
      kind: "annotated with no locally fetched tag object",
      tagType: "tag",
      objectSha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
  ])(
    "resolves the exact $kind tag when a same-named branch exists",
    ({ tagType, objectSha }) => {
      const script = workflowStepShell(
        githubReleaseWorkflow,
        "Resolve the successful protected release",
      );
      const branchCommit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
      const mocks = [
        "git() {",
        `  if [[ "$1" != "rev-parse" || "$2" != "--verify" || "$3" != "${objectSha}^{commit}" ]]; then return 66; fi`,
        '  if [[ "$MOCK_TAG_TYPE" == "tag" ]]; then return 67; fi',
        `  printf '%s\\n' '${releaseCommit}'`,
        "}",
        "gh() {",
        '  if [[ "$1" != "api" ]]; then return 64; fi',
        "  shift",
        '  case "$1" in',
        '    "repos/openai/codex-security/git/ref/tags/npm-v0.1.2")',
        '      if [[ "$3" == ".object.sha" ]]; then',
        `        printf '%s\\n' '${objectSha}'`,
        "      else",
        `        printf '%s\\t%s\\n' '${tagType}' '${objectSha}'`,
        "      fi",
        "      ;;",
        `    "repos/openai/codex-security/git/tags/${objectSha}")`,
        `      printf '%s\\n' '${releaseCommit}'`,
        "      ;;",
        '    "repos/openai/codex-security/commits/npm-v0.1.2")',
        `      printf '%s\\n' '${branchCommit}'`,
        "      ;;",
        `    "repos/openai/codex-security/actions/runs/${releaseRun}")`,
        `      printf '%s\\t%s\\t%s\\t%s\\t%s\\n' 'node-release' 'completed' 'success' '${releaseCommit}' 'npm-v0.1.2'`,
        "      ;;",
        "    *) return 65 ;;",
        "  esac",
        "}",
      ].join("\n");
      const result = spawnSync(bash, ["-c", `${mocks}\n${script}`], {
        encoding: "utf8",
        env: {
          ...process.env,
          GITHUB_OUTPUT: "/dev/null",
          GITHUB_REPOSITORY: "openai/codex-security",
          INPUT_RUN_ID: releaseRun,
          INPUT_TAG: "npm-v0.1.2",
          MOCK_TAG_TYPE: tagType,
        },
        timeout: 10_000,
      });

      expect(result.status).toBe(0);
      expect(result.stderr).not.toContain(
        "The release run must successfully publish the exact tagged commit.",
      );
    },
  );

  test.each(["0", "01", "000123"])(
    "rejects the noncanonical protected GitHub release run ID %j",
    (runId) => {
      const script = workflowStepShell(
        githubReleaseWorkflow,
        "Resolve the successful protected release",
      );
      const mocks = [
        "gh() {",
        '  if [[ "$1" != "api" ]]; then return 64; fi',
        "  shift",
        '  case "$1" in',
        '    "repos/openai/codex-security/git/ref/tags/npm-v0.1.2")',
        `      printf '%s\\t%s\\n' 'commit' '${releaseCommit}'`,
        "      ;;",
        '    "repos/openai/codex-security/actions/runs/"*)',
        `      printf '%s\\t%s\\t%s\\t%s\\t%s\\n' 'node-release' 'completed' 'success' '${releaseCommit}' 'npm-v0.1.2'`,
        "      ;;",
        "    *) return 65 ;;",
        "  esac",
        "}",
      ].join("\n");
      const result = spawnSync(bash, ["-c", `${mocks}\n${script}`], {
        encoding: "utf8",
        env: {
          ...process.env,
          GITHUB_OUTPUT: "/dev/null",
          GITHUB_REPOSITORY: "openai/codex-security",
          INPUT_RUN_ID: runId,
          INPUT_TAG: "npm-v0.1.2",
        },
        timeout: 10_000,
      });

      expect(result.status).toBe(1);
      expect(result.stderr).toContain(
        "No successful protected npm release exists for npm-v0.1.2.",
      );
    },
  );

  test.each([
    {
      description: "verified lightweight release tag",
      existingLookup: "missing",
      tagType: "commit",
      tagObject: releaseCommit,
      peeledCommit: "",
      status: 0,
    },
    {
      description: "verified annotated release tag",
      existingLookup: "missing",
      tagType: "tag",
      tagObject: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      peeledCommit: releaseCommit,
      status: 0,
    },
    {
      description: "deleted release tag",
      existingLookup: "missing",
      tagType: "missing",
      tagObject: "",
      peeledCommit: "",
      status: 1,
    },
    {
      description: "retargeted lightweight release tag",
      existingLookup: "missing",
      tagType: "commit",
      tagObject: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      peeledCommit: "",
      status: 1,
    },
    {
      description: "retargeted annotated release tag",
      existingLookup: "missing",
      tagType: "tag",
      tagObject: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      peeledCommit: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      status: 1,
    },
    {
      description: "release lookup returning an unexpected HTTP 500",
      existingLookup: "unavailable",
      tagType: "commit",
      tagObject: releaseCommit,
      peeledCommit: "",
      status: 1,
    },
    {
      description: "release lookup rejecting its authentication",
      existingLookup: "unauthorized",
      tagType: "commit",
      tagObject: releaseCommit,
      peeledCommit: "",
      status: 1,
    },
    {
      description: "release lookup without an HTTP response",
      existingLookup: "network",
      tagType: "commit",
      tagObject: releaseCommit,
      peeledCommit: "",
      status: 1,
    },
    {
      description: "release lookup returning a malformed HTTP 404",
      existingLookup: "malformed",
      tagType: "commit",
      tagObject: releaseCommit,
      peeledCommit: "",
      status: 1,
    },
  ])(
    "revalidates the $description immediately before creating its GitHub release",
    ({ existingLookup, tagType, tagObject, peeledCommit, status }) => {
      const script = workflowStepShell(
        githubReleaseWorkflow,
        "Publish GitHub Release and generated notes",
      );
      const mocks = [
        "gh() {",
        '  if [[ "$1" == "api" ]]; then',
        "    shift",
        '    if [[ "${1:-}" == "--include" ]]; then shift; fi',
        '    case "$1" in',
        '      "repos/test/codex-security/releases/tags/npm-v0.1.2")',
        '        case "$MOCK_EXISTING_LOOKUP" in',
        "          missing)",
        "            printf '%s\\n' 'HTTP/2.0 404 Not Found' 'content-type: application/json' '' '{\"message\":\"Not Found\"}'",
        "            ;;",
        "          unavailable)",
        "            printf '%s\\n' 'HTTP/2.0 500 Internal Server Error' 'content-type: application/json' '' '{\"message\":\"Unavailable\"}'",
        "            ;;",
        "          unauthorized)",
        "            printf '%s\\n' 'HTTP/2.0 401 Unauthorized' 'content-type: application/json' '' '{\"message\":\"Bad credentials\"}'",
        "            ;;",
        "          network) ;;",
        "          malformed)",
        "            printf '%s\\n' 'HTTP/2.0 404 Not Found' 'content-type: application/json' '' 'not-json'",
        "            ;;",
        "        esac",
        "        return 1",
        "        ;;",
        '      "repos/test/codex-security/git/ref/tags/npm-v0.1.2")',
        '        if [[ "$MOCK_TAG_TYPE" == "missing" ]]; then return 1; fi',
        '        printf \'%s\\t%s\\n\' "$MOCK_TAG_TYPE" "$MOCK_TAG_OBJECT"',
        "        ;;",
        '      "repos/test/codex-security/git/tags/"*)',
        "        printf '%s\\n' \"$MOCK_PEELED_COMMIT\"",
        "        ;;",
        "      *) return 65 ;;",
        "    esac",
        '  elif [[ "$1" == "release" && "$2" == "create" ]]; then',
        "    printf '%s\\n' 'created verified GitHub release'",
        "  else",
        "    return 64",
        "  fi",
        "}",
      ].join("\n");
      const result = spawnSync(bash, [], {
        input: `${mocks}\n${script}`,
        encoding: "utf8",
        env: {
          ...process.env,
          GITHUB_REPOSITORY: "test/codex-security",
          MAKE_LATEST: "false",
          MOCK_EXISTING_LOOKUP: existingLookup,
          MOCK_PEELED_COMMIT: peeledCommit,
          MOCK_TAG_OBJECT: tagObject,
          MOCK_TAG_TYPE: tagType,
          PREVIOUS_TAG: "npm-v0.1.1",
          RELEASE_ARCHIVE: "/tmp/openai-codex-security-0.1.2.tgz",
          RELEASE_SHA: releaseCommit,
          RELEASE_TAG: "npm-v0.1.2",
          RELEASE_VERSION: "0.1.2",
        },
        timeout: 10_000,
      });

      expect(result.status).toBe(status);
      if (status === 0) {
        expect(result.stdout).toContain("created verified GitHub release");
      } else {
        expect(result.stdout).not.toContain("created verified GitHub release");
        expect(result.stderr).toContain(
          existingLookup === "missing"
            ? "GitHub release tag must still point to the verified commit."
            : "Unable to resolve the existing GitHub Release.",
        );
      }
    },
  );

  test("explicitly prevents historical releases becoming latest", () => {
    expect(githubReleaseWorkflow).toContain("--generate-notes");
    expect(githubReleaseWorkflow).toContain('--latest="$MAKE_LATEST"');
    expect(githubReleaseWorkflow).toContain("release-history");
  });

  test("generates notes only from a previously published release", () => {
    expect(githubReleaseWorkflow).toContain(
      "npm view @openai/codex-security versions",
    );
    expect(githubReleaseWorkflow).toContain(
      "steps.history.outputs.previous-tag",
    );
    expect(githubReleaseWorkflow).toContain(
      'release_args+=(--notes-start-tag "$PREVIOUS_TAG")',
    );
  });

  test("recovers a public npm tarball after release artifacts expire", () => {
    expect(githubReleaseWorkflow).toContain("if ! gh run download");
    expect(githubReleaseWorkflow).toContain(
      'npm pack "@openai/codex-security@$RELEASE_VERSION"',
    );
    expect(githubReleaseWorkflow).toContain("--ignore-scripts");
  });

  test("downloads and verifies existing GitHub release asset bytes", () => {
    expect(githubReleaseWorkflow).toContain(
      'gh release download "$RELEASE_TAG"',
    );
    expect(githubReleaseWorkflow).toContain(
      'verify-github-release "$RELEASE_ARCHIVE" "$RELEASE_TAG"',
    );
  });

  test.each([
    {
      description: "the exact successful publishing run",
      exact: true,
      recoveryConclusion: "skipped",
      originalCommit: releaseCommit,
      status: 0,
      message: "Verified npm provenance for the resolved release run.",
    },
    {
      description: "a different signing run without authenticated recovery",
      exact: false,
      recoveryConclusion: "skipped",
      originalCommit: releaseCommit,
      status: 1,
      message:
        "Signed npm provenance must identify the resolved successful release run.",
    },
    {
      description: "the authenticated original signing run after recovery",
      exact: false,
      recoveryConclusion: "success",
      originalCommit: releaseCommit,
      status: 0,
      message:
        "Verified protected recovery provenance from its original signing run.",
    },
    {
      description: "a recovery provenance run for a different source commit",
      exact: false,
      recoveryConclusion: "success",
      originalCommit: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      status: 1,
      message:
        "Recovered npm provenance must identify the exact protected release.",
    },
  ])(
    "binds GitHub release provenance to $description",
    ({ exact, recoveryConclusion, originalCommit, status, message }) => {
      const script = workflowStepShell(
        githubReleaseWorkflow,
        "Verify the public npm package and signed provenance",
      );
      const workspace = mkdtempSync(
        join(tmpdir(), "codex-security-release-provenance-"),
      );
      mkdirSync(join(workspace, "dist"));
      writeFileSync(join(workspace, "dist", "release.tgz"), "verified archive");

      try {
        const mocks = [
          "npm() {",
          '  case "$1" in',
          "    view) printf '%s\\n' '{}' ;;",
          "    install) return 0 ;;",
          "    audit) printf '%s\\n' '{\"verified\":[]}' ;;",
          "    *) return 65 ;;",
          "  esac",
          "}",
          "node() {",
          '  if [[ "${1:-}" == "sdk/typescript/scripts/release-automation.mjs" ]]; then',
          "    cat >/dev/null",
          '    case "$2" in',
          "      verify-github-publication)",
          '        if [[ -z "${CODEX_SECURITY_VERIFIED_PROVENANCE:-}" ||',
          '              "$6" != "$GITHUB_REPOSITORY" ]]; then return 69; fi',
          "        printf '%s\\n' 'verified published artifact'",
          "        ;;",
          "      verify-provenance)",
          '        if [[ "$MOCK_EXACT_PROVENANCE" != "1" || "$7" != "$RELEASE_RUN_ID" ]]; then',
          "          return 68",
          "        fi",
          '        printf \'{"runId":"%s"}\\n\' "$RELEASE_RUN_ID"',
          "        ;;",
          "      verify-recovered-provenance)",
          '        printf \'{"runId":"%s"}\\n\' "$MOCK_ORIGINAL_RUN_ID"',
          "        ;;",
          "      *) return 66 ;;",
          "    esac",
          "    return 0",
          "  fi",
          '  command node "$@"',
          "}",
          "gh() {",
          '  if [[ "$1" != "api" ]]; then return 64; fi',
          "  shift",
          '  case "$1" in',
          `    "repos/test/codex-security/actions/runs/${releaseRun}/jobs?per_page=100")`,
          "      printf '%s\\n' \"$MOCK_RECOVERY_CONCLUSION\"",
          "      ;;",
          '    "repos/test/codex-security/actions/runs/30481596228")',
          "      printf '%s\\t%s\\t%s\\t%s\\n' node-release completed \"$MOCK_ORIGINAL_COMMIT\" npm-v0.1.2",
          "      ;;",
          "    *) return 67 ;;",
          "  esac",
          "}",
        ].join("\n");
        const result = spawnSync(bash, ["-c", `${mocks}\n${script}`], {
          cwd: workspace,
          encoding: "utf8",
          env: {
            ...process.env,
            GITHUB_OUTPUT: "/dev/null",
            GITHUB_REPOSITORY: "test/codex-security",
            MOCK_EXACT_PROVENANCE: exact ? "1" : "0",
            MOCK_ORIGINAL_COMMIT: originalCommit,
            MOCK_ORIGINAL_RUN_ID: "30481596228",
            MOCK_RECOVERY_CONCLUSION: recoveryConclusion,
            RELEASE_RUN_ID: releaseRun,
            RELEASE_SHA: releaseCommit,
            RELEASE_TAG: "npm-v0.1.2",
            RELEASE_VERSION: "0.1.2",
          },
          timeout: 10_000,
        });

        expect(result.status).toBe(status);
        if (status === 0) {
          expect(result.stdout).toContain(message);
        } else {
          expect(result.stderr).toContain(message);
        }
      } finally {
        rmSync(workspace, { recursive: true, force: true });
      }
    },
  );

  test.each([
    {
      description: "empty",
      existingNotes: "",
      updated: true,
      latestTag: "npm-v0.1.3",
      makeLatest: false,
      latestUpdated: false,
      tagType: "commit",
      tagObject: releaseCommit,
      peeledCommit: "",
      status: 0,
    },
    {
      description: "manually written",
      existingNotes: "Manually written release notes",
      updated: true,
      latestTag: "npm-v0.1.3",
      makeLatest: false,
      latestUpdated: false,
      tagType: "commit",
      tagObject: releaseCommit,
      peeledCommit: "",
      status: 0,
    },
    {
      description: "already current",
      existingNotes: "Generated release notes",
      updated: false,
      latestTag: "npm-v0.1.3",
      makeLatest: false,
      latestUpdated: false,
      tagType: "commit",
      tagObject: releaseCommit,
      peeledCommit: "",
      status: 0,
    },
    {
      description:
        "already current on a release predating release-note configuration",
      existingNotes: "Generated release notes",
      updated: false,
      latestTag: "npm-v0.1.2",
      makeLatest: true,
      latestUpdated: false,
      releaseConfiguration: false,
      tagType: "commit",
      tagObject: releaseCommit,
      peeledCommit: "",
      status: 0,
    },
    {
      description:
        "already current on a newest release incorrectly marked non-Latest",
      existingNotes: "Generated release notes",
      updated: false,
      latestTag: "npm-v0.1.1",
      makeLatest: true,
      latestUpdated: true,
      tagType: "commit",
      tagObject: releaseCommit,
      peeledCommit: "",
      status: 0,
    },
    {
      description: "already current when no GitHub release is marked Latest",
      existingNotes: "Generated release notes",
      updated: false,
      latestTag: "__missing__",
      makeLatest: true,
      latestUpdated: true,
      tagType: "commit",
      tagObject: releaseCommit,
      peeledCommit: "",
      status: 0,
    },
    {
      description: "already current when the Latest lookup fails unexpectedly",
      existingNotes: "Generated release notes",
      updated: false,
      latestTag: "__error__",
      makeLatest: true,
      latestUpdated: false,
      tagType: "commit",
      tagObject: releaseCommit,
      peeledCommit: "",
      status: 1,
    },
    {
      description:
        "already current when the Latest lookup has no HTTP response",
      existingNotes: "Generated release notes",
      updated: false,
      latestTag: "__network__",
      makeLatest: true,
      latestUpdated: false,
      tagType: "commit",
      tagObject: releaseCommit,
      peeledCommit: "",
      status: 1,
    },
    {
      description: "already current when the Latest 404 response is malformed",
      existingNotes: "Generated release notes",
      updated: false,
      latestTag: "__malformed_missing__",
      makeLatest: true,
      latestUpdated: false,
      tagType: "commit",
      tagObject: releaseCommit,
      peeledCommit: "",
      status: 1,
    },
    {
      description:
        "already current on a historical release incorrectly marked Latest",
      existingNotes: "Generated release notes",
      updated: false,
      latestTag: "npm-v0.1.2",
      makeLatest: false,
      latestUpdated: true,
      tagType: "tag",
      tagObject: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      peeledCommit: releaseCommit,
      status: 0,
    },
    {
      description: "stale when its lightweight release tag was retargeted",
      existingNotes: "Manually written release notes",
      updated: false,
      latestTag: "npm-v0.1.3",
      makeLatest: false,
      latestUpdated: false,
      tagType: "commit",
      tagObject: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      peeledCommit: "",
      status: 1,
    },
    {
      description: "stale when its annotated release tag was retargeted",
      existingNotes: "Manually written release notes",
      updated: false,
      latestTag: "npm-v0.1.3",
      makeLatest: false,
      latestUpdated: false,
      tagType: "tag",
      tagObject: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      peeledCommit: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      status: 1,
    },
  ])(
    "reconciles $description notes on an existing verified GitHub release",
    ({
      existingNotes,
      updated,
      latestTag,
      makeLatest,
      latestUpdated,
      releaseConfiguration = true,
      tagType,
      tagObject,
      peeledCommit,
      status,
    }) => {
      const script = workflowStepShell(
        githubReleaseWorkflow,
        "Publish GitHub Release and generated notes",
      );
      const mocks = [
        "gh() {",
        '  if [[ "$1" == "api" ]]; then',
        "    shift",
        "    local method=GET",
        "    local include=false",
        '    if [[ "${1:-}" == "--include" ]]; then',
        "      include=true",
        "      shift",
        "    fi",
        '    if [[ "${1:-}" == "--method" ]]; then',
        '      method="$2"',
        "      shift 2",
        "    fi",
        '    case "$method $1" in',
        '      "GET repos/test/codex-security/releases/tags/npm-v0.1.2")',
        '        if [[ "$include" != "true" ]]; then return 71; fi',
        '        printf \'HTTP/2.0 200 OK\\ncontent-type: application/json\\n\\n{"tag_name":"npm-v0.1.2","draft":false,"prerelease":false,"body":"%s","assets":[]}\\n\' "$MOCK_EXISTING_NOTES"',
        "        ;;",
        '      "GET repos/test/codex-security/releases/latest")',
        '        if [[ "$include" != "true" ]]; then return 71; fi',
        '        if [[ "$MOCK_LATEST_TAG" == "__missing__" ]]; then',
        "          printf '%s\\n' 'HTTP/2.0 404 Not Found' 'content-type: application/json' '' '{\"message\":\"Not Found\"}'",
        "          return 1",
        "        fi",
        '        if [[ "$MOCK_LATEST_TAG" == "__error__" ]]; then',
        "          printf '%s\\n' 'HTTP/2.0 500 Internal Server Error' 'content-type: application/json' '' '{\"message\":\"Unavailable\"}'",
        "          return 1",
        "        fi",
        '        if [[ "$MOCK_LATEST_TAG" == "__network__" ]]; then return 1; fi',
        '        if [[ "$MOCK_LATEST_TAG" == "__malformed_missing__" ]]; then',
        "          printf '%s\\n' 'HTTP/2.0 404 Not Found' 'content-type: application/json' '' 'not-json'",
        "          return 1",
        "        fi",
        '        printf \'HTTP/2.0 200 OK\\ncontent-type: application/json\\n\\n{"tag_name":"%s"}\\n\' "$MOCK_LATEST_TAG"',
        "        ;;",
        '      "GET repos/test/codex-security/git/ref/tags/npm-v0.1.2")',
        '        printf \'%s\\t%s\\n\' "$MOCK_TAG_TYPE" "$MOCK_TAG_OBJECT"',
        "        ;;",
        '      "GET repos/test/codex-security/git/tags/"*)',
        "        printf '%s\\n' \"$MOCK_PEELED_COMMIT\"",
        "        ;;",
        '      "POST repos/test/codex-security/releases/generate-notes")',
        '        if [[ "$MOCK_RELEASE_CONFIGURATION" == "missing" &&',
        '              "$*" == *"configuration_file_path=.github/release.yml"* ]]; then',
        "          printf '%s\\n' 'Could not find a configuration file at .github/release.yml' >&2",
        "          return 1",
        "        fi",
        "        printf '%s\\n' 'Generated release notes'",
        "        ;;",
        "      *) return 65 ;;",
        "    esac",
        '  elif [[ "$1" == "release" ]]; then',
        "    shift",
        '    case "$1" in',
        "      download)",
        "        shift",
        "        local destination= pattern=",
        "        while (( $# > 0 )); do",
        '          case "$1" in',
        '            --dir) destination="$2"; shift 2 ;;',
        '            --pattern) pattern="$2"; shift 2 ;;',
        "            --repo) shift 2 ;;",
        "            *) shift ;;",
        "          esac",
        "        done",
        "        printf '%s\\n' 'verified archive' > \"$destination/$pattern\"",
        "        ;;",
        "      edit)",
        "        shift",
        "        local edit_latest= notes=0",
        '        for argument in "$@"; do',
        '          if [[ "$argument" == "--verify-tag" ]]; then',
        "            printf '%s\\n' 'unknown flag: --verify-tag' >&2",
        "            return 67",
        "          fi",
        '          if [[ "$argument" == --latest=* ]]; then',
        '            edit_latest="${argument#--latest=}"',
        "          fi",
        '          if [[ "$argument" == "--notes-file" ]]; then notes=1; fi',
        "        done",
        '        if [[ "$edit_latest" != "$MOCK_MAKE_LATEST" ]]; then return 68; fi',
        "        printf 'updated latest: %s\\n' \"$edit_latest\"",
        '        if [[ "$notes" == 1 ]]; then',
        "          printf '%s: ' 'updated release notes'",
        "          cat",
        "        fi",
        "        ;;",
        "      create) return 70 ;;",
        "      *) return 66 ;;",
        "    esac",
        "  else",
        "    return 64",
        "  fi",
        "}",
        "git() {",
        '  if [[ "$1" == "cat-file" && "$2" == "-e" &&',
        '        "$3" == "$RELEASE_SHA:.github/release.yml" ]]; then',
        '    [[ "$MOCK_RELEASE_CONFIGURATION" == "present" ]]',
        "    return",
        "  fi",
        '  command git "$@"',
        "}",
        "node() {",
        '  if [[ "${1:-}" == "sdk/typescript/scripts/release-automation.mjs" &&',
        '        "${2:-}" == "verify-github-release" ]]; then',
        "    cat >/dev/null",
        "    printf '%s\\n' 'verified existing GitHub release asset'",
        "    return 0",
        "  fi",
        '  command node "$@"',
        "}",
      ].join("\n");
      const result = spawnSync(bash, [], {
        input: `${mocks}\n${script}`,
        encoding: "utf8",
        env: {
          ...process.env,
          GITHUB_REPOSITORY: "test/codex-security",
          MAKE_LATEST: String(makeLatest),
          MOCK_EXISTING_NOTES: existingNotes,
          MOCK_LATEST_TAG: latestTag,
          MOCK_MAKE_LATEST: String(makeLatest),
          MOCK_PEELED_COMMIT: peeledCommit,
          MOCK_RELEASE_CONFIGURATION: releaseConfiguration
            ? "present"
            : "missing",
          MOCK_TAG_OBJECT: tagObject,
          MOCK_TAG_TYPE: tagType,
          PREVIOUS_TAG: "npm-v0.1.1",
          RELEASE_ARCHIVE: "/tmp/openai-codex-security-0.1.2.tgz",
          RELEASE_SHA: releaseCommit,
          RELEASE_TAG: "npm-v0.1.2",
          RELEASE_VERSION: "0.1.2",
        },
        timeout: 10_000,
      });

      expect(result.status).toBe(status);
      expect(result.stdout).toContain("verified existing GitHub release asset");
      if (status !== 0) {
        const latestLookupFailed = [
          "__error__",
          "__network__",
          "__malformed_missing__",
        ].includes(latestTag);
        expect(result.stderr).toContain(
          latestLookupFailed
            ? "Unable to resolve the current Latest GitHub Release."
            : "GitHub release tag must still point to the verified commit.",
        );
        return;
      }
      if (updated) {
        expect(result.stdout).toContain(
          "updated release notes: Generated release notes",
        );
        expect(result.stdout).toContain(
          "Updated existing GitHub Release with generated notes.",
        );
      } else if (latestUpdated) {
        expect(result.stdout).not.toContain("updated release notes:");
        expect(result.stdout).toContain(`updated latest: ${makeLatest}`);
        expect(result.stdout).toContain(
          "Updated existing GitHub Release Latest status.",
        );
      } else {
        expect(result.stdout).not.toContain("updated release notes:");
        expect(result.stdout).toContain(
          "The verified GitHub Release already exists.",
        );
      }
    },
  );

  test("cryptographically verifies the exact npm provenance bundle", () => {
    expect(githubReleaseWorkflow).toContain('node-version: "24.15.0"');
    expect(githubReleaseWorkflow).toContain(
      'if [[ "$(npm --version)" != "11.12.1" ]]; then',
    );
    expect(githubReleaseWorkflow).toContain("npm audit signatures");
    expect(githubReleaseWorkflow).toContain("--include-attestations");
    expect(githubReleaseWorkflow).toContain("verify-recovered-provenance");
  });

  test("installs the exact attestation-capable npm through the Socket Firewall", () => {
    for (const workflow of [githubReleaseWorkflow, protectedReleaseWorkflow]) {
      expect(workflow).toContain("Install provenance-capable npm");
      expect(workflow).toContain("npm@11.12.1");
      expect(workflow).toContain(
        "--registry=https://openai.firewall.socket.dev/npm/",
      );
      expect(workflow).toContain('>> "$GITHUB_PATH"');
      expect(workflow).not.toContain("npm install --global");
    }
  });

  test("serializes label reconciliation and reads the current PR title", () => {
    expect(releaseLabelsWorkflow).toContain(
      "group: node-release-labels-${{ github.event.pull_request.number }}",
    );
    expect(releaseLabelsWorkflow).toContain(
      'gh api "repos/$GITHUB_REPOSITORY/issues/$PR_NUMBER"',
    );
    expect(releaseLabelsWorkflow).toContain(
      'label="$(release_note_label "$current_title")"',
    );
    expect(releaseLabelsWorkflow).toContain(
      "enhancement | bug | documentation | skip-release-notes)",
    );
    expect(releaseLabelsWorkflow).toContain("gh api --method DELETE");
    expect(releaseLabelsWorkflow).toContain("return 0");
  });

  test.each([
    { title: "fix: retitle an internal change", expectedLabel: "bug" },
    { title: "feat: retitle an internal change", expectedLabel: "enhancement" },
    {
      title: "docs: retitle an internal change",
      expectedLabel: "documentation",
    },
    { title: "chore: retitle an internal change", expectedLabel: null },
  ])(
    "preserves a manually excluded release and reconciles its category after retitling to $title",
    ({ title, expectedLabel }) => {
      const script = workflowStepShell(
        releaseLabelsWorkflow,
        "Categorize pull request without checking out its code",
      );
      const mock = [
        "gh() {",
        '  if [[ "$1" != "api" ]]; then return 64; fi',
        "  shift",
        "  local method=GET",
        '  if [[ "${1:-}" == "--method" ]]; then',
        '    method="$2"',
        "    shift 2",
        "  fi",
        '  local endpoint="$1"',
        "  shift",
        '  case "$method $endpoint" in',
        '    "GET repos/test/codex-security/issues/17")',
        "      printf '%s\\n' \"$MOCK_PR_TITLE\"",
        "      ;;",
        '    "GET repos/test/codex-security/issues/17/labels")',
        "      printf '%s\\n' enhancement skip-release-notes",
        "      ;;",
        '    "GET repos/test/codex-security/issues/17/timeline?per_page=100")',
        "      printf '%s\\n' 'github-actions[bot]' 'trusted-reviewer'",
        "      ;;",
        '    "DELETE repos/test/codex-security/issues/17/labels/enhancement")',
        "      printf '%s\\n' 'removed a stale managed category'",
        "      ;;",
        '    "DELETE repos/test/codex-security/issues/17/labels/skip-release-notes")',
        "      printf '%s\\n' 'removed a manually excluded release label'",
        "      return 70",
        "      ;;",
        '    "POST repos/test/codex-security/issues/17/labels")',
        "      printf '%s\\n' \"$@\"",
        "      ;;",
        "    *) return 65 ;;",
        "  esac",
        "}",
      ].join("\n");
      const result = spawnSync(bash, ["-c", `${mock}\n${script}`], {
        encoding: "utf8",
        env: {
          ...process.env,
          GITHUB_REPOSITORY: "test/codex-security",
          MOCK_PR_TITLE: title,
          PR_NUMBER: "17",
        },
        timeout: 10_000,
      });

      expect(result.status).toBe(0);
      expect(result.stdout).toContain(
        "Preserving existing skip-release-notes label.",
      );
      expect(result.stdout).not.toContain(
        "removed a manually excluded release label",
      );
      if (expectedLabel === "enhancement") {
        expect(result.stdout).not.toContain("removed a stale managed category");
        expect(result.stdout).not.toContain("labels[]=enhancement");
      } else {
        expect(result.stdout).toContain("removed a stale managed category");
        if (expectedLabel === null) {
          expect(result.stdout).not.toContain("labels[]=");
        } else {
          expect(result.stdout).toContain(`labels[]=${expectedLabel}`);
        }
      }
    },
  );

  test("preserves the latest unattributed skip label after earlier automation", () => {
    const script = workflowStepShell(
      releaseLabelsWorkflow,
      "Categorize pull request without checking out its code",
    );
    const mock = [
      "gh() {",
      '  if [[ "$1" != "api" ]]; then return 64; fi',
      "  shift",
      "  local method=GET",
      '  if [[ "${1:-}" == "--method" ]]; then',
      '    method="$2"',
      "    shift 2",
      "  fi",
      '  local endpoint="$1"',
      "  shift",
      '  case "$method $endpoint" in',
      '    "GET repos/test/codex-security/issues/17")',
      "      printf '%s\\n' 'feat: customer-visible change'",
      "      ;;",
      '    "GET repos/test/codex-security/issues/17/labels")',
      "      printf '%s\\n' skip-release-notes",
      "      ;;",
      '    "GET repos/test/codex-security/issues/17/timeline?per_page=100")',
      '      if [[ "$*" == *"__unattributed__"* ]]; then',
      "        printf '%s\\n' 'github-actions[bot]' '__unattributed__'",
      "      else",
      "        printf '%s\\n' 'github-actions[bot]' ''",
      "      fi",
      "      ;;",
      '    "DELETE repos/test/codex-security/issues/17/labels/skip-release-notes")',
      "      printf '%s\\n' 'removed an unattributed release exclusion'",
      "      return 70",
      "      ;;",
      '    "POST repos/test/codex-security/issues/17/labels")',
      "      printf '%s\\n' \"$@\"",
      "      ;;",
      "    *) return 65 ;;",
      "  esac",
      "}",
    ].join("\n");
    const result = spawnSync(bash, ["-c", `${mock}\n${script}`], {
      encoding: "utf8",
      env: {
        ...process.env,
        GITHUB_REPOSITORY: "test/codex-security",
        PR_NUMBER: "17",
      },
      timeout: 10_000,
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain(
      "Preserving existing skip-release-notes label.",
    );
    expect(result.stdout).not.toContain("removed an unattributed release");
    expect(result.stdout).toContain("labels[]=enhancement");
  });

  test.each([
    { title: "feat: publish a customer feature", label: "enhancement" },
    { title: "fix: publish a customer fix", label: "bug" },
    { title: "docs: publish customer documentation", label: "documentation" },
    { title: "chore: stop excluding an internal change", label: null },
  ])(
    "reconciles an automatic skip label after retitling to $title",
    ({ title, label }) => {
      const script = workflowStepShell(
        releaseLabelsWorkflow,
        "Categorize pull request without checking out its code",
      );
      const mock = [
        "gh() {",
        '  if [[ "$1" != "api" ]]; then return 64; fi',
        "  shift",
        "  local method=GET",
        '  if [[ "${1:-}" == "--method" ]]; then',
        '    method="$2"',
        "    shift 2",
        "  fi",
        '  local endpoint="$1"',
        "  shift",
        '  case "$method $endpoint" in',
        '    "GET repos/test/codex-security/issues/17")',
        "      printf '%s\\n' \"$MOCK_PR_TITLE\"",
        "      ;;",
        '    "GET repos/test/codex-security/issues/17/labels")',
        "      printf '%s\\n' skip-release-notes",
        "      ;;",
        '    "GET repos/test/codex-security/issues/17/timeline?per_page=100")',
        "      printf '%s\\n' 'github-actions[bot]'",
        "      ;;",
        '    "DELETE repos/test/codex-security/issues/17/labels/skip-release-notes")',
        "      printf '%s\\n' 'removed automatically applied skip-release-notes'",
        "      ;;",
        '    "POST repos/test/codex-security/issues/17/labels")',
        "      printf '%s\\n' \"$@\"",
        "      ;;",
        "    *) return 65 ;;",
        "  esac",
        "}",
      ].join("\n");
      const result = spawnSync(bash, ["-c", `${mock}\n${script}`], {
        encoding: "utf8",
        env: {
          ...process.env,
          GITHUB_REPOSITORY: "test/codex-security",
          MOCK_PR_TITLE: title,
          PR_NUMBER: "17",
        },
        timeout: 10_000,
      });

      expect(result.status).toBe(0);
      expect(result.stdout).toContain(
        "removed automatically applied skip-release-notes",
      );
      expect(result.stdout).not.toContain(
        "Preserving existing skip-release-notes label.",
      );
      if (label === null) {
        expect(result.stdout).toContain(
          "No automatic release-note category applies.",
        );
      } else {
        expect(result.stdout).toContain(`labels[]=${label}`);
      }
    },
  );

  test.each([
    { title: "feat!: breaking feature", label: "enhancement" },
    { title: "feat(api)!: breaking feature", label: "enhancement" },
    { title: "fix!: breaking fix", label: "bug" },
    { title: "fix(api)!: breaking fix", label: "bug" },
    { title: "docs!: breaking documentation", label: "documentation" },
    {
      title: "docs(api)!: breaking documentation",
      label: "documentation",
    },
  ])("categorizes breaking-change title $title", ({ title, label }) => {
    const script = workflowStepShell(
      releaseLabelsWorkflow,
      "Categorize pull request without checking out its code",
    );
    const mock = [
      "gh() {",
      '  if [[ "$1" != "api" ]]; then return 64; fi',
      "  shift",
      "  local method=GET",
      '  if [[ "${1:-}" == "--method" ]]; then',
      '    method="$2"',
      "    shift 2",
      "  fi",
      '  local endpoint="$1"',
      "  shift",
      '  case "$method $endpoint" in',
      '    "GET repos/test/codex-security/issues/17")',
      "      printf '%s\\n' \"$MOCK_PR_TITLE\"",
      "      ;;",
      '    "GET repos/test/codex-security/issues/17/labels")',
      "      return 0",
      "      ;;",
      '    "POST repos/test/codex-security/issues/17/labels")',
      "      printf '%s\\n' \"$@\"",
      "      ;;",
      "    *) return 65 ;;",
      "  esac",
      "}",
    ].join("\n");
    const result = spawnSync(bash, ["-c", `${mock}\n${script}`], {
      encoding: "utf8",
      env: {
        ...process.env,
        GITHUB_REPOSITORY: "test/codex-security",
        MOCK_PR_TITLE: title,
        PR_NUMBER: "17",
      },
      timeout: 10_000,
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain(`labels[]=${label}`);
  });

  test("executes and recovers from concurrent skip-label creation", () => {
    const script = workflowStepShell(
      releaseLabelsWorkflow,
      "Categorize pull request without checking out its code",
    );
    const mock = [
      "skip_label_exists=0",
      "gh() {",
      '  if [[ "$1" != "api" ]]; then return 64; fi',
      "  shift",
      "  local method=GET",
      '  if [[ "${1:-}" == "--method" ]]; then',
      '    method="$2"',
      "    shift 2",
      "  fi",
      '  local endpoint="$1"',
      '  case "$method $endpoint" in',
      '    "GET repos/test/codex-security/issues/17")',
      "      printf '%s\\n' 'release: automate published notes'",
      "      ;;",
      '    "GET repos/test/codex-security/issues/17/labels")',
      "      return 0",
      "      ;;",
      '    "GET repos/test/codex-security/labels/skip-release-notes")',
      '      [[ "$skip_label_exists" == 1 ]]',
      "      ;;",
      '    "POST repos/test/codex-security/labels")',
      "      skip_label_exists=1",
      "      return 1",
      "      ;;",
      '    "POST repos/test/codex-security/issues/17/labels")',
      '      if [[ "$skip_label_exists" != 1 ]]; then return 65; fi',
      "      printf '%s\\n' 'applied skip-release-notes'",
      "      ;;",
      "    *) return 66 ;;",
      "  esac",
      "}",
    ].join("\n");
    const result = spawnSync(bash, ["-c", `${mock}\n${script}`], {
      encoding: "utf8",
      env: {
        ...process.env,
        GITHUB_REPOSITORY: "test/codex-security",
        PR_NUMBER: "17",
      },
      timeout: 10_000,
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("applied skip-release-notes");
  });

  test("documents JSON stdin for every verification command", () => {
    const result = spawnSync(
      "node",
      [fileURLToPath(automationScript), "unknown"],
      { encoding: "utf8", timeout: 10_000 },
    );
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("published npm versions JSON from stdin");
    expect(result.stderr).toContain("package metadata JSON from stdin");
    expect(result.stderr).toContain("signature audit JSON from stdin");
    expect(result.stderr).toContain("GitHub release JSON from stdin");
  });
});
