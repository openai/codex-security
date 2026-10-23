import { afterEach, expect, test } from "bun:test";
import { cp, mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import {
  loadContract,
  readScanFile,
  requireScanFile,
} from "../src/contract.js";
import type {
  CoverageDocument,
  Finding,
  FindingsDocument,
  ScanManifest,
} from "../src/models.js";
import { copyCompletedScan, PLUGIN_ROOT } from "./plugin-root.js";
import { sha256 } from "./support/finding-identity.js";
import { readJson, writeJson } from "./support/json.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const fixtures = createApiTestFixtures("sealed-contract-validation-");
afterEach(fixtures.cleanup);
const { validateTrackingSource, loadSealedContract } = (
  await import(pathToFileURL(join(PLUGIN_ROOT, "mcp", "helpers.mjs")).href)
).default as {
  validateTrackingSource(
    scanDir: string,
    options?: { pluginRoot: string },
  ): Promise<Finding[]>;
  loadSealedContract(
    scanDir: string,
    options: { pluginRoot: string; profile: "tracking" },
  ): Promise<{ contract: { coverage: CoverageDocument } }>;
};

type Documents = {
  scanDir: string;
  manifest: ScanManifest;
  findings: FindingsDocument;
  coverage: CoverageDocument;
};

async function fixture(): Promise<Documents> {
  const scanDir = await copyCompletedScan(await fixtures.temporaryDirectory());
  return {
    scanDir,
    manifest: await readJson<ScanManifest>(join(scanDir, "scan-manifest.json")),
    findings: await readJson<FindingsDocument>(join(scanDir, "findings.json")),
    coverage: await readJson<CoverageDocument>(join(scanDir, "coverage.json")),
  };
}

async function saveAndSeal(documents: Documents, findingsText?: string) {
  const { scanDir, manifest, findings, coverage } = documents;
  await writeFile(
    join(scanDir, "findings.json"),
    findingsText ?? JSON.stringify(findings),
  );
  await writeJson(join(scanDir, "coverage.json"), coverage);
  for (const artifact of manifest.scan.artifacts) {
    artifact.sha256 = sha256(await readFile(join(scanDir, artifact.path)));
  }
  await writeJson(join(scanDir, "scan-manifest.json"), manifest);
}

async function addArtifact(documents: Documents, path: string) {
  const filename = join(documents.scanDir, path);
  await mkdir(dirname(filename), { recursive: true });
  await writeFile(filename, "synthetic receipt");
  documents.manifest.scan.artifacts.push({
    path,
    sha256: "",
    mediaType: "text/plain",
  });
}

test.each(["receiptRefs", "deferred"] as const)(
  "preserves omitted tracking coverage %s when the selected schema permits it",
  async (field) => {
    const documents = await fixture();
    const pluginRoot = await fixtures.temporaryDirectory();
    await cp(join(PLUGIN_ROOT, "schemas"), join(pluginRoot, "schemas"), {
      recursive: true,
    });
    const schemaPath = join(pluginRoot, "schemas", "coverage.schema.json");
    const schema = JSON.parse(await readFile(schemaPath, "utf8"));
    const definition =
      field === "receiptRefs" ? schema.properties.surfaces.items : schema;
    definition.required = definition.required.filter(
      (required: string) => required !== field,
    );
    await writeJson(schemaPath, schema);

    for (const selectedRoot of [PLUGIN_ROOT, pluginRoot]) {
      const { contract } = await loadSealedContract(documents.scanDir, {
        pluginRoot: selectedRoot,
        profile: "tracking",
      });
      expect(contract.coverage).toEqual(documents.coverage);
      expect(
        (await loadContract(documents.scanDir, { pluginRoot: selectedRoot }))
          .coverage,
      ).toEqual(documents.coverage);
    }

    const target =
      field === "receiptRefs"
        ? documents.coverage.surfaces[0]!
        : documents.coverage;
    Reflect.set(target, field, null);
    await saveAndSeal(documents);
    await expect(
      validateTrackingSource(documents.scanDir, { pluginRoot }),
    ).rejects.toThrow(field);
    await expect(
      loadContract(documents.scanDir, { pluginRoot }),
    ).rejects.toThrow(field);

    Reflect.deleteProperty(target, field);
    await saveAndSeal(documents);
    const original = await readFile(join(documents.scanDir, "coverage.json"));
    await expect(validateTrackingSource(documents.scanDir)).rejects.toThrow(
      field,
    );
    await expect(
      loadContract(documents.scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).rejects.toThrow(field);
    await expect(
      loadContract(documents.scanDir, { pluginRoot }),
    ).rejects.toThrow();
    await expect(
      validateTrackingSource(documents.scanDir, { pluginRoot }),
    ).resolves.toEqual(documents.findings.findings);
    const { contract } = await loadSealedContract(documents.scanDir, {
      pluginRoot,
      profile: "tracking",
    });
    expect(contract.coverage).toEqual(documents.coverage);
    expect(
      Object.hasOwn(
        field === "receiptRefs"
          ? contract.coverage.surfaces[0]!
          : contract.coverage,
        field,
      ),
    ).toBe(false);
    expect(await readFile(join(documents.scanDir, "coverage.json"))).toEqual(
      original,
    );
  },
);

test.each([
  ["./artifacts/receipt.json", false],
  [".//./artifacts/receipt.json", false],
  ["artifacts//receipt.json", true],
  ["artifacts/./receipt.json", true],
  ["artifacts/receipt.json/", true],
] as const)(
  "preserves tracking receipt normalization and SDK admission for %s",
  async (reference, sdkAccepts) => {
    const documents = await fixture();
    await addArtifact(documents, "artifacts/receipt.json");
    documents.coverage.surfaces[0]!.receiptRefs = [reference];
    await saveAndSeal(documents);
    const original = await readFile(join(documents.scanDir, "coverage.json"));

    await expect(validateTrackingSource(documents.scanDir)).resolves.toEqual(
      documents.findings.findings,
    );
    const { contract } = await loadSealedContract(documents.scanDir, {
      pluginRoot: PLUGIN_ROOT,
      profile: "tracking",
    });
    expect(contract.coverage.surfaces[0]!.receiptRefs).toEqual([
      "artifacts/receipt.json",
    ]);
    const sdk = loadContract(documents.scanDir, { pluginRoot: PLUGIN_ROOT });
    if (sdkAccepts)
      expect((await sdk).coverage.surfaces[0]!.receiptRefs).toEqual([
        reference,
      ]);
    else await expect(sdk).rejects.toThrow("coverage.json");
    expect(await readFile(join(documents.scanDir, "coverage.json"))).toEqual(
      original,
    );
  },
);

test.each([
  "./artifacts/../receipt.json",
  "./artifacts/CON.txt",
  "./artifacts/receipt.json ",
  "./artifacts/receipt.json.",
  "./artifacts/receipt\u001b.json",
  "./artifacts\\receipt.json",
  "/artifacts/receipt.json",
  "C:/artifacts/receipt.json",
])(
  "rejects unsafe receipt spellings before normalization: %s",
  async (reference) => {
    const documents = await fixture();
    await addArtifact(documents, "artifacts/receipt.json");
    documents.coverage.surfaces[0]!.receiptRefs = [reference];
    await saveAndSeal(documents);
    await expect(validateTrackingSource(documents.scanDir)).rejects.toThrow();
    await expect(
      loadContract(documents.scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).rejects.toThrow();
  },
);

test.each(["coverage", "receipt", "missing receipt"] as const)(
  "retains original-byte seal checks after receipt normalization: %s",
  async (changed) => {
    const documents = await fixture();
    await addArtifact(documents, "artifacts/receipt.json");
    documents.coverage.surfaces[0]!.receiptRefs = ["./artifacts/receipt.json"];
    await saveAndSeal(documents);
    await expect(validateTrackingSource(documents.scanDir)).resolves.toEqual(
      documents.findings.findings,
    );
    if (changed === "coverage") {
      // An equivalent normalized view must not authorize different saved bytes.
      documents.coverage.surfaces[0]!.receiptRefs = ["artifacts/receipt.json"];
      await writeJson(
        join(documents.scanDir, "coverage.json"),
        documents.coverage,
      );
    } else if (changed === "receipt") {
      await writeFile(
        join(documents.scanDir, "artifacts/receipt.json"),
        "changed",
      );
    } else {
      await unlink(join(documents.scanDir, "artifacts/receipt.json"));
    }
    await expect(validateTrackingSource(documents.scanDir)).rejects.toThrow();
  },
);

test.each([
  ["BOM only", "\ufeff", true, false],
  ["NEXT LINE only", "\u0085", false, true],
  ["NBSP only", "\u00a0", false, false],
  ["zero-width space only", "\u200b", true, true],
  ["line separator", "artifacts/receipt\u2028.json", true, false],
  ["paragraph separator", "artifacts/\u2029receipt.json", true, false],
  ["reserved prefix without extension", "artifacts/CON\u2028", true, false],
] as const)(
  "preserves tracking and SDK artifact admission for %s",
  async (_name, path, trackingAccepts, sdkAccepts) => {
    const documents = await fixture();
    await addArtifact(documents, path);
    if (path.startsWith("artifacts/"))
      documents.coverage.surfaces[0]!.receiptRefs = [path];
    await saveAndSeal(documents);
    const tracking = validateTrackingSource(documents.scanDir);
    if (trackingAccepts)
      await expect(tracking).resolves.toEqual(documents.findings.findings);
    else await expect(tracking).rejects.toThrow();
    const sdk = loadContract(documents.scanDir, { pluginRoot: PLUGIN_ROOT });
    if (sdkAccepts) expect((await sdk).findings).toEqual(documents.findings);
    else await expect(sdk).rejects.toThrow();
    if (path === "\ufeff") {
      await expect(
        readScanFile(documents.scanDir, path, "supplementary artifact"),
      ).rejects.toThrow("safe scan-relative POSIX path");
      await expect(
        requireScanFile(documents.scanDir, path, "supplementary artifact"),
      ).rejects.toThrow("safe scan-relative POSIX path");
    }
  },
);

test.each(["CON\u0131N$", "CON\u0130N$.txt", "CON.\u2028txt", "AUX.\u2029txt"])(
  "rejects historical tracking reserved component %s before filesystem access",
  async (component) => {
    const documents = await fixture();
    documents.manifest.scan.artifacts.push({
      path: `artifacts/${component}`,
      sha256: "0".repeat(64),
      mediaType: "text/plain",
    });
    await writeJson(
      join(documents.scanDir, "scan-manifest.json"),
      documents.manifest,
    );
    await expect(validateTrackingSource(documents.scanDir)).rejects.toThrow(
      "safe scan-relative POSIX path",
    );
    await expect(
      loadContract(documents.scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).rejects.toThrow(
      /[\u2028\u2029]/u.test(component)
        ? "must match pattern"
        : "expected a file inside the scan directory",
    );
  },
);

const evidence = {
  id: "proof",
  label: "Proof",
  path: "src/example.ts",
  startLine: 41,
  endLine: 41,
  code: "example()",
  explanation: "Synthetic evidence.",
} satisfies NonNullable<Finding["codeEvidence"]>[number];

const invalidCases: Array<[string, (documents: Documents) => void, string]> = [
  [
    "duplicate canonical evidence",
    ({ findings }) => {
      findings.findings[0]!.codeEvidence = [evidence, { ...evidence }];
    },
    "duplicate code-evidence id",
  ],
  [
    "blank canonical evidence code",
    ({ findings }) => {
      findings.findings[0]!.codeEvidence = [{ ...evidence, code: " \u001c" }];
    },
    ".code: expected a non-empty string",
  ],
  [
    "duplicate coverage surface",
    ({ coverage }) => {
      coverage.surfaces.push({ ...coverage.surfaces[0]! });
    },
    "duplicate surface id",
  ],
  [
    "blank coverage surface label",
    ({ coverage }) => {
      coverage.surfaces[0]!.label = " ";
    },
    ".label: expected a non-empty string",
  ],
  [
    "duplicate resolved work",
    ({ coverage }) => {
      coverage.resolvedDeferred = [
        { id: "task", reason: "Done." },
        { id: "task", reason: "Also done." },
      ];
    },
    "duplicate resolved deferred id",
  ],
  [
    "resolved work that remains active",
    ({ coverage }) => {
      coverage.deferred = [{ id: "task", reason: "Pending." }];
      coverage.resolvedDeferred = [{ id: "task", reason: "Done." }];
    },
    "deferred work is still active",
  ],
  [
    "resolved candidate that remains active",
    ({ coverage }) => {
      coverage.deferred = [
        { id: "task", candidateId: "candidate", reason: "Pending." },
      ];
      coverage.resolvedDeferred = [{ id: "candidate", reason: "Done." }];
    },
    "deferred work is still active",
  ],
  [
    "blank resolution reason",
    ({ coverage }) => {
      coverage.resolvedDeferred = [{ id: "task", reason: " " }];
    },
    ".reason: expected a non-empty string",
  ],
  [
    "blank producer",
    ({ manifest }) => {
      manifest.scan.producer.name = " ";
    },
    ".producer.name: expected a non-empty string",
  ],
  [
    "empty revision on a revision target",
    ({ manifest }) => {
      manifest.scan.target.kind = "git_revision";
      manifest.scan.target.revision = "";
    },
    ".revision: expected a non-empty string",
  ],
  [
    "remote control characters normalized by URL parsing",
    ({ manifest }) => {
      manifest.scan.target.remote = "https://example.com\t/repository";
    },
    "expected a sanitized canonical absolute URL",
  ],
  [
    "noncanonical fingerprint properties",
    ({ findings }) => {
      findings.findings[0]!.fingerprints["extra"] = "synthetic";
    },
    "does not match derived fingerprint",
  ],
  [
    "Unicode drive-like repository paths",
    ({ findings }) => {
      findings.findings[0]!.locations[0]!.path = "é:file";
    },
    "safe repository-relative POSIX path",
  ],
  [
    "a threat model containing only a next-line character",
    ({ manifest }) => {
      manifest.scan.threatModel = { format: "markdown", content: "\u0085" };
    },
    "scan-manifest.json",
  ],
];

test.each(invalidCases)(
  "rejects tracking %s while preserving the SDK read behavior",
  async (_name, mutate, message) => {
    const documents = await fixture();
    mutate(documents);
    await saveAndSeal(documents);
    expect(
      (await loadContract(documents.scanDir, { pluginRoot: PLUGIN_ROOT }))
        .findings,
    ).toEqual(documents.findings);
    await expect(validateTrackingSource(documents.scanDir)).rejects.toThrow(
      message,
    );
  },
);

const historicalTrackingCases: Array<
  [string, (documents: Documents) => void, string]
> = [
  [
    "a localhost file remote",
    ({ manifest }) => {
      manifest.scan.target.remote = "file://localhost/repo";
    },
    "expected a sanitized canonical absolute URL",
  ],
  [
    "a file remote with a port",
    ({ manifest }) => {
      manifest.scan.target.remote = "file://example.com:123/repo";
    },
    "expected a sanitized canonical absolute URL",
  ],
  [
    "a scoped IPv6 remote",
    ({ manifest }) => {
      manifest.scan.target.remote = "ssh://[fe80::1%25eth0]/repo";
    },
    "expected a sanitized canonical absolute URL",
  ],
  [
    "overflowing timezone minutes",
    ({ manifest }) => {
      manifest.scan.startedAt = "2026-01-02T03:04:05+00:60";
    },
    'must match format "date-time"',
  ],
  [
    "a canonical evidence ID with a final newline",
    ({ findings }) => {
      findings.findings[0]!.codeEvidence = [{ ...evidence, id: "proof\n" }];
    },
    "must match pattern",
  ],
  [
    "a discarded legacy surrogate",
    ({ findings }) => {
      const finding = findings.findings[0]! as Record<string, unknown>;
      finding["code_evidence"] = "\ud800";
    },
    "expected well-formed Unicode JSON strings",
  ],
  [
    "a surrogate in discarded duplicate legacy evidence",
    ({ findings }) => {
      findings.findings[0]!.code_evidence = [
        { id: "legacy", code: "example()" },
        { id: "legacy", code: "duplicate()", discarded: "\ud800" },
      ];
    },
    "expected well-formed Unicode JSON strings",
  ],
  [
    "a surrogate in a discarded unknown evidence reference",
    ({ findings }) => {
      findings.findings[0]!.rootCause = {
        summary: "Synthetic cause.",
        evidenceRefs: ["\ud800"],
      };
    },
    "expected well-formed Unicode JSON strings",
  ],
  [
    "a snapshot digest with a final newline",
    ({ manifest }) => {
      manifest.scan.target.snapshotDigest += "\n";
    },
    "must match pattern",
  ],
  [
    "an optional writeup path with a final newline",
    ({ findings }) => {
      findings.findings[0]!.writeup = {
        reportPath: "findings/proof/proof.md\n",
      };
    },
    "must match pattern",
  ],
  [
    "a threat model containing a byte-order-mark character",
    ({ manifest }) => {
      manifest.scan.threatModel = { format: "markdown", content: "\ufeff" };
    },
    "scan-manifest.json",
  ],
];

test.each(historicalTrackingCases)(
  "preserves tracking admission of %s and the SDK rejection",
  async (_name, mutate, message) => {
    const documents = await fixture();
    mutate(documents);
    await saveAndSeal(documents);
    const paths = ["scan-manifest.json", "findings.json", "coverage.json"];
    const before = await Promise.all(
      paths.map((path) => readFile(join(documents.scanDir, path))),
    );
    await expect(
      loadContract(documents.scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).rejects.toThrow(message);
    expect(
      (await validateTrackingSource(documents.scanDir)).map(
        (finding) => finding.findingId,
      ),
    ).toEqual(documents.findings.findings.map((finding) => finding.findingId));
    expect(
      await Promise.all(
        paths.map((path) => readFile(join(documents.scanDir, path))),
      ),
    ).toEqual(before);
  },
);

const remoteAuthorityCases: Array<[string, boolean, boolean]> = [
  [" https://example.test/repo", true, false],
  ["  ssh://example.test/repo", true, false],
  ["\u00a0https://example.test/repo", false, false],
  ["\ufeffhttps://example.test/repo", false, false],
  ["https://example.test ", false, true],
  ["https://example.test /repo", false, false],
  ["https://example.test/repo ", true, true],
  ["https://example.123/repo", true, false],
  ["https://example.123:443/repo", true, false],
  ["https://example.123./repo", true, false],
  ["https://example.09/repo", true, false],
  ["https://256.256.256.256/repo", true, false],
  ["https://example.123x/repo", true, true],
  ["file://example.123/repo", true, false],
  ["https://exa%20mple.test/repo", true, false],
  ["https://exa%40mple.test/repo", true, false],
  ["https://exa%2fmple.test/repo", true, false],
  ["https://exa%00mple.test/repo", true, false],
  ["https://exa%zzmple.test/repo", true, false],
  ["https://exa%mple.test/repo", true, false],
  ["ssh://exa%20mple.test/repo", true, true],
  ["ssh://exa\u00a0mple.test/repo", false, true],
  ["ssh://exa\u2007mple.test/repo", false, true],
  ["ssh://exa\u202fmple.test/repo", false, true],
  ["ssh://exa\u3000mple.test/repo", false, true],
  ["ssh://exa\ufeffmple.test/repo", true, true],
  ["ssh://exa\u200bmple.test/repo", true, true],
  ["ssh://exa\uff1ample.test/repo", false, true],
  ["ssh://exa\uff20mple.test/repo", false, true],
  ["ssh://exa\uff0fmple.test/repo", false, true],
  ["ssh://exa\uff1fmple.test/repo", false, true],
  ["ssh://exa\uff03mple.test/repo", false, true],
  ["ssh://exa\u2100mple.test/repo", false, true],
  ["ssh://ex\uff41mple.test/repo", true, true],
  ["ssh://[fe80::1%eth\ufeff0]/repo", true, false],
  ["ssh://[fe80::1%eth\u00a00]/repo", false, false],
  ["ssh://[::1]:/repo", true, true],
  ["ssh://[::1]suffix/repo", false, false],
  ["ssh://[::1]]/repo", false, false],
  ["ssh://[::1]:22:23/repo", false, false],
  ["ssh://example.test:/repo", true, true],
  ["ssh://example.test:00022/repo", true, true],
  ["ssh://example.test:65535/repo", true, true],
  ["ssh://example.test:65536/repo", false, false],
  ["ssh://example.test:+22/repo", false, false],
  ["ssh://example.test:\uff12\uff12/repo", false, false],
];

test.each(remoteAuthorityCases)(
  "preserves tracking and SDK remote authority admission for %s",
  async (remote, trackingAccepts, sdkAccepts) => {
    const documents = await fixture();
    documents.manifest.scan.target.remote = remote;
    await saveAndSeal(documents);
    const manifestPath = join(documents.scanDir, "scan-manifest.json");
    const before = await readFile(manifestPath);
    const message = "expected a sanitized canonical absolute URL";
    if (trackingAccepts) {
      expect(await validateTrackingSource(documents.scanDir)).toEqual(
        documents.findings.findings,
      );
    } else {
      await expect(validateTrackingSource(documents.scanDir)).rejects.toThrow(
        message,
      );
    }
    if (sdkAccepts) {
      expect(
        (await loadContract(documents.scanDir, { pluginRoot: PLUGIN_ROOT }))
          .manifest,
      ).toEqual(documents.manifest);
    } else {
      await expect(
        loadContract(documents.scanDir, { pluginRoot: PLUGIN_ROOT }),
      ).rejects.toThrow(message);
    }
    expect(await readFile(manifestPath)).toEqual(before);
  },
);

test.each([
  ["?query", false],
  ["#fragment", false],
  ["?query#fragment", false],
  ["#?", false],
  ["?", true],
  ["#", true],
  ["?#", true],
] as const)(
  "preserves remote delimiter semantics with custom schemas: %s",
  async (suffix, accepts) => {
    const documents = await fixture();
    documents.manifest.scan.target.remote = `ssh://example.test/repo${suffix}`;
    await saveAndSeal(documents);
    const pluginRoot = await fixtures.temporaryDirectory();
    await cp(join(PLUGIN_ROOT, "schemas"), join(pluginRoot, "schemas"), {
      recursive: true,
    });
    const schemaPath = join(pluginRoot, "schemas", "scan-manifest.schema.json");
    const schema = JSON.parse(await readFile(schemaPath, "utf8"));
    delete schema.properties.scan.properties.target.properties.remote.pattern;
    await writeJson(schemaPath, schema);
    if (accepts) {
      expect(
        await validateTrackingSource(documents.scanDir, { pluginRoot }),
      ).toEqual(documents.findings.findings);
      expect(
        (await loadContract(documents.scanDir, { pluginRoot })).manifest,
      ).toEqual(documents.manifest);
    } else {
      const message =
        "remote URL must not contain credentials, query, or fragment";
      await expect(
        validateTrackingSource(documents.scanDir, { pluginRoot }),
      ).rejects.toThrow(message);
      await expect(
        loadContract(documents.scanDir, { pluginRoot }),
      ).rejects.toThrow(message);
    }
  },
);

test.each([
  "ssh://[fe80::1%]/repo",
  "ssh://[fe80::1%a%b]/repo",
  "ssh://[fe80::1%a b]/repo",
  "ssh://[fe80::1%a@b]/repo",
  "ssh://[fe80::1%a?b]/repo",
  "ssh://[fe80::1%a/b]/repo",
  "ssh://[fe80::1%a\\b]/repo",
  "ssh://[fe80::1%a\u0085b]/repo",
  "ssh://[not-ip%zone]/repo",
  "file://example.com:65536/repo",
])("retains rejection of invalid remote %s", async (remote) => {
  const documents = await fixture();
  documents.manifest.scan.target.remote = remote;
  await saveAndSeal(documents);
  await expect(
    loadContract(documents.scanDir, { pluginRoot: PLUGIN_ROOT }),
  ).rejects.toThrow();
  await expect(validateTrackingSource(documents.scanDir)).rejects.toThrow();
});

test.each([
  "2026-01-02T03:04:05+23:60",
  "2026-01-02T03:04:05-23:60",
  "2026-01-02T03:04:05+99:99",
  "2026-02-30T03:04:05+00:60",
])("retains rejection of invalid timestamp %s", async (timestamp) => {
  const documents = await fixture();
  documents.manifest.scan.startedAt = timestamp;
  await saveAndSeal(documents);
  await expect(
    loadContract(documents.scanDir, { pluginRoot: PLUGIN_ROOT }),
  ).rejects.toThrow('must match format "date-time"');
  await expect(validateTrackingSource(documents.scanDir)).rejects.toThrow(
    'must match format "date-time"',
  );
});

test.each(["ruleId", "anchor", "instance"] as const)(
  "retains rejection of a final newline in identity slug %s",
  async (field) => {
    const documents = await fixture();
    const finding = documents.findings.findings[0]!;
    if (field === "ruleId") finding.ruleId = "proof\n";
    else finding.identity[field] = "proof\n";
    await saveAndSeal(documents);
    await expect(
      loadContract(documents.scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).rejects.toThrow("must match pattern");
    await expect(validateTrackingSource(documents.scanDir)).rejects.toThrow(
      "must match pattern",
    );
  },
);

test("rejects invalid Unicode retained in canonical evidence", async () => {
  const documents = await fixture();
  documents.findings.findings[0]!.codeEvidence = [
    { ...evidence, code: "\ud800" },
  ];
  await saveAndSeal(documents);
  await expect(
    loadContract(documents.scanDir, { pluginRoot: PLUGIN_ROOT }),
  ).rejects.toThrow("expected well-formed Unicode JSON strings");
  await expect(validateTrackingSource(documents.scanDir)).rejects.toThrow(
    "expected well-formed Unicode JSON strings",
  );
});

test("requires both canonical artifact seals", async () => {
  const documents = await fixture();
  for (const required of ["findings.json", "coverage.json"]) {
    const manifest = structuredClone(documents.manifest);
    manifest.scan.artifacts = manifest.scan.artifacts.filter(
      ({ path }) => path !== required,
    );
    await writeJson(join(documents.scanDir, "scan-manifest.json"), manifest);
    await expect(
      loadContract(documents.scanDir, { pluginRoot: PLUGIN_ROOT }),
    ).rejects.toThrow("scan-manifest.json");
  }
});

for (const group of ["locations", "codeEvidence"] as const) {
  for (const field of ["startLine", "endLine"] as const) {
    test.each(["41.0", "41e0"])(
      `rejects tracking ${group}.${field} encoded as %s while preserving SDK reads`,
      async (token) => {
        const documents = await fixture();
        const finding = documents.findings.findings[0]!;
        finding.locations = [
          { path: "src/example.ts", startLine: 41, endLine: 41 },
        ];
        finding.codeEvidence = [{ ...evidence }];
        finding[group]![0]![field] = 123456;
        const raw = JSON.stringify(documents.findings).replace(
          `"${field}":123456`,
          `"${field}":${token}`,
        );
        await saveAndSeal(documents, raw);
        expect(
          (await loadContract(documents.scanDir, { pluginRoot: PLUGIN_ROOT }))
            .findings,
        ).toEqual(JSON.parse(raw));
        await expect(validateTrackingSource(documents.scanDir)).rejects.toThrow(
          "expected an integer JSON number",
        );
      },
    );
  }
}

test("preserves permissive historical details and ordinary decimal values", async () => {
  const documents = await fixture();
  const finding = documents.findings.findings[0]!;
  finding.code_evidence = [
    { id: "legacy", code: "example()" },
    { id: "legacy", code: "duplicate()" },
    { id: " ", code: " " },
  ];
  finding.attackPath = { dataFlow: { evidenceRefs: ["missing"] } };
  finding.extensions = { startLine: 41.5, endLine: 42.0 };
  finding.severity.score = 5;
  finding.severity.scoringSystem = "Synthetic";
  const raw = JSON.stringify(documents.findings).replace(
    '"score":5',
    '"score":5.0',
  );
  await saveAndSeal(documents, raw);
  const loaded = await loadContract(documents.scanDir, {
    pluginRoot: PLUGIN_ROOT,
  });
  expect(loaded.findings.findings[0]!.code_evidence).toEqual(
    finding.code_evidence,
  );
  expect(loaded.findings.findings[0]!.attackPath).toEqual(finding.attackPath);
  expect(
    (await validateTrackingSource(documents.scanDir)).map(
      (finding) => finding.findingId,
    ),
  ).toEqual(documents.findings.findings.map((finding) => finding.findingId));
  expect(await readFile(join(documents.scanDir, "findings.json"), "utf8")).toBe(
    raw,
  );
});
