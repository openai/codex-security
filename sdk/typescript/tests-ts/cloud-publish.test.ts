import { createHash } from "node:crypto";
import {
  chmod,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  publishFindingsCsvToCloud,
  publishScanToCloud,
} from "../src/cloud-publish.js";
import {
  codexSecurityCredentialHome,
  setCodexSecurityCredentialLogout,
} from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const directories: string[] = [];
const login = {
  auth_mode: "chatgpt",
  tokens: {
    access_token: "synthetic-access-token",
    account_id: "synthetic-account",
    refresh_token: "synthetic-refresh-token",
    id_token: "synthetic-id-token",
  },
};
const receipt = {
  status: "accepted",
  finding_ids: ["finding-1"],
  finding_count: 1,
};
const csvHeader = [
  "occurrence_id",
  "finding_id",
  "title",
  "summary",
  "severity",
  "confidence",
  "status",
  "close_reason",
  "note",
  "remediation",
  "path",
  "start_line",
  "end_line",
].join(",");
const csvRow = [
  "occ_e79cb19591e696572a1c22be",
  "csf_852f90d6e1177502ff113d4a",
  '"Unsafe archive extraction, including nested entries"',
  "An attacker-controlled path reaches a filesystem write.",
  "high",
  "high",
  "open",
  "",
  "",
  "Normalize and validate destinations.",
  "src/extract.py",
  "41",
  "44",
].join(",");

async function csvFixture(contents = `${csvHeader}\n${csvRow}\n`) {
  const root = await mkdtemp(join(tmpdir(), "codex-security-cloud-csv-"));
  directories.push(root);
  const path = join(root, "findings.csv");
  await writeFile(path, contents);
  return path;
}

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "codex-security-cloud-"));
  directories.push(root);
  const scan = join(root, "scan");
  const home = join(root, "home");
  await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), scan, {
    recursive: true,
  });
  if (process.platform !== "win32") await chmod(scan, 0o700);
  await mkdir(home, { mode: 0o700 });
  await writeFile(join(home, "auth.json"), JSON.stringify(login), {
    mode: 0o600,
  });
  await writeFile(
    join(home, "config.toml"),
    'cli_auth_credentials_store = "file"\n',
  );
  return {
    scan,
    home,
    environment: {
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    },
  };
}

async function addSecondFinding(scan: string): Promise<void> {
  const findingsPath = join(scan, "findings.json");
  const manifestPath = join(scan, "scan-manifest.json");
  const findings = JSON.parse(await readFile(findingsPath, "utf8")) as {
    findings: Array<{
      findingId: string;
      occurrenceId: string;
      ruleId: string;
      identity: { anchor: string; instance?: string };
      fingerprints: { primary: string };
      title: string;
    }>;
  };
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
    scan: {
      id: string;
      target: { targetId: string };
      artifacts: Array<{ path: string; sha256: string }>;
    };
  };
  const second = structuredClone(findings.findings[0]!);
  second.identity.instance = "second-instance";
  second.title = "A second synthetic finding";
  const sha256 = (value: string): string =>
    createHash("sha256").update(value).digest("hex");
  const fingerprint = `codex-security/v1:sha256:${sha256(
    [
      "codex-security/v1",
      manifest.scan.target.targetId,
      second.ruleId,
      second.identity.anchor,
      second.identity.instance,
    ].join("\0"),
  )}`;
  second.findingId = `csf_${sha256(fingerprint).slice(0, 24)}`;
  second.occurrenceId = `occ_${sha256(
    [manifest.scan.id, fingerprint].join("\0"),
  ).slice(0, 24)}`;
  second.fingerprints.primary = fingerprint;
  findings.findings.push(second);
  await writeFile(findingsPath, `${JSON.stringify(findings, null, 2)}\n`);
  const artifact = manifest.scan.artifacts.find(
    ({ path }) => path === "findings.json",
  )!;
  artifact.sha256 = createHash("sha256")
    .update(await readFile(findingsPath))
    .digest("hex");
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}

describe("Cloud publication", () => {
  test("previews a validated findings export CSV without credentials or network access", async () => {
    const path = await csvFixture();
    let requests = 0;
    const result = await publishFindingsCsvToCloud(path, {
      dryRun: true,
      fetch: async () => {
        requests++;
        throw new Error("unexpected request");
      },
    });
    expect(result).toMatchObject({
      scanId: expect.stringMatching(/^scan_csv_[a-f0-9]{24}$/),
      findingIds: [],
      findingCount: 1,
      dryRun: true,
      findings: [
        {
          findingId: expect.stringMatching(/^csf_[a-f0-9]{24}$/),
          occurrenceId: expect.stringMatching(/^occ_[a-f0-9]{24}$/),
          title: "Unsafe archive extraction, including nested entries",
          severity: { level: "high" },
          confidence: { level: "high" },
          locations: [{ path: "src/extract.py", startLine: 41, endLine: 44 }],
          validation: {
            method: "Source-reported CSV import metadata",
            status: "open",
            summary:
              "Source finding ID: csf_852f90d6e1177502ff113d4a\nSource occurrence ID: occ_e79cb19591e696572a1c22be\nSource status: open",
          },
          provenance: { source: "csv_import" },
        },
      ],
    });
    expect(requests).toBe(0);
  });

  test("posts CSV findings with generated scan provenance", async () => {
    const path = await csvFixture();
    const { environment } = await fixture();
    let payload: Record<string, unknown> | undefined;
    const result = await publishFindingsCsvToCloud(path, {
      environment,
      fetch: async (_url, options) => {
        payload = JSON.parse(String(options.body));
        return Response.json(receipt, { status: 201 });
      },
    });
    expect(result).toEqual({
      scanId: result.scanId,
      findingIds: ["finding-1"],
      findingCount: 1,
    });
    expect(result.scanId).toMatch(/^scan_csv_[a-f0-9]{24}$/);
    expect(payload).toMatchObject({
      schemaVersion: "1.0",
      scan: {
        id: result.scanId,
        producer: { name: "codex-security-cli" },
        status: "completed",
        startedAt: "1970-01-01T00:00:00.000Z",
        target: {
          kind: "directory_snapshot",
          displayName: "findings.csv",
        },
      },
      findings: [
        {
          remediation: "Normalize and validate destinations.",
          provenance: { source: "csv_import" },
        },
      ],
    });
    const [finding] = payload!["findings"] as Array<{
      findingId: string;
      occurrenceId: string;
    }>;
    expect(finding!.findingId).toMatch(/^csf_[a-f0-9]{24}$/);
    expect(finding!.occurrenceId).toMatch(/^occ_[a-f0-9]{24}$/);
  });

  test("accepts the candidate_id column from a Deep scan export", async () => {
    const path = await csvFixture(
      `${csvHeader.replace("finding_id,", "finding_id,candidate_id,")}\n${csvRow.replace("csf_852f90d6e1177502ff113d4a,", "csf_852f90d6e1177502ff113d4a,candidate-001,")}\n`,
    );
    const result = await publishFindingsCsvToCloud(path, { dryRun: true });
    expect(result.findings?.[0]?.extensions).toEqual({
      candidateId: "candidate-001",
    });
  });

  test("preserves source IDs and triage fields in finding validation", async () => {
    const path = await csvFixture(
      `${csvHeader}\n${csvRow.replace(",open,,,", ',closed,wont_fix,"Accepted risk.",')}\n`,
    );
    const result = await publishFindingsCsvToCloud(path, { dryRun: true });
    expect(result.findings?.[0]?.validation).toEqual({
      method: "Source-reported CSV import metadata",
      status: "closed",
      summary:
        "Source finding ID: csf_852f90d6e1177502ff113d4a\nSource occurrence ID: occ_e79cb19591e696572a1c22be\nSource status: closed\nSource close reason: wont_fix\nSource note: Accepted risk.",
    });
    expect(result.findings?.[0]?.provenance).toEqual({
      source: "csv_import",
    });
  });

  test("decodes exported CSV cells without stripping literal apostrophes", async () => {
    const path = await csvFixture(
      `${csvHeader}\n${csvRow
        .replace(
          '"Unsafe archive extraction, including nested entries"',
          '"\'\tTabbed title"',
        )
        .replace(
          "An attacker-controlled path reaches a filesystem write.",
          "'Literal apostrophe.",
        )
        .replace(
          "Normalize and validate destinations.",
          "'  @owner should remediate.",
        )
        .replace("src/extract.py", "'-generated/extract.py")}\n`,
    );
    const result = await publishFindingsCsvToCloud(path, { dryRun: true });
    expect(result.findings?.[0]).toMatchObject({
      title: "\tTabbed title",
      summary: "'Literal apostrophe.",
      remediation: "  @owner should remediate.",
      locations: [{ path: "-generated/extract.py" }],
    });
  });

  test.each([
    ["missing required header", csvHeader.replace("summary,", "")],
    ["unknown header", `${csvHeader},unknown`],
    ["no findings", csvHeader],
    ["wrong column count", `${csvHeader}\n${csvRow},extra`],
    [
      "invalid finding ID",
      `${csvHeader}\n${csvRow.replace("csf_852f90d6e1177502ff113d4a", "finding-1")}`,
    ],
    [
      "empty title",
      `${csvHeader}\n${csvRow.replace('"Unsafe archive extraction, including nested entries"', '""')}`,
    ],
    [
      "invalid severity",
      `${csvHeader}\n${csvRow.replace(",high,high,", ",urgent,high,")}`,
    ],
    [
      "invalid close reason",
      `${csvHeader}\n${csvRow.replace(",open,,,", ",closed,deferred,,")}`,
    ],
    [
      "missing required close note",
      `${csvHeader}\n${csvRow.replace(",open,,,", ",closed,false_positive,,")}`,
    ],
    [
      "unsafe path",
      `${csvHeader}\n${csvRow.replace("src/extract.py", "../escape.py")}`,
    ],
    [
      "invalid line range",
      `${csvHeader}\n${csvRow.replace(",41,44", ",45,44")}`,
    ],
    ["duplicate finding", `${csvHeader}\n${csvRow}\n${csvRow}`],
  ])("rejects a CSV with %s before authentication", async (_name, source) => {
    const path = await csvFixture(`${source}\n`);
    let requests = 0;
    await expect(
      publishFindingsCsvToCloud(path, {
        environment: {},
        fetch: async () => {
          requests++;
          throw new Error("unexpected request");
        },
      }),
    ).rejects.toThrow(/Findings CSV/);
    expect(requests).toBe(0);
  });

  test.each([false, true])(
    "rejects artifacts from another scan before upload or preview (dryRun=%s)",
    async (dryRun) => {
      const { scan, environment } = await fixture();
      let requests = 0;
      await expect(
        publishScanToCloud(scan, {
          environment,
          dryRun,
          expectedScanId: "another-scan",
          fetch: async () => {
            requests++;
            throw new Error("unexpected request");
          },
        }),
      ).rejects.toThrow(
        "Scan artifacts do not match selected scan another-scan.",
      );
      expect(requests).toBe(0);
    },
  );

  test("previews validated findings without credentials or network access", async () => {
    const { scan, home, environment } = await fixture();
    await rm(join(home, "auth.json"));
    const manifest = JSON.parse(
      await readFile(join(scan, "scan-manifest.json"), "utf8"),
    );
    const findings = JSON.parse(
      await readFile(join(scan, "findings.json"), "utf8"),
    );
    let requests = 0;
    expect(
      await publishScanToCloud(scan, {
        environment,
        dryRun: true,
        expectedScanId: manifest.scan.id,
        fetch: async () => {
          requests++;
          throw new Error("unexpected request");
        },
      }),
    ).toEqual({
      scanId: manifest.scan.id,
      findingIds: [],
      findingCount: findings.findings.length,
      dryRun: true,
      findings: findings.findings,
    });
    expect(requests).toBe(0);
    await writeFile(join(scan, "findings.json"), "{}");
    await expect(
      publishScanToCloud(scan, { environment, dryRun: true }),
    ).rejects.toThrow();
  });

  test("posts validated findings and scan provenance with only ChatGPT access credentials", async () => {
    const { scan, environment } = await fixture();
    const manifest = JSON.parse(
      await readFile(join(scan, "scan-manifest.json"), "utf8"),
    );
    const findings = JSON.parse(
      await readFile(join(scan, "findings.json"), "utf8"),
    );
    let requests = 0;
    const result = await publishScanToCloud(scan, {
      environment: { ...environment, OPENAI_API_KEY: "synthetic-api-key" },
      fetch: async (url, options) => {
        requests++;
        expect(new URL(String(url)).origin).toBe("https://chatgpt.com");
        expect(options).toMatchObject({
          method: "POST",
          redirect: "error",
          headers: {
            Authorization: "Bearer synthetic-access-token",
            "ChatGPT-Account-ID": "synthetic-account",
            "Content-Type": "application/json",
            Accept: "application/json",
          },
        });
        expect(JSON.parse(String(options!.body))).toEqual({
          schemaVersion: "1.0",
          scan: manifest.scan,
          findings: findings.findings,
        });
        expect(JSON.stringify(options)).not.toContain(
          "synthetic-refresh-token",
        );
        expect(JSON.stringify(options)).not.toContain("synthetic-id-token");
        expect(options!.signal).toBeInstanceOf(AbortSignal);
        return Response.json(receipt, { status: 201 });
      },
    });
    expect(result).toEqual({
      scanId: manifest.scan.id,
      findingIds: ["finding-1"],
      findingCount: 1,
    });
    expect(requests).toBe(1);
  });

  test("accepts opaque Cloud finding IDs that differ from local finding IDs", async () => {
    const { scan, environment } = await fixture();
    const localFindings = JSON.parse(
      await readFile(join(scan, "findings.json"), "utf8"),
    ) as { findings: Array<{ findingId: string }> };
    const opaqueId = "cloud-observation-synthetic";
    expect(
      localFindings.findings.map(({ findingId }) => findingId),
    ).not.toContain(opaqueId);
    expect(
      await publishScanToCloud(scan, {
        environment,
        fetch: async () =>
          Response.json({
            status: "accepted",
            finding_ids: [opaqueId],
            finding_count: 1,
          }),
      }),
    ).toEqual({
      scanId: "scan_example_001",
      findingIds: [opaqueId],
      findingCount: 1,
    });
  });

  test("honors a Cloud publication URL override", async () => {
    const { scan, environment } = await fixture();
    const publishUrl =
      "https://chatgpt-staging.com/backend-api/aardvark/cli/findings";
    let requestedUrl: string | undefined;
    await publishScanToCloud(scan, {
      environment: {
        ...environment,
        CODEX_SECURITY_CLOUD_PUBLISH_URL: publishUrl,
      },
      fetch: async (url) => {
        requestedUrl = String(url);
        return Response.json(receipt);
      },
    });
    expect(requestedUrl).toBe(publishUrl);
  });

  test("reuses the dedicated Codex Security login and honors an explicit logout", async () => {
    const { scan, environment } = await fixture();
    const home = codexSecurityCredentialHome(environment);
    await mkdir(home, { recursive: true, mode: 0o700 });
    await writeFile(
      join(home, "auth.json"),
      JSON.stringify({
        ...login,
        tokens: { ...login.tokens, account_id: "dedicated-account" },
      }),
      { mode: 0o600 },
    );
    await writeFile(
      join(home, "config.toml"),
      'cli_auth_credentials_store = "auto"\n',
    );
    let requests = 0;
    const send = async (_url: string, options: RequestInit) => {
      requests++;
      expect(new Headers(options!.headers).get("ChatGPT-Account-ID")).toBe(
        "dedicated-account",
      );
      return Response.json(receipt);
    };
    await publishScanToCloud(scan, { environment, fetch: send });
    await setCodexSecurityCredentialLogout(home, true);
    await expect(
      publishScanToCloud(scan, { environment, fetch: send }),
    ).rejects.toThrow("ChatGPT login already available to Codex Security");
    expect(requests).toBe(1);
  });

  test("resolves missing or empty CODEX_HOME through the existing user-home helper", async () => {
    const { scan, home, environment } = await fixture();
    await mkdir(join(home, ".codex"), { mode: 0o700 });
    await writeFile(join(home, ".codex", "auth.json"), JSON.stringify(login), {
      mode: 0o600,
    });
    await writeFile(
      join(home, ".codex", "config.toml"),
      'cli_auth_credentials_store = "file"\n',
    );
    for (const codexHome of [undefined, "", "  "]) {
      const result = await publishScanToCloud(scan, {
        environment: {
          ...environment,
          CODEX_HOME: codexHome,
          HOME: home,
          USERPROFILE: home,
        },
        fetch: async () => Response.json(receipt),
      });
      expect(result.findingIds).toEqual(["finding-1"]);
    }
  });

  test("requires an explicit file credential setting before reading auth.json", async () => {
    const { scan, home, environment } = await fixture();
    let requests = 0;
    const send = async () => {
      requests++;
      return Response.json(receipt);
    };
    for (const config of [undefined, "[features]\nplugins = true\n"]) {
      if (config === undefined) {
        await rm(join(home, "config.toml"));
      } else {
        await writeFile(join(home, "config.toml"), config);
      }
      await expect(
        publishScanToCloud(scan, { environment, fetch: send }),
      ).rejects.toThrow("ChatGPT login already available to Codex Security");
    }
    expect(requests).toBe(0);
  });

  test("rejects unsupported, missing, or malformed credentials without leaking their contents", async () => {
    const { scan, home, environment } = await fixture();
    let requests = 0;
    const send = async () => {
      requests++;
      return Response.json(receipt);
    };
    for (const credentials of [
      { auth_mode: "apikey", OPENAI_API_KEY: "synthetic-api-secret" },
      { ...login, auth_mode: "personal_access_token" },
      { ...login, tokens: { access_token: "synthetic-access-token" } },
      {},
    ]) {
      await writeFile(join(home, "auth.json"), JSON.stringify(credentials), {
        mode: 0o600,
      });
      await expect(
        publishScanToCloud(scan, { environment, fetch: send }),
      ).rejects.toThrow("ChatGPT login already available to Codex Security");
    }
    await writeFile(join(home, "auth.json"), "malformed-synthetic-secret");
    await expect(
      publishScanToCloud(scan, { environment, fetch: send }),
    ).rejects.toThrow("ChatGPT login already available to Codex Security");
    await rm(join(home, "auth.json"));
    await expect(
      publishScanToCloud(scan, { environment, fetch: send }),
    ).rejects.toThrow("ChatGPT login already available to Codex Security");
    expect(requests).toBe(0);
  });

  test("does not use a stale file when keyring or automatic credential storage is selected", async () => {
    const { scan, home, environment } = await fixture();
    let requests = 0;
    for (const mode of ["keyring", "auto"]) {
      await writeFile(
        join(home, "config.toml"),
        `cli_auth_credentials_store = "${mode}"\n`,
      );
      const error = await publishScanToCloud(scan, {
        environment,
        fetch: async () => {
          requests++;
          return Response.json(receipt);
        },
      }).then(
        () => undefined,
        (failure: unknown) => failure,
      );
      expect(String(error)).toContain(
        "ChatGPT login already available to Codex Security",
      );
    }
    expect(requests).toBe(0);

    await writeFile(
      join(home, "config.toml"),
      'cli_auth_credentials_store = "file"\n',
    );
    await publishScanToCloud(scan, {
      environment,
      fetch: async () => {
        requests++;
        return Response.json(receipt);
      },
    });
    expect(requests).toBe(1);
  });

  test("rejects tampered scan artifacts before reading credentials or uploading", async () => {
    const { scan, environment } = await fixture();
    await writeFile(join(scan, "findings.json"), "{}");
    let requests = 0;
    await expect(
      publishScanToCloud(scan, {
        environment,
        fetch: async () => {
          requests++;
          return Response.json(receipt);
        },
      }),
    ).rejects.toThrow();
    expect(requests).toBe(0);
  });

  test("does not retry HTTP errors or expose server response bodies", async () => {
    const { scan, environment } = await fixture();
    for (const status of [401, 403, 404, 413, 422, 429, 503]) {
      let requests = 0;
      try {
        await publishScanToCloud(scan, {
          environment,
          fetch: async () => {
            requests++;
            return new Response("synthetic-access-token", { status });
          },
        });
        throw new Error("expected publication to fail");
      } catch (error) {
        expect(String(error)).toContain(`HTTP ${status}`);
        expect(String(error)).not.toContain("synthetic-access-token");
      }
      expect(requests).toBe(1);
    }
  });

  test("does not retry an ambiguous transport failure", async () => {
    const { scan, environment } = await fixture();
    let requests = 0;
    await expect(
      publishScanToCloud(scan, {
        environment,
        fetch: async () => {
          requests++;
          throw new Error("synthetic-access-token");
        },
      }),
    ).rejects.toThrow("Cloud publication was not confirmed");
    expect(requests).toBe(1);
  });

  test("requires a complete acceptance receipt instead of treating any 2xx as success", async () => {
    const { scan, environment } = await fixture();
    for (const body of [
      {},
      { ...receipt, status: "queued" },
      { ...receipt, finding_count: 2 },
      { ...receipt, finding_ids: [] },
    ]) {
      await expect(
        publishScanToCloud(scan, {
          environment,
          fetch: async () => Response.json(body),
        }),
      ).rejects.toThrow("invalid acceptance receipt");
    }
    await expect(
      publishScanToCloud(scan, {
        environment,
        fetch: async () => Response.json(receipt, { status: 202 }),
      }),
    ).rejects.toThrow("invalid acceptance receipt");
  });

  test("rejects duplicate opaque IDs in an otherwise complete receipt", async () => {
    const { scan, environment } = await fixture();
    await addSecondFinding(scan);
    await expect(
      publishScanToCloud(scan, {
        environment,
        fetch: async () =>
          Response.json({
            status: "accepted",
            finding_ids: [
              "cloud-observation-duplicate",
              "cloud-observation-duplicate",
            ],
            finding_count: 2,
          }),
      }),
    ).rejects.toThrow("invalid acceptance receipt");
  });
});
