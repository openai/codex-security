import {
  codexSecurityCredentialHome,
  setCodexSecurityCredentialLogout,
} from "../src/runtime.js";
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
import { join } from "node:path";
import { afterEach, describe, expect, spyOn, test } from "bun:test";
import {
  publishFindingsCsvToCloud,
  publishScanToCloud,
  selectCloudDestination,
} from "../src/cloud-publish.js";
import type {
  CreateImportedScan,
  ImportedScanReceipt,
  ImportDestination,
} from "../src/cloud-import-models.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const directories: string[] = [];
const destination: ImportDestination = {
  environment_id: "env-1",
  environment_name: "Example",
  repository_id: "repo-1",
  repository_full_name: "example/repo",
  repository_remote: "https://github.com/example/repo.git",
  connector_id: "connector-1",
};
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
  const scan = join(root, "scan"),
    home = join(root, "home");
  await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), scan, {
    recursive: true,
  });
  if (process.platform !== "win32") await chmod(scan, 0o700);
  await mkdir(home, { mode: 0o700 });
  await writeFile(
    join(home, "auth.json"),
    JSON.stringify({
      auth_mode: "chatgpt",
      tokens: {
        access_token: "synthetic-access-token",
        account_id: "synthetic-account",
      },
    }),
    { mode: 0o600 },
  );
  await writeFile(
    join(home, "config.toml"),
    'cli_auth_credentials_store = "file"\n',
  );
  const manifest = JSON.parse(
    await readFile(join(scan, "scan-manifest.json"), "utf8"),
  );
  manifest.scan.target.repositoryPath = ".";
  manifest.scan.target.revision = "a".repeat(40);
  await writeFile(join(scan, "scan-manifest.json"), JSON.stringify(manifest));
  return {
    scan,
    home,
    environment: {
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    },
  };
}
function server(
  options: {
    destinations?: ImportDestination[];
    accepted?: boolean;
    finalizing?: boolean;
    retentionFailed?: boolean;
    finalizeStatus?: "accepted" | "finalizing";
    failed?: boolean;
    rejectPutOnce?: boolean;
  } = {},
) {
  const calls: { url: string; method: string; body?: BodyInit | null }[] = [];
  let publication: ImportedScanReceipt | undefined;
  let create: CreateImportedScan | undefined;
  let rejected = false;
  const fetch = async (url: string, request: RequestInit) => {
    calls.push({ url, method: request.method!, body: request.body });
    expect((request.headers as Record<string, string>)["Authorization"]).toBe(
      "Bearer synthetic-access-token",
    );
    expect(request.redirect).toBe("error");
    if (url.includes("/destinations"))
      return Response.json({
        protocol_version: 1,
        destinations: options.destinations ?? [destination],
      });
    if (url.endsWith("/v1")) {
      create = JSON.parse(String(request.body));
      publication ??= {
        protocol_version: 1,
        imported_scan_id: "import-1",
        source: "cli",
        source_scan_id: create!.source_scan_id,
        environment_id: destination.environment_id,
        repository_id: destination.repository_id,
        repository_full_name: destination.repository_full_name,
        repository_remote: create!.repository_remote,
        connector_id: create!.connector_id,
        target_kind: create!.target_kind,
        base_commit: create!.base_commit,
        snapshot_digest: create!.snapshot_digest ?? null,
        upload_status:
          options.finalizing || options.retentionFailed
            ? "finalizing"
            : options.accepted
              ? "accepted"
              : "uploading",
        materialization_status:
          options.failed || options.retentionFailed ? "failed" : "pending",
        dedupe_status: "pending",
        artifacts: create!.artifacts.map((item) => ({
          ...item,
          uploaded: Boolean(
            options.accepted || options.finalizing || options.retentionFailed,
          ),
          download_url: null,
        })),
        created_at: "2026-06-01T00:00:00Z",
        scan_started_at: create!.scan_started_at,
        scan_completed_at: create!.scan_completed_at,
        finalized_at: null,
        finalization_started_at: null,
        materialization_completed_at: null,
        finding_count: null,
        failure_code: options.retentionFailed
          ? "artifact_retention_failed"
          : null,
        status_url: "/api/aardvark/imported-scans/v1/import-1",
      };
    } else if (request.method === "PUT") {
      if (options.rejectPutOnce && !rejected && url.endsWith("findings.json")) {
        rejected = true;
        throw new Error("connection lost");
      }
      const name = url.split("/").at(-1);
      const artifact = publication!.artifacts.find(
        (item) => item.name === name,
      )!;
      const contents = request.body as Uint8Array;
      expect(createHash("sha256").update(contents).digest("hex")).toBe(
        artifact.sha256,
      );
      expect(contents.byteLength).toBe(artifact.size_bytes);
      artifact.uploaded = true;
    } else if (url.endsWith("/finalize"))
      publication!.upload_status = options.finalizeStatus ?? "accepted";
    else if (url.endsWith("/retry"))
      publication!.materialization_status = "pending";
    return Response.json(publication);
  };
  return {
    fetch,
    calls,
    get create() {
      return create;
    },
  };
}

describe("native Cloud publication", () => {
  test("uploads complete artifact bytes with saved SCM identity and returns asynchronous stages", async () => {
    const { scan, environment } = await fixture();
    const cloud = server();
    const result = await publishScanToCloud(scan, {
      environment,
      fetch: cloud.fetch,
    });
    expect(cloud.create).toMatchObject({
      protocol_version: 1,
      repository_remote: "https://github.com/example/repo",
      base_commit: "a".repeat(40),
      snapshot_digest: expect.stringMatching(/^[a-f0-9]{64}$/),
      coverage_mode: "full_repository",
    });
    expect(result.publication).toMatchObject({
      upload_status: "accepted",
      materialization_status: "pending",
      dedupe_status: "pending",
    });
    expect(result.findingIds).toEqual([]);
    expect(cloud.calls.filter((item) => item.method === "PUT")).toHaveLength(4);
    const reportBytes = await readFile(join(scan, "report.md"));
    expect(cloud.create?.artifacts).toContainEqual({
      name: "report.md",
      size_bytes: reportBytes.byteLength,
      sha256: createHash("sha256").update(reportBytes).digest("hex"),
    });
    expect(
      Buffer.from(
        cloud.calls.find(
          (item) => item.method === "PUT" && item.url.endsWith("report.md"),
        )!.body as Uint8Array,
      ),
    ).toEqual(reportBytes);
    expect(
      cloud.calls.every((item) => !item.url.includes("cli/findings")),
    ).toBe(true);
  });
  test("publishes a BOM-prefixed validated manifest without changing its bytes", async () => {
    const { scan, environment } = await fixture();
    const path = join(scan, "scan-manifest.json");
    const bytes = Buffer.concat([
      Buffer.from([0xef, 0xbb, 0xbf]),
      await readFile(path),
    ]);
    await writeFile(path, bytes);
    const cloud = server();
    await publishScanToCloud(scan, { environment, fetch: cloud.fetch });
    expect(
      Buffer.from(
        cloud.calls.find(
          (item) =>
            item.method === "PUT" && item.url.endsWith("scan-manifest.json"),
        )!.body as Uint8Array,
      ),
    ).toEqual(bytes);
  });
  test("publishes supported external scans without an optional report", async () => {
    const { scan, environment } = await fixture();
    await rm(join(scan, "report.md"));
    const cloud = server();
    await publishScanToCloud(scan, { environment, fetch: cloud.fetch });
    expect(cloud.calls.filter((item) => item.method === "PUT")).toHaveLength(3);
  });
  test.skipIf(process.platform === "win32")(
    "rejects a report symlink before creating an upload",
    async () => {
      const { scan, environment } = await fixture();
      await rm(join(scan, "report.md"));
      await symlink(join(scan, "findings.json"), join(scan, "report.md"));
      const cloud = server();
      await expect(
        publishScanToCloud(scan, { environment, fetch: cloud.fetch }),
      ).rejects.toThrow();
      expect(cloud.calls).toHaveLength(0);
    },
  );
  test("resumes interrupted upload, skips verified objects and returns the same publication", async () => {
    const { scan, environment } = await fixture();
    const cloud = server({ rejectPutOnce: true });
    await expect(
      publishScanToCloud(scan, { environment, fetch: cloud.fetch }),
    ).rejects.toThrow("resume");
    const result = await publishScanToCloud(scan, {
      environment,
      fetch: cloud.fetch,
    });
    expect(result.publication?.imported_scan_id).toBe("import-1");
    expect(
      cloud.calls.filter(
        (item) =>
          item.method === "PUT" && item.url.endsWith("scan-manifest.json"),
      ),
    ).toHaveLength(1);
  });
  test("republication of accepted content does not reupload or reset processing", async () => {
    const { scan, environment } = await fixture();
    const cloud = server({ accepted: true });
    await publishScanToCloud(scan, { environment, fetch: cloud.fetch });
    expect(cloud.calls.map((item) => item.method)).toEqual(["GET", "POST"]);
  });
  test("reports asynchronous finalization without claiming acceptance", async () => {
    const { scan, environment } = await fixture();
    const cloud = server({ finalizeStatus: "finalizing" });
    const result = await publishScanToCloud(scan, {
      environment,
      fetch: cloud.fetch,
    });
    expect(result.publication?.upload_status).toBe("finalizing");
    expect(result.publication?.finalized_at).toBeNull();
  });
  test("replays finalizing publication without reupload while retention is progressing", async () => {
    const { scan, environment } = await fixture();
    const cloud = server({ finalizing: true });
    const result = await publishScanToCloud(scan, {
      environment,
      fetch: cloud.fetch,
    });
    expect(result.publication?.upload_status).toBe("finalizing");
    expect(cloud.calls.map((item) => item.method)).toEqual(["GET", "POST"]);
  });
  test("repairs failed preacceptance retention with the same declared artifact bytes", async () => {
    const { scan, environment } = await fixture();
    const cloud = server({
      retentionFailed: true,
      finalizeStatus: "finalizing",
    });
    const result = await publishScanToCloud(scan, {
      environment,
      fetch: cloud.fetch,
    });
    expect(result.publication?.imported_scan_id).toBe("import-1");
    expect(result.publication?.upload_status).toBe("finalizing");
    expect(cloud.calls.filter((item) => item.method === "PUT")).toHaveLength(4);
    expect(cloud.calls.at(-1)?.url).toEndWith("/finalize");
  });
  test("failed parsing retries from retained artifacts", async () => {
    const { scan, environment } = await fixture();
    const cloud = server({ accepted: true, failed: true });
    await publishScanToCloud(scan, { environment, fetch: cloud.fetch });
    expect(cloud.calls.at(-1)?.url).toEndWith("/retry");
    expect(cloud.calls.some((item) => item.method === "PUT")).toBe(false);
  });
  test("retains large evidence in the full findings artifact", async () => {
    const { scan, environment } = await fixture();
    const cloud = server();
    const path = join(scan, "findings.json"),
      document = JSON.parse(await readFile(path, "utf8"));
    document.findings[0].summary = "Large artifact-backed evidence. ".repeat(
      12000,
    );
    await writeFile(path, JSON.stringify(document));
    const manifestPath = join(scan, "scan-manifest.json"),
      manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.scan.artifacts.find(
      (item: { path: string }) => item.path === "findings.json",
    ).sha256 = createHash("sha256")
      .update(await readFile(path))
      .digest("hex");
    await writeFile(manifestPath, JSON.stringify(manifest));
    await publishScanToCloud(scan, { environment, fetch: cloud.fetch });
    const uploaded = cloud.calls.find(
      (item) => item.method === "PUT" && item.url.endsWith("findings.json"),
    )!;
    expect(
      Buffer.from(uploaded.body as Uint8Array).equals(await readFile(path)),
    ).toBe(true);
    expect((uploaded.body as Uint8Array).byteLength).toBeGreaterThan(
      256 * 1024,
    );
  });
  test("rejects old synchronous proxy success instead of treating it as native acceptance", async () => {
    const { scan, environment } = await fixture();
    await expect(
      publishScanToCloud(scan, {
        environment,
        fetch: async (url) =>
          url.includes("destinations")
            ? Response.json({
                protocol_version: 1,
                destinations: [destination],
              })
            : Response.json({
                status: "accepted",
                finding_ids: ["legacy"],
                finding_count: 1,
              }),
      }),
    ).rejects.toThrow("incompatible scan import receipt");
  });
  test("zero findings is a valid publication", async () => {
    const { scan, environment } = await fixture();
    const cloud = server();
    const path = join(scan, "findings.json");
    const document = JSON.parse(await readFile(path, "utf8"));
    document.findings = [];
    await writeFile(path, JSON.stringify(document));
    const manifestPath = join(scan, "scan-manifest.json"),
      manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.scan.artifacts.find(
      (item: { path: string }) => item.path === "findings.json",
    ).sha256 = createHash("sha256")
      .update(await readFile(path))
      .digest("hex");
    await writeFile(manifestPath, JSON.stringify(manifest));
    expect(
      (await publishScanToCloud(scan, { environment, fetch: cloud.fetch }))
        .findingCount,
    ).toBe(0);
  });
  test("no matching environment fails before creating an upload", async () => {
    const { scan, environment } = await fixture();
    const cloud = server({ destinations: [] });
    await expect(
      publishScanToCloud(scan, { environment, fetch: cloud.fetch }),
    ).rejects.toThrow("No existing authorized");
    expect(cloud.calls).toHaveLength(1);
  });
  test("no legacy fallback on unsupported server", async () => {
    const { scan, environment } = await fixture();
    let calls = 0;
    await expect(
      publishScanToCloud(scan, {
        environment,
        fetch: async () => {
          calls++;
          return new Response("", { status: 404 });
        },
      }),
    ).rejects.toThrow("no legacy publication");
    expect(calls).toBe(1);
  });
  test("rejects CSV even for dry-run", async () => {
    await expect(
      publishFindingsCsvToCloud("findings.csv", { dryRun: true }),
    ).rejects.toThrow("CSV imports are unsupported");
  });
  test("dry-run requires eligible provenance but neither credentials nor network", async () => {
    const { scan } = await fixture();
    const result = await publishScanToCloud(scan, {
      dryRun: true,
      environment: {},
      fetch: async () => {
        throw new Error("unexpected network");
      },
    });
    expect(result.dryRun).toBe(true);
  });
  test.each([true, false])(
    "rejects an oversized artifact before network (dry-run: %s)",
    async (dryRun) => {
      const { scan } = await fixture();
      await truncate(join(scan, "report.md"), 64 * 1024 * 1024 + 1);
      await expect(
        publishScanToCloud(scan, {
          dryRun,
          environment: {},
          fetch: async () => {
            throw new Error("unexpected network");
          },
        }),
      ).rejects.toThrow("does not satisfy the Cloud import contract");
    },
  );
  test.each([true, false])(
    "rejects an unsupported commit format before network (dry-run: %s)",
    async (dryRun) => {
      const { scan } = await fixture();
      const path = join(scan, "scan-manifest.json");
      const manifest = JSON.parse(await readFile(path, "utf8"));
      manifest.scan.target.revision = "a".repeat(64);
      await writeFile(path, JSON.stringify(manifest));
      await expect(
        publishScanToCloud(scan, {
          dryRun,
          environment: {},
          fetch: async () => {
            throw new Error("unexpected network");
          },
        }),
      ).rejects.toThrow("does not satisfy the Cloud import contract");
    },
  );
  test.each(["auto", "keyring"])(
    "rejects stale file credentials when %s storage is active",
    async (storage) => {
      const { scan, home, environment } = await fixture();
      await writeFile(
        join(home, "config.toml"),
        `cli_auth_credentials_store = "${storage}"\n`,
      );
      await expect(
        publishScanToCloud(scan, {
          environment,
          fetch: async () => {
            throw new Error("unexpected network");
          },
        }),
      ).rejects.toThrow("ChatGPT login");
    },
  );
  test("reuses the dedicated login and honors explicit logout", async () => {
    const { scan, environment } = await fixture();
    const home = codexSecurityCredentialHome(environment);
    await mkdir(home, { recursive: true, mode: 0o700 });
    await writeFile(
      join(home, "auth.json"),
      JSON.stringify({
        auth_mode: "chatgpt",
        tokens: {
          access_token: "synthetic-access-token",
          account_id: "dedicated-account",
        },
      }),
      { mode: 0o600 },
    );
    await writeFile(
      join(home, "config.toml"),
      'cli_auth_credentials_store = "auto"\n',
    );
    const cloud = server();
    const fetch = async (url: string, options: RequestInit) => {
      expect(new Headers(options.headers).get("ChatGPT-Account-ID")).toBe(
        "dedicated-account",
      );
      return cloud.fetch(url, options);
    };
    await publishScanToCloud(scan, { environment, fetch });
    const before = cloud.calls.length;
    await setCodexSecurityCredentialLogout(home, true);
    await expect(
      publishScanToCloud(scan, { environment, fetch }),
    ).rejects.toThrow("ChatGPT login");
    expect(cloud.calls.length).toBe(before);
  });
  test("resolves user-home credentials when CODEX_HOME is empty", async () => {
    const { scan, home, environment } = await fixture();
    await mkdir(join(home, ".codex"));
    await cp(join(home, "auth.json"), join(home, ".codex", "auth.json"));
    await cp(join(home, "config.toml"), join(home, ".codex", "config.toml"));
    const cloud = server();
    await publishScanToCloud(scan, {
      environment: {
        ...environment,
        CODEX_HOME: "",
        HOME: home,
        USERPROFILE: home,
      },
      fetch: cloud.fetch,
    });
    expect(cloud.create?.source_scan_id).toBe("scan_example_001");
  });
  test("missing credential policy and malformed credentials fail before network", async () => {
    const { scan, home, environment } = await fixture();
    const fetch = async () => {
      throw new Error("unexpected network");
    };
    await rm(join(home, "config.toml"));
    await expect(
      publishScanToCloud(scan, { environment, fetch }),
    ).rejects.toThrow("ChatGPT login");
    await writeFile(
      join(home, "config.toml"),
      'cli_auth_credentials_store = "file"\n',
    );
    await writeFile(join(home, "auth.json"), "malformed");
    await expect(
      publishScanToCloud(scan, { environment, fetch }),
    ).rejects.toThrow("ChatGPT login");
  });
  test("allows artifact transfers beyond the metadata request deadline", async () => {
    const { scan, environment } = await fixture();
    const cloud = server();
    let elapsed = 0;
    const deadlines: { at: number; controller: AbortController }[] = [];
    const timeout = spyOn(AbortSignal, "timeout").mockImplementation(
      (delay) => {
        const controller = new AbortController();
        deadlines.push({ at: elapsed + delay, controller });
        return controller.signal;
      },
    );
    try {
      const result = await publishScanToCloud(scan, {
        environment,
        fetch: async (url, options) => {
          // A supported 64 MiB artifact takes about 54 seconds at 10 Mbps.
          if (options.method === "PUT") elapsed += 54_000;
          for (const deadline of deadlines) {
            if (deadline.at <= elapsed)
              deadline.controller.abort(
                new DOMException("Timed out", "TimeoutError"),
              );
          }
          options.signal?.throwIfAborted();
          return cloud.fetch(url, options);
        },
      });
      expect(result.publication?.upload_status).toBe("accepted");
      expect(cloud.calls.filter((call) => call.method === "PUT")).toHaveLength(
        4,
      );
    } finally {
      timeout.mockRestore();
    }
  });
  test("caller cancellation prevents subsequent artifact upload", async () => {
    const { scan, environment } = await fixture();
    const controller = new AbortController();
    const cloud = server();
    await expect(
      publishScanToCloud(scan, {
        environment,
        signal: controller.signal,
        fetch: async (url, options) => {
          const response = await cloud.fetch(url, options);
          if (options.method === "PUT") controller.abort(new Error("canceled"));
          return response;
        },
      }),
    ).rejects.toThrow("canceled");
    expect(cloud.calls.filter((item) => item.method === "PUT")).toHaveLength(1);
  });
  test("rejects a scoped target before network", async () => {
    const { scan, environment } = await fixture();
    const path = join(scan, "scan-manifest.json"),
      manifest = JSON.parse(await readFile(path, "utf8"));
    manifest.scan.target.repositoryPath = "src";
    await writeFile(path, JSON.stringify(manifest));
    await expect(
      publishScanToCloud(scan, {
        environment,
        fetch: async () => {
          throw new Error("unexpected network");
        },
      }),
    ).rejects.toThrow("full-repository");
  });
  test("old scans lacking frozen repository provenance fail rather than using cwd", async () => {
    const { scan, environment } = await fixture();
    const path = join(scan, "scan-manifest.json"),
      manifest = JSON.parse(await readFile(path, "utf8"));
    delete manifest.scan.target.remote;
    await writeFile(path, JSON.stringify(manifest));
    await expect(
      publishScanToCloud(scan, {
        environment,
        fetch: async () => {
          throw new Error("unexpected network");
        },
      }),
    ).rejects.toThrow("saved SCM provenance");
  });
});

describe("Cloud environment selection", () => {
  const other = { ...destination, environment_id: "env-2" };
  test("automatically selects one authorized match", async () => {
    expect(await selectCloudDestination([destination], {})).toEqual(
      destination,
    );
  });
  test("noninteractive ambiguity requires explicit selection", async () => {
    await expect(
      selectCloudDestination([destination, other], {}),
    ).rejects.toThrow("--cloud-environment");
  });
  test("interactive selection uses only existing matches", async () => {
    expect(
      await selectCloudDestination([destination, other], {
        selectEnvironment: async (choices) => choices[1]!.environment_id,
      }),
    ).toEqual(other);
  });
  test("explicit flag selects among matches without a prompt", async () => {
    expect(
      await selectCloudDestination([destination, other], {
        cloudEnvironment: "env-2",
      }),
    ).toEqual(other);
  });
  test("mismatched explicit environment fails", async () => {
    await expect(
      selectCloudDestination([destination], { cloudEnvironment: "env-other" }),
    ).rejects.toThrow("not an authorized match");
  });
});
