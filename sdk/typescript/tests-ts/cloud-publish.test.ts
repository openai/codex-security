import {
  codexSecurityCredentialHome,
  setCodexSecurityCredentialLogout,
} from "../src/runtime.js";
import { createHash } from "node:crypto";
import {
  chmod,
  cp,
  mkdir,
  readFile,
  rm,
  symlink,
  truncate,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, spyOn, test } from "bun:test";
import {
  publishFindingsCsvToCloud,
  publishScanToCloud,
  selectCloudDestination,
} from "../src/cloud-publish.js";
import {
  nativeCloudServer as server,
  nativeCloudDestination as destination,
} from "./support/cloud-import.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { loadContract } from "../src/contract.js";
import { CodexSecurityError } from "../src/errors.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-cloud-",
  false,
);
afterEach(cleanup);
async function fixture(homeName = "home") {
  const root = await temporaryDirectory();
  const scan = join(root, "scan"),
    home = join(root, homeName);
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

describe("native Cloud preflight and diagnostics", () => {
  test.each(["failed", "canceled", "interrupted"] as const)(
    "rejects a sealed zero-finding %s directory before credentials or network",
    async (status) => {
      const { scan } = await fixture();
      const manifestPath = join(scan, "scan-manifest.json");
      const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
      manifest.scan.status = status;
      for (const name of ["findings.json", "coverage.json"]) {
        const path = join(scan, name);
        const document = JSON.parse(await readFile(path, "utf8"));
        if (name === "findings.json") document.findings = [];
        else {
          document.completeness = "partial";
          document.surfaces = [];
        }
        const contents = JSON.stringify(document);
        await writeFile(path, contents);
        manifest.scan.artifacts.find(
          (item: { path: string }) => item.path === name,
        ).sha256 = createHash("sha256").update(contents).digest("hex");
      }
      await writeFile(manifestPath, JSON.stringify(manifest));
      const loaded = await loadContract(scan, { pluginRoot: PLUGIN_ROOT });
      expect(loaded.manifest.scan.status).toBe(status);
      expect(loaded.findings.findings).toEqual([]);
      for (const dryRun of [true, false]) {
        await expect(
          publishScanToCloud(scan, {
            dryRun,
            environment: {},
            fetch: async () => {
              throw new Error("unexpected network");
            },
          }),
        ).rejects.toThrow(`requires a completed scan; this scan is ${status}`);
      }
    },
  );

  test.each(["broken-success", "malformed-success", "broken-error"] as const)(
    "retains response failure detail and recovery guidance for %s",
    async (scenario) => {
      const { scan, environment } = await fixture();
      const cloud = server();
      const failure = new Error("synthetic response body transport failure");
      let caught: unknown;
      try {
        await publishScanToCloud(scan, {
          environment,
          fetch: async (url, request) => {
            if (request.method === "GET") return cloud.fetch(url, request);
            if (scenario === "malformed-success")
              return new Response('{"protocol_version":');
            return new Response(
              new ReadableStream({
                pull(body) {
                  body.error(failure);
                },
              }),
              { status: scenario === "broken-error" ? 503 : 200 },
            );
          },
        });
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(CodexSecurityError);
      const error = caught as CodexSecurityError;
      expect(error.cause).toBeInstanceOf(Error);
      expect(error.message).toContain((error.cause as Error).message);
      expect(error.message).toContain("Repeat the same publication to resume");
      expect(error.message).toContain(
        scenario === "broken-error" ? "HTTP 503" : "not confirmed",
      );
      if (scenario !== "malformed-success") expect(error.cause).toBe(failure);
    },
  );

  test.each([200, 503])(
    "preserves cancellation when an HTTP %i body fails",
    async (status) => {
      const { scan, environment } = await fixture();
      const cloud = server();
      const controller = new AbortController();
      const cancellation = new Error("synthetic cancellation reason");
      await expect(
        publishScanToCloud(scan, {
          environment,
          signal: controller.signal,
          fetch: async (url, request) => {
            if (request.method === "GET") return cloud.fetch(url, request);
            return new Response(
              new ReadableStream({
                pull(body) {
                  controller.abort(cancellation);
                  body.error(
                    new Error("synthetic body failure after cancellation"),
                  );
                },
              }),
              { status },
            );
          },
        }),
      ).rejects.toBe(cancellation);
    },
  );

  test("resumes an accepted finalization after losing its response body without reupload", async () => {
    const { scan, environment } = await fixture();
    const cloud = server();
    let dropped = false;
    const fetch = async (url: string, request: RequestInit) => {
      const response = await cloud.fetch(url, request);
      if (url.endsWith("/finalize") && !dropped) {
        dropped = true;
        return new Response(
          new ReadableStream({
            pull(body) {
              body.error(new Error("synthetic lost finalization response"));
            },
          }),
        );
      }
      return response;
    };
    await expect(
      publishScanToCloud(scan, { environment, fetch }),
    ).rejects.toThrow("resume its immutable upload session");
    expect(cloud.calls.filter((call) => call.method === "PUT")).toHaveLength(4);
    const before = cloud.calls.length;
    const replay = await publishScanToCloud(scan, { environment, fetch });
    expect(replay.publication?.upload_status).toBe("accepted");
    expect(cloud.calls.slice(before).map((call) => call.method)).toEqual([
      "GET",
      "POST",
    ]);
  });

  test("reports a rejected create request with the service detail and no uploads", async () => {
    const { scan, environment } = await fixture();
    const cloud = server();
    const calls: string[] = [];
    await expect(
      publishScanToCloud(scan, {
        environment,
        fetch: async (url, request) => {
          calls.push(request.method!);
          if (request.method === "POST")
            return Response.json(
              {
                detail: "Artifact declaration does not match the saved scan.",
                code: "invalid_artifacts",
              },
              { status: 422 },
            );
          return cloud.fetch(url, request);
        },
      }),
    ).rejects.toThrow(
      /HTTP 422.*Artifact declaration does not match.*invalid_artifacts.*Resolve this rejection/s,
    );
    expect(calls).toEqual(["GET", "POST"]);
  });

  test("rejects the aggregate artifact limit before credentials for dry-run and publication", async () => {
    const { scan } = await fixture();
    const manifestPath = join(scan, "scan-manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    const size = 45 * 1024 * 1024;
    for (const name of ["findings.json", "coverage.json", "report.md"]) {
      const path = join(scan, name);
      const original = await readFile(path);
      const padded = Buffer.concat([
        original,
        Buffer.alloc(size - original.byteLength, " "),
      ]);
      await writeFile(path, padded);
      const artifact = manifest.scan.artifacts.find(
        (item: { path: string }) => item.path === name,
      );
      if (artifact)
        artifact.sha256 = createHash("sha256").update(padded).digest("hex");
    }
    await writeFile(manifestPath, JSON.stringify(manifest));
    for (const dryRun of [true, false]) {
      await expect(
        publishScanToCloud(scan, {
          dryRun,
          environment: {},
          fetch: async () => {
            throw new Error("unexpected network");
          },
        }),
      ).rejects.toThrow(/artifacts total \d+ bytes.*134217728 bytes/);
    }
    expect((await readFile(join(scan, "report.md"))).byteLength).toBe(size);
  });

  test.skipIf(process.platform === "win32")(
    "preserves significant whitespace in the credential home",
    async () => {
      const { scan, home, environment } = await fixture(" home ");
      await mkdir(home.trim(), { mode: 0o700 });
      await writeFile(
        join(home.trim(), "config.toml"),
        'cli_auth_credentials_store = "file"\n',
      );
      await writeFile(
        join(home.trim(), "auth.json"),
        JSON.stringify({
          auth_mode: "chatgpt",
          tokens: {
            access_token: "wrong-trimmed-home-token",
            account_id: "wrong-account",
          },
        }),
        { mode: 0o600 },
      );
      const cloud = server();
      const result = await publishScanToCloud(scan, {
        environment,
        fetch: cloud.fetch,
      });
      expect(result.publication?.upload_status).toBe("accepted");
    },
  );

  test("honors the configured native import base URL", async () => {
    const { scan, environment } = await fixture();
    const cloud = server();
    const base = "http://127.0.0.1:12345/imported-scans/v1";
    await publishScanToCloud(scan, {
      environment: { ...environment, CODEX_SECURITY_CLOUD_PUBLISH_URL: base },
      fetch: async (url, request) => {
        expect(url.startsWith(base)).toBe(true);
        return cloud.fetch(url, request);
      },
    });
  });

  test("rejects malformed and unsupported credentials before discovery", async () => {
    const { scan, home, environment } = await fixture();
    for (const credentials of [
      { auth_mode: "apikey", OPENAI_API_KEY: "synthetic-api-secret" },
      {
        auth_mode: "personal_access_token",
        tokens: {
          access_token: "synthetic-token",
          account_id: "synthetic-account",
        },
      },
      { tokens: { access_token: "synthetic-token" } },
      {},
    ]) {
      await writeFile(join(home, "auth.json"), JSON.stringify(credentials), {
        mode: 0o600,
      });
      await expect(
        publishScanToCloud(scan, {
          environment,
          fetch: async () => {
            throw new Error("unexpected network");
          },
        }),
      ).rejects.toThrow("ChatGPT login");
    }
  });

  test("rejects artifact tampering before credentials or discovery", async () => {
    const { scan } = await fixture();
    await writeFile(join(scan, "findings.json"), "{}");
    await expect(
      publishScanToCloud(scan, {
        environment: {},
        fetch: async () => {
          throw new Error("unexpected network");
        },
      }),
    ).rejects.toThrow();
  });

  test("preserves cancellation while reading a response", async () => {
    const { scan, environment } = await fixture();
    const controller = new AbortController();
    const cancellation = new Error("response canceled");
    await expect(
      publishScanToCloud(scan, {
        environment,
        signal: controller.signal,
        fetch: async () => {
          const response = Response.json({});
          response.json = async () => {
            controller.abort(cancellation);
            throw controller.signal.reason;
          };
          return response;
        },
      }),
    ).rejects.toBe(cancellation);
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
