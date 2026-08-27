import { chmod, cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { publishScanToCustomInternal as publishScanToCustom } from "../src/custom-publish.js";
import type { FindingsDocument } from "../src/models.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function fixture() {
  const scan = await mkdtemp(join(tmpdir(), "custom-publish-"));
  directories.push(scan);
  await cp(join(PLUGIN_ROOT, "examples/completed-scan"), scan, {
    recursive: true,
  });
  if (process.platform !== "win32") await chmod(scan, 0o700);
  const source = await readFile(join(scan, "findings.json"), "utf8");
  const document = JSON.parse(source) as FindingsDocument;
  return { scan, source, document };
}

test("publishes complete sealed findings with their repository ID to a custom base URL", async () => {
  const { scan, source, document } = await fixture();
  const controller = new AbortController();
  const ids = document.findings.map((finding) => finding.findingId);
  let calls = 0;
  const result = await publishScanToCustom(
    scan,
    {
      findingsUrl: "http://synthetic.test/service",
      expectedScanId: document.scanId,
      signal: controller.signal,
    },
    {
      fetch: async (url, options) => {
        calls++;
        expect(String(url)).toBe(
          "http://synthetic.test/service/v1/bulk/findings",
        );
        expect(options).toEqual({
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            findings: document.findings,
            repositoryId: "target_sha256_example",
          }),
          signal: controller.signal,
        });
        return Response.json(ids, { status: 201 });
      },
    },
  );
  expect(result).toEqual({
    scanId: document.scanId,
    repositoryId: "target_sha256_example",
    findingIds: ids,
    findingCount: ids.length,
  });
  expect(calls).toBe(1);
  expect(await readFile(join(scan, "findings.json"), "utf8")).toBe(source);
});

test("dry-run previews the complete upload without HTTP or credentials", async () => {
  const { scan, document } = await fixture();
  const result = await publishScanToCustom(
    scan,
    { findingsUrl: "http://localhost:3000", dryRun: true },
    {
      fetch: async () => {
        throw new Error("dry-run must not send a request");
      },
    },
  );
  expect(result).toEqual({
    scanId: document.scanId,
    repositoryId: "target_sha256_example",
    findingIds: document.findings.map((finding) => finding.findingId),
    findingCount: document.findings.length,
    dryRun: true,
    findings: document.findings,
  });
});

test("does not retry failed uploads or report incomplete receipts as successful", async () => {
  const { scan } = await fixture();
  for (const [receipt, status, message] of [
    [{}, 503, "HTTP 503"],
    [{}, 201, "did not acknowledge all"],
    [[], 201, "did not acknowledge all"],
    [["wrong-finding"], 201, "did not acknowledge all"],
  ] as const) {
    let calls = 0;
    await expect(
      publishScanToCustom(
        scan,
        { findingsUrl: "http://synthetic.test" },
        {
          fetch: async () => {
            calls++;
            return Response.json(receipt, { status });
          },
        },
      ),
    ).rejects.toThrow(message);
    expect(calls).toBe(1);
  }
});

test("rejects mismatched or changed sealed artifacts before publication, including dry-run", async () => {
  const { scan, source } = await fixture();
  const dependencies = {
    fetch: async () => {
      throw new Error("must not upload invalid artifacts");
    },
  };
  await expect(
    publishScanToCustom(
      scan,
      {
        findingsUrl: "http://synthetic.test",
        expectedScanId: "wrong-scan",
      },
      dependencies,
    ),
  ).rejects.toThrow("do not match selected scan");
  await writeFile(join(scan, "findings.json"), source + "\n");
  for (const dryRun of [false, true]) {
    await expect(
      publishScanToCustom(
        scan,
        {
          findingsUrl: "http://synthetic.test",
          dryRun,
        },
        dependencies,
      ),
    ).rejects.toThrow();
  }
});
