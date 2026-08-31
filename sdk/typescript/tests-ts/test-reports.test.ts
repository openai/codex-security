import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test } from "bun:test";
import { bashCommand } from "./support/shell.js";

const bash = bashCommand();
const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function fixtures() {
  const root = await mkdtemp(join(tmpdir(), "codex-security-test-reports-"));
  directories.push(root);
  return {
    root,
    async report(
      name: string,
      cases: string[],
      failures = 0,
      count = cases.length,
    ) {
      const path = join(root, name);
      await writeFile(
        path,
        `<testsuites tests="${count}" failures="${failures}" time="1.25"><testsuite>${cases.join("")}</testsuite></testsuites>`,
      );
      return path;
    },
  };
}

function testcase(name: string, status = "") {
  return `<testcase file="tests-ts/example.test.ts" classname="example" name="${name}">${status}</testcase>`;
}

async function compare(baseline: string, ...candidates: string[]) {
  const child = Bun.spawn({
    cmd: [
      "node",
      fileURLToPath(
        new URL("../scripts/compare-test-reports.mjs", import.meta.url),
      ),
      baseline,
      ...candidates,
    ],
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  const [status, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return { status, stdout, stderr };
}

describe("JUnit inventory comparison", () => {
  test("runs every workflow comparison before reporting a mismatch", async () => {
    const fixture = await fixtures();
    const workflow = Bun.YAML.parse(
      await readFile(
        new URL("../../../.github/workflows/test-quality.yml", import.meta.url),
        "utf8",
      ),
    ) as {
      jobs: { compare: { steps: Array<{ name?: string; run?: string }> } };
    };
    const script = workflow.jobs.compare.steps.find(
      (step) => step.name === "Compare inventories and outcomes",
    )!.run!;
    const expected = [
      ...["ubuntu-latest", "windows-latest"].flatMap((os) =>
        ["isolated", "parallel"].map(
          (mode) => `reports/runner-${os}-${mode}.xml`,
        ),
      ),
      "reports/runner-windows-latest-shard-*.xml",
    ];
    const mock = `node() {
  printf '%s\\n' "$3"
  [[ "$3" != "$CODEX_SECURITY_TEST_FAIL_REPORT" ]]
}`;
    const summary = join(fixture.root, "summary.md");
    for (const failedReport of ["", expected[0]!]) {
      await writeFile(summary, "");
      const child = Bun.spawn({
        cmd: [bash, "-e", "-o", "pipefail", "-c", `${mock}\n${script}`],
        cwd: fixture.root,
        stdin: "ignore",
        stdout: "ignore",
        stderr: "pipe",
        env: {
          ...process.env,
          GITHUB_STEP_SUMMARY: "summary.md",
          CODEX_SECURITY_TEST_FAIL_REPORT: failedReport,
        },
        timeout: 10_000,
      });
      const [status, stderr] = await Promise.all([
        child.exited,
        new Response(child.stderr).text(),
      ]);
      expect(status, stderr).toBe(failedReport === "" ? 0 : 1);
      expect((await readFile(summary, "utf8")).trim().split(/\r?\n/u)).toEqual(
        expected,
      );
    }
  });

  test("merges native shards without depending on test order", async () => {
    const fixture = await fixtures();
    const passed = testcase("accepts &amp; preserves");
    const skipped = testcase("platform-only", "<skipped/>");
    const baseline = await fixture.report("baseline.xml", [passed, skipped]);
    await fixture.report("shard-1.xml", [skipped]);
    await fixture.report("shard-2.xml", [passed]);
    const result = await compare(baseline, join(fixture.root, "shard-*.xml"));
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toContain("combined test time: 2.50s");
  });

  test("parses XML entities while ignoring comments and CDATA markup", async () => {
    const fixture = await fixtures();
    const baseline = await fixture.report("baseline.xml", [
      testcase("a &amp; &quot; &apos; &lt; &gt;"),
    ]);
    const candidate = join(fixture.root, "candidate.xml");
    await writeFile(
      candidate,
      `<?xml version="1.0"?>
<testsuites tests="1" time="1.25"><testsuite>
<!-- <testcase name="comment"><failure/></testcase> -->
<system-out><![CDATA[<testcase name="log"><failure/></testcase>]]></system-out>
${testcase("&#97; &#38; &#x22; &#39; &#60; &#62;")}
</testsuite></testsuites>`,
    );
    const result = await compare(baseline, candidate);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toBe("");
  });

  test("normalizes report paths and rejects duplicates across candidate files", async () => {
    const fixture = await fixtures();
    const original = testcase("portable");
    const baseline = await fixture.report("baseline.xml", [original]);
    const candidate = await fixture.report("candidate.xml", [
      original.replace(
        "tests-ts/example.test.ts",
        "./tests-ts\\example.test.ts",
      ),
    ]);
    expect((await compare(baseline, candidate)).status).toBe(0);
    const result = await compare(baseline, candidate, candidate);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "Extra (1): tests-ts/example.test.ts > example > portable > passed",
    );
  });

  test("preserves file, character-class, hidden-file, and nonrecursive glob matching", async () => {
    const fixture = await fixtures();
    const cases = [testcase("portable")];
    const baseline = await fixture.report("baseline.xml", cases);
    const directory = join(fixture.root, "reports with spaces");
    await mkdir(directory);
    await fixture.report("reports with spaces/shard-a.xml", cases);
    await fixture.report("reports with spaces/.hidden.xml", [
      testcase("hidden"),
    ]);
    await mkdir(join(directory, "nested"));
    await fixture.report("reports with spaces/nested/shard-b.xml", [
      testcase("nested"),
    ]);
    for (const pattern of [
      "reports with spaces/shard-?.xml",
      "reports with spaces/shard-[ab].xml",
      "reports with spaces/shard-[!b].xml",
      "reports with spaces/*.xml",
      "**/shard-*.xml",
    ]) {
      const result = await compare(baseline, join(fixture.root, pattern));
      expect(result.status, `${pattern}: ${result.stderr}`).toBe(0);
    }
    const hidden = await fixture.report("hidden-baseline.xml", [
      testcase("hidden"),
    ]);
    expect((await compare(hidden, join(directory, ".*.xml"))).status).toBe(0);
    for (const name of ["{a,b}.xml", "!report.xml", "@(shard).xml"]) {
      const path = await fixture.report(name, cases);
      expect((await compare(baseline, path)).status, name).toBe(0);
    }
  });

  test("detects error status and nested summary failures with failure overriding skipped", async () => {
    const fixture = await fixtures();
    const baseline = await fixture.report("baseline.xml", [
      testcase("example"),
    ]);
    for (const status of ["<error/><skipped/>", "<skipped/><error/>"]) {
      const candidate = await fixture.report("error.xml", [
        testcase("example", status),
      ]);
      const result = await compare(baseline, candidate);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("test run failed");
      expect(result.stderr).toContain("example > example > failed");
      expect(result.stderr).not.toContain("example > example > skipped");
    }
    const nested = join(fixture.root, "nested.xml");
    await writeFile(
      nested,
      `<testsuites tests="1"><testsuite><testsuite errors="1">${testcase("example")}</testsuite></testsuite></testsuites>`,
    );
    const result = await compare(baseline, nested);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("test run failed");
  });

  test("rejects malformed XML and invalid report numbers", async () => {
    const fixture = await fixtures();
    const baseline = await fixture.report("baseline.xml", [
      testcase("example"),
    ]);
    for (const xml of [
      "<testsuite><testcase></testsuite>",
      "<testsuite><testcase/>",
      '<testsuite><testcase name="a" name="b"/></testsuite>',
      '<testsuite><testcase name="&missing;"/></testsuite>',
      "<testsuite><testcase/></testsuite><extra/>",
      '<testsuite tests="1.0"><testcase/></testsuite>',
      '<testsuite failures="invalid"><testcase/></testsuite>',
      '<testsuite time="1oops"><testcase/></testsuite>',
    ]) {
      const candidate = join(fixture.root, "invalid.xml");
      await writeFile(candidate, xml);
      const result = await compare(baseline, candidate);
      expect(result.status, xml).toBe(1);
      expect(result.stdout).not.toContain("Identical test inventory");
    }
  });

  test("uses count and timing defaults and only direct unqualified status children", async () => {
    const fixture = await fixtures();
    const baseline = await fixture.report("baseline.xml", [
      testcase("example"),
    ]);
    const candidate = join(fixture.root, "defaults.xml");
    await writeFile(
      candidate,
      `<testsuite xmlns:other="urn:example">${testcase("example", "<properties><failure/></properties><other:error/>")}</testsuite>`,
    );
    const result = await compare(baseline, candidate);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("| defaults.xml | 1 | 0 | 0.00 |");
  });

  test("rejects ambiguous test identities even when totals match", async () => {
    const fixture = await fixtures();
    const first = testcase("same parameterized name");
    for (const [name, repeated] of [
      ["same-outcome", first],
      ["different-outcome", testcase("same parameterized name", "<skipped/>")],
    ] as const) {
      const baseline = await fixture.report(`${name}-baseline.xml`, [
        first,
        repeated,
      ]);
      const candidate = await fixture.report(`${name}-candidate.xml`, [
        first,
        repeated,
      ]);
      const result = await compare(baseline, candidate);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("duplicate test identity");
    }
  });

  test("reports every shard's timing even when an earlier shard fails", async () => {
    const fixture = await fixtures();
    const first = testcase("first");
    const second = testcase("second");
    const baseline = await fixture.report("baseline.xml", [first, second]);
    const failed = await fixture.report("shard-1.xml", [
      testcase("first", "<failure/>"),
    ]);
    const passed = await fixture.report("shard-2.xml", [second]);
    const result = await compare(baseline, failed, passed);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("test run failed");
    expect(result.stdout).toContain("shard-1.xml");
    expect(result.stdout).toContain("shard-2.xml");
  });

  test("rejects dropped, duplicated, skipped, failed, or incomplete results", async () => {
    const fixture = await fixtures();
    const first = testcase("first");
    const second = testcase("second");
    const baseline = await fixture.report("baseline.xml", [first, second]);
    for (const [name, cases, failures, count] of [
      ["missing", [first], 0, 1],
      ["duplicate", [first, second, second], 0, 3],
      ["skipped", [first, testcase("second", "<skipped/>")], 0, 2],
      ["failed", [first, testcase("second", "<failure/>")], 1, 2],
      ["summary-failed", [first, second], 1, 2],
      ["incomplete", [first], 0, 2],
      ["empty", [], 0, 0],
    ] as const) {
      const candidate = await fixture.report(
        `${name}.xml`,
        [...cases],
        failures,
        count,
      );
      expect((await compare(baseline, candidate)).status, name).toBe(1);
    }
    expect(
      (await compare(baseline, join(fixture.root, "absent-*.xml"))).status,
    ).toBe(1);
  });
});
