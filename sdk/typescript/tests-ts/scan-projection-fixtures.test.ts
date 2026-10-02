import { afterEach, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import fixtureTemplate from "../../../plugins/codex-security/tests/fixtures/scan-projection/canonical-child.json";
import type { Finding } from "../src/models.js";
import { readScanFile } from "../src/contract.js";
import {
  prepareScanArtifactRestorer,
  runCodexCommand,
} from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const python =
  process.env["PYTHON"] ?? Bun.which("python3") ?? Bun.which("python");
const sourcePlugin = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);
const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function canonicalChild() {
  if (python === null)
    throw new Error("Python is required for projection fixtures.");
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "projection-fixture-")),
  );
  roots.push(root);
  const parent = join(root, "parent");
  const source = join(parent, fixtureTemplate.relativeDirectory);
  const environment = {
    ...process.env,
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
  };
  const prepared = await runCodexCommand(
    { command: python },
    [
      "-I",
      "-X",
      "utf8",
      "-B",
      "-c",
      `
import json, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / "tests"))
sys.path.insert(0, str(Path(sys.argv[2]) / "scripts"))
import workbench_test_support as support
support.SCRIPT = Path(sys.argv[2]) / "scripts/workbench_db.py"
source, target, parent_dir = map(Path, sys.argv[3:6])
raw_fixture = sys.stdin.read()
for name in ("src/extract.py", "shared/control.py", "outside.py"):
    path = target / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("print('synthetic fixture')\\n" * 2)
state = Path(os.environ["CODEX_SECURITY_STATE_DIR"])
parent = support.register(state, target, parent_dir, mode="deep")
child = support.register(state, target, source, parent=parent["scanId"], role="deep_pass", paths=("src",))
fixture = json.loads(raw_fixture.replace("@CHILD@", child["scanId"]))
fixture.update(parentScanId=parent["scanId"], sourceScanId=child["scanId"])
support.write_completed_contract(source, child["scanId"], target, include_paths=["src"], coverage_mode="scoped_path", inventory_strategy="scoped_path")
for name, values in (("findings", {"findings": fixture["findings"]}), ("coverage", fixture["coverage"])):
    path = source / (name + ".json")
    path.write_text(json.dumps({**json.loads(path.read_text()), **values}))
for name, contents in fixture["files"].items():
    path = source / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents)
support.run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
print(json.dumps(fixture))
`,
      sourcePlugin,
      PLUGIN_ROOT,
      source,
      join(root, "target"),
      parent,
    ],
    environment,
    JSON.stringify(fixtureTemplate),
  );
  expect(prepared.success, prepared.stderr).toBe(true);
  const fixture = JSON.parse(prepared.stdout) as typeof fixtureTemplate;
  const original = JSON.parse(
    await readFile(join(source, "findings.json"), "utf8"),
  ) as { findings: Finding[] };
  const options = {
    python,
    pluginRoot: PLUGIN_ROOT,
    environment,
  };
  return { root, parent, source, fixture, original, options };
}

test("completed projection follows the shared canonical child fixture", async () => {
  const h = await canonicalChild();
  const { fixture } = h;
  const writer = await prepareScanArtifactRestorer(h.options, h.parent);
  const projected = await writer.projectChild(
    fixture.parentScanId,
    fixture.sourceScanId,
    h.source,
  );
  expect(projected.sourceFindings).toEqual(
    fixture.expected.sourceFindingIndexes.map(
      (index) => h.original.findings[index]!,
    ),
  );
  for (const [index, expected] of fixture.expected.findings.entries()) {
    expect(projected.draft.findings[index]).toMatchObject({
      identity: expected.identity,
      locations: expected.locations,
      provenance: {
        sourceFindingIds: expected.sourceFindingIds,
        extensions: { fixture: "preserve-source-provenance" },
      },
      ...("writeup" in expected ? { writeup: expected.writeup } : {}),
    });
  }
  expect(
    await writer.projectChild(
      fixture.parentScanId,
      fixture.sourceScanId,
      h.source,
    ),
  ).toEqual(projected);
  for (const [destination, original] of Object.entries(
    fixture.expected.fileProjections,
  )) {
    expect(await readFile(join(h.parent, destination))).toEqual(
      await readFile(join(h.source, original)),
    );
  }
  expect(
    JSON.parse(await readFile(join(h.source, "findings.json"), "utf8")),
  ).toEqual(h.original);
  // Supporting evidence is read again on the next projection; there is no cross-call cache.
  const evidence = Object.entries(fixture.expected.fileProjections).find(
    ([, path]) => path.endsWith("trace.txt"),
  )!;
  const replacement = Buffer.from([0, 128, 255, 3]);
  await writeFile(join(h.source, evidence[1]), replacement);
  await writer.projectChild(
    fixture.parentScanId,
    fixture.sourceScanId,
    h.source,
  );
  expect(await readFile(join(h.parent, evidence[0]))).toEqual(replacement);
});

test("normalizes sealed legacy findings for merging while retaining exact source evidence", async () => {
  const h = await canonicalChild();
  const { fixture } = h;
  const first = fixture.expected.sourceFindingIndexes[0]!;
  const legacy = {
    ...h.original,
    findings: h.original.findings.map((finding, index) =>
      index === first
        ? {
            ...finding,
            attackPath: {
              steps: { first: "upload" },
              preconditions: "An attacker can submit an archive.",
            },
          }
        : finding,
    ),
  };
  const sourceBytes = JSON.stringify(legacy);
  const findingsPath = join(h.source, "findings.json");
  await writeFile(findingsPath, sourceBytes);
  const manifestPath = join(h.source, "scan-manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
    scan: { artifacts: Array<{ path: string; sha256: string }> };
  };
  manifest.scan.artifacts.find(
    (artifact) => artifact.path === "findings.json",
  )!.sha256 = createHash("sha256").update(sourceBytes).digest("hex");
  await writeFile(manifestPath, JSON.stringify(manifest));
  // Older completed rows did not pin a manifest digest; their binding still applies.
  const unpinned = await runCodexCommand(
    { command: h.options.python },
    [
      "-I",
      "-X",
      "utf8",
      "-B",
      "-c",
      `
import sys
sys.path.insert(0, sys.argv[1])
from workbench_db import connect
with connect() as connection:
    connection.execute("UPDATE scans SET seal_manifest_digest = NULL WHERE id = ?", (sys.argv[2],))
`,
      join(PLUGIN_ROOT, "scripts"),
      fixture.sourceScanId,
    ],
    h.options.environment,
  );
  expect(unpinned.success, unpinned.stderr).toBe(true);

  const writer = await prepareScanArtifactRestorer(h.options, h.parent);
  const projected = await writer.projectChild(
    fixture.parentScanId,
    fixture.sourceScanId,
    h.source,
  );
  expect(projected.draft.findings[0]!.attackPath).toEqual({
    preconditions: ["An attacker can submit an archive."],
  });
  expect(projected.sourceFindings).toEqual(
    fixture.expected.sourceFindingIndexes.map(
      (index) => legacy.findings[index]!,
    ),
  );
  expect(await readFile(findingsPath, "utf8")).toBe(sourceBytes);
});

test.each(["source ID", "seal", "parent directory"])(
  "rejects changed %s at the projection boundary",
  async (change) => {
    const h = await canonicalChild();
    const { fixture } = h;
    const writer = await prepareScanArtifactRestorer(h.options, h.parent);
    let source = h.source;
    let scanId = fixture.sourceScanId;
    if (change === "source ID") scanId = "different-child";
    if (change === "seal")
      await writeFile(join(source, "findings.json"), "{}\n");
    if (change === "parent directory") {
      const moved = join(h.root, "moved-parent");
      await rename(h.parent, moved);
      await mkdir(h.parent, { mode: 0o700 });
      source = join(moved, fixture.relativeDirectory);
    }
    await expect(
      writer.projectChild(fixture.parentScanId, scanId, source),
    ).rejects.toThrow();
    expect(existsSync(join(h.parent, "findings"))).toBe(false);
  },
);

test.skipIf(process.platform === "win32")(
  "retained evidence references cannot read through a child symlink",
  async () => {
    const h = await canonicalChild();
    const { fixture } = h;
    const outside = join(h.root, "outside.txt");
    await writeFile(outside, "Synthetic outside evidence");
    await symlink(outside, join(h.source, "findings/check/unsafe.txt"));
    const writer = await prepareScanArtifactRestorer(h.options, h.parent);
    await writer.projectChild(
      fixture.parentScanId,
      fixture.sourceScanId,
      h.source,
    );
    await expect(
      readScanFile(
        h.parent,
        `${fixture.relativeDirectory}/findings/check/unsafe.txt`,
        "supporting evidence",
      ),
    ).rejects.toThrow();
    expect(
      existsSync(
        join(h.parent, `findings/${fixture.sourceScanId}/check/unsafe.txt`),
      ),
    ).toBe(false);
  },
);

async function pythonWrapper(root: string, block = false) {
  const wrapper = join(root, "selected-python");
  const trace = join(root, "projection-processes.jsonl");
  const ready = join(root, "projection-ready");
  const closed = join(root, "projection-closed");
  await writeFile(
    wrapper,
    `#!${python}
import json, os, signal, sys, time
with open(${JSON.stringify(trace)}, "a") as trace:
    trace.write(json.dumps(sys.argv[1:]) + "\\n")
if ${block ? "True" : "False"} and sys.argv[-1].endswith("project_scan_artifacts.py"):
    def finish(signum, frame):
        time.sleep(0.1)
        with open(${JSON.stringify(closed)}, "w") as closed:
            closed.write("completed child cleanup")
        sys.exit(0)
    signal.signal(signal.SIGTERM, finish)
    with open(${JSON.stringify(ready)}, "w") as ready:
        ready.write("ready")
    while True:
        signal.pause()
os.execv(${JSON.stringify(python)}, [${JSON.stringify(python)}, *sys.argv[1:]])
`,
  );
  await chmod(wrapper, 0o700);
  return { wrapper, trace, ready, closed };
}

test.skipIf(process.platform === "win32")(
  "projects many evidence files with one selected Python process",
  async () => {
    const h = await canonicalChild();
    const { fixture } = h;
    const many = join(h.source, "findings/check/many");
    await mkdir(many);
    const files = Array.from({ length: 64 }, (_, index) => ({
      name: `${index}.bin`,
      bytes: Buffer.alloc(32 * 1024, index),
    }));
    await Promise.all(
      files.map(({ name, bytes }) => writeFile(join(many, name), bytes)),
    );
    const wrapper = await pythonWrapper(h.root);
    const writer = await prepareScanArtifactRestorer(
      { ...h.options, python: wrapper.wrapper },
      h.parent,
    );
    await writeFile(wrapper.trace, "");
    await writer.projectChild(
      fixture.parentScanId,
      fixture.sourceScanId,
      h.source,
    );
    const invocations = (await readFile(wrapper.trace, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as string[]);
    expect(invocations).toHaveLength(1);
    expect(invocations[0]!.at(-1)).toBe(
      join(PLUGIN_ROOT, "scripts/project_scan_artifacts.py"),
    );
    for (const { name, bytes } of files) {
      expect(
        await readFile(
          join(
            h.parent,
            `${fixture.relativeDirectory}/findings/check/many`,
            name,
          ),
        ),
      ).toEqual(bytes);
    }
  },
);

test.skipIf(process.platform === "win32")(
  "cancellation waits for the admitted projection process to close",
  async () => {
    const h = await canonicalChild();
    const { fixture } = h;
    const wrapper = await pythonWrapper(h.root, true);
    const controller = new AbortController();
    const writer = await prepareScanArtifactRestorer(
      { ...h.options, python: wrapper.wrapper },
      h.parent,
    );
    const pending = writer.projectChild(
      fixture.parentScanId,
      fixture.sourceScanId,
      h.source,
      controller.signal,
    );
    const settled = pending.then(
      () => undefined,
      (error: unknown) => error,
    );
    try {
      const deadline = Date.now() + 3000;
      while (!existsSync(wrapper.ready) && Date.now() < deadline)
        await new Promise((resolve) => setTimeout(resolve, 10));
      expect(existsSync(wrapper.ready)).toBe(true);
      const reason = new Error("Synthetic projection cancellation");
      controller.abort(reason);
      expect(await settled).toBe(reason);
      expect(await readFile(wrapper.closed, "utf8")).toBe(
        "completed child cleanup",
      );
    } finally {
      controller.abort();
      await settled;
    }
  },
);

test("preserves report and evidence basenames under the child namespace", async () => {
  const h = await canonicalChild();
  const { fixture } = h;
  const evidence = `${fixture.sourceScanId}-check-3.md`;
  await writeFile(
    join(h.source, "findings/check-3", evidence),
    "Supporting evidence",
  );
  const writer = await prepareScanArtifactRestorer(h.options, h.parent);
  const projected = await writer.projectChild(
    fixture.parentScanId,
    fixture.sourceScanId,
    h.source,
  );
  const directory = `${fixture.relativeDirectory}/findings/check-3`;
  expect(
    projected.draft.findings.some(
      (finding) => finding.writeup?.reportPath === `${directory}/check-3.md`,
    ),
  ).toBe(true);
  for (const name of ["check-3.md", evidence])
    expect(await readFile(join(h.parent, directory, name))).toEqual(
      await readFile(join(h.source, "findings/check-3", name)),
    );
});
