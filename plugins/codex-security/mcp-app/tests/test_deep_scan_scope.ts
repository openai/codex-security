import assert from "node:assert/strict";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { finding } from "./scan-draft-fixture.ts";
import { fixture } from "./scan-draft-recovery-fixture.ts";
import { readJson } from "./support/json.ts";
const findings = [
  finding("api", "api/source.py"),
  finding("jobs", "background jobs/source.py"),
  finding("unrelated", "unrelated/source.py"),
  finding("prefix", "api-other/source.py"),
];

for (const [mode, complete] of [
  ["deep", true],
  ["deep", false],
  ["standard", true],
] as const) {
  test(`${mode} parent publication keeps its scope behavior (complete=${complete})`, async (t) => {
    const f = await fixture(t, mode);
    f.context.targetContract = {
      ...f.context.targetContract,
      scope: {
        requiredIncludePaths: ["api", "background jobs"],
        requiredExcludePaths: [],
      },
    };
    const input = { ...f.draft({}, true), complete, findings };
    await f.write(input);
    const result = await readJson(f.root, "findings.json");
    assert.deepEqual(
      result.findings.map(
        (row: { identity: { anchor: string } }) => row.identity.anchor,
      ),
      mode === "deep"
        ? ["api", "jobs"]
        : ["api", "jobs", "unrelated", "prefix"],
    );
    assert.equal(input.findings.length, 4);
  });
}

test("Deep publication keeps a finding with any matching location and supports exact files", async (t) => {
  const f = await fixture(t, "deep");
  f.context.targetContract = {
    ...f.context.targetContract,
    scope: {
      requiredIncludePaths: ["api/source.py", "background jobs"],
      requiredExcludePaths: [],
    },
  };
  const mixed = finding("mixed", "unrelated/source.py");
  mixed.locations.push({ path: "api/source.py", startLine: 1, endLine: 2 });
  await f.write({
    ...f.draft({}, true),
    findings: [...findings, mixed, finding("other-api", "api/other.py")],
  });
  const result = await readJson(f.root, "findings.json");
  assert.deepEqual(
    result.findings.map(
      (row: { identity: { anchor: string } }) => row.identity.anchor,
    ),
    ["api", "jobs", "mixed"],
  );
  assert.deepEqual(result.findings.at(-1).locations, mixed.locations);
});

for (const scope of ["./api/", "api/source.py"]) {
  test(`Deep parent publication respects ${scope}`, async (t) => {
    const f = await fixture(t, "deep");
    await mkdir(join(f.root, "api"));
    await writeFile(join(f.root, "api/source.py"), "# scoped file\n");
    f.context.targetContract = {
      ...f.context.targetContract,
      scope: {
        requiredIncludePaths: [scope],
        requiredExcludePaths: [],
        filePaths: scope === "api/source.py" ? [scope] : [],
      },
    };
    await f.write({
      ...f.draft({}, true),
      findings: [findings[0], finding("descendant", "api/source.py/generated")],
    });
    const result = await readJson(f.root, "findings.json");
    assert.deepEqual(
      result.findings.map(
        (row: { identity: { anchor: string } }) => row.identity.anchor,
      ),
      scope === "./api/" ? ["api", "descendant"] : ["api"],
    );
  });
}

for (const layout of ["deep"] as const) {
  for (const scope of ["./api/", "./api/source.py"]) {
    test(`${layout} preserves original ${scope} scope after checkout changes`, async (t) => {
      const f = await fixture(t, layout);
      await mkdir(join(f.root, "api"));
      await writeFile(join(f.root, "api/source.py"), "# original target\n");
      const filePaths = scope.endsWith(".py") ? ["api/source.py"] : [];
      Object.assign(f.context, { includePaths: [scope], filePaths });
      f.context.targetContract = {
        ...f.context.targetContract,
        scope: {
          requiredIncludePaths: [scope],
          requiredExcludePaths: [],
          filePaths,
        },
      };
      const input = {
        ...f.draft({}, true),
        findings: [
          findings[0],
          finding("descendant", "api/source.py/generated"),
        ],
      };
      await f.write(input);
      const checkpoints = await Promise.all(
        (await readdir(join(f.root, "checkpoints"), { withFileTypes: true }))
          .filter((entry) => entry.isFile())
          .map((entry) => entry.name)
          .map(
            async (name) =>
              [
                name,
                await readFile(join(f.root, "checkpoints", name)),
              ] as const,
          ),
      );
      if (filePaths.length) {
        await rm(join(f.root, "api/source.py"));
        await mkdir(join(f.root, "api/source.py"));
      } else {
        await rm(join(f.root, "api"), { recursive: true });
        await writeFile(join(f.root, "api"), "new checkout file\n");
      }
      await f.write(input);
      const result = await readJson(f.root, "findings.json");
      assert.deepEqual(
        result.findings.map(
          (row: { identity: { anchor: string } }) => row.identity.anchor,
        ),
        filePaths.length ? ["api"] : ["api", "descendant"],
      );
      for (const [name, bytes] of checkpoints)
        assert.deepEqual(
          await readFile(join(f.root, "checkpoints", name)),
          bytes,
        );
    });
  }
}
