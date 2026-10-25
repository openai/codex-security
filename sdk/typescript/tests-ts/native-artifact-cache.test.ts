import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, renameSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { git } from "./git-fixture.js";
import { bashCommand, writeSource } from "./support/shell.js";

interface Step {
  name?: string;
  id?: string;
  uses?: string;
  run?: string;
  if?: string;
  with?: Record<string, unknown>;
  "continue-on-error"?: boolean;
}

function workflow(name: string) {
  return Bun.YAML.parse(
    readFileSync(
      new URL(`../../../.github/workflows/${name}.yml`, import.meta.url),
      "utf8",
    ),
  ) as {
    on: { workflow_call?: { inputs: Record<string, { default?: unknown }> } };
    jobs: Record<
      string,
      {
        needs?: string | string[];
        if?: string;
        with?: Record<string, unknown>;
        steps?: Step[];
      }
    >;
  };
}

const native = workflow("native-artifacts");
const prepare = native.jobs["prepare"]!;
const keyScript = prepare.steps!.find((step) => step.id === "key")!.run!;

test("native reuse hashes committed inputs with Git alone across platforms", () => {
  const root = mkdtempSync(join(tmpdir(), "native-cache-"));
  const repository = join(root, "repository");
  const output = join(root, "output");
  const source = "plugins/codex-security/native/src/lib.rs";
  const helper = "plugins/codex-security/mcp-app/src/native.ts";
  writeSource(repository, source, "native source\n");
  writeSource(repository, helper, "helper source\n");
  writeSource(repository, "README.md", "documentation\n");
  git(repository, "init", "-q");
  const commit = () => {
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "fixture");
  };
  const key = (week = "2026-43") => {
    writeSource(root, "output", "");
    const result = spawnSync(
      Bun.which(bashCommand())!,
      [
        "--noprofile",
        "--norc",
        "-c",
        `git() { "$TEST_GIT" "$@"; }\ndate() { printf '%s\\n' "$TEST_WEEK"; }\n${keyScript}`,
      ],
      {
        cwd: repository,
        encoding: "utf8",
        env: {
          ...process.env,
          // macOS does not ship GNU sha256sum. Only Git and Bash builtins are
          // available here; the workflow's date command is fixed for this test.
          PATH: root,
          TEST_GIT: Bun.which("git")!,
          GITHUB_OUTPUT: output,
          TEST_WEEK: week,
        },
      },
    );
    expect(result.status, result.stderr).toBe(0);
    return readFileSync(output, "utf8").trim();
  };
  try {
    commit();
    const initial = key();
    expect(initial).toMatch(/^key=native-universal-v1-2026-43-[a-f0-9]{40}$/);
    writeSource(repository, "README.md", "updated documentation\n");
    writeSource(
      repository,
      ".github/scripts/invoice-desk-target.mjs",
      "invoice\n",
    );
    writeSource(
      repository,
      "plugins/codex-security/mcp-app/tests/support/new.ts",
      "fixture\n",
    );
    commit();
    expect(key()).toBe(initial);

    writeSource(
      repository,
      ".github/scripts/new-proof-input.mts",
      "compile me\n",
    );
    commit();
    const changedCompilerInput = key();
    expect(changedCompilerInput).not.toBe(initial);

    writeSource(repository, source, "updated native source\n");
    commit();
    const changedNative = key();
    expect(changedNative).not.toBe(changedCompilerInput);

    writeSource(repository, helper, "updated helper source\n");
    commit();
    const changedHelper = key();
    expect(changedHelper).not.toBe(changedNative);

    renameSync(
      join(repository, source),
      join(repository, "plugins/codex-security/native/src/renamed.rs"),
    );
    commit();
    expect(key()).not.toBe(changedHelper);
    expect(key("2026-44")).not.toBe(key());
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("only exact hits replace fresh native builds and cache failures fall back to proofs", () => {
  const restore = prepare.steps!.find((step) => step.id === "restore")!;
  expect(restore["continue-on-error"]).toBe(true);
  expect(restore.with).not.toHaveProperty("restore-keys");
  const upload = prepare.steps!.find((step) =>
    step.uses?.startsWith("actions/upload-artifact@"),
  )!;
  expect(upload.if).toBe("steps.restore.outputs.cache-hit == 'true'");
  expect(upload.with?.["if-no-files-found"]).toBe("error");
  expect(upload.with?.["name"]).toBe(
    "native-universal-${{ inputs.ref || github.sha }}",
  );
  for (const platform of ["unix", "windows", "musl"]) {
    expect(native.jobs[platform]).toMatchObject({
      needs: "prepare",
      if: "needs.prepare.outputs.cache-hit != 'true'",
    });
  }
});

test("only a successful fresh matrix can save a main-branch cache", () => {
  const bundle = native.jobs["bundle"]!;
  expect(bundle.needs).toEqual(["prepare", "unix", "windows", "musl"]);
  expect(bundle.if).toBe("${{ !cancelled() }}");
  const save = bundle.steps!.find((step) =>
    step.uses?.startsWith("actions/cache/save@"),
  )!;
  expect(save.if).toBe(
    "needs.prepare.outputs.cache-hit != 'true' && github.ref == 'refs/heads/main' && (github.event_name == 'push' || github.event_name == 'schedule') && (inputs.ref == '' || inputs.ref == github.sha)",
  );
  expect(save["continue-on-error"]).toBe(true);
});

test.each([
  {
    cache: "true",
    prepare: "success",
    unix: "skipped",
    windows: "skipped",
    musl: "skipped",
    passes: true,
  },
  {
    cache: "false",
    prepare: "success",
    unix: "success",
    windows: "success",
    musl: "success",
    passes: true,
  },
  {
    cache: "true",
    prepare: "failure",
    unix: "skipped",
    windows: "skipped",
    musl: "skipped",
    passes: false,
  },
  {
    cache: "false",
    prepare: "success",
    unix: "success",
    windows: "failure",
    musl: "success",
    passes: false,
  },
  {
    cache: "",
    prepare: "success",
    unix: "success",
    windows: "success",
    musl: "skipped",
    passes: false,
  },
])("native completion checks the cache or every fresh proof: %j", (result) => {
  const guard = native.jobs["bundle"]!.steps![0]!.run!;
  const checked = spawnSync(bashCommand(), ["-c", guard], {
    encoding: "utf8",
    env: {
      ...process.env,
      CACHE_HIT: result.cache,
      PREPARE_RESULT: result.prepare,
      UNIX_RESULT: result.unix,
      WINDOWS_RESULT: result.windows,
      MUSL_RESULT: result.musl,
    },
  });
  expect(checked.status === 0, checked.stderr).toBe(result.passes);
});

test("source CI and rotating properties opt in to native artifact reuse", () => {
  expect(native.on.workflow_call?.inputs["reuse-verified"]?.default).toBe(
    false,
  );
  expect(workflow("node-ci").jobs["native"]?.with?.["reuse-verified"]).toBe(
    true,
  );
  expect(
    workflow("test-quality").jobs["native"]?.with?.["reuse-verified"],
  ).toBe("${{ !inputs.compare-layouts }}");
  for (const caller of ["node-release", "container-release", "container-ci"]) {
    expect(
      workflow(caller).jobs["native"]?.with?.["reuse-verified"],
    ).toBeUndefined();
  }
});
