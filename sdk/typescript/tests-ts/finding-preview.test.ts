import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

function checkSourceScope(scenario: string, expected: unknown = null): void {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  const result = Bun.spawnSync(
    [
      python!,
      "-I",
      "-B",
      fileURLToPath(new URL("./fixtures/source_scopes.py", import.meta.url)),
      join(PLUGIN_ROOT, "scripts"),
      scenario,
    ],
    { stdout: "pipe", stderr: "pipe" },
  );
  expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
  expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual(expected);
}

describe("bundled finding previews", () => {
  test("reads only the immutable source objects selected for the scan", () => {
    checkSourceScope("boundaries", {
      selected: "1  public source",
      outside: null,
      additional: "1  selected file",
      repository: "1  private source",
      fileDescendant: null,
      traversal: null,
      absolute: null,
      redirected: null,
      escaped: null,
      legacyScoped: "1  public source",
      legacyUnmarkedFile: "1  selected file",
      legacyUnmarkedFileDescendant: null,
      legacyRoot: "1  private source",
      legacyKnownDirectory: "1  public source",
      legacyKnownFile: "1  selected file",
      legacyFileDescendant: null,
      emptyAuthority: null,
      dirty: null,
      fallback: "1  public source",
      rootControl: "1  public source",
      replacedFile: "1  selected file",
      replacedFileDescendant: null,
      removedDirectory: "1  nested source",
      offline: "1  public source",
      missingObject: null,
    });
  }, 30_000);

  test("keeps captured filesystem aliases usable after their source paths disappear", () => {
    checkSourceScope("aliases", {
      case: expect.any(Boolean),
      unicode: expect.any(Boolean),
      nonAscii: expect.any(Boolean),
      collisionChecked: true,
    });
  }, 30_000);

  test("requires distinct filesystem witnesses for colliding descendants", () => {
    checkSourceScope("descendant_aliases");
  }, 30_000);

  test("keeps saved immutable objects readable after replacement refs change", () => {
    checkSourceScope("replacements");
  }, 30_000);

  test("does not run working-tree filters when registering a committed-ref scan", () => {
    checkSourceScope("replacement_filters");
  }, 30_000);

  test("omits source authority when replacement refs changed the scanned tree", () => {
    checkSourceScope("replacement_snapshot");
  }, 30_000);

  test("omits stale committed excerpts for working-tree diff scans", () => {
    checkSourceScope("working_tree_excerpt", {
      authorityOmitted: true,
      currentExcerptOmitted: true,
      legacyExcerptOmitted: true,
      rangeExcerptPreserved: true,
    });
  }, 30_000);

  test("indexes Git names once for large explicit scope lists", () => {
    checkSourceScope("indexed_scopes", 256);
  }, 30_000);

  test("selects source excerpts from the displayed finding locations", () => {
    checkSourceScope("display_locations", 8);
  }, 30_000);

  test("does not grant source scope through a selected directory link", () => {
    checkSourceScope("selected_redirects");
  }, 30_000);

  test("rejects unsafe finding locations before invoking Git", () => {
    checkSourceScope("unsafe_locations");
  }, 30_000);

  test("does not treat links or reparse points as filesystem alias evidence", () => {
    checkSourceScope("alias_evidence", {
      ordinary: true,
      hardlink: false,
      symlink: false,
      reparse: false,
    });
  }, 30_000);

  test("keeps subdirectory and linked-worktree targets bound to their selected tree", () => {
    checkSourceScope("worktrees");
  }, 30_000);

  test.each(["workspace", "prompt", "headless", "deep", "cli"])(
    "records source authority through the %s scan-start path",
    (writer) => {
      checkSourceScope(`writer_${writer}`, writer);
    },
    30_000,
  );

  test("preserves legacy scans and separately owned migration history", () => {
    checkSourceScope("migration");
  }, 30_000);
});

test("bundled finding previews normalize details without changing stored findings", () => {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  const original = {
    attackPath: { likelihood: "medium" },
    code_evidence: [{ id: "source", code: "synthetic_source()" }],
    rootCause: { summary: "Synthetic root cause." },
  };
  const program = [
    "import json, sys",
    "sys.path.insert(0, sys.argv[1])",
    "from finding_preview import bounded_finding_details",
    "original = json.loads(sys.stdin.read())",
    "projected = bounded_finding_details(original)",
    "print(json.dumps({'projected': projected, 'original': original}))",
  ].join("\n");
  const result = Bun.spawnSync(
    [python!, "-I", "-B", "-c", program, join(PLUGIN_ROOT, "scripts")],
    {
      stdin: new TextEncoder().encode(JSON.stringify(original)),
      stdout: "pipe",
      stderr: "pipe",
    },
  );

  expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
  expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual({
    projected: {
      ...original,
      attackPath: { likelihood: { level: "medium" } },
    },
    original,
  });
});
