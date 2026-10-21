import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

function sourceScopeProbe(scenario: string): Record<string, unknown> {
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
  return JSON.parse(new TextDecoder().decode(result.stdout)) as Record<
    string,
    unknown
  >;
}

describe("bundled finding previews", () => {
  test("reads only the immutable source objects selected for the scan", () => {
    expect(sourceScopeProbe("boundaries")).toEqual({
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
    expect(sourceScopeProbe("aliases")).toEqual({
      case: expect.any(Boolean),
      unicode: expect.any(Boolean),
      nonAscii: expect.any(Boolean),
      collisionChecked: true,
    });
  }, 30_000);

  test("requires distinct filesystem witnesses for colliding descendants", () => {
    expect(sourceScopeProbe("descendant_aliases")).toEqual({
      fileAndDirectoryCollisionsChecked: true,
      missingWitnessesOmitted: true,
    });
  }, 30_000);

  test("keeps saved immutable objects readable after replacement refs change", () => {
    expect(sourceScopeProbe("replacements")).toEqual({
      savedObjectsUnchanged: true,
      newReplacementViewOmitted: true,
    });
  }, 30_000);

  test("does not run working-tree filters when registering a committed-ref scan", () => {
    expect(sourceScopeProbe("replacement_filters")).toEqual({
      workingTreeFilterNotRun: true,
      registrationRecipeUnchanged: true,
    });
  }, 30_000);

  test("omits source authority when replacement refs changed the scanned tree", () => {
    expect(sourceScopeProbe("replacement_snapshot")).toEqual({
      mismatchedCaptureOmitted: true,
      ambiguousLegacyViewOmitted: true,
    });
  }, 30_000);

  test("omits stale committed excerpts for working-tree diff scans", () => {
    expect(sourceScopeProbe("working_tree_excerpt")).toEqual({
      authorityOmitted: true,
      currentExcerptOmitted: true,
      legacyExcerptOmitted: true,
      rangeExcerptPreserved: true,
    });
  }, 30_000);

  test("indexes Git names once for large explicit scope lists", () => {
    expect(sourceScopeProbe("indexed_scopes")).toEqual({
      selected: 256,
      linearNormalization: true,
    });
  }, 30_000);

  test("selects source excerpts from the displayed finding locations", () => {
    expect(sourceScopeProbe("display_locations")).toEqual({
      displayed: 8,
      excerptUsesDisplayedLocation: true,
    });
  }, 30_000);

  test("does not grant source scope through a selected directory link", () => {
    expect(sourceScopeProbe("selected_redirects")).toEqual({
      selectedLinkOmitted: true,
      linkedAncestorOmitted: true,
      registrationRecipeUnchanged: true,
      directSelectionPreserved: true,
    });
  }, 30_000);

  test("rejects unsafe finding locations before invoking Git", () => {
    expect(sourceScopeProbe("unsafe_locations")).toEqual({
      unsafePathsRejectedBeforeGit: true,
      invalidLocationRejectedBeforeGit: true,
    });
  }, 30_000);

  test("does not treat links or reparse points as filesystem alias evidence", () => {
    expect(sourceScopeProbe("alias_evidence")).toEqual({
      ordinary: true,
      hardlink: false,
      symlink: false,
      reparse: false,
    });
  }, 30_000);

  test("keeps subdirectory and linked-worktree targets bound to their selected tree", () => {
    expect(sourceScopeProbe("worktrees")).toEqual({
      subdirectoryBound: true,
      linkedWorktreeBound: true,
    });
  }, 30_000);

  test.each(["workspace", "prompt", "headless", "deep", "cli"])(
    "records source authority through the %s scan-start path",
    (writer) => {
      expect(sourceScopeProbe(`writer_${writer}`)).toEqual({
        writer,
        sourceAuthorityRecorded: true,
        launchRecipeUnchanged: true,
        legacyExactScopesPreserved: true,
      });
    },
    30_000,
  );

  test("preserves legacy scans and separately owned migration history", () => {
    expect(sourceScopeProbe("migration")).toEqual({
      legacyAuthorityUnset: true,
      otherMigrationsPreserved: true,
      conflictRejected: true,
    });
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
