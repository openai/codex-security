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

function projectFindingDetails(original: Record<string, unknown>) {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();

  const program = [
    "import json, sys",
    "sys.path.insert(0, sys.argv[1])",
    "from finding_preview import bounded_finding_details",
    "original = json.loads(sys.stdin.read())",
    "projected = {name: bounded_finding_details(details) for name, details in original.items()}",
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
  return JSON.parse(new TextDecoder().decode(result.stdout));
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

  test("normalizes attack-path assessments without changing stored finding details", () => {
    const original = {
      scalar: {
        attackPath: {
          impact: "Native memory corruption is possible.",
          likelihood: "medium",
        },
      },
      structured: {
        attackPath: {
          impact: { level: "low", rationale: "Synthetic assessment." },
          likelihood: null,
        },
      },
      absentAssessments: {
        attackPath: { narrative: "Synthetic attack path." },
      },
      absentAttackPath: {
        rootCause: { summary: "Synthetic root cause." },
      },
      bothEvidenceAliases: {
        codeEvidence: [{ id: "canonical", code: "canonical_source()" }],
        code_evidence: [{ id: "legacy", code: "legacy_source()" }],
        rootCause: { summary: "Synthetic root cause." },
      },
      bothRootCauseAliases: {
        rootCause: { code: "SELECT * FROM users" },
        root_cause: {
          code: "os.system(user_input)",
          evidence_refs: ["legacy-source"],
          language: "python",
          summary: "The destination is not contained.",
        },
      },
      invalidLegacyEvidenceFields: {
        code_evidence: [
          {
            id: "legacy-source",
            code: "dangerous_call()",
            startLine: 0,
            endLine: "12",
            label: 7,
            role: { kind: "sink" },
          },
        ],
      },
      malformedCanonicalRootCause: {
        rootCause: { summary: 42 },
        root_cause: {
          summary: "The valid legacy root cause.",
          evidence_refs: ["legacy-root"],
        },
        code_evidence: [{ id: "legacy-root", code: "legacy_root()" }],
      },
    };
    expect(projectFindingDetails(original)).toEqual({
      projected: {
        scalar: {
          attackPath: {
            impact: { rationale: "Native memory corruption is possible." },
            likelihood: { level: "medium" },
          },
        },
        structured: original.structured,
        absentAssessments: original.absentAssessments,
        absentAttackPath: original.absentAttackPath,
        bothEvidenceAliases: {
          codeEvidence: [
            { id: "canonical", code: "canonical_source()" },
            { id: "legacy", code: "legacy_source()" },
          ],
          rootCause: { summary: "Synthetic root cause." },
        },
        bothRootCauseAliases: {
          rootCause: {
            code: "SELECT * FROM users",
            evidenceRefs: ["legacy-source"],
            summary: "The destination is not contained.",
          },
        },
        invalidLegacyEvidenceFields: {
          code_evidence: [{ id: "legacy-source", code: "dangerous_call()" }],
        },
        malformedCanonicalRootCause: {
          rootCause: {
            summary: "The valid legacy root cause.",
            evidenceRefs: ["legacy-root"],
          },
          code_evidence: [{ id: "legacy-root", code: "legacy_root()" }],
        },
      },
      original,
    });
  });

  test("preserves nested attack-path string arrays without relaxing section depth", () => {
    const original = {
      supported: {
        attackPath: {
          dataflow: { evidenceRefs: ["source-to-sink"] },
          reachability: { preconditions: ["The handler is reachable."] },
        },
      },
      tooDeep: {
        attackPath: {
          dataflow: {
            nested: { evidenceRefs: ["must remain depth-limited"] },
          },
        },
      },
    };

    expect(projectFindingDetails(original)).toEqual({
      projected: {
        supported: original.supported,
        tooDeep: {
          attackPath: {
            dataflow: {
              nested: { evidenceRefs: [null] },
            },
          },
        },
      },
      original,
    });
  });

  test("preserves counter-evidence under the validation preview budget", () => {
    const original = {
      finding: {
        validation: {
          evidence: ["x".repeat(20_000)],
          summary: `The traversal was reproduced. ${"x".repeat(20_000)}`,
          method: "focused extraction test",
          evidenceRefs: ["evidence-0"],
          futureMetadata: "x".repeat(20_000),
          counterEvidence: ["Known mitigations remain unverified."],
        },
      },
    };

    const result = projectFindingDetails(original);

    expect(result.projected.finding.validation.counterEvidence).toEqual([
      "Known mitigations remain unverified.",
    ]);
    expect(result.original).toEqual(original);
  });

  test("deduplicates evidence before applying the preview limit", () => {
    const original = {
      finding: {
        codeEvidence: [
          { id: "shared", code: "canonical_shared()" },
          { id: "shared", code: "duplicate_shared()" },
          { id: "canonical-two", code: "canonical_two()" },
          { id: "canonical-three", code: "canonical_three()" },
        ],
        code_evidence: [
          { id: "shared", code: "legacy_shared()" },
          { id: "legacy-four", code: "legacy_four()" },
          { id: "legacy-five", code: "legacy_five()" },
        ],
      },
    };

    const result = projectFindingDetails(original);

    expect(
      result.projected.finding.codeEvidence.map(
        (item: { id: string }) => item.id,
      ),
    ).toEqual(["shared", "canonical-two", "canonical-three", "legacy-four"]);
    expect(result.projected.finding.codeEvidence[0].code).toBe(
      "canonical_shared()",
    );
    expect(result.original).toEqual(original);
  });

  test("filters malformed evidence before applying the preview limit", () => {
    const original = {
      finding: {
        code_evidence: [
          null,
          "junk",
          {},
          { id: "empty", code: "" },
          { id: "valid", code: "valid_source()" },
        ],
      },
    };

    const result = projectFindingDetails(original);

    expect(result.projected.finding.code_evidence).toEqual([
      { id: "valid", code: "valid_source()" },
    ]);
    expect(result.original).toEqual(original);
  });
});
