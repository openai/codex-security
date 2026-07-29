import { describe, expect, test } from "bun:test";

type PackageProvenance = {
  assertExpectedGitHead: (
    packageJson: { gitHead?: unknown },
    expectedGitHead: string | undefined,
  ) => void;
};

const { assertExpectedGitHead } = (await import(
  new URL("../scripts/package-provenance.mjs", import.meta.url).href
)) as PackageProvenance;

const releaseCommit = "e94d6bef9797a192febfde89a26ec7f831bc09b2";

describe("npm package release provenance", () => {
  test("accepts the exact release commit recorded in the package", () => {
    expect(() =>
      assertExpectedGitHead({ gitHead: releaseCommit }, releaseCommit),
    ).not.toThrow();
  });

  test("keeps gitHead optional for local, CI, and container packages", () => {
    expect(() => assertExpectedGitHead({}, undefined)).not.toThrow();
  });

  test("rejects a release package without gitHead", () => {
    expect(() => assertExpectedGitHead({}, releaseCommit)).toThrow(
      `npm package gitHead must match release commit ${releaseCommit}.`,
    );
  });

  test("rejects a release package built from a different commit", () => {
    expect(() =>
      assertExpectedGitHead(
        { gitHead: "f22d4a36f26d16287bcdfd707b369116e02a08c3" },
        releaseCommit,
      ),
    ).toThrow(
      `npm package gitHead must match release commit ${releaseCommit}.`,
    );
  });

  test("rejects an invalid expected release commit", () => {
    expect(() => assertExpectedGitHead({}, "main")).toThrow(
      "Expected release gitHead must be a full 40-character lowercase Git commit SHA.",
    );
  });
});
