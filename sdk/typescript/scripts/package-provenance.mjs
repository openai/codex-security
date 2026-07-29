const fullGitCommit = /^[0-9a-f]{40}$/u;

export function assertExpectedGitHead(packageJson, expectedGitHead) {
  if (expectedGitHead === undefined) return;

  if (!fullGitCommit.test(expectedGitHead)) {
    throw new Error(
      "Expected release gitHead must be a full 40-character lowercase Git commit SHA.",
    );
  }

  if (packageJson.gitHead !== expectedGitHead) {
    throw new Error(
      `npm package gitHead must match release commit ${expectedGitHead}.`,
    );
  }
}
