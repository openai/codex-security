import { describe, expect, test } from "bun:test";

type PackageSmokeTimeouts = {
  packageSmokeTimeouts: (platform?: NodeJS.Platform) => {
    commandTimeoutMs: number;
    processTimeoutMs: number;
  };
};

const { packageSmokeTimeouts } = (await import(
  new URL("../scripts/package-smoke-timeouts.mjs", import.meta.url).href
)) as PackageSmokeTimeouts;

describe("npm package smoke timeouts", () => {
  test("preserves the command timeout on Linux and macOS", () => {
    for (const platform of ["linux", "darwin"] as const) {
      expect(packageSmokeTimeouts(platform).commandTimeoutMs).toBe(120_000);
    }
  });

  test("allows the Windows npm install to complete", () => {
    expect(packageSmokeTimeouts("win32").commandTimeoutMs).toBe(180_000);
  });

  test.each(["linux", "darwin", "win32"] as const)(
    "allows installation and verification to each use a command budget on %s",
    (platform) => {
      const { commandTimeoutMs, processTimeoutMs } =
        packageSmokeTimeouts(platform);

      const remainingAfterInstallation = processTimeoutMs - commandTimeoutMs;
      expect(remainingAfterInstallation).toBeGreaterThan(commandTimeoutMs);
    },
  );

  test("uses the active runtime platform by default", () => {
    expect(packageSmokeTimeouts()).toEqual(
      packageSmokeTimeouts(process.platform),
    );
  });
});
