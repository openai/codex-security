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
  test("preserves the existing timeout on Linux and macOS", () => {
    for (const platform of ["linux", "darwin"] as const) {
      expect(packageSmokeTimeouts(platform)).toEqual({
        commandTimeoutMs: 120_000,
        processTimeoutMs: 150_000,
      });
    }
  });

  test("allows the Windows npm install to complete", () => {
    expect(packageSmokeTimeouts("win32")).toEqual({
      commandTimeoutMs: 180_000,
      processTimeoutMs: 210_000,
    });
  });

  test("keeps the parent smoke timeout above the command timeout", () => {
    for (const platform of ["linux", "darwin", "win32"] as const) {
      const { commandTimeoutMs, processTimeoutMs } =
        packageSmokeTimeouts(platform);

      expect(processTimeoutMs).toBe(commandTimeoutMs + 30_000);
    }
  });

  test("uses the active runtime platform by default", () => {
    expect(packageSmokeTimeouts()).toEqual(
      packageSmokeTimeouts(process.platform),
    );
  });
});
