import { describe, expect, test } from "bun:test";

import { packageSmokeTimeouts } from "../scripts/package-smoke-timeouts.mjs";

describe("npm package smoke timeouts", () => {
  test("preserves the command timeout on Linux and macOS", () => {
    for (const platform of ["linux", "darwin"] as const) {
      expect(packageSmokeTimeouts(platform).commandTimeoutMs).toBe(120_000);
    }
  });

  test("extends the Windows install budget without slowing other command failures", () => {
    const { installTimeoutMs, commandTimeoutMs } =
      packageSmokeTimeouts("win32");
    expect(installTimeoutMs).toBe(600_000);
    expect(commandTimeoutMs).toBe(180_000);
  });

  test.each(["linux", "darwin", "win32"] as const)(
    "allows verification and the deliberate Deep Scan retry on %s",
    (platform) => {
      const {
        commandTimeoutMs,
        installTimeoutMs,
        deepScanTimeoutMs,
        processTimeoutMs,
      } = packageSmokeTimeouts(platform);

      expect(deepScanTimeoutMs).toBeGreaterThanOrEqual(
        commandTimeoutMs + 60_000 * 1.3,
      );
      const remainingForCleanup =
        processTimeoutMs -
        installTimeoutMs -
        commandTimeoutMs -
        deepScanTimeoutMs;
      expect(remainingForCleanup).toBeGreaterThan(0);
    },
  );

  test("uses the active runtime platform by default", () => {
    expect(packageSmokeTimeouts()).toEqual(
      packageSmokeTimeouts(process.platform),
    );
  });
});
