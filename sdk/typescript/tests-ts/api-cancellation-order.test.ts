import { afterEach, expect, test } from "bun:test";
import { ScanCostTrackingError } from "../src/deep-scan.js";
import { ScanInterruptedError } from "../src/errors.js";
import { ScanPermissionError } from "../src/scan-execution.js";
import type { WorkbenchCommandOptions as RequiredWorkbenchCommandOptions } from "../src/runtime.js";
import {
  cancellationSetup,
  mockWorkbench,
  TestClient,
} from "./support/api-client.js";
import { createApiTestFixtures } from "./support/api-events.js";

const fixtures = createApiTestFixtures();
afterEach(fixtures.cleanup);

test.each(["ordinary", "permission", "cost tracking"] as const)(
  "records an earlier %s failure when the caller cancels afterward",
  async (kind) => {
    const { repository, scanDir, commands, controller, dependencies } =
      await cancellationSetup(await fixtures.temporaryDirectory());
    const failure =
      kind === "ordinary"
        ? new Error("underlying scan failure")
        : kind === "permission"
          ? new ScanPermissionError(
              "Selected permissions could not be verified",
            )
          : new ScanCostTrackingError("Child usage is unavailable", scanDir);
    const client = new TestClient(
      {},
      {
        ...dependencies,
        runWorkbench: async (
          options: WorkbenchCommandOptions,
          args: readonly string[],
          input?: string,
        ) => {
          commands.push(args);
          if (args[0] === "get-scan-feedback") {
            if (kind === "ordinary")
              return await Promise.reject<never>(failure).finally(() => {
                controller.abort("caller canceled");
              });
            // The host aborts its internal signal with the failure before draining
            // accounting. Deliver the caller's cancellation at that boundary.
            options.signal!.addEventListener(
              "abort",
              () => controller.abort("caller canceled later"),
              { once: true },
            );
            throw failure;
          }
          return mockWorkbench(args, input);
        },
        createCodex: () => {
          throw new Error("Execution must not start after feedback failure");
        },
      },
    );
    try {
      const pending = client.run(repository, { signal: controller.signal });
      if (kind === "ordinary") {
        await expect(pending).rejects.toBeInstanceOf(ScanInterruptedError);
        expect(commands.map(([command]) => command)).toEqual([
          "register-cli-scan",
          "get-scan-feedback",
          "fail-scan",
        ]);
      } else await expect(pending).rejects.toBe(failure);
      expect(controller.signal.aborted).toBe(true);
      expect(commands.filter(([command]) => command === "cancel-scan")).toEqual(
        [],
      );
      expect(commands.some(([command]) => command === "complete-scan")).toBe(
        false,
      );
      expect(commands.at(-1)).toEqual([
        "fail-scan",
        "--scan-id",
        "scan_example_001",
        "--message",
        failure.message,
      ]);
    } finally {
      await client.close();
    }
  },
);

type WorkbenchCommandOptions = Omit<
  RequiredWorkbenchCommandOptions,
  "python"
> & { python?: string };
