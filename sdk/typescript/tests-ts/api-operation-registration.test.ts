import { afterEach, expect, spyOn, test } from "bun:test";
import { CodexSecurity } from "../src/api.js";
import * as targets from "../src/targets.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "operation-registration-",
);
afterEach(cleanup);

async function client() {
  const forbidden = () => {
    throw new Error("Unexpected runtime or model boundary");
  };
  return new CodexSecurity(
    {},
    {
      environment: { CODEX_SECURITY_STATE_DIR: await temporaryDirectory() },
      createCodex: forbidden,
      prepareRuntime: forbidden,
    },
    { surface: "sdk" },
  );
}

test.each(["validate", "patch"] as const)(
  "%s reserves its operation before serializing a finding",
  async (method) => {
    const security = await client();
    const gate = Promise.withResolvers<void>();
    const signals: AbortSignal[] = [];
    const normalize = spyOn(targets, "normalizeRepository").mockImplementation(
      async (_path, signal) => {
        signals.push(signal!);
        await gate.promise;
        throw new Error("Synthetic repository boundary");
      },
    );
    let serialized = false;
    let nested: Promise<unknown> | undefined;
    let pending: Promise<unknown> | undefined;
    try {
      pending = security[method]({
        repositoryPath: "/synthetic-outer-never-read",
        finding: {
          toJSON() {
            serialized = true;
            nested = security[method === "validate" ? "patch" : "validate"]({
              repositoryPath: "/synthetic-inner-never-read",
              finding: "Synthetic finding",
            }).catch((error: Error) => error.message);
            return { title: "Synthetic outer finding" };
          },
        },
      }).catch((error: Error) => error.message);
      expect(serialized).toBe(true);
      expect(signals).toHaveLength(1);
      expect(await nested).toContain("operation is already in progress");
      let closed = false;
      const closing = security.close().then(() => {
        closed = true;
      });
      await Promise.resolve();
      expect(closed).toBe(false);
      expect(signals[0]!.aborted).toBe(true);
      gate.resolve();
      expect(await pending).toContain("CodexSecurity is closed");
      await closing;
    } finally {
      gate.resolve();
      await Promise.allSettled([pending, nested]);
      await security.close();
      normalize.mockRestore();
    }
  },
);

test("a synchronous operation callback failure permits same-turn retry", async () => {
  await using security = await client();
  const failure = new Error("Synthetic option getter");
  const pending = security
    .run("/synthetic-never-read", {
      get workflowId(): string {
        throw failure;
      },
    })
    .catch((error: Error) => error);
  const immediateRetry = security
    .validate({
      repositoryPath: "/synthetic-never-read",
      finding: "",
    })
    .catch((error: Error) => error.message);
  const concurrentRetry = security
    .validate({
      repositoryPath: "/synthetic-never-read",
      finding: "",
    })
    .catch((error: Error) => error.message);
  expect(await pending).toBe(failure);
  expect(await immediateRetry).toContain(
    "A finding must be nonempty text or a JSON object",
  );
  expect(await concurrentRetry).toContain("operation is already in progress");
});

test("an asynchronously rejected operation owns its slot until settlement", async () => {
  await using security = await client();
  const failure = new Error("Synthetic finding serialization");
  const pending = security
    .validate({
      repositoryPath: "/synthetic-never-read",
      finding: {
        toJSON() {
          throw failure;
        },
      },
    })
    .catch((error: Error) => error);
  const concurrent = security
    .validate({
      repositoryPath: "/synthetic-never-read",
      finding: "",
    })
    .catch((error: Error) => error.message);
  expect(await pending).toBe(failure);
  expect(await concurrent).toContain("operation is already in progress");
  await expect(
    security.validate({ repositoryPath: "/synthetic-never-read", finding: "" }),
  ).rejects.toThrow("A finding must be nonempty text or a JSON object");
});
