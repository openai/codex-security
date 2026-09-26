import { expect } from "bun:test";
import type { JsonObject } from "../../src/config.js";
import type { runWorkbench } from "../../src/runtime.js";

function request(
  args: readonly string[],
  input: string | undefined,
): JsonObject {
  expect(args).toEqual(["finding-workflow"]);
  expect(input).toBeDefined();
  return JSON.parse(input!);
}

export function scriptedWorkbench(
  steps: readonly {
    request: object;
    response?: object | ((request: JsonObject) => object);
    error?: Error;
  }[],
) {
  const requests: {
    args: readonly string[];
    input: string | undefined;
  }[] = [];
  const run: typeof runWorkbench = async (_options, args, input) => {
    const step = steps[requests.length];
    requests.push({ args, input });
    if (!step)
      throw new Error(
        `Unexpected workbench request: ${JSON.stringify({ args, input })}`,
      );
    if (step.error) throw step.error;
    const response =
      typeof step.response === "function"
        ? step.response(request(args, input))
        : step.response;
    return structuredClone(response ?? {}) as JsonObject;
  };
  return {
    run,
    assertDone() {
      // The caller may intentionally catch workbench errors.
      expect(
        requests.map(({ args, input }) => request(args, input)),
      ).toMatchObject(steps.map((step) => step.request));
    },
  };
}

/** A bound workflow's checkpoint storage; no workflow transitions or SQL behavior. */
export function checkpointWorkbench(workflowId: string, source: JsonObject) {
  const reviews = new Map<string, unknown>();
  const saved: JsonObject[] = [];
  const fixture: {
    source: JsonObject;
    saved: JsonObject[];
    run: typeof runWorkbench;
  } = {
    source,
    saved,
    run: (async (_options, args, input) => {
      const payload = request(args, input);
      expect(payload["id"]).toBe(workflowId);
      switch (payload["action"]) {
        case "source":
          expect(payload["repository"]).toBe(fixture.source["repository"]);
          return { source: structuredClone(fixture.source) };
        case "get-review":
          expect(typeof payload["key"]).toBe("string");
          return {
            review: structuredClone(
              reviews.get(payload["key"] as string) ?? null,
            ),
          } as JsonObject;
        case "save-review":
          expect(typeof payload["key"]).toBe("string");
          expect(payload["binding"]).toBeObject();
          expect(payload).toHaveProperty("result");
          saved.push(structuredClone(payload));
          reviews.set(
            payload["key"] as string,
            structuredClone(payload["result"]),
          );
          return {};
        default:
          throw new Error(
            `Unexpected checkpoint request: ${JSON.stringify(payload)}`,
          );
      }
    }) satisfies typeof runWorkbench,
  };
  return fixture;
}
