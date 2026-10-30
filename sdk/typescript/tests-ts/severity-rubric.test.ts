import { createHash } from "node:crypto";
import { afterEach, expect, mock, spyOn, test } from "bun:test";
import {
  bundledSeverityRubric,
  getDefaultSeverityRubric,
  severityRubricSchema,
} from "../src/severity-rubric.js";
import { rubricConfigResponse } from "./support/rubric-config.js";

const enabledEnvironment = {
  CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC: "1",
};
const previousOptIn =
  process.env["CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC"];

afterEach(() => {
  mock.restore();
  if (previousOptIn === undefined)
    delete process.env["CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC"];
  else
    process.env["CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC"] = previousOptIn;
});

test("uses the bundled policy by default without a request or timeout", async () => {
  delete process.env["CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC"];
  const request = spyOn(globalThis, "fetch").mockRejectedValue(
    new Error("Unexpected remote rubric request"),
  );
  const timeout = spyOn(AbortSignal, "timeout");
  expect(await getDefaultSeverityRubric()).toEqual(bundledSeverityRubric);
  expect(request).not.toHaveBeenCalled();
  expect(timeout).not.toHaveBeenCalled();
});

test.each([undefined, "", "0", "false", "true", " 1", "1 "])(
  "selected environment value %j disables fetching even when the parent opted in",
  async (value) => {
    process.env["CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC"] = "1";
    const request = spyOn(globalThis, "fetch").mockRejectedValue(
      new Error("Unexpected remote rubric request"),
    );
    const timeout = spyOn(AbortSignal, "timeout");
    expect(
      await getDefaultSeverityRubric({
        environment: { CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC: value },
      }),
    ).toEqual(bundledSeverityRubric);
    expect(request).not.toHaveBeenCalled();
    expect(timeout).not.toHaveBeenCalled();
  },
);

test("concurrent operations keep their opt-in and selected policies isolated", async () => {
  const config = { markdown: "# Selected remote policy", revision: 9 };
  const request = spyOn(globalThis, "fetch").mockResolvedValue(
    rubricConfigResponse(config),
  );
  const [enabled, disabled] = await Promise.all([
    getDefaultSeverityRubric({ environment: enabledEnvironment }),
    getDefaultSeverityRubric({ environment: {} }),
  ]);
  expect(enabled).toMatchObject(config);
  expect(disabled).toEqual(bundledSeverityRubric);
  expect(request).toHaveBeenCalledTimes(1);
});

test.each([{}, enabledEnvironment])(
  "already canceled operations reject without fetching with environment %j",
  async (environment) => {
    const reason = new Error("Owner canceled");
    const request = spyOn(globalThis, "fetch").mockRejectedValue(
      new Error("Unexpected remote rubric request"),
    );
    await expect(
      getDefaultSeverityRubric({
        environment,
        signal: AbortSignal.abort(reason),
      }),
    ).rejects.toBe(reason);
    expect(request).not.toHaveBeenCalled();
  },
);

test("resolves the shared config without account credentials and refreshes each operation", async () => {
  const config = {
    markdown: "# Policy\nUse the supplied evidence.\n",
    revision: 8,
  };
  const request = spyOn(globalThis, "fetch").mockResolvedValue(
    rubricConfigResponse(config),
  );
  const first = await getDefaultSeverityRubric({
    environment: enabledEnvironment,
  });
  expect(first).toEqual({
    ...config,
    sha256: createHash("sha256").update(config.markdown).digest("hex"),
  });
  const [url, init] = request.mock.calls[0]!;
  expect(url).toBe("https://ab.chatgpt.com/v1/get_config");
  expect(init?.headers).not.toHaveProperty("Authorization");
  expect(JSON.parse(init!.body as string)).toEqual({
    configName: "codex_security_default_severity_rubric",
    statsigMetadata: { exposureLoggingDisabled: true },
  });
  expect(init?.redirect).toBe("error");
  request.mockResolvedValue(rubricConfigResponse({ ...config, revision: 9 }));
  expect(
    (await getDefaultSeverityRubric({ environment: enabledEnvironment }))
      .revision,
  ).toBe(9);
  expect(first.revision).toBe(8);
});

test.each([
  null,
  {},
  { markdown: "", revision: 1 },
  { markdown: " \n", revision: 1 },
  { markdown: false, revision: 1 },
  { markdown: "Policy\0", revision: 1 },
  { markdown: "Policy\ud800", revision: 1 },
  { markdown: "Policy", revision: 0 },
  { markdown: "Policy", revision: 1.5 },
  { markdown: "Policy", revision: Number.MAX_SAFE_INTEGER + 1 },
  { markdown: "Policy", revision: "1" },
  { markdown: "Policy", revision: 1, extra: true },
])("invalid config %j uses the bundled SDK policy", async (config) => {
  spyOn(globalThis, "fetch").mockResolvedValue(rubricConfigResponse(config));
  expect(
    await getDefaultSeverityRubric({ environment: enabledEnvironment }),
  ).toEqual(bundledSeverityRubric);
});

test("oversized UTF-8 Markdown uses the bundled policy", async () => {
  spyOn(globalThis, "fetch").mockResolvedValue(
    rubricConfigResponse({
      markdown: "😀".repeat(196_608 / 4 + 1),
      revision: 1,
    }),
  );
  expect(
    await getDefaultSeverityRubric({ environment: enabledEnvironment }),
  ).toEqual(bundledSeverityRubric);
});

test.each(["missing", "wrong-name", "json", "http", "network", "timeout"])(
  "%s runtime failure preserves the bundled default",
  async (scenario) => {
    const request = spyOn(globalThis, "fetch");
    if (scenario === "missing") request.mockResolvedValue(Response.json({}));
    if (scenario === "wrong-name")
      request.mockResolvedValue(
        rubricConfigResponse(
          { markdown: "Policy", revision: 3 },
          "unrelated_config",
        ),
      );
    if (scenario === "json")
      request.mockResolvedValue(new Response("not JSON"));
    if (scenario === "http")
      request.mockResolvedValue(new Response("Unavailable", { status: 503 }));
    if (scenario === "network")
      request.mockRejectedValue(new TypeError("Offline"));
    if (scenario === "timeout") {
      const timeout = AbortSignal.abort(
        new DOMException("Timed out", "TimeoutError"),
      );
      spyOn(AbortSignal, "timeout").mockReturnValue(timeout);
      request.mockRejectedValue(timeout.reason);
    }
    expect(
      await getDefaultSeverityRubric({ environment: enabledEnvironment }),
    ).toEqual(bundledSeverityRubric);
  },
);

test("caller cancellation rejects instead of silently selecting a fallback", async () => {
  const controller = new AbortController();
  const reason = new Error("Owner canceled");
  spyOn(globalThis, "fetch").mockRejectedValue(reason);
  queueMicrotask(() => controller.abort(reason));
  await expect(
    getDefaultSeverityRubric({
      signal: controller.signal,
      environment: enabledEnvironment,
    }),
  ).rejects.toBe(reason);
});

test("an unrelated response field cannot invalidate the requested rubric", async () => {
  const value = { markdown: "# Selected rubric", revision: 14 };
  spyOn(globalThis, "fetch").mockResolvedValue(
    Response.json({
      name: "codex_security_default_severity_rubric",
      value,
      dynamic_configs: { unrelated: null },
    }),
  );
  expect(
    await getDefaultSeverityRubric({ environment: enabledEnvironment }),
  ).toMatchObject(value);
});

test.each(["read", "cleanup"])(
  "caller cancellation during response %s preserves its reason",
  async (phase) => {
    const controller = new AbortController();
    const reason = new Error("Caller stopped");
    const value = { markdown: "# Selected rubric", revision: 14 };
    const response =
      phase === "read"
        ? rubricConfigResponse(value)
        : new Response(
            new ReadableStream({
              cancel() {
                controller.abort(reason);
              },
            }),
            { status: 503 },
          );
    if (phase === "read") {
      const json = response.json.bind(response);
      spyOn(response, "json").mockImplementation(async () => {
        controller.abort(reason);
        return json();
      });
    }
    spyOn(globalThis, "fetch").mockResolvedValue(response);
    await expect(
      getDefaultSeverityRubric({
        environment: enabledEnvironment,
        signal: controller.signal,
      }),
    ).rejects.toBe(reason);
  },
);

test("explicit snapshots require the exact Markdown hash", () => {
  expect(severityRubricSchema.parse(bundledSeverityRubric)).toEqual(
    bundledSeverityRubric,
  );
  expect(() =>
    severityRubricSchema.parse({
      ...bundledSeverityRubric,
      markdown: "changed",
    }),
  ).toThrow("SHA-256");
});
