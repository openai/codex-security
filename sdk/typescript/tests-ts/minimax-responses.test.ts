import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { Codex, type ModelReasoningEffort } from "@openai/codex-sdk";
import { afterEach, expect, test } from "bun:test";
import {
  DEFAULT_CODEX_CONFIG,
  EXTERNAL_CODEX_PROVIDERS,
  mergedCodexConfig,
  resolveCodexProfile,
  scanModelConfiguration,
} from "../src/config.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-minimax-responses-",
);
afterEach(cleanup);

const selections = [
  ["minimax", "MiniMax-M3.1-Flash"],
  ["minimax-cn", "MiniMax-M3.1-Flash"],
  ["minimax", "MiniMax-M3"],
  ["minimax-cn", "MiniMax-M3"],
] as const;

test.each(selections)(
  "%s preserves explicit %s selections in saved profiles",
  async (provider, model) => {
    const config = await mergedCodexConfig({
      codexOverrides: {
        model: "saved-root-model",
        profile: "saved-scan",
        profiles: {
          "saved-scan": {
            model,
            model_provider: provider,
            model_reasoning_effort: "high",
          },
        },
        model_providers: { [provider]: EXTERNAL_CODEX_PROVIDERS[provider] },
      },
    });
    expect(scanModelConfiguration(config)).toEqual({
      model,
      reasoningEffort: "high",
    });
    expect(resolveCodexProfile(config)["model_provider"]).toBe(provider);
    expect(config["service_tier"]).toBeUndefined();
    expect(config["model"]).toBe("saved-root-model");
  },
);

test("preserves a custom MiniMax endpoint, model, effort, and explicit tier", async () => {
  const overrides = {
    model_provider: "minimax",
    model: "custom/text-model",
    model_reasoning_effort: "max",
    service_tier: "priority",
    model_providers: {
      minimax: {
        ...EXTERNAL_CODEX_PROVIDERS.minimax,
        base_url: "https://gateway.example.test/v1",
        env_key: "CUSTOM_GATEWAY_KEY",
      },
    },
  };
  expect(await mergedCodexConfig({ codexOverrides: overrides })).toMatchObject(
    overrides,
  );
});

test.each(selections)(
  "%s sends %s through the SDK Responses HTTP boundary",
  async (provider, model) => {
    const preset = EXTERNAL_CODEX_PROVIDERS[provider];
    expect(preset.base_url).toBe(
      provider === "minimax"
        ? "https://api.minimax.io/v1"
        : "https://api.minimaxi.com/v1",
    );
    const requests: {
      method: string;
      path: string;
      authorization: string | null;
      body: Record<string, unknown>;
    }[] = [];
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      async fetch(request) {
        requests.push({
          method: request.method,
          path: new URL(request.url).pathname,
          authorization: request.headers.get("authorization"),
          body: (await request.json()) as Record<string, unknown>,
        });
        const item = {
          type: "message",
          id: "message_fixture",
          role: "assistant",
          status: "completed",
          phase: "final_answer",
          content: [
            {
              type: "output_text",
              text: "Synthetic response.",
              annotations: [],
            },
          ],
        };
        const events = [
          {
            type: "response.created",
            response: {
              id: "response_fixture",
              status: "in_progress",
              output: [],
            },
          },
          { type: "response.output_item.added", output_index: 0, item },
          { type: "response.output_item.done", output_index: 0, item },
          {
            type: "response.completed",
            response: {
              id: "response_fixture",
              status: "completed",
              output: [item],
              usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 },
            },
          },
        ];
        return new Response(
          events
            .map(
              (event) =>
                `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`,
            )
            .join(""),
          { headers: { "Content-Type": "text/event-stream" } },
        );
      },
    });
    try {
      const root = await temporaryDirectory();
      const home = join(root, "codex-home");
      await mkdir(home, { mode: 0o700 });
      const config = await mergedCodexConfig({
        codexOverrides: {
          model,
          model_provider: provider,
          model_providers: { [provider]: preset },
        },
      });
      const selected = scanModelConfiguration(config);
      const codexPathOverride = process.env["CODEX_SECURITY_TEST_CODEX_PATH"];
      const codex = new Codex({
        ...(codexPathOverride ? { codexPathOverride } : {}),
        env: {
          PATH: process.env["PATH"] ?? "",
          HOME: root,
          CODEX_HOME: home,
          MINIMAX_API_KEY: "synthetic-minimax-key",
        },
        config: {
          model_provider: provider,
          model_providers: {
            [provider]: { ...preset, base_url: `${server.url.origin}/v1` },
          },
          features: { plugins: false, api_key_model_discovery: false },
        },
      });
      const thread = codex.startThread({
        model: selected.model,
        modelReasoningEffort: selected.reasoningEffort as ModelReasoningEffort,
        workingDirectory: root,
        skipGitRepoCheck: true,
        approvalPolicy: "never",
        sandboxMode: "read-only",
        webSearchMode: "disabled",
      });
      const turn = await thread.run(
        "Return a synthetic response without using tools.",
        { signal: AbortSignal.timeout(20_000) },
      );
      expect(turn.finalResponse).toBe("Synthetic response.");
      expect(selected.reasoningEffort).toBe(
        model === "MiniMax-M3.1-Flash"
          ? "max"
          : (DEFAULT_CODEX_CONFIG["model_reasoning_effort"] as string),
      );
      expect(requests).toHaveLength(1);
      expect(requests[0]).toMatchObject({
        method: "POST",
        path: "/v1/responses",
        authorization: "Bearer synthetic-minimax-key",
        body: { model, stream: true },
      });
      expect(requests[0]!.body["service_tier"]).toBeUndefined();
      expect(requests[0]!.body["reasoning"]).toMatchObject({
        effort: selected.reasoningEffort,
      });
      if (provider === "minimax" && model === "MiniMax-M3.1-Flash") {
        const continued = await thread.run(
          "Continue from the prior synthetic response.",
          { signal: AbortSignal.timeout(20_000) },
        );
        expect(continued.finalResponse).toBe("Synthetic response.");
        expect(requests).toHaveLength(2);
        expect(requests[1]!.body["previous_response_id"]).toBeUndefined();
        expect(JSON.stringify(requests[1]!.body["input"])).toContain(
          "Synthetic response.",
        );
      }
    } finally {
      await server.stop(true);
    }
  },
  60_000,
);
