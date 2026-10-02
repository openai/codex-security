import { expect, test } from "bun:test";
import { prepareExecutionSource } from "../src/execution-preparation.js";
import { environmentValue, rawEnvironmentValue } from "../src/codex-home.js";

test("execution inputs retain selected config, executable and environment", () => {
  const command = { command: "/selected/codex" };
  const configuration = { model: "selected", features: { plugins: true } };
  const environment = {
    OPENAI_API_KEY: "synthetic-original",
    CODEX_HOME: "/selected/home",
  };
  const source = prepareExecutionSource({
    command,
    configuration,
    environment,
  });
  command.command = "/later/codex";
  configuration.features.plugins = false;
  environment.OPENAI_API_KEY = "synthetic-later";
  environment.CODEX_HOME = "/later/home";
  expect(source.command.command).toBe("/selected/codex");
  expect(source.configuration).toEqual({
    model: "selected",
    features: { plugins: true },
  });
  expect(source.environment["CODEX_HOME"]).toBe("/selected/home");
  expect(source.apiKey).toBe("synthetic-original");
});

test("provider selection does not mutate another scan's authentication", () => {
  const environment = {
    OPENAI_API_KEY: "synthetic-openai",
    OPENROUTER_API_KEY: "synthetic-external",
  };
  const chatgpt = prepareExecutionSource({
    command: { command: "codex" },
    configuration: {},
    environment,
    auth: "chatgpt",
  });
  const external = prepareExecutionSource({
    command: { command: "codex" },
    configuration: { model_provider: "openrouter" },
    environment,
  });
  expect(chatgpt.environment["OPENAI_API_KEY"]).toBeUndefined();
  expect(external.environment["OPENAI_API_KEY"]).toBeUndefined();
  expect(external.apiKey).toBe("synthetic-external");
  expect(environment.OPENAI_API_KEY).toBe("synthetic-openai");
});

test("shared environment lookup preserves raw and trimmed contracts", () => {
  const environment = {
    PATH: "  selected path  ",
    empty: "  ",
    Mixed: " value ",
  };
  expect(rawEnvironmentValue(environment, "PATH")).toBe("  selected path  ");
  expect(environmentValue(environment, "PATH")).toBe("selected path");
  expect(rawEnvironmentValue(environment, "mixed")).toBe(" value ");
  expect(rawEnvironmentValue(environment, "empty")).toBeUndefined();
});
