import { resolving } from "./support/promises.js";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test, mock } from "bun:test";
import { main } from "../src/cli.js";
import type { FindingsDocument } from "../src/models.js";
import type { OwnerSuggestions } from "../src/suggest-owners.js";
import { capture, dependencies, FakeSignals } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "owner-cli-",
  false,
);
afterEach(cleanup);

async function input() {
  const directory = await temporaryDirectory();
  const contents = await readFile(
    join(PLUGIN_ROOT, "examples", "completed-scan", "findings.json"),
    "utf8",
  );
  await writeFile(join(directory, "findings.json"), contents);
  return {
    directory,
    contents,
    document: JSON.parse(contents) as FindingsDocument,
  };
}

const report: OwnerSuggestions = {
  schemaVersion: 1,
  revision: "a".repeat(40),
  model: "synthetic-model",
  reasoningEffort: "high",
  results: [],
};

test("accepts exported findings, forwards model settings, and leaves the input unchanged", async () => {
  const { directory, contents, document } = await input();
  await mkdir(join(directory, "source repo"));
  const deps = dependencies({ currentDirectory: directory });
  const stdout = capture();
  const stderr = capture();
  deps.suggestOwners = async (repository, findings, options, surface) => {
    expect(repository).toBe(join(directory, "source repo"));
    expect(findings).toEqual(document.findings);
    expect(options).toMatchObject({
      model: "synthetic-model",
      reasoningEffort: "high",
      environment: deps.environment,
    });
    expect(options!.signal).toBeInstanceOf(AbortSignal);
    expect(surface).toBe("cli");
    return report;
  };
  expect(
    await main(
      [
        "suggest-owners",
        "findings.json",
        "--source-root",
        "source repo",
        "--model",
        "synthetic-model",
        "--effort",
        "high",
        "--json",
      ],
      stdout.stream,
      stderr.stream,
      deps,
    ),
    stderr.text(),
  ).toBe(0);
  expect(JSON.parse(stdout.text())).toEqual(report);
  expect(await readFile(join(directory, "findings.json"), "utf8")).toBe(
    contents,
  );
});

test("uses the current repository by default and emits a partial report with exit code 2", async () => {
  const { directory } = await input();
  const deps = dependencies({ currentDirectory: directory });
  const stdout = capture();
  deps.suggestOwners = async (repository, findings, options) => {
    expect(repository).toBe(directory);
    expect(options!.model).toBeUndefined();
    expect(options!.reasoningEffort).toBeUndefined();
    return {
      ...report,
      results: [
        {
          findingId: findings[0]!.findingId,
          occurrenceId: null,
          status: "error",
          owner: null,
          reason: "Model unavailable.",
          evidence: [],
          limitations: [],
        },
      ],
    };
  };
  expect(
    await main(
      ["suggest-owners", "findings.json", "--json"],
      stdout.stream,
      capture().stream,
      deps,
    ),
  ).toBe(2);
  expect(JSON.parse(stdout.text()).results[0].status).toBe("error");
});

test("rejects invalid input and extra arguments before model execution", async () => {
  const { directory } = await input();
  await writeFile(
    join(directory, "invalid.json"),
    '{"findings":[{"title":"Incomplete"}]}',
  );
  const deps = dependencies({ currentDirectory: directory });
  const suggestOwners = mock(resolving(report));
  deps.suggestOwners = suggestOwners;
  for (const args of [
    [],
    ["invalid.json"],
    ["findings.json", "extra"],
    ["findings.json", "--source-root"],
  ]) {
    expect(
      await main(
        ["suggest-owners", ...args],
        capture().stream,
        capture().stream,
        deps,
      ),
    ).toBe(2);
  }
  expect(suggestOwners).not.toHaveBeenCalled();
});

test.each([
  ["SIGINT", 130],
  ["SIGTERM", 143],
] as const)(
  "forwards %s and removes signal listeners",
  async (signal, code) => {
    const { directory } = await input();
    const signals = new FakeSignals();
    const deps = dependencies({ currentDirectory: directory, signals });
    deps.suggestOwners = async (_repository, _findings, options) => {
      signals.emit(signal);
      options!.signal!.throwIfAborted();
      return report;
    };
    expect(
      await main(
        ["suggest-owners", "findings.json"],
        capture().stream,
        capture().stream,
        deps,
      ),
    ).toBe(code);
    expect(signals.listeners.get("SIGINT")?.size).toBe(0);
    expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
  },
);

test("reports owner lookup errors without changing the diagnostic or leaving listeners", async () => {
  const { directory } = await input();
  const signals = new FakeSignals();
  const deps = dependencies({ currentDirectory: directory, signals });
  deps.suggestOwners = async () => {
    throw new Error("Owner lookup failed.");
  };
  const stderr = capture();
  expect(
    await main(
      ["suggest-owners", "findings.json"],
      capture().stream,
      stderr.stream,
      deps,
    ),
  ).toBe(2);
  expect(stderr.text()).toBe("codex-security: Owner lookup failed.\n");
  expect(signals.listeners.get("SIGINT")?.size).toBe(0);
  expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
});
