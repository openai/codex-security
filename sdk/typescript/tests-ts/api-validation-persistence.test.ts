import { Database } from "bun:sqlite";
import {
  chmod,
  mkdir,
  readFile,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { join, relative } from "node:path";
import { type ThreadEvent } from "@openai/codex-sdk";
import { describe, expect, test } from "bun:test";
import { OutputDirectoryError, ScanInterruptedError } from "../src/index.js";
import { resolveCodexProfile, type JsonObject } from "../src/config.js";
import { runWorkbench } from "../src/runtime.js";

import { reviewSqliteHome } from "../src/deduplication/codex-review.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { gitText } from "./support/shell.js";
import { createValidationFixtures } from "./support/validation.js";

describe("CodexSecurity finding validation", () => {
  const {
    validationEvents,
    validationClient,
    persistedValidationClient,
    temporaryDirectory,
  } = createValidationFixtures();

  test.each([
    "environment",
    "root configuration",
    "selected profile",
    "repository root",
    "repository ancestor",
  ] as const)(
    "keeps native SQLite state out of validation cache snapshots: %s",
    async (setting) => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const coversRepository =
        setting === "repository root" || setting === "repository ancestor";
      const sqliteHome =
        setting === "repository root"
          ? repository
          : setting === "repository ancestor"
            ? root
            : join(repository, ".native-state", "nested");
      let modelCalls = 0;
      let changeSource = false;
      const writeNativeState = async () => {
        await mkdir(sqliteHome, { recursive: true, mode: 0o700 });
        const database = new Database(join(sqliteHome, "state.sqlite"));
        try {
          database.run("CREATE TABLE IF NOT EXISTS events (message TEXT)");
          database
            .query("INSERT INTO events VALUES (?)")
            .run("Synthetic validation thread");
        } finally {
          database.close();
        }
      };
      async function* events(): AsyncGenerator<ThreadEvent> {
        modelCalls++;
        expect(fixture.captured.codex?.env?.["CODEX_HOME"]).toBe(
          fixture.codexHome,
        );
        expect(
          reviewSqliteHome(
            fixture.captured.codex!.env!,
            resolveCodexProfile(fixture.captured.codex!.config as JsonObject),
          ),
        ).toBe(sqliteHome);
        await writeNativeState();
        if (changeSource)
          await writeFile(join(repository, "source.txt"), "Changed source.\n");
        yield* validationEvents();
      }
      const fixture = await persistedValidationClient(
        events,
        PLUGIN_ROOT,
        root,
        {
          CODEX_HOME: join(root, "ambient-home"),
          CODEX_SQLITE_HOME:
            setting === "root configuration" || setting === "selected profile"
              ? join(root, "unused-environment-storage")
              : sqliteHome,
        },
      );
      await using client = fixture.client;
      if (setting === "root configuration")
        client.config.codexOverrides!["sqlite_home"] = relative(
          fixture.codexHome,
          sqliteHome,
        );
      if (setting === "selected profile") {
        client.config.codexOverrides!["sqlite_home"] = join(
          root,
          "unused-root-storage",
        );
        client.config.codexOverrides!["profile"] = "selected";
        client.config.codexOverrides!["profiles"] = {
          selected: { sqlite_home: relative(fixture.codexHome, sqliteHome) },
        };
      }
      await writeFile(join(repository, "source.txt"), "Original source.\n");
      await writeFile(join(repository, ".gitignore"), ".native-state/\n");
      gitText(["-C", repository, "init", "-q"]);
      gitText(["-C", repository, "add", "."]);
      gitText([
        "-C",
        repository,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.com",
        "commit",
        "-qm",
        "initial",
      ]);
      const snapshots: JsonObject[] = [];
      fixture.workbench.mockImplementation(async (options, args, input) => {
        if (args[0] === "finding-workflow" && input !== undefined) {
          const request = JSON.parse(input) as JsonObject;
          if (
            request["action"] === "source" &&
            request["repository"] === repository
          )
            snapshots.push(request);
        }
        return await runWorkbench(options, args, input);
      });
      const workflowId = await fixture.bindWorkflow("native-sqlite-validation");
      const request = { ...fixture.options, workflowId };
      const first = await client.validate(request);
      expect(first.disposition).toBe("reportable");
      expect(modelCalls).toBe(1);
      await writeNativeState();
      const second = await client.validate(request);
      if (coversRepository) {
        expect(second.disposition).toBe("reportable");
        expect(modelCalls).toBe(2);
        expect(snapshots).toEqual([]);
      } else {
        expect(second).toEqual(first);
        expect(modelCalls).toBe(1);
        expect(
          snapshots.map((snapshot) => snapshot["privateStatePaths"]),
        ).toEqual(Array(4).fill([sqliteHome]));
        changeSource = true;
        await expect(
          client.validate({ ...request, finding: "Another candidate" }),
        ).rejects.toThrow("Repository changed during validation.");
        expect(modelCalls).toBe(2);
      }
    },
  );

  test.each([
    "unchanged",
    "deleted",
    "modified",
    "git metadata",
    "unbound",
    ...(process.platform === "win32" ? [] : ["shared permissions"]),
  ])(
    "checks saved validation evidence before cache reuse: %s",
    async (change) => {
      let modelCalls = 0;
      async function* events(): AsyncGenerator<ThreadEvent> {
        modelCalls++;
        const directory = fixture.captured.thread!.workingDirectory!;
        await writeFile(
          join(directory, "proof.txt"),
          `Synthetic evidence ${modelCalls}.\n`,
        );
        await mkdir(join(directory, ".git"));
        await writeFile(
          join(directory, ".git", "HEAD"),
          "Synthetic Git metadata.\n",
        );
        yield* validationEvents();
      }
      const fixture = await persistedValidationClient(events);
      await using client = fixture.client;
      let unbound = change === "unbound";
      fixture.workbench.mockImplementation(async (options, args, input) => {
        if (args[0] === "finding-workflow" && input !== undefined) {
          const payload = JSON.parse(input);
          if (unbound && payload.action === "save-review") {
            payload.result = payload.result.assessment ?? payload.result;
            input = JSON.stringify(payload);
            unbound = false;
          }
        }
        return await runWorkbench(options, args, input);
      });
      const workflowId = await fixture.bindWorkflow("validation-evidence");
      const request = {
        ...fixture.options,
        outputDir: undefined,
        workflowId,
      };
      const first = await client.validate(request);
      expect(await readFile(join(first.outputDir, "proof.txt"), "utf8")).toBe(
        "Synthetic evidence 1.\n",
      );
      if (change === "deleted") await rm(first.outputDir, { recursive: true });
      if (change === "modified")
        await writeFile(
          join(first.outputDir, "proof.txt"),
          "Changed evidence.\n",
        );
      if (change === "git metadata")
        await writeFile(
          join(first.outputDir, ".git", "HEAD"),
          "Changed metadata.\n",
        );
      if (change === "shared permissions") await chmod(first.outputDir, 0o777);
      const second = await client.validate(request);
      const reusesEvidence =
        change === "unchanged" || change === "shared permissions";
      expect(modelCalls).toBe(reusesEvidence ? 1 : 2);
      expect(await readFile(join(second.outputDir, "proof.txt"), "utf8")).toBe(
        `Synthetic evidence ${modelCalls}.\n`,
      );
      expect(await client.validate(request)).toEqual(second);
      expect(modelCalls).toBe(reusesEvidence ? 1 : 2);
      if (change === "shared permissions") {
        expect(second.outputDir).toBe(first.outputDir);
        expect((await stat(first.outputDir)).mode & 0o777).toBe(0o777);
        expect(await readFile(join(first.outputDir, "proof.txt"), "utf8")).toBe(
          "Synthetic evidence 1.\n",
        );
      }
    },
  );

  test("reuses explicit validation output without overwriting changed evidence", async () => {
    let modelCalls = 0;
    async function* events(): AsyncGenerator<ThreadEvent> {
      modelCalls++;
      await writeFile(
        join(fixture.captured.thread!.workingDirectory!, "proof.txt"),
        "Original evidence.\n",
      );
      yield* validationEvents();
    }
    const fixture = await persistedValidationClient(events);
    await using client = fixture.client;
    const workflowId = await fixture.bindWorkflow(
      "explicit-validation-evidence",
    );
    const request = { ...fixture.options, workflowId };
    const first = await client.validate(request);
    expect(await client.validate(request)).toEqual(first);
    expect(modelCalls).toBe(1);
    if (process.platform !== "win32") {
      await chmod(first.outputDir, 0o770);
      expect(await client.validate(request)).toEqual(first);
      expect((await stat(first.outputDir)).mode & 0o777).toBe(0o770);
    }
    await writeFile(join(first.outputDir, "proof.txt"), "Changed evidence.\n");
    await expect(client.validate(request)).rejects.toBeInstanceOf(
      OutputDirectoryError,
    );
    expect(modelCalls).toBe(1);
    expect(await readFile(join(first.outputDir, "proof.txt"), "utf8")).toBe(
      "Changed evidence.\n",
    );
  });

  test.each(["empty", "nonempty"])(
    "respects a different explicit validation output directory that is %s",
    async (contents) => {
      let modelCalls = 0;
      async function* events(): AsyncGenerator<ThreadEvent> {
        modelCalls++;
        await writeFile(
          join(fixture.captured.thread!.workingDirectory!, "proof.txt"),
          `Synthetic evidence ${modelCalls}.\n`,
        );
        yield* validationEvents();
      }
      const fixture = await persistedValidationClient(events);
      await using client = fixture.client;
      const workflowId = await fixture.bindWorkflow(
        "validation-output-destination",
      );
      const request = { ...fixture.options, workflowId };
      const first = await client.validate(request);
      const outputDir = join(fixture.root, "other-validation");
      await mkdir(outputDir, { mode: 0o700 });
      if (contents === "nonempty") {
        await writeFile(join(outputDir, "proof.txt"), "Existing evidence.\n");
        await expect(
          client.validate({ ...request, outputDir }),
        ).rejects.toBeInstanceOf(OutputDirectoryError);
        expect(modelCalls).toBe(1);
        expect(await readFile(join(outputDir, "proof.txt"), "utf8")).toBe(
          "Existing evidence.\n",
        );
      } else {
        const second = await client.validate({ ...request, outputDir });
        expect(second.outputDir).toBe(await realpath(outputDir));
        expect(modelCalls).toBe(2);
        expect(await readFile(join(outputDir, "proof.txt"), "utf8")).toBe(
          "Synthetic evidence 2.\n",
        );
        expect(await client.validate({ ...request, outputDir })).toEqual(
          second,
        );
        expect(modelCalls).toBe(2);
      }
      expect(await readFile(join(first.outputDir, "proof.txt"), "utf8")).toBe(
        "Synthetic evidence 1.\n",
      );
    },
  );

  test.each(["unavailable", "aborted"] as const)(
    "handles %s evidence fingerprints without caching an invalid result",
    async (mode) => {
      const controller = new AbortController();
      let modelCalls = 0;
      let saved = 0;
      async function* events(): AsyncGenerator<ThreadEvent> {
        modelCalls++;
        yield* validationEvents();
      }
      const fixture = await persistedValidationClient(events);
      await using client = fixture.client;
      fixture.workbench.mockImplementation(async (options, args, input) => {
        if (args[0] === "finding-workflow" && input !== undefined) {
          const payload = JSON.parse(input);
          if (payload.action === "save-review") saved++;
          if (payload.action === "source" && payload.evidence === true) {
            if (mode === "unavailable") return { source: null };
            controller.abort();
          }
        }
        return await runWorkbench(options, args, input);
      });
      const workflowId = await fixture.bindWorkflow(
        "optional-validation-evidence",
      );
      const request = {
        ...fixture.options,
        outputDir: undefined,
        workflowId,
        signal: controller.signal,
      };
      if (mode === "aborted") {
        await expect(client.validate(request)).rejects.toBeInstanceOf(
          ScanInterruptedError,
        );
        expect(modelCalls).toBe(1);
      } else {
        expect((await client.validate(request)).disposition).toBe("reportable");
        expect((await client.validate(request)).disposition).toBe("reportable");
        expect(modelCalls).toBe(2);
      }
      expect(saved).toBe(0);
    },
  );

  function usePersistedValidationWorkbench(
    fixture: Awaited<ReturnType<typeof validationClient>>,
    targetChanged: () => boolean = () => false,
  ) {
    fixture.workbench.mockImplementation(async (options, args, input) => {
      if (args[0] === "get-scan") {
        if (targetChanged())
          throw new Error("The recorded scan target changed.");
        return { scan: { targetPath: fixture.options.repositoryPath } };
      }
      return await runWorkbench(options, args, input);
    });
  }

  test("resumes workflow validation from persisted assessments across clients", async () => {
    let modelCalls = 0;
    let targetChanged = false;
    async function* events() {
      modelCalls += 1;
      if (modelCalls === 2) throw new Error("Second assessment failed.");
      yield* validationEvents();
    }
    const original = await persistedValidationClient(events);
    usePersistedValidationWorkbench(original, () => targetChanged);
    await using originalClient = original.client;
    await original.bindWorkflow("validation-retry");
    const request = {
      ...original.options,
      outputDir: undefined,
      scanId: "recorded-scan",
      workflowId: "validation-retry",
      safetyIdentifier: "synthetic-validation-first",
    };
    const first = await originalClient.validate(request);
    await expect(
      originalClient.validate({ ...request, finding: "Second candidate" }),
    ).rejects.toThrow("Second assessment failed.");
    await originalClient.close();

    const resumed = await persistedValidationClient(
      events,
      PLUGIN_ROOT,
      original.root,
    );
    usePersistedValidationWorkbench(resumed, () => targetChanged);
    await using client = resumed.client;
    expect(await client.validate(request)).toEqual(first);
    expect(modelCalls).toBe(2);
    await client.validate({ ...request, finding: "Second candidate" });
    expect(modelCalls).toBe(3);
    targetChanged = true;
    await expect(client.validate(request)).rejects.toThrow(
      "scan target changed",
    );
    expect(modelCalls).toBe(3);
  });

  test("separates persisted validation by model and access program across clients", async () => {
    let modelCalls = 0;
    async function* events() {
      modelCalls += 1;
      yield* validationEvents();
    }
    const original = await persistedValidationClient(events);
    usePersistedValidationWorkbench(original);
    await using originalClient = original.client;
    await original.bindWorkflow("validation-settings");
    const request = {
      ...original.options,
      outputDir: undefined,
      scanId: "recorded-scan",
      workflowId: "validation-settings",
      safetyIdentifier: "synthetic-validation-first",
    };
    await originalClient.validate(request);
    await originalClient.close();

    const resumed = await persistedValidationClient(
      events,
      PLUGIN_ROOT,
      original.root,
    );
    usePersistedValidationWorkbench(resumed);
    await using client = resumed.client;
    await client.validate(request);
    expect(modelCalls).toBe(1);
    client.config.codexOverrides!["model"] = "changed-validation-model";
    const changedModel = await client.validate(request);
    expect(modelCalls).toBe(2);
    const blue = await client.validate({
      ...request,
      cyberAccessProgram: "daybreak_blue",
    });
    expect(modelCalls).toBe(3);
    const red = await client.validate({
      ...request,
      cyberAccessProgram: "daybreak_red",
    });
    expect(modelCalls).toBe(4);
    expect(
      await client.validate({
        ...request,
        cyberAccessProgram: "daybreak_blue",
      }),
    ).toEqual(blue);
    expect(
      await client.validate({ ...request, cyberAccessProgram: "daybreak_red" }),
    ).toEqual(red);
    expect(modelCalls).toBe(4);
    expect(await client.validate(request)).toEqual(changedModel);
    expect(modelCalls).toBe(4);
  });

  test("separates persisted validation by safety identifier across clients", async () => {
    let modelCalls = 0;
    async function* events() {
      modelCalls += 1;
      yield* validationEvents();
    }
    const original = await persistedValidationClient(events);
    original.client.config.codexOverrides!["model"] =
      "changed-validation-model";
    usePersistedValidationWorkbench(original);
    await using originalClient = original.client;
    await original.bindWorkflow("validation-safety-identifier");
    const request = {
      ...original.options,
      outputDir: undefined,
      scanId: "recorded-scan",
      workflowId: "validation-safety-identifier",
      safetyIdentifier: "synthetic-validation-first",
    };
    const first = await originalClient.validate(request);
    await originalClient.close();

    const resumed = await persistedValidationClient(
      events,
      PLUGIN_ROOT,
      original.root,
    );
    usePersistedValidationWorkbench(resumed);
    await using client = resumed.client;
    client.config.codexOverrides!["model"] = "changed-validation-model";
    await client.validate({ ...request, finding: "Second candidate" });
    expect(modelCalls).toBe(2);
    expect(resumed.captured.codex?.env?.["CODEX_SAFETY_IDENTIFIER"]).toBe(
      request.safetyIdentifier,
    );
    for (const safetyIdentifier of ["synthetic-validation-second", undefined]) {
      const previousCalls = modelCalls;
      const changedRequest = { ...request, safetyIdentifier };
      const assessment = await client.validate(changedRequest);
      expect(modelCalls).toBe(previousCalls + 1);
      expect(resumed.captured.codex?.env?.["CODEX_SAFETY_IDENTIFIER"]).toBe(
        safetyIdentifier,
      );
      expect(await client.validate(changedRequest)).toEqual(assessment);
      expect(modelCalls).toBe(previousCalls + 1);
    }
    expect(await client.validate(request)).toEqual(first);
    expect(modelCalls).toBe(4);
  });
});
