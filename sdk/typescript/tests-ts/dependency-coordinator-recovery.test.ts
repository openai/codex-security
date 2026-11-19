import { expect, test } from "bun:test";
import { Ajv2020 } from "ajv/dist/2020.js";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { runCodexSkillCommand } from "../src/cli.js";
import { capture } from "./cli-fixtures.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";
const fixture = fileURLToPath(
  new URL("./fixtures/dependency-recovery.mjs", import.meta.url),
);

for (const scenario of [
  "interrupted",
  "already-complete",
  "second-exit",
  "pending-write",
  "denial",
  "provider-error",
  "stderr-denial",
  "invalid-answer",
  "wrong-thread",
]) {
  test("persistent investigation process lifecycle: " + scenario, async () => {
    await using repo = await scopedTemporaryDirectory(
      "native-recovery-repository-",
    );
    await using state = await scopedTemporaryDirectory(
      "native-recovery-state-",
    );
    const stdout = capture(),
      stderr = capture();
    const evidence: unknown[] = [];
    const execution = runCodexSkillCommand(
      [fixture, repo.path, scenario],
      {
        command: "exploitability check",
        ...(scenario === "invalid-answer" && {
          responseSchema: new Ajv2020().compile({ type: "object" }),
        }),
        stdout: stdout.stream,
        stderr: stderr.stream,
        directory: repo.path,
        appServer: {
          directory: repo.path,
          prompt: "Original investigator assignment.",
          threadSource: "security_validation",
          persistentCoordinator: true,
          cyberAccessProgram: "standard",
          linkedEvidence: {
            async item(e) {
              const p = e["params"] as { item: { result?: unknown } };
              if (p.item.result) evidence.push(p.item.result);
            },
          },
        },
      },
      { command: process.execPath },
      { ...process.env, CODEX_SECURITY_STATE_DIR: state.path },
    );
    const rc =
      scenario === "invalid-answer"
        ? await execution.then(
            () => {
              throw new Error("Accepted malformed answer");
            },
            (error: unknown) => {
              expect(error).toBeInstanceOf(SyntaxError);
              return -1;
            },
          )
        : await execution;
    const calls = (await readFile(join(repo.path, "commands"), "utf8"))
      .trim()
      .split("\n")
      .map((s) => JSON.parse(s) as Record<string, unknown>);
    const resumed = [
      "interrupted",
      "already-complete",
      "second-exit",
      "wrong-thread",
    ].includes(scenario);
    expect(calls.filter((v) => v["launch"])).toHaveLength(resumed ? 2 : 1);
    expect(calls.filter((v) => v["method"] === "thread/start")).toEqual([
      {
        method: "thread/start",
        permissions: "dependency_investigation",
        ephemeral: false,
      },
    ]);
    expect(calls.filter((v) => v["method"] === "thread/resume")).toEqual(
      resumed
        ? [
            {
              method: "thread/resume",
              threadId: "original-thread",
              permissions: "dependency_investigation",
            },
          ]
        : [],
    );
    expect(
      calls.filter((v) => v["prompt"] === "Original investigator assignment."),
    ).toHaveLength(1);
    expect(calls.filter((v) => v["mutation"] === "committed")).toHaveLength(
      scenario === "pending-write" ? 0 : 1,
    );
    expect(evidence).toHaveLength(scenario === "pending-write" ? 0 : 1);
    if (scenario === "interrupted" || scenario === "already-complete") {
      expect(rc).toBe(0);
      expect(stdout.text()).toContain('"restored":true');
    } else expect(rc).not.toBe(0);
    expect(calls.filter((v) => v["method"] === "turn/start")).toHaveLength(
      scenario === "interrupted" || scenario === "second-exit" ? 2 : 1,
    );
  });
}

for (const fails of [false, true]) {
  test(
    "same coordinator thread validates successive submissions" +
      (fails ? " and propagates a terminal error" : ""),
    async () => {
      await using repo = await scopedTemporaryDirectory(
        "native-feedback-repository-",
      );
      await using state = await scopedTemporaryDirectory(
        "native-feedback-state-",
      );
      const stdout = capture(),
        stderr = capture();
      const answers: string[] = [];
      const stop = new Error("The submitted report is blocked.");
      let tokens = 0;
      const execute = runCodexSkillCommand(
        [fixture, repo.path, "feedback"],
        {
          command: "exploitability check",
          stdout: stdout.stream,
          stderr: stderr.stream,
          directory: repo.path,
          appServer: {
            directory: repo.path,
            prompt: "Original investigator assignment.",
            threadSource: "security_validation",
            persistentCoordinator: true,
            cyberAccessProgram: "standard",
            linkedEvidence: {
              async item() {},
              usage(value) {
                tokens += value.total_tokens;
              },
            },
            async onCoordinatorAnswer(text) {
              answers.push(text);
              expect(tokens).toBe(5 * answers.length);
              if (fails && answers.length === 3) throw stop;
              return answers.length < 5
                ? "Check citation " + answers.length
                : undefined;
            },
          },
        },
        { command: process.execPath },
        { ...process.env, CODEX_SECURITY_STATE_DIR: state.path },
      );
      if (fails) await expect(execute).rejects.toBe(stop);
      else {
        expect(await execute).toBe(0);
        expect(stdout.text()).toBe("Submission 5\n");
      }
      const commands = (await readFile(join(repo.path, "commands"), "utf8"))
        .trim()
        .split("\n")
        .map((raw) => JSON.parse(raw));
      expect(commands.filter((v) => v.launch)).toHaveLength(1);
      expect(commands.filter((v) => v.method === "thread/start")).toHaveLength(
        1,
      );
      expect(commands.filter((v) => v.method === "thread/resume")).toHaveLength(
        0,
      );
      expect(commands.filter((v) => v.prompt).map((v) => v.prompt)).toEqual(
        [
          "Original investigator assignment.",
          "Check citation 1",
          "Check citation 2",
          "Check citation 3",
          "Check citation 4",
        ].slice(0, fails ? 3 : 5),
      );
      expect(answers).toEqual(
        Array.from(
          { length: fails ? 3 : 5 },
          (_, i) => "Submission " + (i + 1),
        ),
      );
    },
  );
}
