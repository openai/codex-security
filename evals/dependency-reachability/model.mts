import { cp, mkdir, readFile, realpath } from "node:fs/promises";
import { join } from "node:path";
import {
  Codex,
  type Usage,
} from "../../sdk/typescript/node_modules/@openai/codex-sdk/dist/index.js";
import * as auth from "../../sdk/typescript/dist/auth.js";
import {
  createIsolatedHome,
  resolveCodexCommand,
} from "../../sdk/typescript/dist/runtime.js";
import {
  preflightEval,
  runStructuredTurn,
} from "../secret-discovery/harness.mts";
import { withEvalState } from "../secret-discovery/runtime.mts";
import { routingSettings } from "../workflow-routing/harness.mts";

const plugin = join(import.meta.dirname, "../../plugins/codex-security");
const skill = "skills/attack-path-analysis";

export async function stageSkill(root: string) {
  const runtime = join(root, "runtime");
  await mkdir(runtime);
  for (const directory of [skill, "references"]) {
    await cp(join(plugin, directory), join(runtime, directory), {
      recursive: true,
    });
  }
  const path = join(runtime, skill, "SKILL.md");
  return { runtime, path, instructions: await readFile(path, "utf8") };
}

interface ModelState {
  root: string;
  signal: AbortSignal;
  run(
    repo: string,
    question: string,
    schema: unknown,
  ): Promise<{
    answer: unknown;
    usage: Usage | null;
  }>;
}

export function modelSettings(
  home: string,
  codexPath: string,
  environment = process.env,
) {
  const settings = routingSettings(home, codexPath, environment);
  // These native CLI authentication fields are non-inheritable by model tools.
  for (const name of [
    "OPENAI_FEDERATION_RULE_ID",
    "OPENAI_IDENTITY_TOKEN_FILE",
    "OPENAI_WORKLOAD_IDENTITY_CONTEXT",
  ]) {
    if (environment[name] !== undefined) settings.env[name] = environment[name];
  }
  return settings;
}

export async function withModel(
  model: string | undefined,
  execute: (state: ModelState) => Promise<void>,
) {
  const ambientHome = (
    auth as unknown as typeof import("../../sdk/typescript/src/auth.js")
  ).configuredCodexHome(process.env);
  await withEvalState(
    createIsolatedHome,
    ambientHome,
    async ({ root, home, signal }) => {
      const codexPath = await realpath(resolveCodexCommand({}).command);
      const settings = modelSettings(home, codexPath);
      const { runtime, path, instructions } = await stageSkill(root);
      await execute({
        root,
        signal,
        async run(repo, question, schema) {
          signal.throwIfAborted();
          const prepared = { repo, runtime };
          const codex = new Codex(
            await preflightEval(prepared, settings, signal),
          );
          const prompt = [
            "Apply the production attack-path-analysis skill below to the supplied finding. Inspect the current source snapshot offline and read-only. Return the requested JSON.",
            `Resolve skill references relative to ${path}.`,
            instructions,
            question,
          ].join("\n\n");
          const { finalResponse, usage } = await runStructuredTurn(
            prepared,
            codex,
            prompt,
            schema,
            { model, signal },
          );
          return {
            answer: JSON.parse(finalResponse) as unknown,
            usage: usage ?? null,
          };
        },
      });
    },
  );
}
