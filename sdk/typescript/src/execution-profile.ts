import { randomUUID } from "node:crypto";
import { lstat, rm } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import type {
  Codex,
  CodexOptions,
  Thread,
  ThreadOptions,
  TurnOptions,
} from "@openai/codex-sdk";
import { writeCodexConfig, type JsonObject } from "./config.js";
import { createPermissionCheckedCodex } from "./permission-profile.js";
import {
  bundledPluginRoot,
  executablePathForSpawn,
  requirePrivateCredentialHome,
  resolveCodexCommand,
} from "./runtime.js";

/** Use Codex's per-launch profile while keeping its credential store and rollouts. */
export function createExecutionProfileCodex(
  options: CodexOptions,
  codexHome: string,
  configuration: JsonObject,
  checkPermissions = false,
): Pick<Codex, "startThread" | "resumeThread"> {
  const wrap = (
    threadOptions: ThreadOptions,
    resumedId: string | null = null,
  ): Thread => {
    let id = resumedId;
    const thread = {
      get id() {
        return id;
      },
      async runStreamed(input: string, turnOptions: TurnOptions = {}) {
        return {
          events: (async function* () {
            const name = `codex_security_${randomUUID()}`;
            const path = join(codexHome, `${name}.config.toml`);
            if (process.platform === "win32")
              await requirePrivateCredentialHome(
                await lstat(codexHome),
                codexHome,
              );
            try {
              await writeCodexConfig(path, configuration);
              const client = await import(
                pathToFileURL(
                  join(
                    await bundledPluginRoot(),
                    "scripts",
                    "codex_profile.mjs",
                  ),
                ).href
              );
              const command =
                options.codexPathOverride ??
                resolveCodexCommand(options.env).command;
              const codex = client.createCodexProfileClient({
                ...options,
                codexPathOverride: executablePathForSpawn(command),
                profileName: name,
              }) as Pick<Codex, "startThread" | "resumeThread">;
              const checked = checkPermissions
                ? createPermissionCheckedCodex(options, codex)
                : codex;
              const current =
                id === null
                  ? checked.startThread(threadOptions)
                  : checked.resumeThread(id, threadOptions);
              const { events } = await current.runStreamed(input, turnOptions);
              for await (const event of events) {
                id = current.id;
                yield event;
              }
            } finally {
              await rm(path, { force: true });
            }
          })(),
        };
      },
      async run(input: string, turnOptions: TurnOptions = {}) {
        const items: Awaited<ReturnType<Thread["run"]>>["items"] = [];
        let finalResponse = "";
        let usage: Awaited<ReturnType<Thread["run"]>>["usage"] = null;
        const { events } = await thread.runStreamed(input, turnOptions);
        for await (const event of events) {
          if (event.type === "item.completed") {
            items.push(event.item);
            if (event.item.type === "agent_message")
              finalResponse = event.item.text;
          } else if (event.type === "turn.completed") usage = event.usage;
          else if (event.type === "turn.failed")
            throw new Error(event.error.message);
        }
        return { items, finalResponse, usage };
      },
    };
    return thread as Thread;
  };
  return {
    startThread: (options = {}) => wrap(options),
    resumeThread: (id, options = {}) => wrap(options, id),
  };
}
