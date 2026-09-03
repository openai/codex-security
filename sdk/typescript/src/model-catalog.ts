import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { configuredCodexHome } from "./auth.js";
import { codexConfigOverrides, type JsonObject } from "./config.js";
import {
  executablePathForSpawn,
  type CodexCommand,
  type ProcessEnvironment,
} from "./runtime.js";
import { VERSION } from "./version.js";

export interface CatalogModel {
  id: string;
  model: string;
  hidden: boolean;
  upgrade?: string | null;
  upgradeInfo?: { model: string } | null;
  supportedReasoningEfforts: { reasoningEffort: string }[];
  defaultReasoningEffort: string;
  isDefault?: boolean;
}

interface CatalogPage {
  data: CatalogModel[];
  nextCursor?: string | null;
}

interface Message {
  id?: number | string;
  method?: string;
  error?: { message: string };
  result?: unknown;
}

/**
 * Read Codex's catalog using the scan's prepared home and environment.
 * API-key catalogs describe API support, not the selected key's entitlements.
 */
export async function readModelCatalog(
  command: CodexCommand,
  environment: ProcessEnvironment,
  options: { config?: JsonObject; apiKey?: string; signal?: AbortSignal } = {},
): Promise<CatalogModel[]> {
  const { config = {}, apiKey, signal } = options;
  signal?.throwIfAborted();
  const args = [
    "app-server",
    "--stdio",
    ...codexConfigOverrides(config).flatMap((value) => ["--config", value]),
  ];
  if (apiKey !== undefined) {
    args.push("--config", 'cli_auth_credentials_store="ephemeral"');
  }
  const child = spawn(executablePathForSpawn(command.command), args, {
    cwd: configuredCodexHome(environment),
    env: environment,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
    signal,
  });
  const closed = new Promise<void>((resolve) =>
    child.once("close", () => resolve()),
  );
  let processError: Error | undefined;
  child.once("error", (error) => {
    processError = error;
  });
  child.stdin.on("error", (error) => {
    processError = error;
    child.kill();
  });
  child.stderr.resume();
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  const messages = lines[Symbol.asyncIterator]();
  const send = (message: object) =>
    child.stdin.write(`${JSON.stringify(message)}\n`);
  let nextId = 0;
  const request = async (method: string, params: object): Promise<unknown> => {
    signal?.throwIfAborted();
    const id = ++nextId;
    send({ id, method, params });
    while (true) {
      const next = await messages.next();
      signal?.throwIfAborted();
      if (next.done) {
        throw (
          processError ??
          new Error("Codex exited before returning the model catalog.")
        );
      }
      let message: Message;
      try {
        message = JSON.parse(next.value) as Message;
      } catch {
        throw new Error("Codex returned malformed model catalog JSON.");
      }
      if (message.id !== undefined && message.method !== undefined) {
        send({
          id: message.id,
          error: { code: -32601, message: "Unsupported catalog request" },
        });
      } else if (message.id === id) {
        if (message.error !== undefined) {
          throw new Error(message.error.message);
        }
        return message.result;
      }
    }
  };
  try {
    await request("initialize", {
      clientInfo: { name: "codex-security", version: VERSION },
    });
    send({ method: "initialized" });
    if (apiKey !== undefined) {
      await request("account/login/start", { type: "apiKey", apiKey });
    } else {
      const account = (await request("account/read", {
        refreshToken: false,
      })) as { account?: { type: string } | null } | undefined;
      if (account?.account?.type !== "chatgpt") {
        throw new Error(
          "Account-specific model availability could not be determined.",
        );
      }
    }
    const models: CatalogModel[] = [];
    const seenCursors = new Set<string>();
    let cursor: string | null | undefined;
    do {
      const page = (await request("model/list", {
        includeHidden: true,
        ...(cursor === undefined ? {} : { cursor }),
      })) as CatalogPage | undefined;
      if (!Array.isArray(page?.data)) {
        throw new Error("Codex returned an invalid model catalog.");
      }
      models.push(...page.data);
      cursor = page.nextCursor;
      if (cursor !== undefined && cursor !== null) {
        if (seenCursors.has(cursor)) {
          throw new Error("Codex returned a repeated model catalog cursor.");
        }
        seenCursors.add(cursor);
      }
    } while (cursor !== undefined && cursor !== null);
    return models;
  } finally {
    lines.close();
    child.stdin.end();
    if (child.exitCode === null) child.kill();
    await closed;
  }
}
