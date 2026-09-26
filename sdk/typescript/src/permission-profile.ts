import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { isDeepStrictEqual } from "node:util";
import {
  Codex,
  type CodexOptions,
  type Thread,
  type ThreadOptions,
  type TurnOptions,
} from "@openai/codex-sdk";
import { parse as parseToml } from "smol-toml";
import { deepMerge, inlineToml, type JsonObject } from "./config.js";
import { ScanPermissionError } from "./scan-execution.js";
import { VERSION } from "./version.js";

/** Verify managed permissions before each fresh or resumed Deep Scan worker turn. */
export function createPermissionCheckedCodex({
  config,
  configOverrides,
  ...options
}: CodexOptions) {
  // Raw tables preserve literal MCP server names and filesystem selectors.
  const overrides = [
    ...Object.entries((config ?? {}) as JsonObject).map(
      ([name, value]) => `${name}=${inlineToml(value)}`,
    ),
    ...(configOverrides ?? []),
  ];
  const environment = { ...options.env };
  environment["CODEX_INTERNAL_ORIGINATOR_OVERRIDE"] ||= "codex_sdk_ts";
  if (options.apiKey) environment["CODEX_API_KEY"] = options.apiKey;
  const codex = new Codex({
    ...options,
    env: environment,
    configOverrides: overrides,
  });
  const wrap = (thread: Thread, threadOptions: ThreadOptions) => ({
    get id() {
      return thread.id;
    },
    async runStreamed(input: string, turnOptions: TurnOptions = {}) {
      const parentSignal = turnOptions.signal;
      const controller = new AbortController();
      const signal = controller.signal;
      const turnConfig = {
        ...(options.baseUrl ? { openai_base_url: options.baseUrl } : {}),
        ...(threadOptions.model ? { model: threadOptions.model } : {}),
        ...(threadOptions.sandboxMode
          ? { sandbox_mode: threadOptions.sandboxMode }
          : {}),
        ...(threadOptions.modelReasoningEffort
          ? { model_reasoning_effort: threadOptions.modelReasoningEffort }
          : {}),
        ...(threadOptions.networkAccessEnabled === undefined
          ? {}
          : {
              "sandbox_workspace_write.network_access":
                threadOptions.networkAccessEnabled,
            }),
        ...(threadOptions.webSearchMode
          ? { web_search: threadOptions.webSearchMode }
          : threadOptions.webSearchEnabled === undefined
            ? {}
            : {
                web_search: threadOptions.webSearchEnabled
                  ? "live"
                  : "disabled",
              }),
        ...(threadOptions.approvalPolicy
          ? { approval_policy: threadOptions.approvalPolicy }
          : {}),
      };
      const effectiveOverrides = [
        ...overrides,
        ...Object.entries(turnConfig).map(
          ([name, value]) => `${name}=${inlineToml(value)}`,
        ),
      ];
      const effectiveConfig = effectiveOverrides.reduce(
        (result, override) =>
          deepMerge(result, parseToml(override) as JsonObject),
        {} as JsonObject,
      );
      const profileId = effectiveConfig["default_permissions"];
      const expectedProfile =
        typeof profileId === "string"
          ? record(record(effectiveConfig["permissions"])?.[profileId])
          : undefined;
      if (
        typeof profileId !== "string" ||
        !expectedProfile ||
        !options.codexPathOverride
      ) {
        throw new ScanPermissionError(
          "Scan permissions could not be verified.",
        );
      }
      // The parent signal can outlive this turn and its SDK child.
      const abort = () => controller.abort(parentSignal?.reason);
      const detachAbort = () =>
        parentSignal?.removeEventListener("abort", abort);
      if (parentSignal?.aborted) abort();
      else parentSignal?.addEventListener("abort", abort, { once: true });
      try {
        await verifyPermissionProfile({
          executable: options.codexPathOverride,
          cwd: threadOptions.workingDirectory ?? process.cwd(),
          environment,
          overrides: effectiveOverrides,
          profileId,
          expectedProfile,
          signal,
        });
      } catch (error) {
        detachAbort();
        throw error;
      }
      return {
        events: (async function* () {
          try {
            const { events } = await thread.runStreamed(input, {
              ...turnOptions,
              signal,
            });
            for await (const event of events) {
              const message =
                event.type === "error"
                  ? event.message
                  : event.type === "item.completed" &&
                      event.item.type === "error"
                    ? event.item.message
                    : undefined;
              if (isPermissionFallback(message, profileId)) {
                const error = new ScanPermissionError(
                  `Codex rejected the required ${profileId} permission profile. The scan was stopped.`,
                );
                controller.abort(error);
                throw error;
              }
              yield event;
            }
          } finally {
            detachAbort();
          }
        })(),
      };
    },
  });
  return {
    startThread: (threadOptions: ThreadOptions) =>
      wrap(codex.startThread(threadOptions), threadOptions),
    resumeThread: (id: string, threadOptions: ThreadOptions) =>
      wrap(codex.resumeThread(id, threadOptions), threadOptions),
  };
}

async function verifyPermissionProfile(options: {
  executable: string;
  cwd: string;
  environment: Record<string, string>;
  overrides: readonly string[];
  profileId: string;
  expectedProfile: Record<string, unknown>;
  signal: AbortSignal;
}): Promise<void> {
  options.signal.throwIfAborted();
  const child = spawn(
    options.executable,
    [
      ...options.overrides.flatMap((override) => ["--config", override]),
      "app-server",
      "--stdio",
    ],
    {
      cwd: options.cwd,
      env: options.environment,
      signal: options.signal,
      stdio: "pipe",
    },
  );
  const closed = new Promise<void>((resolve) =>
    child.once("close", () => resolve()),
  );
  const failed = new Promise<never>((_resolve, reject) => {
    child.on("error", reject);
    child.stdin.on("error", reject);
  });
  child.stderr.resume();
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  const iterator = lines[Symbol.asyncIterator]();
  let nextId = 0;
  const request = async (method: string, params: Record<string, unknown>) => {
    const id = ++nextId;
    child.stdin.write(`${JSON.stringify({ id, method, params })}\n`);
    while (true) {
      const line = await Promise.race([iterator.next(), failed]);
      if (line.done)
        throw new Error(
          "Codex permission preflight ended before its response.",
        );
      if (!line.value.trim()) continue;
      const message = record(JSON.parse(line.value));
      if (!message)
        throw new Error("Invalid Codex permission preflight response.");
      if (message["id"] === undefined || message["method"] !== undefined)
        continue;
      if (
        message["id"] !== id ||
        message["error"] !== undefined ||
        !record(message["result"])
      ) {
        throw new Error(`Codex permission preflight failed for ${method}.`);
      }
      return message["result"] as Record<string, unknown>;
    }
  };
  try {
    await request("initialize", {
      clientInfo: {
        name: "codex_security_deep_scan",
        version: VERSION,
      },
      capabilities: { experimentalApi: true },
    });
    child.stdin.write(
      `${JSON.stringify({ method: "initialized", params: {} })}\n`,
    );
    const configResponse = await request("config/read", {
      cwd: options.cwd,
      includeLayers: false,
    });
    let selected: Record<string, unknown> | undefined;
    let cursor: string | undefined;
    const cursors = new Set<string>();
    do {
      const catalog = await request("permissionProfile/list", {
        cwd: options.cwd,
        ...(cursor === undefined ? {} : { cursor }),
      });
      if (!Array.isArray(catalog["data"]))
        throw new Error("Invalid Codex permission profile catalog.");
      for (const value of catalog["data"]) {
        const entry = record(value);
        if (entry?.["id"] !== options.profileId) continue;
        if (selected) throw new Error("Duplicate Codex permission profile.");
        selected = entry;
      }
      if (catalog["nextCursor"] === null) break;
      if (
        typeof catalog["nextCursor"] !== "string" ||
        !catalog["nextCursor"] ||
        cursors.has(catalog["nextCursor"])
      ) {
        throw new Error("Invalid Codex permission profile cursor.");
      }
      cursor = catalog["nextCursor"];
      cursors.add(cursor);
    } while (true);
    const actual = record(configResponse["config"]);
    const actualProfile = record(
      record(actual?.["permissions"])?.[options.profileId],
    );
    if (
      selected?.["allowed"] !== true ||
      actual?.["default_permissions"] !== options.profileId ||
      !actualProfile ||
      !isDeepStrictEqual(
        comparableProfile(actualProfile),
        comparableProfile(options.expectedProfile),
      )
    ) {
      throw new ScanPermissionError(
        `Codex did not accept the required ${options.profileId} permission profile. The scan did not start.`,
      );
    }
  } catch (error) {
    options.signal.throwIfAborted();
    if (error instanceof ScanPermissionError) throw error;
    throw new ScanPermissionError("Scan permissions could not be verified.", {
      cause: error,
    });
  } finally {
    lines.close();
    child.kill();
    await closed;
  }
}

function comparableProfile(profile: Record<string, unknown>): unknown {
  const { description, ...permissions } = profile;
  if (
    description !== undefined &&
    description !== null &&
    typeof description !== "string"
  ) {
    throw new Error("Invalid permission profile description.");
  }
  return stripNullFields(permissions);
}

function stripNullFields(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stripNullFields);
  const object = record(value);
  return object
    ? Object.fromEntries(
        Object.entries(object)
          .filter(([, item]) => item !== null)
          .map(([name, item]) => [name, stripNullFields(item)]),
      )
    : value;
}

function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function isPermissionFallback(message: unknown, profileId: string): boolean {
  if (typeof message !== "string") return false;
  const warning = message.trim();
  return (
    warning.startsWith(
      "Configured value for `permission_profile` is disallowed by requirements; " +
        `falling back from \`${profileId}\` to required value \``,
    ) && warning.endsWith("`.")
  );
}
