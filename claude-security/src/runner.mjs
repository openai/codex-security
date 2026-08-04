import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

import { withoutApiKeys } from "./auth.mjs";
import { PLUGIN_ROOT, SecurityError, isRecord } from "./util.mjs";

export const DEFAULT_MODEL = "claude-opus-5";
export const DEFAULT_EFFORT = "high";
export const EFFORT_LEVELS = ["low", "medium", "high", "xhigh", "max"];

/**
 * Resolves the Claude Code executable.
 *
 * The scan deliberately runs through the installed CLI rather than an API
 * client: the CLI is what holds the subscription OAuth credentials, so this is
 * what makes a scan bill against a Claude Code plan instead of API credits.
 */
export function resolveClaudeCommand(environment = process.env) {
  const explicit = environment["CLAUDE_SECURITY_CLAUDE_PATH"];
  if (typeof explicit === "string" && explicit.trim() !== "") return explicit.trim();
  return process.platform === "win32" ? "claude.exe" : "claude";
}

/**
 * Settings handed to the scan session.
 *
 * Two things matter here. The scan must never modify the repository it is
 * auditing, so writes into the target are denied outright rather than left to
 * the model's judgment. And the session must not inherit the operator's own
 * hooks or CLAUDE.md, which would inject unrelated instructions into a scan
 * prompt and can silently change what gets reported.
 */
export function scanSettings(repositoryRoot) {
  const target = repositoryRoot.split("\\").join("/").replace(/\/+$/, "");
  return {
    permissions: {
      deny: [
        `Edit(${target}/**)`,
        `Write(${target}/**)`,
        `NotebookEdit(${target}/**)`,
        `Edit(${target})`,
        `Write(${target})`,
      ],
    },
  };
}

export function buildClaudeArgs(options) {
  const args = [
    "--print",
    "--output-format",
    "stream-json",
    "--verbose",
    "--model",
    options.model,
    "--permission-mode",
    "bypassPermissions",
    "--plugin-dir",
    PLUGIN_ROOT,
    "--no-session-persistence",
  ];
  if (options.effort) args.push("--effort", options.effort);
  if (options.hermetic !== false) args.push("--setting-sources", "");
  if (options.settings) args.push("--settings", JSON.stringify(options.settings));
  for (const directory of options.addDirs ?? []) args.push("--add-dir", directory);
  if (options.maxTurns !== undefined) args.push("--max-turns", String(options.maxTurns));
  if (options.appendSystemPrompt) {
    args.push("--append-system-prompt", options.appendSystemPrompt);
  }
  if (options.sessionName) args.push("--name", options.sessionName);
  return args;
}

/**
 * Runs one Claude Code session and returns its terminal result.
 *
 * stdout is a JSON stream; anything that fails to parse is kept as raw
 * diagnostic text instead of aborting the scan, because a single malformed
 * line should not discard an otherwise complete run.
 */
export async function runClaudeSession(options) {
  const command = resolveClaudeCommand(options.environment);
  const args = buildClaudeArgs(options);
  const observer = options.observer ?? {};

  return await new Promise((resolvePromise, rejectPromise) => {
    let child;
    try {
      child = spawn(command, args, {
        cwd: options.cwd,
        // Stripped here rather than at the call sites so every session this tool
        // starts — scan, discovery worker, reducer, tail — stays on the plan.
        env: withoutApiKeys(options.environment ?? process.env),
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
      });
    } catch (error) {
      rejectPromise(spawnFailure(command, error));
      return;
    }

    const state = {
      sessionId: null,
      model: null,
      finalText: "",
      result: null,
      usage: null,
      costUsd: null,
      isError: false,
      subtype: null,
      toolCalls: 0,
      rawTail: [],
      stderr: [],
    };
    let settled = false;

    const abort = () => {
      if (settled) return;
      child.kill("SIGTERM");
      // A scan session can be mid-write; give it a moment before escalating.
      setTimeout(() => {
        if (!settled) child.kill("SIGKILL");
      }, 5000).unref?.();
    };
    if (options.signal) {
      if (options.signal.aborted) abort();
      else options.signal.addEventListener("abort", abort, { once: true });
    }

    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      rejectPromise(spawnFailure(command, error));
    });

    const stdout = createInterface({ input: child.stdout, crlfDelay: Infinity });
    stdout.on("line", (line) => {
      const trimmed = line.trim();
      if (trimmed === "") return;
      let event;
      try {
        event = JSON.parse(trimmed);
      } catch {
        state.rawTail.push(trimmed.slice(0, 500));
        if (state.rawTail.length > 20) state.rawTail.shift();
        return;
      }
      try {
        consumeEvent(event, state, observer);
      } catch (error) {
        observer.onObserverError?.(error);
      }
    });

    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => {
      state.stderr.push(chunk);
      if (state.stderr.length > 50) state.stderr.shift();
      observer.onStderr?.(chunk);
    });

    child.on("close", (code, signalName) => {
      if (settled) return;
      settled = true;
      options.signal?.removeEventListener?.("abort", abort);
      const stderrText = state.stderr.join("").trim();

      if (options.signal?.aborted) {
        rejectPromise(new SecurityError("The scan was interrupted.", { exitCode: 130 }));
        return;
      }
      if (state.result === null && code !== 0) {
        rejectPromise(
          new SecurityError(
            claudeFailureMessage(code, signalName, stderrText, state.rawTail),
            { exitCode: 1 },
          ),
        );
        return;
      }
      if (state.result === null) {
        rejectPromise(
          new SecurityError(
            "Claude Code exited without returning a result event." +
              (stderrText === "" ? "" : `\n${stderrText}`),
          ),
        );
        return;
      }
      resolvePromise({
        sessionId: state.sessionId,
        model: state.model,
        text: state.finalText,
        isError: state.isError,
        subtype: state.subtype,
        usage: state.usage,
        costUsd: state.costUsd,
        toolCalls: state.toolCalls,
        exitCode: code ?? 0,
        stderr: stderrText,
      });
    });

    if (child.stdin) {
      child.stdin.on("error", () => {});
      child.stdin.end(options.prompt);
    }
  });
}

function consumeEvent(event, state, observer) {
  if (!isRecord(event)) return;
  observer.onEvent?.(event);
  switch (event["type"]) {
    case "system": {
      if (event["subtype"] === "init") {
        state.sessionId = stringOrNull(event["session_id"]) ?? state.sessionId;
        state.model = stringOrNull(event["model"]) ?? state.model;
        observer.onInit?.({
          sessionId: state.sessionId,
          model: state.model,
          tools: Array.isArray(event["tools"]) ? event["tools"] : [],
        });
      }
      return;
    }
    case "assistant": {
      const message = event["message"];
      if (!isRecord(message)) return;
      const content = Array.isArray(message["content"]) ? message["content"] : [];
      for (const block of content) {
        if (!isRecord(block)) continue;
        if (block["type"] === "text" && typeof block["text"] === "string") {
          observer.onText?.(block["text"]);
        } else if (block["type"] === "tool_use") {
          state.toolCalls += 1;
          observer.onToolUse?.({
            name: stringOrNull(block["name"]) ?? "tool",
            input: isRecord(block["input"]) ? block["input"] : {},
          });
        }
      }
      return;
    }
    case "user": {
      const message = event["message"];
      if (!isRecord(message)) return;
      const content = Array.isArray(message["content"]) ? message["content"] : [];
      for (const block of content) {
        if (isRecord(block) && block["type"] === "tool_result") {
          observer.onToolResult?.({ isError: block["is_error"] === true });
        }
      }
      return;
    }
    case "result": {
      state.result = event;
      state.subtype = stringOrNull(event["subtype"]);
      state.isError = event["is_error"] === true;
      state.finalText = typeof event["result"] === "string" ? event["result"] : "";
      state.usage = isRecord(event["usage"]) ? event["usage"] : null;
      state.costUsd =
        typeof event["total_cost_usd"] === "number" ? event["total_cost_usd"] : null;
      state.sessionId = stringOrNull(event["session_id"]) ?? state.sessionId;
      observer.onResult?.({
        isError: state.isError,
        subtype: state.subtype,
        usage: state.usage,
        costUsd: state.costUsd,
        durationMs: typeof event["duration_ms"] === "number" ? event["duration_ms"] : null,
        numTurns: typeof event["num_turns"] === "number" ? event["num_turns"] : null,
      });
      return;
    }
    default:
  }
}

function stringOrNull(value) {
  return typeof value === "string" && value !== "" ? value : null;
}

function spawnFailure(command, error) {
  if (error?.code === "ENOENT") {
    return new SecurityError(
      `Could not find the Claude Code CLI (${command}). Install it from https://claude.com/claude-code, ` +
        `or set CLAUDE_SECURITY_CLAUDE_PATH to its full path.`,
      { cause: error },
    );
  }
  return new SecurityError(`Could not start Claude Code: ${error?.message ?? error}`, {
    cause: error,
  });
}

function claudeFailureMessage(code, signalName, stderrText, rawTail) {
  const details = [stderrText, rawTail.join("\n")].filter((part) => part && part !== "");
  const suffix = details.length === 0 ? "" : `\n${details.join("\n")}`;
  if (/not logged in|authentication|unauthorized|invalid api key|please run .*login/i.test(stderrText)) {
    return (
      "Claude Code is not authenticated. Run `claude` and sign in with your Claude subscription, " +
      `then retry the scan.${suffix}`
    );
  }
  if (signalName) return `Claude Code was terminated by ${signalName}.${suffix}`;
  return `Claude Code exited with status ${code}.${suffix}`;
}
