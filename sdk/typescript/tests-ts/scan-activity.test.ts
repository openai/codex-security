import { describe, expect, test } from "bun:test";
import { shellEnvironmentReference } from "../src/codex-prompt.js";
import {
  scanActivitiesFromEvent,
  scanActivityFromEvent,
  scanActivityFromSessionEvent,
} from "../src/scan-activity.js";

function commandEvent(
  type: "item.started" | "item.completed",
  command: string,
  status: "in_progress" | "completed" | "failed" = type === "item.started"
    ? "in_progress"
    : "completed",
): Record<string, unknown> {
  return {
    type,
    item: {
      id: "command-1",
      type: "command_execution",
      command,
      aggregated_output: "",
      status,
    },
  };
}

function toolEvent(
  tool: string,
  arguments_: Record<string, unknown>,
): Record<string, unknown> {
  return {
    type: "item.started",
    item: {
      id: "tool-1",
      type: "mcp_tool_call",
      tool,
      arguments: arguments_,
      status: "in_progress",
    },
  };
}

function sessionEvent(
  payload: Record<string, unknown>,
): Record<string, unknown> {
  return { type: "response_item", payload };
}

describe("scan activity", () => {
  test("reports repository files as soon as a read command starts", () => {
    expect(
      scanActivityFromEvent(
        commandEvent(
          "item.started",
          'nl -ba "$CODEX_SECURITY_REPOSITORY/routes/login.ts" "$CODEX_SECURITY_REPOSITORY/routes/admin.ts"',
        ),
        "/code/juice-shop",
      ),
    ).toEqual({
      id: "command-1",
      kind: "command",
      status: "running",
      description:
        'nl -ba "$CODEX_SECURITY_REPOSITORY/routes/login.ts" "$CODEX_SECURITY_REPOSITORY/routes/admin.ts"',
      paths: ["routes/login.ts", "routes/admin.ts"],
    });
  });

  test("updates a started command when reading completes", () => {
    expect(
      scanActivityFromEvent(
        commandEvent("item.completed", "sed -n 1,80p /code/juice-shop/app.ts"),
        "/code/juice-shop",
      ),
    ).toEqual({
      id: "command-1",
      kind: "command",
      status: "completed",
      description: "sed -n 1,80p /code/juice-shop/app.ts",
      paths: ["app.ts"],
    });
  });

  test("shows exact inventory and repository search commands", () => {
    expect(
      scanActivityFromEvent(
        commandEvent("item.started", "rg --files --hidden"),
        "/code/juice-shop",
      ),
    ).toMatchObject({
      description: "rg --files --hidden",
      paths: [],
    });
    expect(
      scanActivityFromEvent(
        commandEvent(
          "item.started",
          'rg -n "subprocess" "$CODEX_SECURITY_REPOSITORY/server.py"',
        ),
        "/code/juice-shop",
      ),
    ).toMatchObject({
      description: 'rg -n "subprocess" "$CODEX_SECURITY_REPOSITORY/server.py"',
      paths: ["server.py"],
    });
  });

  test("shows the actual command without its shell launcher", () => {
    for (const [wrapped, description] of [
      [
        `/bin/zsh -lc 'rg -n "password" "$CODEX_SECURITY_REPOSITORY/routes/login.ts"'`,
        'rg -n "password" "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
      ],
      [
        `/bin/bash -c 'sed -n 1,80p /code/juice-shop/routes/login.ts'`,
        "sed -n 1,80p /code/juice-shop/routes/login.ts",
      ],
      [
        `/usr/bin/sh -c 'cat "$CODEX_SECURITY_REPOSITORY/routes/login.ts"'`,
        'cat "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
      ],
    ] as const) {
      expect(
        scanActivityFromEvent(
          commandEvent("item.started", wrapped),
          "/code/juice-shop",
        ),
      ).toMatchObject({ description, paths: ["routes/login.ts"] });
    }
  });

  test("removes shell launchers around commands with mixed nested quotes", () => {
    const command =
      `/bin/zsh -c "rg -n '(router\\.|app\\.(get|post))' ` +
      `"$CODEX_SECURITY_REPOSITORY/server/src" | head -500'`;
    expect(
      scanActivityFromEvent(
        commandEvent("item.started", command),
        "/code/juice-shop",
      ),
    ).toMatchObject({
      description:
        `rg -n '(router\\.|app\\.(get|post))' ` +
        `"$CODEX_SECURITY_REPOSITORY/server/src" | head -500'`,
      paths: ["server/src"],
    });
  });

  test("unwraps native PowerShell command events and persisted worker commands", () => {
    const script =
      'Get-Content -LiteralPath "$env:CODEX_SECURITY_REPOSITORY/example.txt"';
    for (const launcher of [
      '"C:\\\\tools\\\\pwsh.exe" -NoProfile',
      '"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -NoProfile',
      '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile',
      "PowerShell.EXE -noprofile",
      "pwsh",
    ]) {
      const command = `${launcher} -Command '${script}'`;
      const expected = {
        description: process.platform === "win32" ? script : command,
        paths: process.platform === "win32" ? ["example.txt"] : [],
      };
      for (const type of ["item.started", "item.completed"] as const) {
        expect(
          scanActivityFromEvent(
            commandEvent(type, command),
            "C:\\code\\project",
          ),
        ).toMatchObject(expected);
      }
      expect(
        scanActivityFromSessionEvent(
          sessionEvent({
            type: "function_call",
            name: "exec_command",
            call_id: "worker-command-1",
            arguments: JSON.stringify({ cmd: command }),
          }),
          "C:\\code\\project",
        ),
      ).toMatchObject(expected);
    }
  });

  test("preserves inner PowerShell literals when removing the shell launcher", () => {
    for (const [script, quote] of [
      ["Write-Output '$env:CODEX_SECURITY_REPOSITORY/example.txt'", '"'],
      ['Write-Output "`$env:CODEX_SECURITY_REPOSITORY/example.txt"', "'"],
    ]) {
      const command = `pwsh -NoProfile -Command ${quote}${script}${quote}`;
      expect(
        scanActivityFromEvent(
          commandEvent("item.started", command),
          "C:\\code\\project",
        ),
      ).toMatchObject({
        description: process.platform === "win32" ? script : command,
        paths: [],
      });
    }
  });

  test("does not remove a shell that is part of the actual command", () => {
    for (const command of [
      "/bin/zsh -i",
      "/bin/zsh -lc unquoted-script",
      "echo '/bin/zsh -lc'",
      "pwsh -NoProfile",
      "pwsh -File 'example.ps1'",
      "pwsh -EncodedCommand 'ZQB4AGEAbQBwAGwAZQA='",
      "other.exe -Command 'example'",
      "echo 'pwsh -Command'",
    ]) {
      expect(
        scanActivityFromEvent(
          commandEvent("item.started", command),
          "/code/juice-shop",
        ),
      ).toMatchObject({ description: command });
    }
  });

  test("shows exact targeted file listing commands", () => {
    expect(
      scanActivityFromEvent(
        commandEvent(
          "item.started",
          'rg --files "$CODEX_SECURITY_REPOSITORY/SECURITY.md"',
        ),
        "/code/juice-shop",
      ),
    ).toMatchObject({
      description: 'rg --files "$CODEX_SECURITY_REPOSITORY/SECURITY.md"',
      paths: ["SECURITY.md"],
    });
  });

  test("does not present plugin instructions as repository files", () => {
    expect(
      scanActivityFromEvent(
        commandEvent(
          "item.started",
          'sed -n 1,160p "$CODEX_SECURITY_PLUGIN_ROOT/skills/security-scan/SKILL.md"',
        ),
        "/code/juice-shop",
      ),
    ).toMatchObject({
      description:
        'sed -n 1,160p "$CODEX_SECURITY_PLUGIN_ROOT/skills/security-scan/SKILL.md"',
      paths: [],
    });
  });

  test("preserves spaces in quoted repository file paths", () => {
    expect(
      scanActivityFromEvent(
        commandEvent(
          "item.started",
          'nl -ba "$CODEX_SECURITY_REPOSITORY/routes/login page.ts"',
        ),
        "/code/juice shop",
      ),
    ).toMatchObject({ paths: ["routes/login page.ts"] });
  });

  test("recognizes repository paths generated for the current shell", () => {
    const command = `${process.platform === "win32" ? "Get-Content -LiteralPath" : "cat"} ${shellEnvironmentReference("CODEX_SECURITY_REPOSITORY", "/src/app.ts")}`;
    expect(
      scanActivityFromEvent(
        commandEvent("item.started", command),
        process.platform === "win32" ? "C:\\code\\project" : "/code/project",
      ),
    ).toMatchObject({ paths: ["src/app.ts"] });
  });

  test("recognizes Windows PowerShell repository environment references", () => {
    for (const [argument, path] of [
      ["$env:CODEX_SECURITY_REPOSITORY/src/app.ts", "src/app.ts"],
      ['"$env:CODEX_SECURITY_REPOSITORY\\src\\app page.ts"', "src/app page.ts"],
      ['"${env:CODEX_SECURITY_REPOSITORY}/src/app.ts"', "src/app.ts"],
      ['"$Env:Codex_Security_Repository\\src\\App.ts"', "src/App.ts"],
      ['"${ENV:codex_security_repository}\\src\\App.ts"', "src/App.ts"],
    ]) {
      const command = `Get-Content -LiteralPath ${argument}`;
      const paths = process.platform === "win32" ? [path] : [];
      expect(
        scanActivityFromEvent(
          commandEvent("item.started", command),
          "C:\\code\\project",
        ),
      ).toMatchObject({ paths });
      expect(
        scanActivityFromSessionEvent(
          sessionEvent({
            type: "function_call",
            name: "exec_command",
            call_id: "worker-command-1",
            arguments: JSON.stringify({ cmd: command }),
          }),
          "C:\\code\\project",
        ),
      ).toMatchObject({ paths });
    }
  });

  test("does not mistake PowerShell literals or other variables for repository paths", () => {
    for (const argument of [
      "'$env:CODEX_SECURITY_REPOSITORY/src/app.ts'",
      "'${env:CODEX_SECURITY_REPOSITORY}/src/app.ts'",
      '"`$env:CODEX_SECURITY_REPOSITORY/src/app.ts"',
      '"$env:CODEX_SECURITY_REPOSITORY_BACKUP/src/app.ts"',
      '"${env:CODEX_SECURITY_REPOSITORY_BACKUP}/src/app.ts"',
      '"$env:CODEX_SECURITY_PLUGIN_ROOT/skills/security-scan/SKILL.md"',
      '"prefix$env:CODEX_SECURITY_REPOSITORY/src/app.ts"',
      '"$env:CODEX_SECURITY_REPOSITORY/../credentials.json"',
      '"${env:CODEX_SECURITY_REPOSITORY}\\src\\..\\..\\credentials.json"',
    ]) {
      expect(
        scanActivityFromEvent(
          commandEvent("item.started", `Get-Content -LiteralPath ${argument}`),
          "C:\\code\\project",
        ),
      ).toMatchObject({ paths: [] });
    }
  });

  test("keeps POSIX environment names case-sensitive", () => {
    expect(
      scanActivityFromEvent(
        commandEvent(
          "item.started",
          'cat "$codex_security_repository/src/app.ts" "${Codex_Security_Repository}/src/app.ts"',
        ),
        "/code/project",
      ),
    ).toMatchObject({ paths: [] });
  });

  test("cleans escaped quotes from real wrapped scan commands", () => {
    expect(
      scanActivityFromEvent(
        commandEvent(
          "item.started",
          'nl -ba "$CODEX_SECURITY_REPOSITORY/commands.py\\" printf "next" "$CODEX_SECURITY_REPOSITORY/server.py\\"',
        ),
        "/code/juice-shop",
      ),
    ).toMatchObject({ paths: ["commands.py", "server.py"] });
  });

  test("never reports paths escaping the scan repository", () => {
    expect(
      scanActivityFromEvent(
        commandEvent(
          "item.started",
          'cat "$CODEX_SECURITY_REPOSITORY/../credentials.json"',
        ),
        "/code/juice-shop",
      ),
    ).toMatchObject({ paths: [] });
  });

  test("keeps Unix and Windows tool paths inside the repository", () => {
    for (const [repository, path, paths] of [
      ["/code/juice-shop", "/code/juice-shop/../credentials.json", []],
      [
        "C:\\code\\juice-shop",
        "C:\\code\\juice-shop\\..\\credentials.json",
        [],
      ],
      [
        "C:\\code\\juice-shop",
        "C:\\code\\juice-shop\\routes\\login.ts",
        ["routes/login.ts"],
      ],
    ] as const) {
      expect(
        scanActivityFromEvent(toolEvent("read_file", { path }), repository),
      ).toMatchObject({ paths: [...paths] });
      expect(
        scanActivityFromSessionEvent(
          sessionEvent({
            type: "function_call",
            name: "read_file",
            call_id: "worker-tool-1",
            arguments: JSON.stringify({ path }),
          }),
          repository,
        ),
      ).toMatchObject({ paths: [...paths] });
    }
  });

  test("reports tool reads and completed reasoning", () => {
    expect(
      scanActivityFromEvent(
        toolEvent("read_file", {
          path: "/code/juice-shop/routes/login.ts",
        }),
        "/code/juice-shop",
      ),
    ).toEqual({
      id: "tool-1",
      kind: "tool",
      status: "running",
      description: "read_file",
      paths: ["routes/login.ts"],
    });
    expect(
      scanActivityFromEvent(
        {
          type: "item.completed",
          item: {
            id: "reasoning-1",
            type: "reasoning",
            text: "Checking authentication\n and route boundaries.",
          },
        },
        "/code/juice-shop",
      ),
    ).toEqual({
      id: "reasoning-1",
      kind: "reasoning",
      status: "completed",
      description: "Checking authentication and route boundaries.",
      paths: [],
    });
    expect(
      scanActivityFromEvent(
        {
          type: "item.updated",
          item: {
            id: "reasoning-2",
            type: "reasoning",
            text: "Following login input into the database.",
          },
        },
        "/code/juice-shop",
      ),
    ).toEqual({
      id: "reasoning-2",
      kind: "reasoning",
      status: "running",
      description: "Following login input into the database.",
      paths: [],
    });
  });

  test("shows complete reasoning without terminal Markdown formatting", () => {
    const detail = "Tracing the authentication boundary. ".repeat(40);
    expect(
      scanActivityFromEvent(
        {
          type: "item.completed",
          item: {
            id: "reasoning-1",
            type: "reasoning",
            text: `**Reviewing authentication**\n\n${detail}`,
          },
        },
        "/code/juice-shop",
      ),
    ).toMatchObject({
      kind: "reasoning",
      description: `Reviewing authentication ${detail.trim()}`,
    });
  });

  test("keeps complete reasoning summary headings separate", () => {
    expect(
      scanActivitiesFromEvent(
        {
          type: "item.completed",
          item: {
            id: "reasoning-1",
            type: "reasoning",
            text:
              "**Implementing safe fallback file generation**\n\n" +
              "**Planning batch file size verification and progress output**",
          },
        },
        "/code/juice-shop",
      ),
    ).toEqual([
      {
        id: "reasoning-1",
        kind: "reasoning",
        status: "completed",
        description: "Implementing safe fallback file generation",
        paths: [],
      },
      {
        id: "reasoning-1:1",
        kind: "reasoning",
        status: "completed",
        description:
          "Planning batch file size verification and progress output",
        paths: [],
      },
    ]);

    expect(
      scanActivitiesFromEvent(
        {
          type: "item.updated",
          item: {
            id: "reasoning-2",
            type: "reasoning",
            text: "**Reviewing authentication**\n\nPreserving detailed prose.",
          },
        },
        "/code/juice-shop",
      ),
    ).toEqual([
      {
        id: "reasoning-2",
        kind: "reasoning",
        status: "running",
        description: "Reviewing authentication Preserving detailed prose.",
        paths: [],
      },
    ]);
  });

  test("preserves fenced blocks and inline code in assistant and worker prose", () => {
    const text =
      "**Reviewing**   `server  source.ts`\n\n" +
      "```ts\n  if (user) {\n    return db.query(user);\n  }\n```\n\n" +
      "Then check   `db.query()` for injection.";
    const description =
      "Reviewing `server  source.ts`\n" +
      "```ts\n  if (user) {\n    return db.query(user);\n  }\n```\n" +
      "Then check `db.query()` for injection.";

    for (const activity of [
      scanActivityFromEvent(
        {
          type: "item.completed",
          item: { id: "message-1", type: "agent_message", text },
        },
        "/code/juice-shop",
      ),
      scanActivityFromSessionEvent(
        {
          type: "event_msg",
          timestamp: "2026-07-26T12:00:00.000Z",
          payload: { type: "agent_reasoning_raw_content", text },
        },
        "/code/juice-shop",
      ),
    ]) {
      expect(activity).toMatchObject({ description });
    }
  });

  test("removes internal progress markers from fenced assistant examples", () => {
    expect(
      scanActivityFromEvent(
        {
          type: "item.completed",
          item: {
            id: "message-1",
            type: "agent_message",
            text:
              "Example:\n```text\n" +
              'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":3,"filesTotal":8}\n' +
              "keep this line\n```",
          },
        },
        "/code/juice-shop",
      ),
    ).toMatchObject({ description: "Example:\n```text\nkeep this line\n```" });
  });

  test("shows actual assistant prose and ignores internal progress markers", () => {
    expect(
      scanActivityFromEvent(
        {
          type: "item.completed",
          item: {
            id: "message-1",
            type: "agent_message",
            text: "The login route reaches the database without validation.",
          },
        },
        "/code/juice-shop",
      ),
    ).toEqual({
      id: "message-1",
      kind: "message",
      status: "completed",
      description: "The login route reaches the database without validation.",
      paths: [],
    });
    expect(
      scanActivityFromEvent(
        {
          type: "item.completed",
          item: {
            id: "marker-1",
            type: "agent_message",
            text: 'CODEX_SECURITY_WORKER_STATUS {"phase":"ranking"}',
          },
        },
        "/code/juice-shop",
      ),
    ).toBeNull();
  });

  test("explains streamed exec and worker-messaging tool calls", () => {
    expect(
      scanActivityFromEvent(
        toolEvent("exec", {
          cmd: 'rg -n "password" "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
        }),
        "/code/juice-shop",
      ),
    ).toMatchObject({
      kind: "tool",
      description:
        'rg -n "password" "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
      paths: ["routes/login.ts"],
    });
    expect(
      scanActivityFromEvent(
        toolEvent("send_message", {
          target: "worker-4",
          message: "Check the login route for SQL injection.",
        }),
        "/code/juice-shop",
      ),
    ).toMatchObject({
      kind: "tool",
      description:
        "send_message → worker-4: Check the login route for SQL injection.",
    });
  });

  test("shows the actual command when a scan command fails", () => {
    expect(
      scanActivityFromEvent(
        commandEvent(
          "item.completed",
          'cat "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
          "failed",
        ),
        "/code/juice-shop",
      ),
    ).toMatchObject({
      status: "failed",
      description: 'cat "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
      paths: ["routes/login.ts"],
    });
  });

  test("extracts real worker commands from persisted session events", () => {
    expect(
      scanActivityFromSessionEvent(
        sessionEvent({
          type: "function_call",
          name: "exec_command",
          call_id: "worker-command-1",
          arguments: JSON.stringify({
            cmd: 'rg -n "password" "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
          }),
        }),
        "/code/juice-shop",
      ),
    ).toEqual({
      id: "worker-command-1",
      kind: "command",
      status: "running",
      description:
        'rg -n "password" "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
      paths: ["routes/login.ts"],
    });
  });

  test("removes shell launchers from persisted worker commands", () => {
    expect(
      scanActivityFromSessionEvent(
        sessionEvent({
          type: "function_call",
          name: "exec_command",
          call_id: "worker-command-1",
          arguments: JSON.stringify({
            cmd: `/bin/zsh -lc 'rg -n "password" "$CODEX_SECURITY_REPOSITORY/routes/login.ts"'`,
          }),
        }),
        "/code/juice-shop",
      ),
    ).toMatchObject({
      description:
        'rg -n "password" "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
      paths: ["routes/login.ts"],
    });
  });

  test("shows the exact worker tool without exposing malformed arguments", () => {
    expect(
      scanActivityFromSessionEvent(
        sessionEvent({
          type: "function_call",
          name: "read_file",
          call_id: "worker-tool-1",
          arguments: "invalid secret=do-not-print",
        }),
        "/code/juice-shop",
      ),
    ).toEqual({
      id: "worker-tool-1",
      kind: "tool",
      status: "running",
      description: "read_file",
      paths: [],
    });
  });

  test("extracts the shell command inside a worker exec call", () => {
    expect(
      scanActivityFromSessionEvent(
        sessionEvent({
          type: "custom_tool_call",
          name: "exec",
          call_id: "worker-exec-1",
          input:
            'await tools.exec_command({cmd: "rg -n \\"token\\" \\"$CODEX_SECURITY_REPOSITORY/routes/login.ts\\""})',
        }),
        "/code/juice-shop",
      ),
    ).toEqual({
      id: "worker-exec-1",
      kind: "command",
      status: "running",
      description: 'rg -n "token" "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
      paths: ["routes/login.ts"],
    });
  });

  test("extracts worker commands from JSON-quoted exec arguments", () => {
    for (const [key, command] of [
      ["cmd", 'rg -n "token" "$CODEX_SECURITY_REPOSITORY/routes/login.ts"'],
      ["command", 'sed -n 1,80p "$CODEX_SECURITY_REPOSITORY/routes/login.ts"'],
    ] as const) {
      const input = `const r = await tools.exec_command(${JSON.stringify({
        [key]: command,
        workdir: "/code/juice-shop",
      })}); text(r.output)`;
      expect(
        scanActivityFromSessionEvent(
          sessionEvent({
            type: "custom_tool_call",
            name: "exec",
            call_id: `worker-exec-${key}`,
            input,
          }),
          "/code/juice-shop",
        ),
      ).toEqual({
        id: `worker-exec-${key}`,
        kind: "command",
        status: "running",
        description: command,
        paths: ["routes/login.ts"],
      });
    }
  });

  test("describes worker tool discovery instead of generic exec", () => {
    expect(
      scanActivityFromSessionEvent(
        sessionEvent({
          type: "custom_tool_call",
          name: "exec",
          call_id: "worker-discovery-1",
          input:
            'const hits = ALL_TOOLS.filter(x => /multi.?agent|subagent|spawn.*agent|delegate/i.test(x.name+" "+x.description)); text(hits);',
        }),
        "/code/juice-shop",
      ),
    ).toMatchObject({
      kind: "tool",
      description: "find tools · multi-agent, subagent, spawn-agent, delegate",
    });
  });

  test("shows actual tools inside wrapped worker code", () => {
    for (const [tool, description] of [
      ["multi_agent_v1__spawn_agent", "spawn_agent"],
      ["multi_agent_v1__wait_agent", "wait_agent"],
      ["update_plan", "update_plan"],
      ["create_goal", "create_goal"],
    ] as const) {
      expect(
        scanActivityFromSessionEvent(
          sessionEvent({
            type: "custom_tool_call",
            name: "exec",
            call_id: `worker-${description}`,
            input: `const result = await tools.${tool}({}); text(result);`,
          }),
          "/code/juice-shop",
        ),
      ).toMatchObject({ kind: "tool", description });
    }
  });

  test("shows the recipient and purpose of a worker message", () => {
    expect(
      scanActivityFromSessionEvent(
        sessionEvent({
          type: "function_call",
          name: "send_message",
          call_id: "worker-message-1",
          arguments: JSON.stringify({
            target: "worker-4",
            message: "Review routes/login.ts for SQL injection.",
          }),
        }),
        "/code/juice-shop",
      ),
    ).toEqual({
      id: "worker-message-1",
      kind: "tool",
      status: "running",
      description:
        "send_message → worker-4: Review routes/login.ts for SQL injection.",
      paths: [],
    });
  });

  test("shows actual worker reasoning summaries and assistant transcripts", () => {
    expect(
      scanActivityFromSessionEvent(
        sessionEvent({
          id: "reasoning-1",
          type: "reasoning",
          summary: [
            {
              type: "summary_text",
              text: "Following the login input into the SQL query.",
            },
          ],
          encrypted_content: "encrypted-chain-of-thought",
        }),
        "/code/juice-shop",
      ),
    ).toEqual({
      id: "reasoning-1",
      kind: "reasoning",
      status: "completed",
      description: "Following the login input into the SQL query.",
      paths: [],
    });
    expect(
      scanActivityFromSessionEvent(
        sessionEvent({
          id: "assistant-1",
          type: "message",
          role: "assistant",
          content: [
            {
              type: "output_text",
              text: "The request reaches an unsanitized database query.",
            },
          ],
        }),
        "/code/juice-shop",
      ),
    ).toEqual({
      id: "assistant-1",
      kind: "message",
      status: "completed",
      description: "The request reaches an unsanitized database query.",
      paths: [],
    });
  });

  test("shows live worker reasoning and commentary without internal progress", () => {
    expect(
      scanActivityFromSessionEvent(
        {
          type: "event_msg",
          timestamp: "2026-07-26T12:00:00.000Z",
          payload: {
            type: "agent_reasoning",
            text: "Tracing authentication across the worker's assigned files.",
          },
        },
        "/code/juice-shop",
      ),
    ).toMatchObject({
      kind: "reasoning",
      status: "completed",
      description: "Tracing authentication across the worker's assigned files.",
      paths: [],
    });
    expect(
      scanActivityFromSessionEvent(
        {
          type: "event_msg",
          timestamp: "2026-07-26T12:00:01.000Z",
          payload: {
            type: "agent_message",
            message:
              "Reviewed the login route.\n" +
              'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":3,"filesTotal":8}',
          },
        },
        "/code/juice-shop",
      ),
    ).toMatchObject({
      kind: "message",
      status: "completed",
      description: "Reviewed the login route.",
      paths: [],
    });
  });

  test("shows public raw reasoning and streaming reasoning deltas", () => {
    for (const [type, value, status] of [
      ["agent_reasoning_raw_content", "text", "completed"],
      ["agent_reasoning_raw_content_delta", "delta", "running"],
      ["agent_reasoning_delta", "delta", "running"],
    ] as const) {
      expect(
        scanActivityFromSessionEvent(
          {
            type: "event_msg",
            timestamp: "2026-07-26T12:00:00.000Z",
            payload: {
              type,
              [value]: "**Tracing authentication** across assigned files.",
              encrypted_content: "must-never-be-displayed",
            },
          },
          "/code/juice-shop",
        ),
      ).toMatchObject({
        kind: "reasoning",
        status,
        description: "Tracing authentication across assigned files.",
        paths: [],
      });
    }
  });

  test("keeps worker progress markers out of the activity transcript", () => {
    for (const text of [
      'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":3,"filesTotal":8}',
      'CODEX_SECURITY_WORKER_STATUS {"phase":"file_review","planned":6,"started":3}',
    ]) {
      expect(
        scanActivityFromSessionEvent(
          sessionEvent({
            id: "worker-marker-1",
            type: "message",
            role: "assistant",
            content: [{ type: "output_text", text }],
          }),
          "/code/juice-shop",
        ),
      ).toBeNull();
    }
  });

  test("does not invent or expose encrypted worker reasoning", () => {
    expect(
      scanActivityFromSessionEvent(
        sessionEvent({
          id: "encrypted-1",
          type: "reasoning",
          encrypted_content: "must-never-be-displayed",
          summary: [],
        }),
        "/code/juice-shop",
      ),
    ).toBeNull();
  });
});
