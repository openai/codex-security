import { spawn } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

const [mode, release, role] = process.argv.slice(2);
if (role === "holder") {
  process.send("ready");
  const finish = () => {
    writeFileSync(`${release}.done`, "released");
    process.exit(0);
  };
  const interval = setInterval(() => {
    if (!existsSync(release)) return;
    clearInterval(interval);
    if (mode !== "late") finish();
    const diagnostic = Buffer.from("late café 日本語 😀\n");
    process.stderr.write(diagnostic.subarray(0, 9), () => {
      setImmediate(() => {
        process.stderr.write(diagnostic.subarray(9), finish);
      });
    });
  }, 10);
} else {
  const holder = spawn(
    process.execPath,
    [fileURLToPath(import.meta.url), mode, release, "holder"],
    {
      // The holder must outlive the direct child on Windows.
      detached: process.platform === "win32",
      stdio: ["ignore", 1, 2, "ipc"],
    },
  );
  await new Promise((resolve) => holder.once("message", resolve));
  process.on("SIGTERM", () => {
    if (mode === "active") process.send("ignored-term");
    else process.exit(0);
  });
  process.send({ holderPid: holder.pid });
  process.send("ready");
  if (mode === "abandoned" || mode === "late") process.exit(0);
  setInterval(() => {}, 1000);
  const send = (message, completeLine = true) => {
    process.stdout.write(
      `${JSON.stringify(message)}${completeLine ? "\n" : ""}`,
      () => {
        if (!completeLine) process.exit(0);
      },
    );
  };
  for await (const line of createInterface({ input: process.stdin })) {
    if (mode === "active") continue;
    const message = JSON.parse(line);
    if (["initialize", "account/login/start"].includes(message.method)) {
      send({ id: message.id, result: {} });
    } else if (message.method === "feedback/upload") {
      send(
        mode === "error"
          ? { id: message.id, error: { message: "Synthetic upload failure" } }
          : { id: message.id, result: { threadId: "synthetic-feedback" } },
        mode !== "unterminated",
      );
    } else if (message.method === "thread/start") {
      send({
        id: message.id,
        result: { thread: { id: "thread", ephemeral: true, path: null } },
      });
    } else if (message.method === "turn/start" && mode !== "active") {
      if (mode === "error") {
        send({
          id: message.id,
          error: { message: "Synthetic review failure" },
        });
      } else {
        send({ id: message.id, result: { turn: { id: "turn" } } });
        send({
          id: "decision",
          method: "item/tool/call",
          params: {
            threadId: "thread",
            turnId: "turn",
            tool: "submit_decisions",
            namespace: "review_validator",
            arguments: { decision: "SAME" },
          },
        });
      }
    } else if (message.id === "decision") {
      send(
        {
          method: "turn/completed",
          params: {
            threadId: "thread",
            turn: { id: "turn", status: "completed" },
          },
        },
        mode !== "unterminated",
      );
    }
  }
}
