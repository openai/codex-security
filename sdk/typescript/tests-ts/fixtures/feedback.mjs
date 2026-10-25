import { send } from "./app-server-messages.mjs";
import { createInterface } from "node:readline";
import { readFile, writeFile } from "node:fs/promises";

const requests = [];
if (process.env.FEEDBACK_STDERR)
  process.stderr.write(process.env.FEEDBACK_STDERR);
for await (const line of createInterface({ input: process.stdin })) {
  const request = JSON.parse(line);
  requests.push(request);
  if (request.method === "initialize") {
    send({ id: request.id, result: {} });
  } else if (request.method === "feedback/upload") {
    const attachments = await Promise.all(
      request.params.extraLogFiles.map(async (path) => ({
        path,
        content: await readFile(path, "utf8"),
      })),
    );
    await writeFile(
      process.env.FEEDBACK_REQUEST_FILE,
      JSON.stringify({ requests, attachments }),
    );
    switch (process.env.FEEDBACK_SCENARIO) {
      case "error":
        send({
          id: request.id,
          error: { message: "Upload failed" },
        });
        break;
      case "exit":
      case "exit-diagnostic":
        process.exit(1);
        break;
      case "missing-id":
        send({ id: request.id, result: {} });
        break;
      case "malformed":
        console.log("not JSON");
        break;
      default:
        send({
          id: request.id,
          result: { threadId: "feedback-1" },
        });
    }
  }
}
