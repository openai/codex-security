import { createInterface } from "node:readline";
import { readFile, writeFile } from "node:fs/promises";

const requests = [];
for await (const line of createInterface({ input: process.stdin })) {
  const request = JSON.parse(line);
  requests.push(request);
  if (request.method === "initialize") {
    console.log(JSON.stringify({ id: request.id, result: {} }));
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
        console.log(
          JSON.stringify({
            id: request.id,
            error: { message: "Upload failed" },
          }),
        );
        break;
      case "exit":
        process.exit(1);
        break;
      case "missing-id":
        console.log(JSON.stringify({ id: request.id, result: {} }));
        break;
      case "malformed":
        console.log("not JSON");
        break;
      default:
        console.log(
          JSON.stringify({
            id: request.id,
            result: { threadId: "feedback-1" },
          }),
        );
    }
  }
}
