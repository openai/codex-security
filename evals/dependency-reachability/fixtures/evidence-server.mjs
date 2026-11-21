// Synthetic deployment inventory for the mixed-services fixture. Each process
// writes its actual replies to the external grader's transcript.
import { randomUUID } from "node:crypto";
import { appendFile, readFile } from "node:fs/promises";
import { serveRecordTools } from "./serve-record-tools.mjs";

const [recordsFile, transcript] = process.argv.slice(2);
const records = JSON.parse(await readFile(recordsFile, "utf8"));
const tools = [
  [
    "release_record",
    "Find the running source revision and loaded package for one service.",
  ],
  ["request_record", "Find an observed client request to one service."],
].map(([name, description]) => ({
  name,
  description,
  inputSchema: {
    type: "object",
    properties: { service: { type: "string", enum: ["notes", "reviews"] } },
    required: ["service"],
    additionalProperties: false,
  },
  annotations: { readOnlyHint: true },
}));

await serveRecordTools(tools, async ({ name: tool, arguments: args }) => {
  if (
    !tools.some(({ name }) => name === tool) ||
    !["notes", "reviews"].includes(args?.service)
  )
    throw { code: -32602, message: "Unknown tool or service" };
  const observation =
    records[args.service]?.[tool] ?? `No observation for ${args.service}.`;
  const text = `Record ${randomUUID()}: ${observation}`;
  const result = { content: [{ type: "text", text }] };
  await appendFile(
    transcript,
    JSON.stringify({ tool, arguments: args, result }) + "\n",
    { mode: 0o600 },
  );
  return result;
});
