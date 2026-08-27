import assert from "node:assert/strict";
import { once } from "node:events";
import { appendFile, mkdtemp, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

let sequence = 0;
function sameDecision(findings) {
  return {
    decision: "SAME",
    rationale: "Synthetic shared correction for the complete original reports.",
    canonicalFindingId: findings[0].findingId,
    mergedFinding: {
      ...findings[0],
      title: findings.map((finding) => finding.title).join("; "),
      extensions: { ...findings[0].extensions, mergedOriginals: findings },
    },
  };
}
const server = createServer(async (request, response) => {
  try {
    assert.equal(request.method, "POST");
    assert.equal(request.url, "/v1/responses");
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    const responseId = `response_${++sequence}`;
    let item;
    if (body.input.some((entry) => entry.type === "function_call_output")) {
      item = {
        type: "message",
        id: `message_${sequence}`,
        role: "assistant",
        status: "completed",
        phase: "final_answer",
        content: [{ type: "output_text", text: "Submitted.", annotations: [] }],
      };
    } else {
      const prompt = body.input
        .flatMap((entry) => entry.content ?? [])
        .filter((content) => content.type === "input_text")
        .map((content) => content.text)
        .find((text) => text.includes('{"findings":['));
      assert.ok(prompt);
      const { findings } = JSON.parse(
        prompt.slice(prompt.lastIndexOf("\n\n") + 2),
      );
      const stage = prompt.startsWith("Review the complete assigned")
        ? "screen"
        : "pair";
      if (stage === "pair") assert.equal(findings.length, 2);
      assert.equal(
        body.model,
        stage === "screen" ? "gpt-5.6-luna" : "gpt-5.6-sol",
      );
      assert.equal(body.reasoning.effort, "xhigh");
      const tools = body.input
        .filter((entry) => entry.type === "additional_tools")
        .flatMap((entry) => entry.tools);
      const validator = tools.find((tool) => tool.name === "review_validator");
      assert.equal(validator?.type, "namespace");
      assert.equal(validator.tools[0].name, "submit_decisions");
      assert.equal(validator.tools[0].type, "function");
      const functions = tools.find((tool) => tool.name === "functions").tools;
      const execute = functions.find((tool) => tool.name === "exec");
      assert.match(execute.description, /### `exec_command`/);
      const same = findings.every(
        (finding) => finding.extensions?.smokeGroup !== "distinct",
      );
      const result =
        stage === "screen"
          ? {
              decisions: findings.slice(1).map((finding) => ({
                findingIds: [findings[0].findingId, finding.findingId],
                ...sameDecision([findings[0], finding]),
              })),
            }
          : same
            ? sameDecision(findings)
            : {
                decision: "DISTINCT",
                rationale: "Synthetic review of the original reports.",
              };
      await appendFile(
        join(process.env.CODEX_SECURITY_STATE_DIR, "review-calls.jsonl"),
        JSON.stringify({
          stage,
          findingIds: findings.map((finding) => finding.findingId),
        }) + "\n",
      );
      item = {
        type: "function_call",
        id: `item_${sequence}`,
        call_id: `call_${sequence}`,
        name: "submit_decisions",
        namespace: "review_validator",
        arguments: JSON.stringify(result),
        status: "completed",
      };
    }
    response.writeHead(200, {
      "Content-Type": "text/event-stream",
      Connection: "close",
    });
    for (const event of [
      {
        type: "response.created",
        response: { id: responseId, status: "in_progress", output: [] },
      },
      { type: "response.output_item.added", output_index: 0, item },
      { type: "response.output_item.done", output_index: 0, item },
      {
        type: "response.completed",
        response: {
          id: responseId,
          status: "completed",
          output: [item],
          usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 },
        },
      },
    ])
      response.write(
        `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`,
      );
    response.end();
  } catch (error) {
    console.error(error);
    response.writeHead(400).end("Synthetic model request failed validation.");
  }
});
server.listen(0, "127.0.0.1");
await once(server, "listening");
server.unref();
const modelHome = await mkdtemp(join(tmpdir(), "findings-models-"));
await writeFile(
  join(modelHome, "config.toml"),
  `model_provider = "smoke"
[model_providers.smoke]
name = "Local smoke model"
base_url = "http://127.0.0.1:${server.address().port}/v1"
wire_api = "responses"
env_key = "OPENAI_API_KEY"
supports_websockets = false
`,
  { mode: 0o600 },
);
process.env.CODEX_HOME = modelHome;
