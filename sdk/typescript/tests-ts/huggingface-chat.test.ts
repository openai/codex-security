import { expect, test } from "bun:test";
import {
  huggingFaceChatRequest,
  huggingFaceChatResponse,
} from "../src/huggingface-chat.js";

test("preserves parallel calls, outputs, and output schemas", () => {
  const request = huggingFaceChatRequest({
    model: "synthetic/model",
    instructions: "Review the code",
    reasoning: { effort: "low" },
    text: {
      format: {
        type: "json_schema",
        name: "result",
        schema: { type: "object" },
        strict: true,
      },
    },
    tools: [{ type: "function", name: "read", parameters: { type: "object" } }],
    input: [
      {
        role: "developer",
        content: [{ type: "input_text", text: "Use local tools" }],
      },
      {
        role: "user",
        content: [
          { type: "input_text", text: "Inspect" },
          { type: "input_image", image_url: "data:image/png;base64,synthetic" },
        ],
      },
      { type: "reasoning", summary: [] },
      {
        type: "function_call",
        call_id: "call_1",
        name: "read",
        arguments: "{}",
      },
      {
        type: "function_call",
        call_id: "call_2",
        name: "read",
        arguments: "{}",
      },
      {
        type: "function_call_output",
        call_id: "call_1",
        output: [{ type: "input_text", text: "one" }],
      },
      { type: "function_call_output", call_id: "call_2", output: "two" },
    ],
  });
  expect(request.messages).toHaveLength(7);
  expect(request.messages[4]).toMatchObject({
    role: "assistant",
    tool_calls: [{ id: "call_1" }, { id: "call_2" }],
  });
  expect(request.messages[5]).toEqual({
    role: "tool",
    tool_call_id: "call_1",
    content: [{ type: "text", text: "one" }],
  });
  expect(request).toMatchObject({
    reasoning_effort: "low",
    response_format: {
      type: "json_schema",
      json_schema: { name: "result", schema: { type: "object" }, strict: true },
    },
  });
});

test("assembles interleaved tool deltas and preserves cached and reasoning usage", () => {
  const response = huggingFaceChatResponse();
  response.add({
    choices: [
      {
        index: 0,
        delta: {
          tool_calls: [
            {
              index: 1,
              id: "call_2",
              function: { name: "second", arguments: "{" },
            },
            {
              index: 0,
              id: "call_1",
              function: { name: "first", arguments: "{}" },
            },
          ],
        },
      },
    ],
  });
  response.add({
    choices: [
      {
        index: 0,
        delta: { tool_calls: [{ index: 1, function: { arguments: "}" } }] },
        finish_reason: "tool_calls",
      },
    ],
  });
  response.add({
    choices: [],
    usage: {
      prompt_tokens: 100,
      completion_tokens: 20,
      total_tokens: 120,
      prompt_tokens_details: { cached_tokens: 50 },
      completion_tokens_details: { reasoning_tokens: 10 },
    },
  });
  expect(response.finish()).toMatchObject({
    status: "completed",
    output: [
      { call_id: "call_1", name: "first", arguments: "{}" },
      { call_id: "call_2", name: "second", arguments: "{}" },
    ],
    usage: {
      input_tokens: 100,
      output_tokens: 20,
      total_tokens: 120,
      input_tokens_details: { cached_tokens: 50 },
      output_tokens_details: { reasoning_tokens: 10 },
    },
  });
});

test.each([undefined, "length", "content_filter"])(
  "does not finalize incomplete generation %p",
  (finish_reason) => {
    const response = huggingFaceChatResponse();
    response.add({
      choices: [{ index: 0, delta: { content: "partial" }, finish_reason }],
    });
    expect(() => response.finish()).toThrow("did not complete");
  },
);

test("rejects unsupported conversation items", () => {
  expect(() =>
    huggingFaceChatRequest({ input: [{ type: "computer_call" }] }),
  ).toThrow("does not support");
});

test("does not report a reasoning-only empty completion as assistant output", () => {
  const response = huggingFaceChatResponse();
  response.add({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] });
  expect(() => response.finish()).toThrow(
    "without assistant content or tool calls",
  );
});

test("preserves JSON object mode and the description of structured outputs", () => {
  for (const [format, expected] of [
    [{ type: "json_object" }, { type: "json_object" }],
    [
      {
        type: "json_schema",
        name: "report",
        description: "Scan findings",
        schema: { type: "object" },
      },
      {
        type: "json_schema",
        json_schema: {
          name: "report",
          description: "Scan findings",
          schema: { type: "object" },
        },
      },
    ],
  ] as const) {
    expect(
      huggingFaceChatRequest({ input: "Review", text: { format } })
        .response_format,
    ).toEqual(expected);
  }
});

test.each([
  { previous_response_id: "resp_fixture" },
  { conversation: { id: "conv_fixture" } },
])("rejects inaccessible conversation history %p", (history) => {
  expect(() =>
    huggingFaceChatRequest({ input: "Continue", ...history }),
  ).toThrow("full conversation history");
});

test("surfaces a streamed refusal, including its provider explanation", () => {
  const response = huggingFaceChatResponse();
  response.add({
    choices: [{ index: 0, delta: { content: "Partial.", refusal: "Cannot " } }],
  });
  response.add({
    choices: [
      {
        index: 0,
        delta: { refusal: "continue." },
        finish_reason: "content_filter",
      },
    ],
  });
  expect(() => response.finish()).toThrow("Cannot continue.");
});

test("a missing tool call cannot turn a progress update into a successful completion", () => {
  const response = huggingFaceChatResponse();
  response.add({
    choices: [
      {
        index: 0,
        delta: { content: "I will inspect the files." },
        finish_reason: "tool_calls",
      },
    ],
  });
  expect(() => response.finish()).toThrow("returned no tool calls");
});
