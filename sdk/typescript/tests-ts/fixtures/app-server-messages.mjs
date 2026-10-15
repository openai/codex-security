export const send = (value) =>
  process.stdout.write(`${JSON.stringify(value)}\n`);

export function completeTurn(request, text, threadId) {
  const turnId = "synthetic-turn";
  send({ id: request.id, result: { turn: { id: turnId } } });
  send({
    method: "item/completed",
    params: { threadId, turnId, item: { type: "agentMessage", text: text() } },
  });
  send({
    method: "turn/completed",
    params: { threadId, turn: { id: turnId, status: "completed" } },
  });
}
