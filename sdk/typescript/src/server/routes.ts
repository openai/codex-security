import type { IncomingMessage, ServerResponse } from "node:http";

export function handleFindingsRequest(
  request: IncomingMessage,
  response: ServerResponse,
): void {
  const path = request.url?.split("?", 1)[0];
  const route = `${request.method} ${path}`;
  request.resume();

  switch (route) {
    case "GET /v1/findings":
    case "POST /v1/bulk/findings":
      console.log(route);
      response.writeHead(501, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ error: "not_implemented" }));
      return;
    default:
      response.writeHead(404, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ error: "not_found" }));
  }
}
