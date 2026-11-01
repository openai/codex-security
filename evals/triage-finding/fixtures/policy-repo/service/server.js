import { createServer } from "node:http";

const allowedDestinations = new Set(["/help", "/account"]);

export const server = createServer((request, response) => {
  const url = new URL(request.url, "http://example.test");
  const next = url.searchParams.get("next") ?? "/";

  if (url.pathname === "/redirect") {
    response.writeHead(302, { Location: next });
    response.end();
    return;
  }

  if (url.pathname === "/safe-redirect") {
    if (!allowedDestinations.has(next)) {
      response.writeHead(400);
      response.end();
      return;
    }
    response.writeHead(302, { Location: next });
    response.end();
    return;
  }

  response.writeHead(404);
  response.end();
});
