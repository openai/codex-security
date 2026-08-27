import type { IncomingMessage, ServerResponse } from "node:http";
import type { ValidateFunction } from "ajv";
import { FindingsError } from "./errors.js";
import type { FindingsService } from "./findings-service.js";
import { pagination, type FindingsRequest } from "./validation.js";

export async function handleFindingsRequest(
  request: IncomingMessage,
  response: ServerResponse,
  service: FindingsService,
  validate: ValidateFunction<FindingsRequest>,
): Promise<void> {
  try {
    const url = new URL(request.url ?? "/", "http://localhost");
    const route = `${request.method} ${url.pathname}`;
    if (route === "GET /v1/findings") {
      console.log(route);
      json(response, 200, await service.list(pagination(url.searchParams)));
      return;
    }
    if (route === "POST /v1/bulk/findings") {
      console.log(route);
      const input = await readJson(request);
      if (!validate(input)) {
        throw new FindingsError(
          "invalid_request",
          "Expected {findings: [...]} using the existing Finding schema.",
        );
      }
      json(response, 201, await service.insert(input.findings));
      return;
    }
    request.resume();
    json(response, 404, { error: "not_found" });
  } catch (error) {
    if (error instanceof FindingsError) {
      const status = {
        invalid_request: 400,
        finding_conflict: 409,
        embedding_unavailable: 503,
        embedding_failed: 502,
      }[error.code];
      json(response, status, { error: error.code, message: error.message });
    } else {
      console.error(error);
      json(response, 500, { error: "internal_error" });
    }
  }
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new FindingsError(
      "invalid_request",
      "Request body must be valid JSON.",
    );
  }
}

function json(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "Content-Type": "application/json" });
  response.end(JSON.stringify(body));
}
