import type { IncomingMessage, ServerResponse } from "node:http";
import type { ValidateFunction } from "ajv";
import { FindingsError } from "./errors.js";
import { dashboardQuery, serveDashboard } from "./dashboard.js";
import type { FindingsService } from "./findings-service.js";
import {
  findingSearchScope,
  pagination,
  validateDedupeGroups,
  type FindingsRequest,
} from "./validation.js";

export async function handleFindingsRequest(
  request: IncomingMessage,
  response: ServerResponse,
  service: FindingsService,
  validate: ValidateFunction<FindingsRequest>,
): Promise<void> {
  try {
    const url = new URL(request.url ?? "/", "http://localhost");
    const route = `${request.method} ${url.pathname}`;
    if (
      request.method === "GET" &&
      (await serveDashboard(url.pathname, response))
    )
      return;
    if (route === "GET /v1/dashboard") {
      response.setHeader("Cache-Control", "no-store");
      json(
        response,
        200,
        await service.dashboard(dashboardQuery(url.searchParams)),
      );
      return;
    }
    if (route === "GET /v1/findings") {
      console.log(route);
      json(response, 200, await service.list(pagination(url.searchParams)));
      return;
    }
    const candidates = /^\/v1\/finding\/([^/]+)\/potential-duplicates$/.exec(
      url.pathname,
    );
    if (request.method === "GET" && candidates) {
      console.log("GET /v1/finding/:id/potential-duplicates");
      json(
        response,
        200,
        await service.potentialDuplicates(
          candidates[1]!,
          findingSearchScope(url.searchParams),
        ),
      );
      return;
    }
    const dedupeGroups = /^\/v1\/finding\/([^/]+)\/dedupe-groups$/.exec(
      url.pathname,
    );
    if (request.method === "GET" && dedupeGroups) {
      console.log("GET /v1/finding/:id/dedupe-groups");
      json(response, 200, await service.listDedupeGroups(dedupeGroups[1]!));
      return;
    }
    if (route === "POST /v1/dedupe-groups") {
      console.log(route);
      const input = await readJson(request);
      if (!validateDedupeGroups(input)) {
        throw new FindingsError(
          "invalid_request",
          "Expected {groups: [[findingId, ...], ...]} with at least two distinct finding IDs per group.",
        );
      }
      json(response, 201, await service.storeDedupeGroups(input.groups));
      return;
    }
    if (route === "POST /v1/bulk/findings") {
      console.log(route);
      const input = await readJson(request);
      if (!validate(input)) {
        throw new FindingsError(
          "invalid_request",
          "Expected {findings: [...]} with an optional nonempty repositoryId, using the existing Finding schema.",
        );
      }
      json(
        response,
        201,
        await service.insert(input.findings, input.repositoryId),
      );
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
        finding_not_indexed: 404,
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
