import { readFile } from "node:fs/promises";
import type { ServerResponse } from "node:http";
import type { DashboardQuery, DashboardView } from "./dashboard-types.js";
import { FindingsError } from "./errors.js";
import { pagination } from "./validation.js";

const assets = new Map([
  ["/dashboard", ["index.html", "text/html; charset=utf-8"]],
  ["/dashboard/", ["index.html", "text/html; charset=utf-8"]],
  ["/dashboard/app.js", ["app.js", "text/javascript; charset=utf-8"]],
  ["/dashboard/app.css", ["app.css", "text/css; charset=utf-8"]],
]);

/** Serve only bundled UI assets, never a path supplied by a request or scan. */
export async function serveDashboard(
  path: string,
  response: ServerResponse,
): Promise<boolean> {
  const asset = assets.get(path);
  if (!asset) return false;
  const body = await readFile(
    new URL(`./dashboard/${asset[0]}`, import.meta.url),
  );
  response.writeHead(200, {
    "Content-Type": asset[1]!,
    "Cache-Control": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy":
      "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; frame-ancestors 'none'",
  });
  response.end(body);
  return true;
}

export function dashboardQuery(parameters: URLSearchParams): DashboardQuery {
  const view = parameters.get("view") ?? "scans";
  const sort = parameters.get("sort") ?? "activity";
  if (!["scans", "workflows", "findings", "groups"].includes(view))
    throw new FindingsError("invalid_request", "Unknown dashboard view.");
  if (sort !== "activity" && sort !== "newest")
    throw new FindingsError(
      "invalid_request",
      "sort must be activity or newest.",
    );
  return {
    view: view as DashboardView,
    ...pagination(parameters),
    query: parameters.get("query") ?? "",
    repository: parameters.get("repository") ?? "",
    status: parameters.get("status") ?? "",
    stage: parameters.get("stage") ?? "",
    sort,
    ...(parameters.has("id") ? { id: parameters.get("id")! } : {}),
  };
}
