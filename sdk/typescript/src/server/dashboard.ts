import { readFile } from "node:fs/promises";
import type { ServerResponse } from "node:http";
import type {
  DashboardQuery,
  DashboardSort,
  DashboardSortDirection,
  DashboardView,
} from "./dashboard-types.js";
import { FindingsError } from "./errors.js";
import { pagination } from "./validation.js";

const assets = new Map([
  ["/dashboard/", ["index.html", "text/html; charset=utf-8"]],
  ["/dashboard/app.js", ["app.js", "text/javascript; charset=utf-8"]],
  ["/dashboard/app.css", ["app.css", "text/css; charset=utf-8"]],
]);

/** Serve only bundled UI assets, never a path supplied by a request. */
export async function serveDashboard(
  path: string,
  response: ServerResponse,
): Promise<boolean> {
  if (path === "/" || path === "/dashboard") {
    response.writeHead(308, { Location: "dashboard/" });
    response.end();
    return true;
  }
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
  const view = parameters.get("view") ?? "findings";
  const sort = parameters.get("sort") ?? "activity";
  const direction = parameters.get("direction") ?? "desc";
  if (!["findings", "groups"].includes(view))
    throw new FindingsError("invalid_request", "Unknown dashboard view.");
  if (
    ![
      "activity",
      "newest",
      "title",
      "repository",
      "severity",
      "members",
    ].includes(sort)
  )
    throw new FindingsError(
      "invalid_request",
      "sort must be activity, newest, title, repository, severity, or members.",
    );
  if (
    (view === "findings" && sort === "members") ||
    (view === "groups" && sort === "severity")
  )
    throw new FindingsError(
      "invalid_request",
      `Cannot sort ${view} by ${sort}.`,
    );
  if (direction !== "asc" && direction !== "desc")
    throw new FindingsError(
      "invalid_request",
      "direction must be asc or desc.",
    );
  return {
    view: view as DashboardView,
    ...pagination(parameters),
    query: parameters.get("query") ?? "",
    repository: parameters.get("repository") ?? "",
    sort: sort as DashboardSort,
    direction: direction as DashboardSortDirection,
    ...(parameters.has("id") ? { id: parameters.get("id")! } : {}),
  };
}
