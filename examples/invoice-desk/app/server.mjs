import { createServer } from "node:http";
import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createStore } from "./store.mjs";
import {
  publicUser,
  sessionUser,
  signIn,
  signOut,
  updateProfile,
} from "./accounts.mjs";
import {
  HttpError,
  addComment,
  approveInvoice,
  getInvoice,
  listInvoices,
  ownedInvoice,
  previewInvoice,
  sendInvoice,
  updateInvoice,
} from "./invoices.mjs";
import { importInvoice, updateImportPolicy } from "./imports.mjs";
import {
  connectionSettings,
  deliverInvoice,
  ledgerAccount,
  receivedDeliveries,
  supportReport,
} from "./integrations.mjs";
import {
  dashboardPage,
  importPage,
  integrationsPage,
  invoicePage,
  loginPage,
  profilePage,
} from "./views.mjs";

const assets = new Map([
  [
    "/styles.css",
    ["text/css", readFileSync(new URL("./public/styles.css", import.meta.url))],
  ],
  [
    "/client.js",
    [
      "text/javascript",
      readFileSync(new URL("./public/client.js", import.meta.url)),
    ],
  ],
]);

async function readBody(request) {
  if (!request.headers["content-type"]?.startsWith("application/json"))
    throw new HttpError(415, "Send a JSON document.");
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  let value;
  try {
    value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpError(400, "Invalid JSON document.");
  }
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new HttpError(400, "Send a JSON object.");
  return value;
}

function respond(
  response,
  status,
  value,
  type = "application/json",
  headers = {},
) {
  response.writeHead(status, {
    "Content-Type": `${type}; charset=utf-8`,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    ...headers,
  });
  response.end(type === "application/json" ? JSON.stringify(value) : value);
}

export function createApp() {
  const store = createStore();
  const server = createServer(async (request, response) => {
    try {
      const path = new URL(request.url, "http://127.0.0.1").pathname;
      const method = request.method;
      if (method === "GET" && assets.has(path)) {
        const [type, content] = assets.get(path);
        return respond(response, 200, content, type);
      }
      if (method === "GET" && path === "/health")
        return respond(response, 200, { status: "ok" });
      if (method === "GET" && path === "/login")
        return respond(response, 200, loginPage(), "text/html");
      if (method === "POST" && path === "/api/login") {
        const body = await readBody(request);
        const token = signIn(store, body.email, body.password);
        if (!token) throw new HttpError(401, "Email or password is incorrect.");
        return respond(response, 200, { redirect: "/" }, "application/json", {
          "Set-Cookie": `session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`,
        });
      }
      if (method === "GET" && path === "/api/ledger/account") {
        return respond(
          response,
          200,
          ledgerAccount(
            store,
            request.headers.authorization?.replace(/^Bearer /, ""),
          ),
        );
      }
      const user = sessionUser(store, request.headers.cookie);
      if (!user) {
        if (method === "GET" && !path.startsWith("/api/"))
          return respond(response, 302, "", "text/plain", {
            Location: "/login",
          });
        throw new HttpError(401, "Sign in to continue.");
      }
      const workspace = store.workspaces.get(user.workspaceId);
      if (method === "POST" && path === "/api/logout") {
        await readBody(request);
        signOut(store, request.headers.cookie);
        return respond(
          response,
          200,
          { redirect: "/login" },
          "application/json",
          {
            "Set-Cookie":
              "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
          },
        );
      }
      if (method === "GET" && path === "/")
        return respond(
          response,
          200,
          dashboardPage(user, workspace, listInvoices(store, user)),
          "text/html",
        );
      if (method === "GET" && path === "/imports")
        return respond(response, 200, importPage(user, workspace), "text/html");
      if (method === "GET" && path === "/integrations")
        return respond(
          response,
          200,
          integrationsPage(
            user,
            workspace,
            connectionSettings(store, user),
            receivedDeliveries(store, user),
          ),
          "text/html",
        );
      if (method === "GET" && path === "/profile")
        return respond(
          response,
          200,
          profilePage(user, workspace),
          "text/html",
        );
      const page = path.match(/^\/invoices\/([^/]+)$/);
      if (method === "GET" && page)
        return respond(
          response,
          200,
          invoicePage(user, workspace, ownedInvoice(store, user, page[1])),
          "text/html",
        );
      if (method === "GET" && path === "/api/me")
        return respond(response, 200, publicUser(user));
      if (method === "PATCH" && path === "/api/profile")
        return respond(
          response,
          200,
          updateProfile(user, await readBody(request)),
        );
      if (method === "GET" && path === "/api/invoices")
        return respond(response, 200, listInvoices(store, user));
      if (method === "GET" && path === "/api/import-policy")
        return respond(response, 200, workspace.importPolicy);
      if (method === "PATCH" && path === "/api/import-policy")
        return respond(
          response,
          200,
          updateImportPolicy(
            store,
            user,
            (await readBody(request)).maxAmountCents,
          ),
        );
      if (method === "POST" && path === "/api/imports")
        return respond(
          response,
          201,
          importInvoice(store, user, await readBody(request)),
        );
      if (method === "GET" && path === "/api/integrations")
        return respond(response, 200, connectionSettings(store, user));
      if (method === "GET" && path === "/api/integrations/inbox")
        return respond(response, 200, receivedDeliveries(store, user));
      if (method === "POST" && path === "/api/integrations/deliver") {
        const body = await readBody(request);
        return respond(
          response,
          201,
          deliverInvoice(store, user, body.invoiceId, body.destination),
        );
      }
      if (method === "GET" && path === "/api/support-report")
        return respond(
          response,
          200,
          supportReport(store, user),
          "application/json",
          {
            "Content-Disposition": 'attachment; filename="support-report.json"',
          },
        );
      const invoice = path.match(
        /^\/api\/invoices\/([^/]+)(?:\/(preview|approve|send|comments))?$/,
      );
      if (invoice) {
        const [, id, action] = invoice;
        if (method === "GET" && !action)
          return respond(response, 200, getInvoice(store, id));
        if (method === "PATCH" && !action)
          return respond(
            response,
            200,
            updateInvoice(store, user, id, await readBody(request)),
          );
        if (method === "GET" && action === "preview")
          return respond(response, 200, previewInvoice(store, user, id));
        if (method === "POST") {
          const body = await readBody(request);
          if (action === "approve")
            return respond(response, 200, approveInvoice(store, user, id));
          if (action === "send")
            return respond(response, 200, sendInvoice(store, user, id));
          if (action === "comments")
            return respond(
              response,
              201,
              addComment(store, user, id, body.body),
            );
        }
      }
      throw new HttpError(404, "Page not found.");
    } catch (error) {
      respond(response, error instanceof HttpError ? error.status : 500, {
        error:
          error instanceof HttpError
            ? error.message
            : "The request could not be completed.",
      });
    }
  });
  return server;
}

if (
  process.argv[1] &&
  realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const server = createApp();
  server.listen(Number(process.env.PORT ?? 4310), "127.0.0.1", () => {
    console.log(
      `Invoice Desk is running at http://127.0.0.1:${server.address().port}`,
    );
  });
  for (const signal of ["SIGINT", "SIGTERM"])
    process.once(signal, () => server.close());
}
