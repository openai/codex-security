import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { cp, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createApp } from "../app/server.mjs";

const accounts = {
  alex: ["alex@north.example.test", "river-orchard-24"],
  jules: ["jules@north.example.test", "meadow-paper-56"],
  sam: ["sam@cedar.example.test", "cedar-window-81"],
};
const manifest = JSON.parse(
  readFileSync(new URL("./expected-findings.json", import.meta.url), "utf8"),
);
const registered = new Set();

async function app(t) {
  const server = createApp();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(
    () =>
      new Promise((resolve, reject) => {
        server.closeAllConnections();
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  );
  const origin = `http://127.0.0.1:${server.address().port}`;
  const request = async (
    path,
    { method = "GET", body, cookie, headers = {} } = {},
  ) => {
    const response = await fetch(`${origin}${path}`, {
      method,
      redirect: "manual",
      headers: {
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        ...(cookie ? { Cookie: cookie } : {}),
        ...headers,
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await response.text();
    return {
      status: response.status,
      headers: response.headers,
      body: response.headers.get("content-type")?.startsWith("application/json")
        ? JSON.parse(text)
        : text,
    };
  };
  const login = async (name) => {
    const [email, password] = accounts[name];
    const response = await request("/api/login", {
      method: "POST",
      body: { email, password },
    });
    assert.equal(response.status, 200);
    const cookie = response.headers.get("set-cookie").split(";")[0];
    return (path, options = {}) => request(path, { ...options, cookie });
  };
  return { request, login };
}

function scenario(id, run) {
  const expected = manifest.findings.find((finding) => finding.id === id);
  assert.ok(expected, `Missing manifest entry: ${id}`);
  assert.ok(!registered.has(id), `Duplicate scenario: ${id}`);
  registered.add(id);
  test(`${id}: ${expected.category}`, run);
}

function invoiceDocument(workspaceId, amountCents = 25_000) {
  return {
    schemaVersion: "1",
    workspaceId,
    invoice: { customer: "Garden Office", amountCents },
  };
}

scenario("ID-001", async (t) => {
  const { login, request } = await app(t);
  const alex = await login("alex");
  const settings = await alex("/api/integrations");
  assert.equal(settings.body.accessToken, undefined);
  const report = await alex("/api/support-report");
  assert.equal(report.status, 200);
  const token = report.body.connector.accessToken;
  assert.ok(token);
  const account = await request("/api/ledger/account", {
    headers: { Authorization: `Bearer ${token}` },
  });
  assert.equal(account.status, 200);
  assert.equal(account.body.workspaceId, "north");
  assert.equal(account.body.settlementBalanceCents, 314_200);
  assert.equal((await request("/api/ledger/account")).status, 401);
});

scenario("ID-002", async (t) => {
  const { login } = await app(t);
  const alex = await login("alex");
  assert.ok(
    (await alex("/api/invoices")).body.every(
      (invoice) => invoice.workspaceId === "north",
    ),
  );
  const other = await alex("/api/invoices/inv-cedar-1");
  assert.equal(other.status, 200);
  assert.equal(other.body.workspaceId, "cedar");
});

scenario("ID-003", async (t) => {
  const { login } = await app(t);
  const alex = await login("alex");
  const sam = await login("sam");
  const first = await alex("/api/invoices/inv-north-1/preview");
  const second = await sam("/api/invoices/inv-cedar-1/preview");
  const own = await sam("/api/invoices/inv-cedar-1");
  assert.equal(second.status, 200);
  assert.deepEqual(second.body, first.body);
  assert.notEqual(second.body.customer, own.body.customer);
  assert.notEqual(second.body.amountCents, own.body.amountCents);
});

scenario("ID-004", async (t) => {
  const { login } = await app(t);
  const alex = await login("alex");
  const jules = await login("jules");
  const approved = await jules("/api/invoices/inv-north-1/approve", {
    method: "POST",
    body: {},
  });
  assert.equal(approved.status, 200);
  const changed = await alex("/api/invoices/inv-north-1", {
    method: "PATCH",
    body: { amountCents: 98_000 },
  });
  assert.equal(changed.status, 200);
  assert.notEqual(changed.body.version, changed.body.approval.version);
  const sent = await alex("/api/invoices/inv-north-1/send", {
    method: "POST",
    body: {},
  });
  assert.equal(sent.status, 200);
  assert.equal(sent.body.amountCents, 98_000);
  assert.equal(sent.body.status, "sent");
});

scenario("ID-005", async (t) => {
  const { login } = await app(t);
  const alex = await login("alex");
  const document = invoiceDocument("north", 150_000);
  assert.equal(
    (await alex("/api/imports", { method: "POST", body: document })).status,
    422,
  );
  document.schemaVersion = "2";
  const imported = await alex("/api/imports", {
    method: "POST",
    body: document,
  });
  assert.equal(imported.status, 201);
  assert.equal(imported.body.invoice.amountCents, 150_000);
  assert.equal(imported.body.review.approved, true);
  assert.ok(imported.body.review.warning);
});

scenario("ID-006", async (t) => {
  const { login, request } = await app(t);
  const alex = await login("alex");
  const sam = await login("sam");
  assert.equal(
    (
      await alex("/api/integrations/deliver", {
        method: "POST",
        body: { invoiceId: "inv-north-1", destination: "ledger" },
      })
    ).status,
    201,
  );
  assert.deepEqual((await sam("/api/integrations/inbox")).body, []);
  assert.equal(
    (
      await alex("/api/integrations/deliver", {
        method: "POST",
        body: { invoiceId: "inv-north-1", destination: "archive" },
      })
    ).status,
    201,
  );
  const inbox = await sam("/api/integrations/inbox");
  assert.equal(inbox.body.length, 1);
  const account = await request("/api/ledger/account", {
    headers: { Authorization: `Bearer ${inbox.body[0].credential}` },
  });
  assert.equal(account.status, 200);
  assert.equal(account.body.workspaceId, "north");
  assert.equal(account.body.settlementBalanceCents, 314_200);
  assert.deepEqual((await alex("/api/integrations/inbox")).body, []);
});

scenario("ID-007", async (t) => {
  const { login } = await app(t);
  const jules = await login("jules");
  const sam = await login("sam");
  const document = invoiceDocument("cedar", 150_000);
  assert.equal(
    (await sam("/api/imports", { method: "POST", body: document })).status,
    422,
  );
  assert.equal(
    (
      await jules("/api/import-policy", {
        method: "PATCH",
        body: { maxAmountCents: 200_000 },
      })
    ).status,
    200,
  );
  assert.equal(
    (await sam("/api/import-policy")).body.limits.maxAmountCents,
    200_000,
  );
  assert.equal(
    (await sam("/api/imports", { method: "POST", body: document })).status,
    201,
  );
});

scenario("ID-008", async (t) => {
  const { login } = await app(t);
  const alex = await login("alex");
  const sam = await login("sam");
  assert.equal(
    (
      await alex("/api/imports", {
        method: "POST",
        body: invoiceDocument("cedar"),
      })
    ).status,
    403,
  );
  const document = invoiceDocument("north");
  document.invoice.workspaceId = "cedar";
  const imported = await alex("/api/imports", {
    method: "POST",
    body: document,
  });
  assert.equal(imported.status, 201);
  assert.equal(imported.body.invoice.workspaceId, "cedar");
  assert.ok(
    (await sam("/api/invoices")).body.some(
      (invoice) => invoice.id === imported.body.invoice.id,
    ),
  );
  assert.ok(
    !(await alex("/api/invoices")).body.some(
      (invoice) => invoice.id === imported.body.invoice.id,
    ),
  );
});

scenario("ID-009", async (t) => {
  const { login } = await app(t);
  const alex = await login("alex");
  assert.equal(
    (
      await alex("/api/invoices/inv-north-1/approve", {
        method: "POST",
        body: {},
      })
    ).status,
    403,
  );
  const profile = await alex("/api/profile", {
    method: "PATCH",
    body: { name: "Alex", role: "admin" },
  });
  assert.equal(profile.status, 200);
  assert.equal((await alex("/api/me")).body.profile.role, "admin");
  assert.equal(
    (
      await alex("/api/invoices/inv-north-1/approve", {
        method: "POST",
        body: {},
      })
    ).status,
    200,
  );
});

scenario("ID-010", async (t) => {
  const { login } = await app(t);
  const alex = await login("alex");
  const jules = await login("jules");
  const markup = '<strong data-note="formatting">Account update</strong>';
  assert.equal(
    (
      await alex("/api/invoices/inv-north-1/comments", {
        method: "POST",
        body: { body: markup },
      })
    ).status,
    201,
  );
  const page = await jules("/invoices/inv-north-1");
  assert.equal(page.status, 200);
  assert.ok(page.body.includes(`<div class="comment-body">${markup}</div>`));
  await alex("/api/invoices/inv-north-1", {
    method: "PATCH",
    body: { customer: '<em data-client="name">Client</em>' },
  });
  assert.ok(
    (await jules("/invoices/inv-north-1")).body.includes(
      "&lt;em data-client=&quot;name&quot;&gt;Client&lt;/em&gt;",
    ),
  );
});

test("manifest accounts for all ten separately exercised scenarios", () => {
  assert.equal(manifest.findings.length, 10);
  assert.deepEqual(
    new Set(manifest.findings.map((finding) => finding.id)),
    registered,
  );
  assert.equal(
    new Set(manifest.findings.map((finding) => finding.category)).size,
    10,
  );
});

test(
  "a standalone app copy starts without its parent or QA directory",
  { timeout: 10_000 },
  async (t) => {
    const directory = await mkdtemp(join(tmpdir(), "invoice-desk-"));
    let child;
    t.after(async () => {
      if (child && child.exitCode === null && child.signalCode === null) {
        const exited = once(child, "exit");
        child.kill("SIGTERM");
        await exited;
      }
      await rm(directory, { recursive: true, force: true });
    });
    await cp(new URL("../app/", import.meta.url), directory, {
      recursive: true,
    });
    child = spawn(process.execPath, [join(directory, "server.mjs")], {
      cwd: directory,
      env: { PORT: "0" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const origin = await new Promise((resolve, reject) => {
      let output = "";
      let errors = "";
      child.stderr.on("data", (chunk) => {
        errors += chunk;
      });
      child.stdout.on("data", (chunk) => {
        output += chunk;
        const match = output.match(/http:\/\/127\.0\.0\.1:\d+/);
        if (match) resolve(match[0]);
      });
      child.once("error", reject);
      child.once("exit", (code) =>
        reject(new Error(`App exited ${code}: ${errors}`)),
      );
    });
    const health = await fetch(`${origin}/health`);
    assert.deepEqual(await health.json(), { status: "ok" });
    const login = await fetch(`${origin}/login`);
    assert.equal(login.status, 200);
    assert.ok((await login.text()).includes("Invoice Desk"));
  },
);

test("invoice previews refresh when the invoice version changes", async (t) => {
  const { login } = await app(t);
  const alex = await login("alex");
  assert.equal(
    (await alex("/api/invoices/inv-north-1/preview")).body.amountCents,
    48_500,
  );
  await alex("/api/invoices/inv-north-1", {
    method: "PATCH",
    body: { amountCents: 49_000 },
  });
  assert.equal(
    (await alex("/api/invoices/inv-north-1/preview")).body.amountCents,
    49_000,
  );
});

test("health, static assets, and every ordinary page are served", async (t) => {
  const { request, login } = await app(t);
  assert.deepEqual((await request("/health")).body, { status: "ok" });
  assert.equal((await request("/")).status, 302);
  for (const path of ["/login", "/styles.css", "/client.js"])
    assert.equal((await request(path)).status, 200);
  const alex = await login("alex");
  for (const path of [
    "/",
    "/invoices/inv-north-1",
    "/imports",
    "/integrations",
    "/profile",
  ]) {
    const response = await alex(path);
    assert.equal(response.status, 200);
    assert.ok(response.body.includes("Invoice Desk"));
  }
});

test("anonymous callers and incorrect passwords do not authenticate", async (t) => {
  const { request } = await app(t);
  assert.equal((await request("/api/invoices")).status, 401);
  assert.equal(
    (
      await request("/api/login", {
        method: "POST",
        body: { email: accounts.alex[0], password: "incorrect" },
      })
    ).status,
    401,
  );
  const login = await request("/api/login", {
    method: "POST",
    body: { email: accounts.alex[0], password: accounts.alex[1] },
  });
  assert.match(login.headers.get("set-cookie"), /HttpOnly; SameSite=Strict/);
});

test("scoped writes, previews, HTML pages, and connector deliveries reject another workspace", async (t) => {
  const { login } = await app(t);
  const alex = await login("alex");
  assert.equal(
    (
      await alex("/api/invoices/inv-cedar-1", {
        method: "PATCH",
        body: { amountCents: 1 },
      })
    ).status,
    404,
  );
  assert.equal(
    (
      await alex("/api/invoices/inv-cedar-1/comments", {
        method: "POST",
        body: { body: "Hello" },
      })
    ).status,
    404,
  );
  assert.equal((await alex("/api/invoices/inv-cedar-1/preview")).status, 404);
  assert.equal((await alex("/invoices/inv-cedar-1")).status, 404);
  assert.equal(
    (
      await alex("/api/integrations/deliver", {
        method: "POST",
        body: { invoiceId: "inv-cedar-1", destination: "ledger" },
      })
    ).status,
    404,
  );
});

test("normal approval and delivery work, and unapproved invoices cannot be sent", async (t) => {
  const { login } = await app(t);
  const alex = await login("alex");
  const jules = await login("jules");
  assert.equal(
    (await alex("/api/invoices/inv-north-1/send", { method: "POST", body: {} }))
      .status,
    409,
  );
  assert.equal(
    (
      await alex("/api/import-policy", {
        method: "PATCH",
        body: { maxAmountCents: 200_000 },
      })
    ).status,
    403,
  );
  assert.equal(
    (
      await jules("/api/invoices/inv-north-1/approve", {
        method: "POST",
        body: {},
      })
    ).status,
    200,
  );
  const sent = await alex("/api/invoices/inv-north-1/send", {
    method: "POST",
    body: {},
  });
  assert.equal(sent.status, 200);
  assert.equal(sent.body.version, 1);
});

test("normal imports remain in their workspace and settings omit server credentials", async (t) => {
  const { login } = await app(t);
  const alex = await login("alex");
  const imported = await alex("/api/imports", {
    method: "POST",
    body: invoiceDocument("north"),
  });
  assert.equal(imported.status, 201);
  assert.equal(imported.body.invoice.workspaceId, "north");
  assert.equal(imported.body.review.approved, true);
  assert.deepEqual(Object.keys((await alex("/api/integrations")).body).sort(), [
    "connected",
    "destination",
    "destinations",
  ]);
  assert.equal(
    (
      await alex("/api/integrations/deliver", {
        method: "POST",
        body: { invoiceId: "inv-north-1", destination: "unknown" },
      })
    ).status,
    400,
  );
});

test("logout revokes the current session", async (t) => {
  const { login } = await app(t);
  const alex = await login("alex");
  assert.equal(
    (await alex("/api/logout", { method: "POST", body: {} })).status,
    200,
  );
  assert.equal((await alex("/api/me")).status, 401);
});

test("new app instances reset invoices, credentials, profiles, and import policies", async (t) => {
  const first = await app(t);
  const alex = await first.login("alex");
  const jules = await first.login("jules");
  const token = (await alex("/api/support-report")).body.connector.accessToken;
  await alex("/api/profile", { method: "PATCH", body: { role: "admin" } });
  await alex("/api/invoices/inv-north-1", {
    method: "PATCH",
    body: { amountCents: 1 },
  });
  await jules("/api/import-policy", {
    method: "PATCH",
    body: { maxAmountCents: 200_000 },
  });
  const second = await app(t);
  const fresh = await second.login("alex");
  assert.equal((await fresh("/api/me")).body.profile.role, "member");
  assert.equal(
    (await fresh("/api/invoices/inv-north-1")).body.amountCents,
    48_500,
  );
  assert.equal(
    (await fresh("/api/import-policy")).body.limits.maxAmountCents,
    100_000,
  );
  assert.notEqual(
    (await fresh("/api/support-report")).body.connector.accessToken,
    token,
  );
  assert.equal(
    (
      await second.request("/api/ledger/account", {
        headers: { Authorization: `Bearer ${token}` },
      })
    ).status,
    401,
  );
});
