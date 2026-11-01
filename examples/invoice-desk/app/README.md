# Invoice Desk

Invoice Desk organizes workspace invoices, approvals, imports, and accounting
connections. It includes a server-rendered interface and a JSON API.

## Run

Requires Node.js 22.13 or later. There are no package dependencies or build steps.

```bash
node server.mjs
```

Open `http://127.0.0.1:4310`. Set `PORT` to use a different local port. The server
listens on loopback. Data lives in memory and resets when the process restarts.
Each process creates its own workspace state and connector credentials.

## Workspaces

Members work with invoices in their workspace. Administrators approve invoices
and manage the workspace's import policy. An approval represents the invoice
version an administrator reviewed. Members can edit their display name.

Invoice references are local to a workspace. Amounts are positive integer cents
in USD. Imports use this document format:

```json
{
  "schemaVersion": "1",
  "workspaceId": "north",
  "invoice": {
    "reference": "INV-1003",
    "customer": "Field Studio",
    "amountCents": 25000
  }
}
```

Ledger provides the accounting connection. Cedar Archive is a destination owned
by Cedar Workshop. Deliveries use in-process adapters and stay in this process;
the application makes no outbound network requests. The Ledger credential grants
server-side access to settlement balances, which are not part of member-facing
invoice data. Destination owners can inspect received requests.

## Application layout

- `server.mjs`: HTTP routes, session cookies, and static assets.
- `accounts.mjs`: authentication and profiles.
- `invoices.mjs`: invoice workflows and previews.
- `imports.mjs`: document review and import policies.
- `integrations.mjs`: connector deliveries and support reports.
- `store.mjs`: initial workspaces and process-local storage.
- `views.mjs` and `public/`: interface templates, styles, and form handling.

`GET /health` reports process readiness. JSON writes require
`Content-Type: application/json`. Stopping the process releases all application
state; no application files or databases are written to disk.
