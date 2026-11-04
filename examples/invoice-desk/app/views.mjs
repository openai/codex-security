function h(value) {
  return String(value).replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        character
      ],
  );
}

const money = (amount) =>
  new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(
    amount / 100,
  );
const badge = (status) =>
  `<span class="badge ${h(status)}">${h(status)}</span>`;
const icon = (name) => {
  const paths = {
    invoices:
      '<rect x="5" y="3" width="14" height="18" rx="2"/><path d="M9 8h6M9 12h6M9 16h3"/>',
    imports: '<path d="M12 3v12m-4-4 4 4 4-4M4 16v4h16v-4"/>',
    integrations:
      '<rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/><path d="M14 6h4v8M10 18H6v-8"/>',
    profile:
      '<circle cx="12" cy="8" r="4"/><path d="M4 21v-2a8 8 0 0 1 16 0v2"/>',
  };
  return `<svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">${paths[name]}</svg>`;
};

function document(title, body) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${h(title)} · Invoice Desk</title><link rel="stylesheet" href="/styles.css"><script src="/client.js" defer></script></head><body>${body}<div id="notice" role="status" aria-live="polite" hidden></div></body></html>`;
}

function layout(title, active, user, workspace, content) {
  const links = [
    ["invoices", "/", "Invoices"],
    ["imports", "/imports", "Imports"],
    ["integrations", "/integrations", "Connections"],
    ["profile", "/profile", "My account"],
  ];
  return document(
    title,
    `<div class="shell"><aside class="sidebar"><a class="brand" href="/"><span class="brand-mark">id.</span> Invoice Desk</a><div class="workspace"><span class="workspace-mark">${h(workspace.name[0])}</span><div><strong>${h(workspace.name)}</strong><small>Workspace</small></div></div><div class="nav-label">WORKSPACE</div><nav aria-label="Main navigation">${links.map(([name, href, label]) => `<a href="${href}" ${active === name ? 'aria-current="page"' : ""}>${icon(name)}${label}</a>`).join("")}</nav><div class="sidebar-bottom"><span class="avatar">${h(String(user.profile.name)[0])}</span><div><strong>${h(user.profile.name)}</strong><small>${h(user.profile.role)}</small></div><form data-action="/api/logout"><button class="logout" aria-label="Sign out" title="Sign out">↗</button></form></div></aside><main><header class="topbar"><span>${h(workspace.name)} <span class="slash">/</span> ${h(title)}</span><span class="connection-dot">Workspace connected</span></header><div class="content">${content}</div></main></div>`,
  );
}

export function loginPage() {
  return document(
    "Sign in",
    `<div class="login-shell"><section class="login-intro"><a class="brand" href="/"><span class="brand-mark">id.</span> Invoice Desk</a><div><span class="eyebrow">LESS ADMIN. MORE CLARITY.</span><h1>Good work.<br>Clear invoices.</h1><p>Keep your invoices, approvals, and connections in one place.</p><div class="login-decoration" aria-hidden="true"><span>INV-1001</span><strong>Ready for review <span>↗</span></strong><div class="decoration-line"></div><small>One workspace. Everything in order.</small></div></div><small>Built for teams that make things.</small></section><section class="login-form"><div><span class="eyebrow">YOUR WORKSPACE AWAITS</span><h2>Welcome back</h2><p class="muted">Sign in to pick up where you left off.</p><form data-action="/api/login"><label>Email address<input name="email" type="email" autocomplete="username" placeholder="you@company.com" required></label><label>Password<input name="password" type="password" autocomplete="current-password" required></label><button class="button primary wide">Sign in <span>→</span></button></form><p class="fine-print">Your team’s invoices, thoughtfully organized.</p></div></section></div>`,
  );
}

export function dashboardPage(user, workspace, invoices) {
  const drafts = invoices.filter((invoice) => invoice.status === "draft");
  return layout(
    "Invoices",
    "invoices",
    user,
    workspace,
    `<div class="page-heading"><div><span class="eyebrow">THE BIG PICTURE</span><h1>Your invoices, in order.</h1><p class="muted">A little less paperwork. A little more headspace.</p></div><a class="button primary" href="/imports">+ Import invoice</a></div><div class="stats"><section class="stat"><span>Total invoiced</span><strong>${money(invoices.reduce((sum, invoice) => sum + invoice.amountCents, 0))}</strong><small>Across ${invoices.length} invoices</small></section><section class="stat"><span>Awaiting approval</span><strong>${drafts.length.toString().padStart(2, "0")}</strong><small>Ready for a closer look</small></section><section class="stat"><span>Sent to clients</span><strong>${invoices
      .filter((invoice) => invoice.status === "sent")
      .length.toString()
      .padStart(
        2,
        "0",
      )}</strong><small>Moving things forward</small></section></div><section class="panel"><div class="panel-heading"><h2>All invoices <span class="count">${invoices.length}</span></h2><span class="muted small">Amounts in USD</span></div><div class="table-wrap"><table><thead><tr><th>Invoice</th><th>Client</th><th>Status</th><th class="numeric">Amount</th><th><span class="sr-only">Open</span></th></tr></thead><tbody>${invoices.map((invoice) => `<tr><td><a class="invoice-link" href="/invoices/${encodeURIComponent(invoice.id)}">${h(invoice.reference)}</a><small>Version ${invoice.version}</small></td><td>${h(invoice.customer)}</td><td>${badge(invoice.status)}</td><td class="numeric amount">${money(invoice.amountCents)}</td><td><a class="row-arrow" aria-label="Open ${h(invoice.reference)}" href="/invoices/${encodeURIComponent(invoice.id)}">↗</a></td></tr>`).join("")}</tbody></table></div></section><div class="bottom-note"><span class="note-icon">↳</span><p><strong>Everything starts with a clear handoff.</strong><br>Import an invoice, get it approved, and send it on its way.</p><a href="/integrations">Manage connections →</a></div>`,
  );
}

export function invoicePage(user, workspace, invoice) {
  const api = `/api/invoices/${encodeURIComponent(invoice.id)}`;
  return layout(
    invoice.reference,
    "invoices",
    user,
    workspace,
    `<a class="back-link" href="/">← All invoices</a><div class="page-heading"><div><span class="eyebrow">INVOICE DETAILS</span><h1>${h(invoice.reference)} ${badge(invoice.status)}</h1><p class="muted">${h(invoice.customer)} · Version ${invoice.version}</p></div><button class="button" data-preview="${api}/preview">Preview</button></div><div class="columns"><section class="panel padded"><h2>Invoice information</h2><form data-action="${api}" data-method="PATCH"><label>Client<input name="customer" value="${h(invoice.customer)}" required></label><label>Amount in cents<input name="amountCents" type="number" min="1" step="1" value="${invoice.amountCents}" required><small>${money(invoice.amountCents)} USD</small></label><button class="button primary">Save changes</button></form></section><section class="panel padded"><h2>Approval & delivery</h2><p class="muted">${invoice.approval ? `Approved by ${h(invoice.approval.userId)} on version ${invoice.approval.version}.` : "An administrator can approve this invoice when it is ready."}</p><div class="actions">${user.profile.role === "admin" ? `<form data-action="${api}/approve"><button class="button">Approve invoice</button></form>` : ""}<form data-action="${api}/send"><button class="button primary">Send invoice</button></form></div><hr><h3>Send a copy to a connection</h3><form data-action="/api/integrations/deliver" data-stay><input name="invoiceId" type="hidden" value="${h(invoice.id)}"><label>Destination<select name="destination"><option value="ledger">Ledger</option><option value="archive">Cedar Archive</option></select></label><button class="button">Deliver copy</button></form></section></div><section class="panel padded notes"><h2>Notes <span class="count">${invoice.comments.length}</span></h2>${invoice.comments.length ? invoice.comments.map((comment) => `<article class="comment"><strong>${h(comment.author)}</strong><div class="comment-body">${comment.body}</div></article>`).join("") : '<p class="muted">Keep the conversation close to the work.</p>'}<form data-action="${api}/comments"><label>Add a note<textarea name="body" rows="3" placeholder="Leave an update for your team…" required></textarea></label><button class="button primary">Post note</button></form></section><dialog id="preview-dialog" aria-labelledby="preview-title"><div class="panel-heading"><h2 id="preview-title">Invoice preview</h2><button class="button" data-close>Close</button></div><div class="preview-body"></div></dialog>`,
  );
}

export function importPage(user, workspace) {
  const document = {
    schemaVersion: "1",
    workspaceId: workspace.id,
    invoice: {
      reference: "INV-1003",
      customer: "Field Studio",
      amountCents: 25_000,
    },
  };
  return layout(
    "Imports",
    "imports",
    user,
    workspace,
    `<div class="page-heading"><div><span class="eyebrow">A FRESH START</span><h1>Bring your work together.</h1><p class="muted">Import an invoice from a connected billing workflow.</p></div></div><div class="columns"><section class="panel padded"><h2>Import invoice</h2><p class="muted">Paste a version 1 invoice document. Amounts are in cents.</p><form data-action="/api/imports" data-document><label>Invoice document<textarea class="code-input" name="document" rows="14" spellcheck="false" required>${h(JSON.stringify(document, null, 2))}</textarea></label><button class="button primary">Review & import</button></form></section><section class="panel padded align-start"><h2>Workspace policy</h2><p class="muted">Invoices above the import limit require a separate review.</p><div class="policy-value">${money(workspace.importPolicy.limits.maxAmountCents)}<small>Current import limit</small></div>${user.profile.role === "admin" ? `<form data-action="/api/import-policy" data-method="PATCH"><label>Import limit in cents<input name="maxAmountCents" type="number" min="1" step="1" value="${workspace.importPolicy.limits.maxAmountCents}" required></label><button class="button">Update policy</button></form>` : '<p class="muted small">Ask a workspace administrator to update this policy.</p>'}</section></div>`,
  );
}

export function integrationsPage(user, workspace, settings, deliveries) {
  return layout(
    "Connections",
    "integrations",
    user,
    workspace,
    `<div class="page-heading"><div><span class="eyebrow">BETTER TOGETHER</span><h1>Keep everything connected.</h1><p class="muted">Move invoice details between the tools your team uses.</p></div></div><div class="columns"><section class="panel padded"><div class="connection-card"><span class="service-icon">L</span><div><h2>Ledger</h2><p class="muted">Accounting connection</p></div><span class="badge approved">Connected</span></div><p class="muted">Your workspace account is connected. Send a copy from any invoice to record a delivery.</p><p class="small">Default destination: <strong>${h(settings.destination)}</strong></p></section><section class="panel padded"><span class="eyebrow">NEED A HAND?</span><h2>Connection diagnostics</h2><p class="muted">Download your workspace’s connection details and current policy to help troubleshoot a delivery.</p><a class="button" href="/api/support-report" download>Download support report ↗</a></section></div><section class="panel padded notes"><h2>Received deliveries <span class="count">${deliveries.length}</span></h2><p class="muted">Requests received by connections owned by your workspace.</p>${deliveries.length ? deliveries.map((delivery) => `<details><summary>${h(delivery.invoice.reference)} · ${h(delivery.workspaceId)}</summary><pre>${h(JSON.stringify(delivery, null, 2))}</pre></details>`).join("") : '<div class="empty-state">No deliveries yet. They will appear here when a connection receives an invoice.</div>'}</section>`,
  );
}

export function profilePage(user, workspace) {
  return layout(
    "My account",
    "profile",
    user,
    workspace,
    `<div class="page-heading"><div><span class="eyebrow">THE PERSON BEHIND THE WORK</span><h1>Make yourself at home.</h1><p class="muted">Manage how you appear to your team.</p></div></div><section class="panel padded profile-panel"><h2>Profile details</h2><p class="muted">${h(user.email)} · ${h(user.profile.role)}</p><form data-action="/api/profile" data-method="PATCH"><label>Display name<input name="name" value="${h(user.profile.name)}" required></label><button class="button primary">Save profile</button></form></section>`,
  );
}
