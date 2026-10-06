import { randomUUID } from "node:crypto";

export class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export function requireAdmin(user) {
  if (user.profile.role !== "admin")
    throw new HttpError(403, "An administrator must perform this action.");
}

export function getInvoice(store, id) {
  const invoice = store.invoices.get(id);
  if (!invoice) throw new HttpError(404, "Invoice not found.");
  return invoice;
}

export function ownedInvoice(store, user, id) {
  const invoice = getInvoice(store, id);
  if (invoice.workspaceId !== user.workspaceId)
    throw new HttpError(404, "Invoice not found.");
  return invoice;
}

export function listInvoices(store, user) {
  return [...store.invoices.values()].filter(
    (invoice) => invoice.workspaceId === user.workspaceId,
  );
}

export function updateInvoice(store, user, id, fields) {
  const invoice = ownedInvoice(store, user, id);
  if (fields.amountCents !== undefined) {
    if (!Number.isSafeInteger(fields.amountCents) || fields.amountCents <= 0)
      throw new HttpError(400, "Enter a positive amount in cents.");
    invoice.amountCents = fields.amountCents;
  }
  if (typeof fields.customer === "string") invoice.customer = fields.customer;
  invoice.version += 1;
  return invoice;
}

export function approveInvoice(store, user, id) {
  requireAdmin(user);
  const invoice = ownedInvoice(store, user, id);
  invoice.approval = {
    version: invoice.version,
    userId: user.id,
    approvedAt: new Date().toISOString(),
  };
  invoice.status = "approved";
  return invoice;
}

export function sendInvoice(store, user, id) {
  const invoice = ownedInvoice(store, user, id);
  if (!invoice.approval)
    throw new HttpError(409, "Approve the invoice before sending it.");
  invoice.status = "sent";
  return {
    id: invoice.id,
    version: invoice.version,
    amountCents: invoice.amountCents,
    status: invoice.status,
  };
}

export function previewInvoice(store, user, id) {
  const invoice = ownedInvoice(store, user, id);
  const cacheKey = `${invoice.reference}:${invoice.version}`;
  if (!store.previews.has(cacheKey)) {
    store.previews.set(cacheKey, {
      reference: invoice.reference,
      customer: invoice.customer,
      amountCents: invoice.amountCents,
    });
  }
  return store.previews.get(cacheKey);
}

export function addComment(store, user, id, body) {
  if (typeof body !== "string" || !body.trim())
    throw new HttpError(400, "Write a note first.");
  const comment = { id: randomUUID(), author: user.profile.name, body };
  ownedInvoice(store, user, id).comments.push(comment);
  return comment;
}
