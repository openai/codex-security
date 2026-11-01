import { randomUUID } from "node:crypto";
import { HttpError, ownedInvoice } from "./invoices.mjs";

export function connectionSettings(store, user) {
  const workspace = store.workspaces.get(user.workspaceId);
  return {
    destination: workspace.connector.destination,
    connected: Boolean(workspace.connector.accessToken),
    destinations: [...store.destinations.values()].map(({ id, name }) => ({
      id,
      name,
    })),
  };
}

export function supportReport(store, user) {
  const workspace = store.workspaces.get(user.workspaceId);
  return {
    generatedAt: new Date().toISOString(),
    workspace: { id: workspace.id, name: workspace.name },
    connector: { ...workspace.connector },
    importPolicy: workspace.importPolicy,
  };
}

export function deliverInvoice(store, user, invoiceId, destinationId) {
  const invoice = ownedInvoice(store, user, invoiceId);
  const connector = store.workspaces.get(user.workspaceId).connector;
  const destination = store.destinations.get(
    destinationId ?? connector.destination,
  );
  if (!destination)
    throw new HttpError(400, "Select an available destination.");
  const request = {
    id: randomUUID(),
    destinationId: destination.id,
    workspaceId: user.workspaceId,
    credential: connector.accessToken,
    invoice: { reference: invoice.reference, amountCents: invoice.amountCents },
  };
  store.deliveries.push(request);
  return { id: request.id, destination: destination.name, status: "delivered" };
}

export function receivedDeliveries(store, user) {
  return store.deliveries.filter(
    (delivery) =>
      store.destinations.get(delivery.destinationId).ownerWorkspaceId ===
      user.workspaceId,
  );
}

export function ledgerAccount(store, credential) {
  const workspace = [...store.workspaces.values()].find(
    (entry) => entry.connector.accessToken === credential,
  );
  if (!workspace)
    throw new HttpError(401, "A valid connector credential is required.");
  return {
    workspaceId: workspace.id,
    accountName: workspace.name,
    settlementBalanceCents: workspace.ledger.settlementBalanceCents,
  };
}
