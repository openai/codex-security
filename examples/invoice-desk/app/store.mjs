import { randomBytes, scryptSync } from "node:crypto";

export function passwordRecord(password) {
  const salt = randomBytes(16).toString("hex");
  return { salt, hash: scryptSync(password, salt, 32).toString("hex") };
}

export function createStore() {
  const importDefaults = { limits: { maxAmountCents: 100_000 } };
  const workspace = (id, name, settlementBalanceCents) => ({
    id,
    name,
    importPolicy: { ...importDefaults },
    connector: {
      destination: "ledger",
      accessToken: randomBytes(24).toString("hex"),
    },
    ledger: { settlementBalanceCents },
  });
  const user = (id, email, password, workspaceId, name, role) => ({
    id,
    email,
    workspaceId,
    password: passwordRecord(password),
    profile: { name, role },
  });
  const invoice = (id, workspaceId, reference, customer, amountCents) => ({
    id,
    workspaceId,
    reference,
    customer,
    amountCents,
    version: 1,
    approval: null,
    status: "draft",
    comments: [],
  });
  return {
    workspaces: new Map([
      ["north", workspace("north", "North Studio", 314_200)],
      ["cedar", workspace("cedar", "Cedar Workshop", 89_200)],
    ]),
    users: new Map([
      [
        "alex",
        user(
          "alex",
          "alex@north.example.test",
          "river-orchard-24",
          "north",
          "Alex",
          "member",
        ),
      ],
      [
        "jules",
        user(
          "jules",
          "jules@north.example.test",
          "meadow-paper-56",
          "north",
          "Jules",
          "admin",
        ),
      ],
      [
        "sam",
        user(
          "sam",
          "sam@cedar.example.test",
          "cedar-window-81",
          "cedar",
          "Sam",
          "admin",
        ),
      ],
    ]),
    invoices: new Map([
      [
        "inv-north-1",
        invoice("inv-north-1", "north", "INV-1001", "Aster Design", 48_500),
      ],
      [
        "inv-north-2",
        invoice("inv-north-2", "north", "INV-1002", "Paper Finch", 72_000),
      ],
      [
        "inv-cedar-1",
        invoice("inv-cedar-1", "cedar", "INV-1001", "Willow Office", 93_000),
      ],
    ]),
    destinations: new Map([
      ["ledger", { id: "ledger", name: "Ledger", ownerWorkspaceId: null }],
      [
        "archive",
        { id: "archive", name: "Cedar Archive", ownerWorkspaceId: "cedar" },
      ],
    ]),
    sessions: new Map(),
    previews: new Map(),
    deliveries: [],
  };
}
