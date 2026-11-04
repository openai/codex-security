const express = require("express");
const path = require("path");

const app = express();
const PUBLIC_ROOT = path.resolve(__dirname, "../public");
const REDIRECT_ALLOWLIST = new Set(["/home", "/account"]);

const orders = {
  "order-1": { id: "order-1", ownerId: "user-1", total: 12 },
  "order-2": { id: "order-2", ownerId: "user-2", total: 44 },
};

function runQuery(sql) {
  return { sql };
}

app.get("/redirect", (req, res) => {
  const next = req.query.next || "/home";
  res.redirect(next);
});

app.get("/safe-redirect", (req, res) => {
  const next = req.query.next || "/home";
  if (!REDIRECT_ALLOWLIST.has(next)) {
    return res.status(400).send("invalid redirect");
  }
  return res.redirect(next);
});

app.get("/download", (req, res) => {
  const requestedFile = req.query.file;
  const filePath = path.join(PUBLIC_ROOT, requestedFile);
  return res.sendFile(filePath);
});

app.get("/safe-download", (req, res) => {
  const requestedFile = req.query.file;
  const filePath = path.resolve(PUBLIC_ROOT, requestedFile);
  if (!filePath.startsWith(PUBLIC_ROOT + path.sep)) {
    return res.status(400).send("invalid file");
  }
  return res.sendFile(filePath);
});

app.get("/search", (req, res) => {
  const term = req.query.q || "";
  const sql = "SELECT id, name FROM products WHERE name LIKE '%" + term + "%'";
  return res.json(runQuery(sql));
});

app.get("/orders/:id", (req, res) => {
  const order = orders[req.params.id];
  if (!order) {
    return res.status(404).send("missing");
  }
  return res.json(order);
});

app.get("/safe-profile/:id", (req, res) => {
  if (req.params.id !== req.user.id) {
    return res.status(403).send("forbidden");
  }
  return res.json({ id: req.params.id });
});

app.get("/partner-export", (req, res) => {
  if (process.env.ENABLE_PARTNER_EXPORT !== "true") {
    return res.status(404).send("disabled");
  }
  return res.json({ partnerData: "runtime-gated" });
});

app.get("/parse", (req, res) => {
  const vulnerableParse = require("vulnerable-parse");
  const parsed = vulnerableParse.parse(req.query.payload || "{}");
  return res.json(parsed);
});

module.exports = app;
