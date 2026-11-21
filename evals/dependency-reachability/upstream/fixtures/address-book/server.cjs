const { createServer } = require("node:http");
const { createRequire } = require("node:module");

const profiles = new Map([
  ["main", require.resolve("./package.json")],
  ["contacts", require.resolve("./plugins/contacts/package.json")],
]);
const anchor = profiles.get(process.env.ADDRESS_BOOK_PROFILE);
if (!anchor) throw new Error("Unknown address book profile");
const load = createRequire(anchor);
const parse = load("nodemailer/lib/addressparser");

createServer(async (req, res) => {
  if (req.method !== "POST" || req.url !== "/addresses") {
    res.writeHead(404).end();
    return;
  }
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const addresses = parse(Buffer.concat(chunks).toString("utf8"));
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(addresses));
}).listen(8080);
