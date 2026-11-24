import { createServer } from "node:http";
import { text } from "node:stream/consumers";
import LinkifyIt from "linkify-it";

const links = new LinkifyIt();

createServer(async (request, response) => {
  if (request.method !== "POST" || request.url !== "/preview") {
    response.writeHead(404).end();
    return;
  }
  const matches = links.match(await text(request)) ?? [];
  response.setHeader("content-type", "application/json");
  response.end(JSON.stringify(matches.map((match) => match.url)));
}).listen(8080);
