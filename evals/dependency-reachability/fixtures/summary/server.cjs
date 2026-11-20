"use strict";
const http = require("node:http");
const { sum } = require("./sample-summary");

function handle(request, response) {
  if (request.method === "GET" && request.url === "/health") {
    response.writeHead(200).end("ready");
    return;
  }
  if (request.method !== "POST" || request.url !== "/summary") {
    response.writeHead(404).end();
    return;
  }
  let body = "";
  request.setEncoding("utf8");
  request.on("data", (chunk) => {
    body += chunk;
  });
  request.on("end", function parseBatch() {
    let batch;
    try {
      batch = JSON.parse(body);
    } catch {
      response.writeHead(400).end();
      return;
    }
    if (
      !Array.isArray(batch.samples) ||
      !batch.samples.every(Number.isFinite)
    ) {
      response.writeHead(400).end();
      return;
    }
    response.writeHead(200).end(String(sum(batch.samples)));
  });
}

const server = http.createServer(handle);
server.listen(0, "127.0.0.1", () => console.log(server.address().port));
