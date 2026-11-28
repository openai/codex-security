// Preloaded only by the evaluation driver, outside the service checkout.
"use strict";
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const { subscribe } = require("node:diagnostics_channel");
const { readFileSync, writeFileSync } = require("node:fs");
const { Session } = require("node:inspector");
const { relative, resolve, sep } = require("node:path");
const { fileURLToPath, pathToFileURL } = require("node:url");

const library = resolve("sample-summary/index.cjs");
const lines = readFileSync(library, "utf8").split("\n");
const breakpoint = lines.findIndex((line) => line.includes("samples.reduce("));
assert(breakpoint >= 0);

let ingress;
subscribe("http.server.request.start", ({ request }) => {
  ingress = {
    method: request.method,
    path: request.url,
    peer: request.socket.remoteAddress,
    anonymous: !request.headers.authorization && !request.headers.cookie,
  };
});
const session = new Session();
const urls = new Map();
session.connect();
session.on("Debugger.scriptParsed", ({ params }) => {
  urls.set(params.scriptId, params.url);
});
session.post("Debugger.enable");
session.post("Debugger.setBreakpointByUrl", {
  url: pathToFileURL(library).href,
  lineNumber: breakpoint,
});
session.on("Debugger.paused", ({ params }) => {
  try {
    assert(params.hitBreakpoints.length > 0);
    const frames = params.callFrames.map(({ functionName, location }) => {
      const url = urls.get(location.scriptId) || "";
      const file = url.startsWith("file:")
        ? relative(process.cwd(), fileURLToPath(url)).split(sep).join("/")
        : url;
      return {
        name: functionName || "<anonymous>",
        ...(file && { location: file }),
        line: location.lineNumber + 1,
      };
    });
    assert.equal(frames[0].name, "sum");
    assert.equal(frames[0].location, "sample-summary/index.cjs");
    assert(
      ingress?.method === "POST" &&
        ingress.path === "/summary" &&
        ingress.anonymous,
    );
    const git = (...args) =>
      execFileSync("git", args, { encoding: "utf8" }).trimEnd();
    assert.equal(git("status", "--porcelain"), "");
    const sourceSha = git("rev-parse", "--verify", "HEAD");
    for (const path of [
      "server.cjs",
      "sample-summary/index.cjs",
      "sample-summary/package.json",
    ]) {
      assert.deepEqual(
        readFileSync(path),
        execFileSync("git", ["show", sourceSha + ":" + path]),
      );
    }
    assert(require.cache[library]?.loaded);
    const version = require(resolve("sample-summary/package.json")).version;
    const observedAt = new Date().toISOString();
    writeFileSync(
      process.env.SUMMARY_EVAL_CAPTURE,
      JSON.stringify({
        sourceSha,
        version,
        observedAt,
        frames,
        ingress,
      }),
      { flag: "wx" },
    );
  } finally {
    session.post("Debugger.resume");
  }
});
