import assert from "node:assert/strict";
import { stripVTControlCharacters } from "node:util";
import { render } from "ink-testing-library";
import { act, createElement } from "react";
import { PatchTui } from "../../src/patch-tui.js";
import type { Finding } from "../../src/models.js";

const repository = process.argv[2];
assert.ok(repository, "Expected a temporary repository");
const finding: Finding = JSON.parse(process.argv[3]!);
const app = render(
  createElement(PatchTui, {
    repository,
    findings: [finding],
    color: false,
    onComplete() {},
  }),
);
const frame = () => stripVTControlCharacters(app.lastFrame() ?? "");
const firstFrame = frame();
const range = firstFrame.match(/DETAILS\s+1–(\d+)\/(\d+)/u);
assert.ok(range, firstFrame);
Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
await act(async () => {
  app.stdin.write(
    "\u001B[6~".repeat(Math.ceil(Number(range[2]) / Number(range[1]))),
  );
});
Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: false });
assert.match(frame(), /150000 │ last source line/u);
app.unmount();
