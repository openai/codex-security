import { expect, test } from "bun:test";
import { workbenchArgs } from "../src/workbench-arguments.js";

test("workbench arguments preserve field order, values, and repeated flags", () => {
  expect(
    workbenchArgs("fixture-command", {
      scanId: "scan-example",
      registrationJsonStdin: true,
      archiveExisting: false,
      parentScanId: undefined,
      offset: 0,
      negative: -1e30,
      name: "",
      query: "--query\nUTF-8 λ\0",
      inputWorkerId: ["worker-2", "worker-1", "worker-2"],
      omittedWorkerId: [],
    }),
  ).toEqual([
    "fixture-command",
    "--scan-id",
    "scan-example",
    "--registration-json-stdin",
    "--offset",
    "0",
    "--negative=-1e+30",
    "--name",
    "",
    "--query=--query\nUTF-8 λ\0",
    "--input-worker-id",
    "worker-2",
    "--input-worker-id",
    "worker-1",
    "--input-worker-id",
    "worker-2",
  ]);
});
