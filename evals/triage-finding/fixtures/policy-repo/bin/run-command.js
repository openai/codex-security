#!/usr/bin/env node
import { execSync } from "node:child_process";

const command = process.argv[2];
if (command === undefined) {
  throw new Error("Provide an operator command");
}
execSync(command, { stdio: "inherit" });
