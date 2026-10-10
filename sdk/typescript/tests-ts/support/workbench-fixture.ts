import { readFileSync } from "node:fs";

export const workbenchFixture = readFileSync(
  new URL("./workbench-fixture.py", import.meta.url),
  "utf8",
);
