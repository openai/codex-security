import { expect, test } from "bun:test";
import { readPythonRequirements } from "../src/dependency-manifests.js";

test("hashed requirements continued onto later lines are pins", async () => {
  const hash = "sha256:" + "a".repeat(64);
  const gaps: string[] = [];
  const manifests = await readPythonRequirements(
    ["requirements.txt"],
    "requests",
    async () =>
      `idna==3.6 \\\n    --hash=${hash}\nrequests==2.31.0 \\\n    --hash=${hash} \\\n    --hash=${hash}\n`,
    gaps,
  );
  expect(gaps).toEqual([]);
  expect(manifests[0]!.selection).toEqual({
    kind: "requirements-pin",
    version: "2.31.0",
    lockfile: "requirements.txt",
    packagePath: "requests",
    line: 3,
  });
});
