import { readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures("large-finding-");
afterEach(cleanup);

test.each(["validate", "patch", "verify-fix"])(
  "%s reads a complete oversized finding file",
  async (command) => {
    const repository = await temporaryDirectory();
    const original = join(repository, "finding with spaces.json");
    const finding = JSON.stringify(
      {
        evidence: "Synthetic evidence. ".repeat(100_000),
        tail: "Last evidence",
      },
      null,
      2,
    );
    await writeFile(original, finding);
    let path = "";
    const { runCli, stdout, stderr } = createCliTest(main);
    expect(
      await runCli([command, original], {
        ...dependencies({
          onCodex: async (_args, output, _environment, input) => {
            const prompt = output?.appServer?.prompt ?? input!;
            expect(prompt.length).toBeLessThan(1 << 20);
            path = JSON.parse(prompt.match(/^".*finding\.json"$/m)![0]);
            // The file must outlive the asynchronous worker call.
            await Promise.resolve();
            expect(await readFile(path, "utf8")).toBe(finding);
            output!.stdout.write(
              command === "verify-fix"
                ? JSON.stringify({
                    results: [
                      {
                        id: "finding-1",
                        status: "fixed",
                        evidence: "Synthetic verification passed.",
                      },
                    ],
                  })
                : "Synthetic task completed.",
            );
            return 0;
          },
        }),
        currentDirectory: () => repository,
      }),
      stderr.text(),
    ).toBe(0);
    expect(stdout.text()).not.toBe("");
    await expect(stat(path)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readFile(original, "utf8")).toBe(finding);
  },
);
