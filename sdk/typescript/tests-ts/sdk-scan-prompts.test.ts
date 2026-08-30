import { mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { TestClient } from "./support/api-client.js";
import { createApiTestFixtures } from "./support/api-events.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);

test.each([
  ["scanPromptFile", "scanPrompt"],
  ["validationPromptFile", "validationPrompt"],
  ["postScanPromptFile", "postScanPrompt"],
] as const)(
  "SDK %s uses the existing file protections and permits explicit external files",
  async (fileOption, inlineOption) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const external = join(root, "external");
    const linked = join(repository, "linked");
    await mkdir(repository);
    await mkdir(external);
    const file = join(external, "prompt.md");
    await writeFile(file, "Synthetic private instructions.");
    await symlink(
      external,
      linked,
      process.platform === "win32" ? "junction" : "dir",
    );
    await using client = new TestClient(
      {},
      {
        environment: { CODEX_SECURITY_STATE_DIR: join(root, "state") },
        prepareRuntime: async () => {
          throw new Error("Runtime must not start");
        },
      },
    );
    for (const operation of ["preflight", "run"] as const) {
      await expect(
        client[operation](repository, { [fileOption]: external }),
      ).rejects.toThrow("Input files must be regular files");
      await expect(
        client[operation](repository, {
          [fileOption]: join(linked, "prompt.md"),
        }),
      ).rejects.toThrow(
        "Input files must not follow repository directory links",
      );
    }
    const preflight = await client.preflight(repository, {
      [fileOption]: file,
    });
    expect(preflight.mode).toBe("standard");
    expect(JSON.stringify(preflight)).not.toContain(
      "Synthetic private instructions",
    );
    await expect(
      client.preflight(repository, {
        [fileOption]: join(root, "missing.md"),
        [inlineOption]: "Explicit inline instructions.",
      }),
    ).resolves.toMatchObject({ mode: "standard" });
  },
);

test("SDK prompt files retain empty-file and deep-validation behavior", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  await mkdir(repository);
  const empty = join(root, "empty.md");
  const validation = join(root, "validation.md");
  await writeFile(empty, " \n");
  await writeFile(validation, "Validate the synthetic fixture.");
  await using client = new TestClient(
    {},
    {
      environment: {
        CODEX_HOME: join(root, "ambient"),
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
      },
    },
  );
  await expect(
    client.preflight(repository, {
      scanPromptFile: empty,
      postScanPromptFile: empty,
    }),
  ).resolves.toMatchObject({ mode: "standard" });
  await expect(
    client.preflight(repository, { validationPromptFile: empty }),
  ).rejects.toThrow("The validation prompt must not be empty");
  await expect(
    client.preflight(repository, {
      mode: "deep",
      validationPromptFile: validation,
    }),
  ).rejects.toThrow("Custom validation is not supported for Deep scans");
});
