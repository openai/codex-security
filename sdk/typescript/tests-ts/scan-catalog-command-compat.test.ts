import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, spyOn, test } from "bun:test";
import * as sdkEnvironment from "../src/codex-sdk-environment.js";
import { PluginBootstrapError } from "../src/errors.js";
import { resolveScanCyberAccessProgram } from "../src/scan-cyber-access.js";

test("a launcher without debug tooling preserves native forwarding gates and errors", async () => {
  const root = await mkdtemp(join(tmpdir(), "catalog-command-"));
  try {
    const home = join(root, "home");
    await mkdir(home);
    await writeFile(
      join(home, "config.toml"),
      'cli_auth_credentials_store="file"\nopenai_base_url="http://127.0.0.1:1/v1"\nchatgpt_base_url="http://127.0.0.1:1"\n',
    );
    const launcher = join(root, "launcher.mjs");
    await writeFile(
      launcher,
      `
      import { spawnSync } from "node:child_process";
      const [diagnostic, file, ...args] = process.argv.slice(2);
      if (args.includes("debug") && args.includes("models")) {
        if (diagnostic === "no bundled option") {
          if (!args.includes("--bundled")) {
            const cyber = process.env.CODEX_API_KEY === "synthetic-project-key" ? ["daybreak_blue"] : [];
            console.log(JSON.stringify({models:[{slug:"synthetic-model",available_access_programs:{cyber}}]}));
            process.exit(0);
          }
          console.error("error: unexpected argument '--bundled' found");
          console.error("Usage: codex debug models");
          process.exit(2);
        }
        console.error(diagnostic.replace("<args>", args.slice(args.indexOf("debug")).join(" ")));
        process.exit(2);
      }
      if (file) args.unshift("-c", "model_catalog_json=" + JSON.stringify(file));
      process.exit(spawnSync(${JSON.stringify(sdkEnvironment.resolveBundledCodexExecutable())}, args, {stdio:"inherit"}).status ?? 1);
    `,
    );
    const select = (diagnostic: string, enabled: boolean, file = "") =>
      resolveScanCyberAccessProgram({
        command: {
          command: process.execPath,
          args: [launcher, diagnostic, file],
        },
        cwd: root,
        launcherCwd: root,
        environment: {
          HOME: home,
          CODEX_HOME: home,
          CODEX_API_KEY: "synthetic-project-key",
        },
        config: { features: { cli_daybreak: enabled } },
        model: "synthetic-model",
        signal: new AbortController().signal,
      });
    for (const diagnostic of [
      "unsupported launcher command: <args>",
      "sandboxed launcher does not expose debug models",
      "error: unrecognized subcommand 'models'",
    ]) {
      expect(await select(diagnostic, false)).toBeUndefined();
    }
    expect(await select("unsupported launcher command: <args>", true)).toBe(
      "standard",
    );
    expect(await select("no bundled option", true)).toBe("daybreak_blue");
    for (const diagnostic of [
      "permission denied while reading the model catalog",
      "invalid model_catalog_json: missing required field",
      "error: unexpected argument '--bundled' found",
    ]) {
      await expect(select(diagnostic, true)).rejects.toThrow(diagnostic);
    }
    const file = join(root, "models.json");
    const fixture = JSON.parse(
      await readFile(
        new URL("./fixtures/native-skill-model-catalog.json", import.meta.url),
        "utf8",
      ),
    );
    fixture.models[0].slug = "synthetic-model";
    await writeFile(file, JSON.stringify(fixture));
    expect(
      await select("unsupported launcher command: <args>", true, file),
    ).toBe("daybreak_blue");
    fixture.models[0].available_access_programs.cyber = ["daybreak_red"];
    await writeFile(file, JSON.stringify(fixture));
    await expect(
      select("unsupported launcher command: <args>", true, file),
    ).rejects.toThrow("requires Daybreak Red");
    using missing = spyOn(
      sdkEnvironment,
      "resolveBundledCodexExecutable",
    ).mockImplementation(() => {
      throw new PluginBootstrapError("Optional native package is absent");
    });
    expect(await select("unsupported launcher command: <args>", true)).toBe(
      "standard",
    );
    expect(
      await select("unsupported launcher command: <args>", false),
    ).toBeUndefined();
    expect(missing).toHaveBeenCalled();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
