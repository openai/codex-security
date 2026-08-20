import { readFile } from "node:fs/promises";
import { describe, expect, test } from "bun:test";
import { parse } from "smol-toml";
import {
  type AttackPathDataflow,
  type AttackPathReachability,
  CodexSecurity,
  CodexSecurityError,
  VERSION,
} from "../src/index.js";
import { main } from "../src/cli.js";

function capture(): {
  stream: Pick<NodeJS.WriteStream, "write">;
  text: () => string;
} {
  let value = "";
  return {
    stream: {
      write(chunk: string | Uint8Array): boolean {
        value += chunk.toString();
        return true;
      },
    },
    text: () => value,
  };
}

describe("TypeScript package skeleton", () => {
  test("exports typed attack-path aliases", () => {
    const dataflow: AttackPathDataflow = {
      transformations: ["decode archive entry"],
    };
    const reachability: AttackPathReachability = {
      attacker: "authenticated uploader",
      entrypoint: "archive upload endpoint",
      preconditions: ["archive extraction is enabled"],
    };
    const transformations: string[] | undefined = dataflow.transformations;
    const attacker: string | undefined = reachability.attacker;

    expect(transformations).toEqual(["decode archive entry"]);
    expect(attacker).toBe("authenticated uploader");
  });

  test("advertises the tested Node.js 22, 24, and 26 release lines", async () => {
    const packageJson = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    );

    const supportedReleases = ["22.13.0", "22.14.0", "24.0.0", "26.0.0"];
    const unsupportedReleases = [
      "22.12.0",
      "23.0.0",
      "23.4.0",
      "23.5.0",
      "25.0.0",
      "27.0.0",
    ];

    expect(
      supportedReleases.filter((version) =>
        Bun.semver.satisfies(version, packageJson.engines.node),
      ),
    ).toEqual(supportedReleases);
    expect(
      unsupportedReleases.filter((version) =>
        Bun.semver.satisfies(version, packageJson.engines.node),
      ),
    ).toEqual([]);
  });

  test("pins each Node.js minimum and preserves protected and latest LTS checks", async () => {
    const ciWorkflow = await readFile(
      new URL("../../../.github/workflows/node-ci.yml", import.meta.url),
      "utf8",
    );

    expect(ciWorkflow).toContain(
      "${{ matrix.node == '22.13.0' && '22' || matrix.node }}",
    );
    expect(ciWorkflow).toContain('node: ["22.13.0"]');
    for (const version of ["24.0.0", "24", "26.0.0", "26"]) {
      expect(ciWorkflow).toContain(`node: "${version}"`);
    }
  });

  test("randomizes tests and keeps the default and Windows CI timeouts", async () => {
    const packageJson = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    );
    const ciWorkflow = await readFile(
      new URL("../../../.github/workflows/node-ci.yml", import.meta.url),
      "utf8",
    );
    const bunConfig = parse(
      await readFile(new URL("../bunfig.toml", import.meta.url), "utf8"),
    );

    expect(packageJson.scripts.test).toBe(
      "bun test --timeout 30000 ./tests-ts",
    );
    expect(bunConfig).toMatchObject({ test: { randomize: true } });
    expect(ciWorkflow).toContain(
      "run: node sdk/typescript/scripts/run-windows-ci-tests.mjs ${{ matrix.shard }}",
    );
    expect(ciWorkflow).toContain(
      "run: bun test --timeout 120000 ./tests-ts/windows-machine-policy.test.ts",
    );
    expect(ciWorkflow).toContain(
      "name: windows-latest / node-${{ matrix.node == '22.13.0' && '22' || matrix.node }}",
    );
    expect(ciWorkflow).toContain("run: pnpm --dir sdk/typescript run test");
    expect(ciWorkflow).not.toContain("--timeout 60000");
  });

  test("builds packages without a preinstalled package manager and provides a production audit", async () => {
    const packageJson = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    );

    expect(packageJson.scripts.build).toBe(
      "node --run clean && tsc -p tsconfig.build.json",
    );
    expect(packageJson.scripts.prepack).toBe("node --run build");
    expect(packageJson.scripts["audit:prod"]).toBe(
      "pnpm audit --prod --audit-level high",
    );
  });

  test("keeps production dependency audits non-blocking in CI and releases", async () => {
    for (const workflowName of ["node-ci.yml", "node-release.yml"]) {
      const workflow = await readFile(
        new URL(`../../../.github/workflows/${workflowName}`, import.meta.url),
        "utf8",
      );

      expect(workflow).toMatch(
        /- name: Audit production dependencies\n(?:\s+if: [^\n]+\n)?\s+continue-on-error: true\n\s+run: (?:sfw )?pnpm --dir sdk\/typescript run audit:prod/u,
      );
    }
  });

  test("exports the async client and curated error base", async () => {
    const packageJson = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    );
    const client = new CodexSecurity({ pluginPath: "/tmp/plugin" });
    expect(client.config.pluginPath).toBe("/tmp/plugin");
    expect(client.metadata).toEqual({
      sdk: "@openai/codex-sdk",
      sdkVersion: packageJson.dependencies["@openai/codex-sdk"],
      executable: "@openai/codex",
      executableVersion: packageJson.dependencies["@openai/codex"],
    });
    expect(new CodexSecurityError("failure").name).toBe("CodexSecurityError");
    await client.close();
  });

  test("provides executable help and version behavior", async () => {
    const stdout = capture();
    const stderr = capture();
    expect(await main([], stdout.stream, stderr.stream)).toBe(0);
    expect(stdout.text()).toContain("Usage: codex-security <command>");
    expect(stdout.text()).toContain("Integrations:");
    expect(stderr.text()).toBe("");

    const versionOutput = capture();
    expect(await main(["--version"], versionOutput.stream, stderr.stream)).toBe(
      0,
    );
    expect(versionOutput.text()).toBe(`${VERSION}\n`);

    const scanHelpOutput = capture();
    expect(
      await main(["scan", "--help"], scanHelpOutput.stream, stderr.stream),
    ).toBe(0);
    expect(scanHelpOutput.text()).toContain(
      "Usage: codex-security scan [repository]",
    );
  });
});
