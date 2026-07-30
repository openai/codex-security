import { readFile } from "node:fs/promises";
import { describe, expect, test } from "bun:test";
import { CodexSecurity, CodexSecurityError, VERSION } from "../src/index.js";
import type {
  Finding,
  FindingCodeEvidence,
  FindingRootCause,
  FindingWriteup,
  ScanHardening,
  ScanRecord,
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

  test("pins each supported Node.js minimum and retains latest LTS coverage", async () => {
    const ciWorkflow = await readFile(
      new URL("../../../.github/workflows/node-ci.yml", import.meta.url),
      "utf8",
    );

    expect(ciWorkflow).toContain('node: ["22.13.0"]');
    for (const version of ["24.0.0", "24", "26.0.0", "26"]) {
      expect(ciWorkflow).toContain(`node: "${version}"`);
    }
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

  test("exposes canonical finding and hardening fields with public types", () => {
    const finding = {} as Finding;
    const scan = {} as ScanRecord;
    const writeup: FindingWriteup | undefined = finding.writeup;
    const evidence: FindingCodeEvidence[] | undefined = finding.codeEvidence;
    const rootCause: string | FindingRootCause | undefined = finding.rootCause;
    const hardening: ScanHardening | undefined = scan.hardening;
    const reportPath: string | undefined = finding.writeup?.reportPath;
    const firstEvidencePath: string | undefined =
      finding.codeEvidence?.[0]?.path;
    const portfolioPath: "hardening/hardening.md" | undefined =
      scan.hardening?.portfolioPath;
    expect([
      writeup,
      evidence,
      rootCause,
      hardening,
      reportPath,
      firstEvidencePath,
      portfolioPath,
    ]).toEqual(new Array(7).fill(undefined));
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
