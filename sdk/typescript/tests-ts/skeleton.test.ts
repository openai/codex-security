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
import { main, rootHelp, scanHelp, versionText } from "../src/cli.js";

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
    const client = new CodexSecurity({ pluginPath: "/tmp/plugin" });
    expect(client.config.pluginPath).toBe("/tmp/plugin");
    expect(new CodexSecurityError("failure").name).toBe("CodexSecurityError");
    await client.close();
  });

  test("provides executable help and version behavior", async () => {
    const stdout = capture();
    const stderr = capture();
    expect(await main([], stdout.stream, stderr.stream)).toBe(0);
    expect(stdout.text()).toBe(`${rootHelp()}\n`);
    expect(stderr.text()).toBe("");

    const versionOutput = capture();
    expect(await main(["--version"], versionOutput.stream, stderr.stream)).toBe(
      0,
    );
    expect(versionOutput.text()).toBe(`${versionText()}\n`);
    expect(versionText()).toContain(VERSION);

    const scanHelpOutput = capture();
    expect(
      await main(["scan", "--help"], scanHelpOutput.stream, stderr.stream),
    ).toBe(0);
    expect(scanHelpOutput.text()).toBe(`${scanHelp()}\n`);
  });
});
