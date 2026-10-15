import type { BulkScanPrompt } from "../../src/bulk-scan-discovery.js";
import type { main as cliMain } from "../../src/cli.js";
import { capture } from "../cli-fixtures.js";

type Main = typeof cliMain;

export function createCliTest(
  main: Main,
  {
    stdout = false,
    stderr = false,
  }: { stdout?: boolean | null; stderr?: boolean | null } = {},
) {
  const output = capture(stdout);
  const error = capture(stderr);
  return {
    stdout: output,
    stderr: error,
    runCli: (args: Parameters<Main>[0], dependencies: Parameters<Main>[3]) =>
      main(args, output.stream, error.stream, dependencies),
  };
}

export function captureCli(
  main: Main,
  channel: "stdout" | "stderr",
  isTTY: boolean | null = false,
) {
  const output = capture(isTTY);
  return Object.assign(output, {
    run: (args: Parameters<Main>[0], dependencies: Parameters<Main>[3]) =>
      channel === "stdout"
        ? main(args, output.stream, capture().stream, dependencies)
        : main(args, capture().stream, output.stream, dependencies),
  });
}

export function runCapturedCli(
  main: Main,
  args: Parameters<Main>[0],
  dependencies: Parameters<Main>[3],
) {
  return main(args, capture().stream, capture().stream, dependencies);
}

export function selectionPrompt(
  select: BulkScanPrompt["select"],
  isInteractive = () => true,
) {
  return { isInteractive, select };
}
