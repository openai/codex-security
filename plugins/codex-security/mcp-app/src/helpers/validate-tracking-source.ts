import { parseArgs } from "node:util";
import { loadSealedContract } from "../sealed-contract.js";
import { filesystemErrorMessage, resolvedPathText } from "./helper-files.js";
import { expandHome } from "./resolve-security-md.js";

export interface TrackingSourceOptions {
  findingId?: string;
  fingerprint?: string;
  pluginRoot?: string;
  signal?: AbortSignal;
}

export async function validateTrackingSource(
  scanDirectory: string,
  options: TrackingSourceOptions = {},
  posixHome = process.env.HOME,
) {
  if (options.findingId !== undefined && options.fingerprint !== undefined)
    throw new Error("use only one of --finding-id or --fingerprint");

  const { contract } = await loadSealedContract(
    resolvedPathText(expandHome(scanDirectory, posixHome)),
    {
      pluginRoot: options.pluginRoot,
      signal: options.signal,
      profile: "tracking",
    },
  );
  const findings = contract.findings.findings;
  if (options.findingId === undefined && options.fingerprint === undefined)
    return findings;

  const selected = findings.filter((finding) =>
    options.findingId !== undefined
      ? finding.findingId === options.findingId
      : finding.fingerprints.primary === options.fingerprint,
  );
  if (selected.length !== 1)
    throw new Error("the selector did not resolve exactly one finding");
  return selected;
}

export async function validateTrackingSourceCommand(
  args: string[],
  posixHome = process.env.HOME,
): Promise<number> {
  const usage =
    "usage: launch_codex_security_mcp[.cmd] --helper validate-tracking-source [-h] scan_dir [--finding-id ID | --fingerprint FINGERPRINT]";
  try {
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: {
        help: { type: "boolean", short: "h" },
        "finding-id": { type: "string" },
        fingerprint: { type: "string" },
      },
    });
    if (values.help) {
      console.log(
        `${usage}\n\nValidate a sealed scan and list or select findings for tracking.\n\npositional arguments:\n  scan_dir  Sealed scan directory.\n\noptions:\n  -h, --help  show this help message and exit\n  --finding-id ID\n  --fingerprint FINGERPRINT`,
      );
      return 0;
    }
    if (positionals.length !== 1)
      throw new Error("exactly one scan directory is required");
    const findings = await validateTrackingSource(
      positionals[0]!,
      {
        findingId: values["finding-id"],
        fingerprint: values.fingerprint,
      },
      posixHome,
    );
    for (const finding of findings) console.log(finding.findingId);
    return 0;
  } catch (error) {
    console.error(
      `tracking source preflight failed: ${filesystemErrorMessage(error)}`,
    );
    return 2;
  }
}
