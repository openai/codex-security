import { execFile } from "node:child_process";
import { join } from "node:path";
import { resolvePythonCommand } from "./python_command.js";

interface ScanGuidanceInput {
  pluginRoot: string;
  repository: string;
  scopes: readonly string[];
  diffTarget?: Readonly<Record<string, unknown>>;
  pythonCommand?: string;
  signal?: AbortSignal;
}

// Import the packaged inventory implementation in isolated Python. Repository
// paths travel as JSON data, never as Python code or shell arguments.
const selectGuidance = `
import json
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from workbench.scan_guidance import rust_scan_guidance
request = json.load(sys.stdin)
print(rust_scan_guidance(
    Path(request["repository"]),
    request["scopes"],
    plugin_root=Path(request["pluginRoot"]),
    diff_target=request.get("diffTarget"),
), end="")
`;

/** Select plugin-owned review guidance without opening source file contents. */
export async function loadScanGuidance(input: ScanGuidanceInput): Promise<string> {
  try {
    const pythonCommand = input.pythonCommand ?? await resolvePythonCommand();
    return await new Promise<string>((resolve, reject) => {
      const child = execFile(
        pythonCommand,
        ["-I", "-X", "utf8", "-B", "-c", selectGuidance, join(input.pluginRoot, "scripts")],
        { encoding: "utf8", signal: input.signal },
        (error, stdout) => error ? reject(error) : resolve(stdout)
      );
      child.stdin?.on("error", () => {
        // The process callback reports a failed helper, including early exit.
      });
      child.stdin?.end(JSON.stringify({
        repository: input.repository,
        scopes: input.scopes,
        pluginRoot: input.pluginRoot,
        ...(input.diffTarget ? { diffTarget: input.diffTarget } : {})
      }));
    });
  } catch (error) {
    if (input.signal?.aborted) throw error;
    // Method selection is supplemental; unavailable inventory must not prevent
    // loading a scan or continuing its ordinary security audit.
    return "Supplemental review guidance could not be selected from the scoped file inventory. "
      + "Continue the ordinary audit and select relevant installed review-method skills "
      + "from their descriptions as source languages are encountered. Pass their resolved "
      + "paths and applicable guidance to the assigned reviewers.";
  }
}
