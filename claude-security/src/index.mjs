/**
 * Programmatic entry point.
 *
 * The CLI is the primary interface, but a scan is just `runScan(repository,
 * options)` — useful for wiring the scanner into CI or another tool without
 * shelling out and parsing terminal output.
 *
 *   import { runScan } from "claude-security";
 *   const summary = await runScan(".", { mode: "standard" });
 *   console.log(summary.reportPath, summary.findings.length);
 */
export { preflightScan, runScan } from "./scan.mjs";
export { authStatus, describeAuth } from "./auth.mjs";
export { DEFAULT_EFFORT, DEFAULT_MODEL, EFFORT_LEVELS } from "./runner.mjs";
export { SCAN_MODES, normalizeTarget, targetDescription } from "./targets.mjs";
export { SEVERITY_LEVELS, SecurityError, IncompleteScanError } from "./util.mjs";
export { resolvePython } from "./workbench.mjs";
