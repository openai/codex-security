import { pathToFileURL } from "node:url";

export function failedChecks(needs) {
  if (needs["classify-changes"]?.result !== "success")
    return ["classify-changes"];
  const selected = needs["classify-changes"].outputs;
  if (selected["source-run"]) return [];
  const required = ["static-checks"];
  const groups = {
    "package-required": ["native", "package", "compatibility"],
    "source-required": ["test", "windows-test"],
    "plugin-tests-required": ["mcp", "plugin-host", "plugin-source"],
    "workflow-quality": ["workflow-quality"],
    "container-validate": ["container-validate"],
    "action-ci": ["action-ci"],
    "eval-contracts": ["eval-contracts"],
  };
  for (const [name, checks] of Object.entries(groups)) {
    if (selected[name] === "true") required.push(...checks);
    else if (selected[name] !== "false") return [`${name} classification`];
  }
  return required.filter(
    (name) =>
      needs[name]?.result !== "success" ||
      (name === "action-ci" && needs[name].outputs?.passed !== "true"),
  );
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const needs = JSON.parse(process.env.CI_RESULTS);
  const failures = failedChecks(needs);
  if (failures.length) {
    const details = failures.map((name) => {
      if (name.endsWith(" classification"))
        return `${name} (missing or invalid)`;
      const result = needs[name]?.result;
      if (name === "action-ci" && result === "success")
        return `${name} (passed output was not "true")`;
      return `${name} (${result || "missing result"})`;
    });
    console.error(`Required CI checks did not pass: ${details.join(", ")}`);
    process.exitCode = 1;
  } else console.log("All selected required CI checks passed.");
}
