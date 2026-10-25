import { pathToFileURL } from "node:url";

export function failedChecks(needs) {
  if (needs["classify-changes"]?.result !== "success")
    return ["classify-changes"];
  const selected = needs["classify-changes"].outputs;
  if (selected["source-run"]) return [];
  const required = ["static-checks"];
  const groups = {
    "package-required": ["native", "package", "compatibility"],
    "source-required": [
      "test",
      "mcp",
      "plugin-host",
      "plugin-source",
      "windows-test",
      "windows-verify",
    ],
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
  const failures = failedChecks(JSON.parse(process.env.CI_RESULTS));
  if (failures.length) {
    console.error(`Required CI checks did not pass: ${failures.join(", ")}`);
    process.exitCode = 1;
  } else console.log("All selected required CI checks passed.");
}
