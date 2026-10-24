import { pathToFileURL } from "node:url";

export function failedChecks(needs) {
  if (needs["classify-changes"]?.result !== "success")
    return ["classify-changes"];
  const selected = needs["classify-changes"].outputs;
  const required = ["static-checks"];
  if (selected["source-required"] === "true") {
    required.push(
      "native",
      "package",
      "test",
      "compatibility",
      "mcp",
      "plugin-host",
      "plugin-source",
      "windows-test",
      "windows-verify",
    );
  } else if (selected["source-required"] !== "false") {
    return ["source-required classification"];
  }
  for (const check of ["workflow-quality", "container-validate"]) {
    if (selected[check] === "true") required.push(check);
    else if (selected[check] !== "false") return [`${check} classification`];
  }
  return required.filter((name) => needs[name]?.result !== "success");
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
