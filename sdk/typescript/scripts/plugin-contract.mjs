export function pluginContractFiles(contract, validatePath) {
  const publicManifest = ".codex-plugin/plugin.json";
  const { externalOwnedExact, shippedExact } = contract;
  if (
    !Array.isArray(externalOwnedExact) ||
    !externalOwnedExact.every((path) => typeof path === "string") ||
    !Array.isArray(shippedExact) ||
    !shippedExact.every((path) => typeof path === "string")
  ) {
    throw new Error("Plugin projection contract contains invalid paths.");
  }
  if (!externalOwnedExact.includes(publicManifest)) {
    throw new Error(
      "Plugin projection contract must declare the public manifest as externally owned.",
    );
  }

  const files = [
    publicManifest,
    ...shippedExact.filter((path) => !path.startsWith("sdk/")),
  ];
  if (validatePath) files.forEach(validatePath);
  if (new Set(files).size !== files.length) {
    throw new Error("Plugin projection contract contains duplicate paths.");
  }
  return files;
}
