export const mcpSmokeInput =
  [
    {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "codex-security-package-smoke", version: "1" },
      },
    },
    { jsonrpc: "2.0", method: "notifications/initialized" },
    { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
  ]
    .map((request) => JSON.stringify(request))
    .join("\n") + "\n";

export function mcpSmokeResponses(stdout) {
  return stdout
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
}
