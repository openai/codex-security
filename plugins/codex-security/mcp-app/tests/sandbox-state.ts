import { pathToFileURL } from "node:url";

export function readOnlyParentSandboxState(pluginRoot: string) {
  return {
    permissionProfile: {
      type: "managed",
      file_system: {
        type: "restricted",
        entries: [
          {
            path: { type: "special", value: { kind: "root" } },
            access: "read",
          },
        ],
      },
      network: "restricted",
    },
    sandboxCwd: pathToFileURL(pluginRoot).href,
  };
}
