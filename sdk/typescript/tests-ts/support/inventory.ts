import {
  bundledCodexSdkEnvironment,
  definedEnvironment,
} from "../../src/codex-sdk-environment.js";
import { resolveCodexCommand } from "../../src/runtime.js";

export function inventoryToolEnvironment() {
  return bundledCodexSdkEnvironment(
    resolveCodexCommand({}).command,
    definedEnvironment(process.env),
  );
}
