import { CodexSecurity } from "../../src/index.js";
import { withSyntheticScanEvents } from "./api-client.js";

type Arguments = ConstructorParameters<typeof CodexSecurity>;

class InternalTestSecurity extends CodexSecurity {
  constructor(...[config, dependencies, options]: Arguments) {
    super(
      config,
      dependencies === undefined
        ? undefined
        : withSyntheticScanEvents(dependencies),
      options,
    );
  }
}

export const InternalSecurity = InternalTestSecurity as unknown as new (
  config: Record<string, unknown>,
  dependencies: Record<string, unknown>,
  runtimeOptions?: { surface: "cli" | "sdk" },
) => CodexSecurity;
