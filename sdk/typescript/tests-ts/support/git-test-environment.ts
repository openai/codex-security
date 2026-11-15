import { fileURLToPath } from "node:url";

// Git installations can supply filters and credential helpers. Individual
// tests select their own configuration when they exercise those settings.
process.env["GIT_CONFIG_SYSTEM"] = fileURLToPath(
  new URL("./empty.gitconfig", import.meta.url),
);
