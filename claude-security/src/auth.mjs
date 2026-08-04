import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

import { expandHome, isRecord } from "./util.mjs";

/**
 * Environment variables that would divert Claude Code onto API-key billing.
 *
 * This tool exists to run scans on a Claude Code subscription, so these are
 * stripped from every session it starts. An operator who genuinely wants API
 * billing can opt back in with CLAUDE_SECURITY_ALLOW_API_KEY=1.
 */
export const API_KEY_VARIABLES = ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"];

export function apiKeyOverrideAllowed(environment = process.env) {
  return environment["CLAUDE_SECURITY_ALLOW_API_KEY"] === "1";
}

export function withoutApiKeys(environment) {
  if (apiKeyOverrideAllowed(environment)) return environment;
  const sanitized = { ...environment };
  for (const name of API_KEY_VARIABLES) delete sanitized[name];
  return sanitized;
}

function credentialsPath(environment = process.env) {
  const configDir = environment["CLAUDE_CONFIG_DIR"];
  const base = configDir ? expandHome(configDir) : join(homedir(), ".claude");
  return join(base, ".credentials.json");
}

/**
 * Best-effort read of the local Claude Code sign-in.
 *
 * The credentials file is the source of truth on Windows and Linux. macOS keeps
 * them in the Keychain, and managed installs can use a credential helper, so an
 * unreadable file is reported as `unknown` rather than "signed out": the `claude`
 * CLI itself stays the authority, and guessing here would block working setups.
 */
export async function authStatus(environment = process.env) {
  const apiKeyPresent = API_KEY_VARIABLES.filter((name) => {
    const value = environment[name];
    return typeof value === "string" && value.trim() !== "";
  });

  let raw;
  try {
    raw = JSON.parse(await readFile(credentialsPath(environment), "utf8"));
  } catch {
    return {
      authenticated: true,
      determined: false,
      source: "claude CLI (not verifiable from this host)",
      subscriptionType: null,
      expiresAt: null,
      apiKeyPresent,
      apiKeyIgnored: apiKeyPresent.length > 0 && !apiKeyOverrideAllowed(environment),
    };
  }

  const oauth = isRecord(raw) && isRecord(raw["claudeAiOauth"]) ? raw["claudeAiOauth"] : null;
  if (oauth === null) {
    return {
      authenticated: apiKeyPresent.length > 0 && apiKeyOverrideAllowed(environment),
      determined: true,
      source: "no Claude subscription sign-in found",
      subscriptionType: null,
      expiresAt: null,
      apiKeyPresent,
      apiKeyIgnored: apiKeyPresent.length > 0 && !apiKeyOverrideAllowed(environment),
    };
  }

  const expiresAt = typeof oauth["expiresAt"] === "number" ? oauth["expiresAt"] : null;
  const refreshExpiresAt =
    typeof oauth["refreshTokenExpiresAt"] === "number" ? oauth["refreshTokenExpiresAt"] : null;
  // An expired access token is normal: the CLI refreshes it. Only a dead refresh
  // token actually means the operator has to sign in again.
  const refreshable = refreshExpiresAt === null || refreshExpiresAt > Date.now();

  return {
    authenticated: refreshable,
    determined: true,
    source: "Claude subscription (OAuth)",
    subscriptionType:
      typeof oauth["subscriptionType"] === "string" ? oauth["subscriptionType"] : null,
    expiresAt,
    apiKeyPresent,
    apiKeyIgnored: apiKeyPresent.length > 0 && !apiKeyOverrideAllowed(environment),
  };
}

export function describeAuth(status) {
  const lines = [];
  if (!status.determined) {
    lines.push(
      "Auth: delegated to the local `claude` CLI (credentials are not stored in a readable file on this host).",
    );
  } else if (status.authenticated) {
    const plan = status.subscriptionType === null ? "" : ` — ${status.subscriptionType} plan`;
    lines.push(`Auth: signed in with a Claude subscription${plan}.`);
    if (status.expiresAt !== null) {
      const expiry = new Date(status.expiresAt);
      lines.push(
        expiry.getTime() > Date.now()
          ? `Access token valid until ${expiry.toISOString()} (auto-refreshed).`
          : "Access token expired; the CLI will refresh it on the next call.",
      );
    }
  } else {
    lines.push("Auth: not signed in to a Claude subscription.");
  }
  lines.push("Scans run through the local `claude` CLI, so they bill against that plan.");
  if (status.apiKeyIgnored) {
    lines.push(
      `Ignoring ${status.apiKeyPresent.join(" and ")} so scans stay on the subscription. ` +
        "Set CLAUDE_SECURITY_ALLOW_API_KEY=1 to use API billing instead.",
    );
  } else if (status.apiKeyPresent.length > 0) {
    lines.push(
      `CLAUDE_SECURITY_ALLOW_API_KEY=1 is set, so ${status.apiKeyPresent.join(" and ")} will be used and scans will bill as API usage.`,
    );
  }
  return lines.join("\n");
}
