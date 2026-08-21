import { describe, expect, test } from "bun:test";
import { checkForUpdate } from "../src/version.js";

const registryResponse = (version: string) => async () =>
  new Response(JSON.stringify({ version }));

async function updateAvailable(current: string, latest: string): Promise<boolean> {
  return (
    (await checkForUpdate({
      environment: {},
      currentVersion: current,
      fetch: registryResponse(latest),
    })) !== undefined
  );
}

describe("update notice SemVer prerelease ordering", () => {
  test("uses case-sensitive ASCII ordering for text identifiers", async () => {
    expect(await updateAvailable("1.0.0-A", "1.0.0-a")).toBe(true);
    expect(await updateAvailable("1.0.0-a", "1.0.0-A")).toBe(false);
  });

  test("orders numeric and text prerelease identifiers by SemVer rules", async () => {
    expect(await updateAvailable("1.0.0-beta.1", "1.0.0-beta.alpha")).toBe(
      true,
    );
    expect(await updateAvailable("1.0.0-beta.alpha", "1.0.0-beta.1")).toBe(
      false,
    );
    expect(await updateAvailable("1.0.0-beta.9", "1.0.0-beta.10")).toBe(
      true,
    );
  });

  test("gives a longer equal prerelease identifier list higher precedence", async () => {
    expect(await updateAvailable("1.0.0-alpha", "1.0.0-alpha.1")).toBe(true);
    expect(await updateAvailable("1.0.0-alpha.1", "1.0.0-alpha")).toBe(false);
  });
});
