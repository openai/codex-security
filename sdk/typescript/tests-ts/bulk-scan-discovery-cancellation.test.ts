import { Octokit } from "@octokit/core";
import { describe, expect, test } from "bun:test";
import {
  runBulkScanWizard,
  type BulkScanDiscoveryDependencies,
  type BulkScanPrompt,
} from "../src/bulk-scan-discovery.js";

class SignalPrompt implements BulkScanPrompt {
  public readonly calls: Array<{
    kind: "select" | "input" | "confirm";
    signal: AbortSignal | undefined;
  }> = [];
  readonly #choices = ["personal-account", ""];

  public isInteractive(): boolean {
    return true;
  }

  public write(_value: string): void {}

  public async confirm(
    _question: string,
    _defaultValue = false,
    signal?: AbortSignal,
  ): Promise<boolean> {
    this.calls.push({ kind: "confirm", signal });
    return false;
  }

  public async input(
    _question: string,
    defaultValue = "",
    signal?: AbortSignal,
  ): Promise<string> {
    this.calls.push({ kind: "input", signal });
    return defaultValue;
  }

  public async select<Value extends string>(
    _question: string,
    options: readonly { label: string; value: Value }[],
    _presentation?: { header?: string },
    signal?: AbortSignal,
  ): Promise<Value> {
    this.calls.push({ kind: "select", signal });
    const choice = this.#choices.shift();
    return (options.find(({ value }) => value === choice) ?? options[0]!).value;
  }
}

function github(): Octokit {
  return {
    request: async (route: string) => {
      if (route === "GET /user/orgs") {
        return { data: [{ login: "acme" }], headers: {} };
      }
      if (route === "GET /user") {
        return { data: { login: "personal-account" }, headers: {} };
      }
      throw new Error(`Unexpected request: ${route}`);
    },
    graphql: async () => ({
      repositoryOwner: {
        repositories: {
          nodes: [
            {
              nameWithOwner: "personal-account/project",
              pushedAt: "2026-08-18T00:00:00Z",
              defaultBranchRef: {
                target: {
                  oid: "0123456789abcdef0123456789abcdef01234567",
                },
              },
            },
          ],
          pageInfo: { hasNextPage: false, endCursor: null },
        },
      },
    }),
  } as unknown as Octokit;
}

describe("bulk scan wizard cancellation", () => {
  test("passes the caller signal to every blocking interactive prompt", async () => {
    const prompt = new SignalPrompt();
    const controller = new AbortController();
    const dependencies: BulkScanDiscoveryDependencies = {
      prompt,
      now: () => Date.parse("2026-08-18T07:00:00Z"),
      currentDirectory: () => "/tmp",
      createGitHub: async () => github(),
    };

    await expect(
      runBulkScanWizard(dependencies, controller.signal),
    ).resolves.toBeNull();

    expect(prompt.calls.map(({ kind }) => kind)).toEqual([
      "select",
      "select",
      "input",
      "confirm",
    ]);
    expect(
      prompt.calls.every(({ signal }) => signal === controller.signal),
    ).toBe(true);
  });
});
