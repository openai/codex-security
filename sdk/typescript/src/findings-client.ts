import { CodexSecurityError } from "./errors.js";
import type { Finding } from "./models.js";
import type {
  FindingNeighborhood,
  FindingSearchScope,
} from "./finding-retrieval.js";

export type FindingsRequest = (
  url: URL,
  init: RequestInit,
) => Promise<Response>;

export class FindingsClient {
  constructor(
    private readonly url: string,
    private readonly signal?: AbortSignal,
    private readonly request: FindingsRequest = fetch,
  ) {}

  async potentialDuplicates(
    findingId: string,
    scope: FindingSearchScope,
  ): Promise<FindingNeighborhood> {
    const url = this.endpoint(
      `v1/finding/${encodeURIComponent(findingId)}/potential-duplicates`,
    );
    if (scope.allRepositories === true)
      url.searchParams.set("allRepositories", "true");
    else url.searchParams.set("repositoryId", scope.repositoryId);
    const response = await this.request(url, { signal: this.signal });
    if (!response.ok) {
      throw new CodexSecurityError(
        `Potential-duplicates lookup for ${findingId} failed (HTTP ${response.status}).${
          response.status === 404
            ? " Import the finding with its repositoryId through POST /v1/bulk/findings before deduplicating."
            : ""
        }`,
      );
    }
    return (await response.json()) as FindingNeighborhood;
  }

  async publish(
    findings: readonly Finding[],
    repositoryId: string,
  ): Promise<string[]> {
    const receipt = await this.post("v1/bulk/findings", {
      findings,
      repositoryId,
    });
    const expected = new Set(findings.map((finding) => finding.findingId));
    if (
      !Array.isArray(receipt) ||
      receipt.length !== findings.length ||
      new Set(receipt).size !== expected.size ||
      receipt.some((id) => !expected.has(id))
    ) {
      throw new CodexSecurityError(
        "The findings API did not acknowledge all published finding IDs. Check the service before retrying.",
      );
    }
    return receipt as string[];
  }

  async storeDedupeGroups(groups: readonly string[][]): Promise<void> {
    if (groups.length === 0) return;
    await this.post("v1/dedupe-groups", { groups });
  }

  private endpoint(path: string): URL {
    return new URL(path, this.url.endsWith("/") ? this.url : `${this.url}/`);
  }

  private async post(path: string, body: unknown): Promise<unknown> {
    const response = await this.request(this.endpoint(path), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: this.signal,
    });
    if (!response.ok) {
      throw new CodexSecurityError(
        `Findings API POST /${path} failed (HTTP ${response.status}).`,
      );
    }
    return await response.json();
  }
}
