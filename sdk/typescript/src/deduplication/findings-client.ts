import { CodexSecurityError } from "../errors.js";
import type {
  FindingNeighborhood,
  FindingSearchScope,
} from "../finding-retrieval.js";

export type FindingsRequest = (
  url: URL,
  init: RequestInit,
) => Promise<Response>;

export class FindingsClient {
  constructor(
    private readonly url: string,
    private readonly scope: FindingSearchScope,
    private readonly signal?: AbortSignal,
    private readonly request: FindingsRequest = fetch,
  ) {}

  async potentialDuplicates(findingId: string): Promise<FindingNeighborhood> {
    const url = new URL(
      `v1/finding/${encodeURIComponent(findingId)}/potential-duplicates`,
      this.url.endsWith("/") ? this.url : `${this.url}/`,
    );
    if (this.scope.allRepositories === true)
      url.searchParams.set("allRepositories", "true");
    else url.searchParams.set("repositoryId", this.scope.repositoryId);
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
}
