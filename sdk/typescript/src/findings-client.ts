import { CodexSecurityError } from "./errors.js";
import { retryDelay, waitForRetry } from "./deduplication/retry.js";
import type { Finding } from "./models.js";
import type {
  FindingNeighborhood,
  FindingSearchScope,
} from "./finding-retrieval.js";

export type FindingsRequest = (
  url: URL,
  init: RequestInit,
) => Promise<Response>;

class FindingsHttpError extends CodexSecurityError {
  constructor(
    message: string,
    readonly status: number,
    readonly retryAfter: string | null,
  ) {
    super(message);
  }
}

function isRetryable(error: unknown): boolean {
  if (error instanceof FindingsHttpError)
    return [408, 429, 500, 502, 503, 504].includes(error.status);
  // Fetch rejects network failures with TypeError; JSON truncation can produce SyntaxError.
  return error instanceof TypeError || error instanceof SyntaxError;
}

export class FindingsClient {
  constructor(
    private readonly url: string,
    private readonly signal?: AbortSignal,
    private readonly request: FindingsRequest = fetch,
    private readonly retries: {
      wait?: typeof waitForRetry;
      random?: () => number;
    } = {},
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
    return await this.retry(async () => {
      const response = await this.request(url, { signal: this.signal });
      if (!response.ok) {
        await response.body?.cancel().catch(() => undefined);
        throw new FindingsHttpError(
          `Potential-duplicates lookup for ${findingId} failed (HTTP ${response.status}).${
            response.status === 404
              ? " Import the finding with its repositoryId through POST /v1/bulk/findings before deduplicating."
              : ""
          }`,
          response.status,
          response.headers.get("Retry-After"),
        );
      }
      return (await response.json()) as FindingNeighborhood;
    });
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
    await this.retry(() => this.post("v1/dedupe-groups", { groups }));
  }

  private async retry<T>(operation: () => Promise<T>): Promise<T> {
    for (let attempt = 1; ; attempt++) {
      this.signal?.throwIfAborted();
      try {
        return await operation();
      } catch (error) {
        this.signal?.throwIfAborted();
        if (attempt === 3 || !isRetryable(error)) throw error;
        let delay = retryDelay(attempt, this.retries.random);
        if (error instanceof FindingsHttpError && error.retryAfter !== null) {
          const seconds = Number(error.retryAfter);
          const serverDelay = Number.isFinite(seconds)
            ? seconds * 1000
            : Date.parse(error.retryAfter) - Date.now();
          if (Number.isFinite(serverDelay))
            delay = Math.max(delay, serverDelay);
        }
        await (this.retries.wait ?? waitForRetry)(delay, this.signal);
      }
    }
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
      await response.body?.cancel().catch(() => undefined);
      throw new FindingsHttpError(
        `Findings API POST /${path} failed (HTTP ${response.status}).`,
        response.status,
        response.headers.get("Retry-After"),
      );
    }
    return await response.json();
  }
}
