import { CodexSecurityError } from "./errors.js";
import { setTimeout } from "node:timers/promises";
import type { Finding } from "./models.js";
import {
  isFinding,
  type FindingNeighborhood,
  type FindingSearchScope,
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
    private readonly delay: (
      milliseconds: number,
      signal?: AbortSignal,
    ) => Promise<void> = async (milliseconds, signal) => {
      try {
        await setTimeout(milliseconds, undefined, { signal });
      } catch (error) {
        signal?.throwIfAborted();
        throw error;
      }
    },
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
    let response: Response;
    for (let attempt = 0; ; attempt++) {
      this.signal?.throwIfAborted();
      response = await this.request(url, { signal: this.signal });
      if (
        attempt === 2 ||
        ![408, 429, 500, 502, 503, 504].includes(response.status)
      )
        break;
      const header = response.headers.get("Retry-After");
      const retryAfter =
        header === null
          ? NaN
          : /^\d+(?:\.\d+)?$/u.test(header)
            ? Number(header) * 1000
            : Date.parse(header) - Date.now();
      try {
        await response.body?.cancel();
      } catch {
        // An errored response body must not prevent retrying its transient status.
      }
      this.signal?.throwIfAborted();
      await this.delay(
        Number.isFinite(retryAfter)
          ? Math.max(0, retryAfter)
          : 250 * 2 ** attempt,
        this.signal,
      );
    }
    if (!response.ok) {
      throw new CodexSecurityError(
        `Potential-duplicates lookup for ${findingId} failed (HTTP ${response.status}).${
          response.status === 404
            ? " Import the finding with its repositoryId through POST /v1/bulk/findings before deduplicating."
            : ""
        }`,
      );
    }
    const candidates = (await response.json()) as FindingNeighborhood;
    if (
      !candidates ||
      !isFinding(candidates.finding) ||
      !Array.isArray(candidates.potentialDuplicates) ||
      !candidates.potentialDuplicates.every(isFinding)
    ) {
      throw new CodexSecurityError(
        `Potential-duplicates lookup for ${findingId} returned an invalid finding neighborhood.`,
      );
    }
    return candidates;
  }

  async publish(
    findings: readonly Finding[],
    repositoryId: string,
    idempotencyKey?: string,
  ): Promise<string[]> {
    const receipt = await this.post(
      "v1/bulk/findings",
      {
        findings,
        repositoryId,
      },
      idempotencyKey,
    );
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

  private async post(
    path: string,
    body: unknown,
    idempotencyKey?: string,
  ): Promise<unknown> {
    const response = await this.request(this.endpoint(path), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(idempotencyKey === undefined
          ? {}
          : { "Idempotency-Key": idempotencyKey }),
      },
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
