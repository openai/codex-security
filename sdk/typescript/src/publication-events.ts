import type {
  PreparedPublicationIssue,
  PreparedScanPublication,
} from "./publication.js";

export interface CollectedPublicationEvents {
  created: Array<{
    findingId: string;
    occurrenceId: string;
    issueIdentifier: string;
    url?: string;
  }>;
  failed: Array<{ findingId: string; error: string }>;
}

export function collectPublicationEvents(
  output: string,
  publication: PreparedScanPublication,
  failureMessage: string,
): CollectedPublicationEvents {
  const created = new Map<
    string,
    CollectedPublicationEvents["created"][number]
  >();
  const failed = new Map<string, string>();
  const unexpected: string[] = [];

  for (const line of output.split(/\r?\n/)) {
    if (line.trim().length === 0) continue;
    let event: unknown;
    try {
      event = JSON.parse(line) as unknown;
    } catch {
      continue;
    }
    if (!isRecord(event) || event["type"] !== "item.completed") continue;
    const item = event["item"];
    if (
      !isRecord(item) ||
      item["type"] !== "mcp_tool_call" ||
      item["server"] !== "codex_apps" ||
      (item["tool"] !== "linear.save_issue" &&
        item["tool"] !== "linear_save_issue")
    ) {
      continue;
    }

    const args = item["arguments"];
    const issue = isRecord(args)
      ? matchPublicationIssue(publication, args)
      : undefined;
    if (issue === undefined) {
      unexpected.push("Codex attempted to create an unexpected Linear issue.");
      continue;
    }
    if (failed.has(issue.findingId) || created.has(issue.findingId)) {
      failed.set(
        issue.findingId,
        "Codex attempted to create more than one Linear issue for this finding.",
      );
      continue;
    }
    if (item["status"] !== "completed") {
      const error = item["error"];
      failed.set(
        issue.findingId,
        isRecord(error) && typeof error["message"] === "string"
          ? error["message"]
          : failureMessage,
      );
      continue;
    }

    const saved = savedIssue(item["result"]);
    if (saved === undefined) {
      failed.set(
        issue.findingId,
        "The connected Linear app did not return a created issue identifier.",
      );
      continue;
    }
    created.set(issue.findingId, {
      findingId: issue.findingId,
      occurrenceId: issue.occurrenceId,
      issueIdentifier: saved.issueIdentifier,
      ...(saved.url === undefined ? {} : { url: saved.url }),
    });
  }

  if (unexpected.length > 0 && publication.issues.length > 0) {
    const target =
      publication.issues.find((issue) => !created.has(issue.findingId)) ??
      publication.issues[0]!;
    failed.set(target.findingId, unexpected.join(" "));
  }

  return {
    created: publication.issues.flatMap((issue) => {
      if (failed.has(issue.findingId)) return [];
      const result = created.get(issue.findingId);
      return result === undefined ? [] : [result];
    }),
    failed: publication.issues.flatMap((issue) => {
      const error = failed.get(issue.findingId);
      if (error !== undefined) return [{ findingId: issue.findingId, error }];
      return created.has(issue.findingId)
        ? []
        : [{ findingId: issue.findingId, error: failureMessage }];
    }),
  };
}

export function matchPublicationIssue(
  publication: PreparedScanPublication,
  arguments_: Record<string, unknown>,
): PreparedPublicationIssue | undefined {
  const description = arguments_["description"];
  if (typeof description !== "string") {
    return undefined;
  }

  const matches = publication.issues.filter((issue) =>
    descriptionIdentifiesIssue(description, issue),
  );
  return matches.length === 1 ? matches[0] : undefined;
}

function descriptionIdentifiesIssue(
  description: string,
  issue: PreparedPublicationIssue,
): boolean {
  return (
    containsIdentifier(description, issue.findingId) &&
    containsIdentifier(description, issue.occurrenceId)
  );
}

function containsIdentifier(value: string, identifier: string): boolean {
  const escaped = identifier.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  return new RegExp(`(?<![\\w-])${escaped}(?![\\w-])`, "u").test(value);
}

function savedIssue(
  result: unknown,
): { issueIdentifier: string; url?: string } | undefined {
  if (!isRecord(result)) return undefined;
  const candidates: unknown[] = [
    result["structured_content"],
    result["structuredContent"],
  ];
  if (Array.isArray(result["content"])) {
    for (const content of result["content"]) {
      if (!isRecord(content) || typeof content["text"] !== "string") continue;
      try {
        candidates.push(JSON.parse(content["text"]) as unknown);
      } catch {
        continue;
      }
    }
  }

  for (const candidate of candidates) {
    if (!isRecord(candidate)) continue;
    const nested = candidate["issue"];
    const data = candidate["data"];
    for (const value of [
      candidate,
      nested,
      isRecord(data) ? data["issue"] : undefined,
    ]) {
      if (!isRecord(value)) continue;
      const identifier =
        value["identifier"] ?? value["issueIdentifier"] ?? value["id"];
      if (typeof identifier !== "string" || identifier.trim().length === 0) {
        continue;
      }
      const url = value["url"];
      return {
        issueIdentifier: identifier,
        ...(typeof url !== "string" || url.trim().length === 0 ? {} : { url }),
      };
    }
  }
  return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
