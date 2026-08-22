import {
  linearPublicationArguments,
  type PreparedPublicationIssue,
  type PreparedScanPublication,
} from "./publication.js";

export interface CollectedPublicationEvents {
  created: Array<{
    findingId: string;
    occurrenceId: string;
    issueIdentifier: string;
    url?: string;
  }>;
  failed: Array<{ findingId: string; error: string }>;
  indeterminate?: boolean;
  completedEvents?: string[];
  unresolvedCompletions?: string[];
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
  const completedEvents: Array<{
    findingId: string | undefined;
    line: string;
  }> = [];
  const completedFindings = new Set<string>();
  const indeterminateFindings = new Set<string>();
  const unresolvedCompletions = new Set<string>();

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
    const completed = item["status"] === "completed";
    if (completed) {
      completedEvents.push({ findingId: issue?.findingId, line });
    }
    if (issue === undefined) {
      unexpected.push("Codex attempted to create an unexpected Linear issue.");
      continue;
    }
    if (!completed && completedFindings.has(issue.findingId)) continue;
    const repeatedCompletion =
      completed && completedFindings.has(issue.findingId);
    if (completed) completedFindings.add(issue.findingId);
    if (!hasExpectedPublicationArguments(publication, issue, args)) {
      if (completed) indeterminateFindings.add(issue.findingId);
      failed.set(
        issue.findingId,
        "Codex attempted to create a Linear issue with unexpected arguments or destination.",
      );
      continue;
    }
    if (repeatedCompletion) {
      indeterminateFindings.add(issue.findingId);
      failed.set(
        issue.findingId,
        "Codex attempted to create more than one Linear issue for this finding.",
      );
      continue;
    }
    if (!completed) {
      const error = item["error"];
      failed.set(
        issue.findingId,
        isRecord(error) && typeof error["message"] === "string"
          ? error["message"]
          : failureMessage,
      );
      continue;
    }
    failed.delete(issue.findingId);

    const saved = savedIssue(item["result"]);
    if (saved === undefined) {
      unresolvedCompletions.add(issue.findingId);
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
    const target = publication.issues.find(
      (issue) => !created.has(issue.findingId),
    );
    if (target !== undefined)
      failed.set(target.findingId, unexpected.join(" "));
  }
  const indeterminate = completedEvents.some(
    ({ findingId }) =>
      findingId === undefined || indeterminateFindings.has(findingId),
  );

  return {
    ...(indeterminate ? { indeterminate: true } : {}),
    ...(completedEvents.length > 0
      ? { completedEvents: completedEvents.map(({ line }) => line) }
      : {}),
    ...(unresolvedCompletions.size > 0
      ? { unresolvedCompletions: [...unresolvedCompletions] }
      : {}),
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

export function hasExpectedPublicationArguments(
  publication: PreparedScanPublication,
  issue: PreparedPublicationIssue,
  actual: unknown,
): boolean {
  if (!isRecord(actual)) return false;
  const expected = linearPublicationArguments(publication.destination, issue);
  return (
    Object.keys(actual).length === Object.keys(expected).length &&
    Object.entries(expected).every(
      ([key, value]) =>
        Object.hasOwn(actual, key) && Object.is(actual[key], value),
    )
  );
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

  return resolvePublicationIssueReference(
    candidates.flatMap(publicationIssueReferences),
  );
}

export function publicationIssueReferences(
  value: unknown,
): Array<{ issueIdentifier: string; url?: string }> {
  if (!isRecord(value)) return [];
  const references: Array<{ issueIdentifier: string; url?: string }> = [];
  for (const container of [
    value,
    value["structured_content"],
    value["structuredContent"],
  ]) {
    if (!isRecord(container)) continue;
    const data = container["data"];
    for (const candidate of [
      container,
      container["issue"],
      isRecord(data) ? data["issue"] : undefined,
    ]) {
      if (!isRecord(candidate)) continue;
      for (const identifier of [
        candidate["identifier"],
        candidate["issueIdentifier"],
        candidate["id"],
      ]) {
        if (typeof identifier !== "string" || identifier.trim().length === 0) {
          continue;
        }
        const url = candidate["url"];
        references.push({
          issueIdentifier: identifier,
          ...(typeof url !== "string" || url.trim().length === 0
            ? {}
            : { url }),
        });
      }
    }
  }
  return references;
}

function resolvePublicationIssueReference(
  references: Array<{ issueIdentifier: string; url?: string }>,
): { issueIdentifier: string; url?: string } | undefined {
  const identifiers = new Set(
    references.map(({ issueIdentifier }) => issueIdentifier),
  );
  const urls = new Set(
    references.flatMap(({ url }) => (url === undefined ? [] : [url])),
  );
  if (identifiers.size !== 1 || urls.size > 1) return undefined;
  return {
    issueIdentifier: identifiers.values().next().value!,
    ...(urls.size === 0 ? {} : { url: urls.values().next().value! }),
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
