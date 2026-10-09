import type { DatabaseSync, SQLOutputValue } from "node:sqlite";
import { parseJson } from "../helpers/json";
import { requireSqliteText } from "./database";
import { listDedupeGroups } from "./duplicates";
import { transaction } from "./transaction";

const records = {
  findings: `
    SELECT findings.id, details_json -> '$.title' AS title,
      COALESCE(repositories.ids, '[]') AS repositoryIds,
      json_extract(details_json, '$.severity.level') AS severity,
      findings.created_at AS createdAt, findings.updated_at AS updatedAt
    FROM findings LEFT JOIN (
      SELECT finding_id, json_group_array(repository_id) AS ids
      FROM finding_repositories GROUP BY finding_id
    ) AS repositories ON repositories.finding_id = findings.id
    WHERE details_json IS NOT NULL`,
  groups: `
    SELECT groups.id, json_quote(groups.id) AS title,
      (SELECT json_group_array(DISTINCT repository_id)
       FROM finding_dedupe_group_members AS members
       JOIN finding_repositories ON finding_repositories.finding_id = members.finding_id
       WHERE members.group_id = groups.id) AS repositoryIds,
      groups.created_at AS createdAt, groups.created_at AS updatedAt,
      (SELECT COUNT(*) FROM finding_dedupe_group_members WHERE group_id = groups.id) AS memberCount
    FROM finding_dedupe_groups AS groups`,
};

const sorts = {
  activity: "julianday(upper(records.updatedAt))",
  newest: "julianday(upper(records.createdAt))",
  title: "dashboard_lower(records.title)",
  repository: "repository_label(records.repositoryIds)",
  severity:
    "CASE records.severity WHEN 'informational' THEN 0 WHEN 'low' THEN 1 " +
    "WHEN 'medium' THEN 2 WHEN 'high' THEN 3 WHEN 'critical' THEN 4 END",
  members: "records.memberCount",
};

export interface DashboardQuery {
  view: keyof typeof records;
  sort: keyof typeof sorts;
  direction?: "asc" | "desc";
  limit: number;
  offset: number;
  query?: string;
  repository?: string;
  id?: string;
}

function compare(left: string, right: string) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function repositoryIds(value: string[]): string[] {
  return value.sort(
    (left, right) =>
      compare(left.toLowerCase(), right.toLowerCase()) || compare(left, right),
  );
}

function item(
  row: Record<string, SQLOutputValue>,
): Record<string, SQLOutputValue | string[]> {
  const value = JSON.parse(row.item as string);
  repositoryIds(value.repositoryIds);
  return value;
}

function detail(
  database: DatabaseSync,
  view: DashboardQuery["view"],
  selected: Record<string, SQLOutputValue>,
) {
  const selectedItem = item(selected);
  const id = selectedItem.id as string;
  return view === "findings"
    ? {
        item: selectedItem,
        finding: parseJson(
          database
            .prepare("SELECT details_json FROM findings WHERE id = ?")
            .get(id)!.details_json as string,
        ),
        groups: listDedupeGroups(database, id).groups,
      }
    : {
        item: selectedItem,
        group: JSON.parse(
          database
            .prepare(
              `SELECT json_object('groupId', ?, 'createdAt', ?, 'findingIds', json_group_array(finding_id)) AS value
               FROM (SELECT finding_id FROM finding_dedupe_group_members WHERE group_id = ? ORDER BY finding_id)`,
            )
            .get(id, selectedItem.createdAt as string, id)!.value as string,
        ),
      };
}

/** Read one snapshot without loading artifacts or modifying stored data. */
export function dashboard(database: DatabaseSync, query: DashboardQuery) {
  requireSqliteText([query.query, query.repository, query.id]);
  // JSON preserves text across Node 22 SQLite result and callback boundaries.
  database.function("dashboard_lower", { deterministic: true }, (value) =>
    (JSON.parse(value as string) as string).toLowerCase(),
  );
  const search = query.query?.toUpperCase() ?? "";
  database.function("dashboard_contains", { deterministic: true }, (value) =>
    Number(
      ((JSON.parse(value as string) as string | null) ?? "")
        .toUpperCase()
        .includes(search),
    ),
  );
  database.function("repository_label", { deterministic: true }, (value) =>
    repositoryIds(JSON.parse(value as string))
      .join(", ")
      .toLowerCase(),
  );
  const clauses: string[] = [];
  const values: string[] = [];
  if (query.query) {
    const columns = ["json_quote(records.id)", "records.title"];
    clauses.push(
      `(${columns.map((column) => `dashboard_contains(${column})`).join(" OR ")} OR
        EXISTS (SELECT 1 FROM json_each(records.repositoryIds)
          WHERE dashboard_contains(json_quote(value))))`,
    );
  }
  if (query.repository) {
    clauses.push(
      "EXISTS (SELECT 1 FROM json_each(records.repositoryIds) WHERE value = ?)",
    );
    values.push(query.repository);
  }
  const where = clauses.length ? ` WHERE ${clauses.join(" AND ")}` : "";
  const direction = ({ asc: "ASC", desc: "DESC" } as const)[
    query.direction ?? "desc"
  ];
  let order = `${sorts[query.sort]} ${direction}`;
  if (query.view === "findings" && query.sort === "activity")
    order += `, ${sorts.severity} DESC`;
  order += ", records.id";
  const source = records[query.view];
  const field = query.view === "findings" ? "severity" : "memberCount";
  const projection = `json_object('id', records.id, 'title', json(records.title),
    'repositoryIds', json(repositoryIds), 'createdAt', createdAt, 'updatedAt', updatedAt,
    '${field}', ${field}) AS item`;
  return transaction(database, "BEGIN", () => {
    const repositories = database
      .prepare(
        `SELECT json_object('id', repository_id, 'label', repository_id) AS value
         FROM (SELECT DISTINCT repository_id FROM finding_repositories ORDER BY repository_id)`,
      )
      .all()
      .map((row) => JSON.parse(row.value as string));
    const total = database
      .prepare(`SELECT COUNT(*) AS count FROM (${source}) AS records ${where}`)
      .get(...values)!.count as number;
    const rows = database
      .prepare(
        `SELECT ${projection} FROM (${source}) AS records ${where} ORDER BY ${order} LIMIT ? OFFSET ?`,
      )
      .all(...values, query.limit, query.offset);
    const selected = query.id
      ? database
          .prepare(
            `SELECT ${projection} FROM (${source}) AS records WHERE records.id = ?`,
          )
          .get(query.id)
      : undefined;
    const nextOffset = query.offset + rows.length;
    return {
      overview: {
        ...database
          .prepare(
            `SELECT (SELECT COUNT(*) FROM findings WHERE details_json IS NOT NULL) AS findings,
              (SELECT COUNT(*) FROM finding_dedupe_groups) AS groups`,
          )
          .get()!,
      },
      repositories,
      items: rows.map(item),
      total,
      limit: query.limit,
      offset: query.offset,
      nextOffset: nextOffset < total ? nextOffset : null,
      detail: selected ? detail(database, query.view, selected) : null,
    };
  });
}
