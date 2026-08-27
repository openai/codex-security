import { useEffect, useRef, useState, type ReactNode } from "react";
import { Badge } from "@openai/apps-sdk-ui/components/Badge";
import { Button } from "@openai/apps-sdk-ui/components/Button";
import { Input } from "@openai/apps-sdk-ui/components/Input";
import type {
  DashboardDetail,
  DashboardItem,
  DashboardSnapshot,
  DashboardView,
} from "../src/server/dashboard-types.js";
import { pollDashboard } from "./polling.js";

const views: { id: DashboardView; label: string; description: string }[] = [
  {
    id: "findings",
    label: "Findings",
    description: "Findings stored in this service.",
  },
  {
    id: "groups",
    label: "Duplicate groups",
    description:
      "Reviewed duplicate relationships. Overlapping groups stay separate.",
  },
];
const count = (value: number | null | undefined) =>
  value == null ? "—" : value.toLocaleString();
const timestamp = (value: string | null | undefined) =>
  value ? new Date(value).toLocaleString() : "—";

function age(value: string | null | undefined, now: number) {
  if (!value) return "—";
  const seconds = Math.max(0, Math.floor((now - Date.parse(value)) / 1_000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3_600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3_600)}h ago`;
  return `${Math.floor(seconds / 86_400)}d ago`;
}

function Field({ name, children }: { name: string; children: ReactNode }) {
  return (
    <div className="detail-field">
      <dt>{name}</dt>
      <dd>{children ?? "—"}</dd>
    </div>
  );
}

type Navigate = (view: DashboardView, id?: string) => void;

function RecordLinks({
  ids,
  view,
  navigate,
  empty = "None",
}: {
  ids: string[];
  view: DashboardView;
  navigate: Navigate;
  empty?: string;
}) {
  if (ids.length === 0) return <p className="text-secondary">{empty}</p>;
  return (
    <ul className="record-links">
      {ids.map((id) => (
        <li key={id}>
          <button className="record-link" onClick={() => navigate(view, id)}>
            {id}
          </button>
        </li>
      ))}
    </ul>
  );
}

function Inspector({
  detail,
  navigate,
}: {
  detail: DashboardDetail;
  navigate: Navigate;
}) {
  const finding = detail.finding;
  return (
    <>
      {finding && (
        <>
          <section className="detail-section">
            <h3>{finding.title}</h3>
            <div className="inline-values">
              <Badge
                color={
                  finding.severity.level === "critical" ||
                  finding.severity.level === "high"
                    ? "danger"
                    : "secondary"
                }
              >
                {finding.severity.level}
              </Badge>
              <span className="text-secondary">
                {finding.confidence.level} confidence
              </span>
            </div>
            <p className="finding-copy">{finding.summary}</p>
            <dl>
              <Field name="Finding ID">
                <code>{finding.findingId}</code>
              </Field>
              <Field name="Repository associations">
                {detail.item.repositoryIds.join(", ") || "Not recorded"}
              </Field>
            </dl>
          </section>
          <section className="detail-section">
            <h3>Affected locations</h3>
            <ul className="record-links">
              {finding.locations.map((location, i) => (
                <li key={i}>
                  <code>
                    {location.path}:{location.startLine}
                    {location.endLine != null ? `–${location.endLine}` : ""}
                  </code>
                </li>
              ))}
            </ul>
          </section>
          {(
            [
              ["writeup", "Writeup"],
              ["codeEvidence", "Code evidence"],
              ["remediation", "Remediation"],
              ["validation", "Validation"],
              ["attackPath", "Attack path"],
            ] as const
          ).map(([key, title]) =>
            finding[key] != null ? (
              <section className="detail-section" key={key}>
                <h3>{title}</h3>
                <FindingContent value={finding[key]} />
              </section>
            ) : null,
          )}
          <section className="detail-section">
            <h3>Duplicate groups</h3>
            <RecordLinks
              ids={(detail.groups ?? []).map((group) => group.groupId)}
              view="groups"
              navigate={navigate}
              empty="No stored duplicate groups."
            />
          </section>
        </>
      )}
      {detail.group && (
        <section className="detail-section">
          <h3>Group members · {detail.group.findingIds.length}</h3>
          <p className="text-secondary">
            Reviewed together. Membership does not replace the original findings
            or merge overlapping groups.
          </p>
          <RecordLinks
            ids={detail.group.findingIds}
            view="findings"
            navigate={navigate}
          />
          <dl>
            <Field name="Created">{timestamp(detail.group.createdAt)}</Field>
          </dl>
        </section>
      )}
    </>
  );
}

function FindingContent({ value }: { value: unknown }) {
  if (typeof value === "string") return <p className="finding-copy">{value}</p>;
  return <pre className="finding-copy">{JSON.stringify(value, null, 2)}</pre>;
}

function Results({
  view,
  items,
  selected,
  navigate,
  now,
}: {
  view: DashboardView;
  items: DashboardItem[];
  selected: string;
  navigate: Navigate;
  now: number;
}) {
  return (
    <div className="table-scroll">
      <table>
        <caption className="sr-only">
          {views.find((v) => v.id === view)!.label}
        </caption>
        <thead>
          <tr>
            <th scope="col">{view === "findings" ? "Finding" : "Group"}</th>
            <th scope="col">Repository</th>
            {view === "findings" && <th scope="col">Severity</th>}
            {view === "groups" && <th scope="col">Members</th>}
            <th scope="col">Created</th>
            <th scope="col">Last update</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id} data-selected={selected === item.id || undefined}>
              <th scope="row">
                <button
                  className="record-link row-title"
                  onClick={() => navigate(view, item.id)}
                >
                  {item.title}
                </button>
                {item.id !== item.title && (
                  <code className="row-subtitle">{item.id}</code>
                )}
              </th>
              <td className="repository-cell">
                {item.repositoryIds.join(", ") || "—"}
              </td>
              {view === "findings" && (
                <td>
                  <Badge
                    color={
                      item.severity === "critical" || item.severity === "high"
                        ? "danger"
                        : "secondary"
                    }
                  >
                    {item.severity}
                  </Badge>
                </td>
              )}
              {view === "groups" && (
                <td className="numeric">{count(item.memberCount)}</td>
              )}
              <td>
                <time dateTime={item.createdAt}>
                  {timestamp(item.createdAt)}
                </time>
              </td>
              <td>
                <time
                  dateTime={item.updatedAt}
                  title={timestamp(item.updatedAt)}
                >
                  {age(item.updatedAt, now)}
                </time>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function App() {
  const [view, setView] = useState<DashboardView>("findings");
  const [query, setQuery] = useState("");
  const [repository, setRepository] = useState("");
  const [sort, setSort] = useState("activity");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState("");
  const inspectorHeading = useRef<HTMLHeadingElement>(null);
  const resultsElement = useRef<HTMLElement>(null);
  useEffect(() => {
    // On narrow screens details follow the table; bring a new selection into view.
    if (selected) inspectorHeading.current?.focus();
  }, [selected, view]);
  const [saved, setSaved] = useState<{
    key: string;
    data: DashboardSnapshot;
    refreshed: number;
  }>();
  const [error, setError] = useState<{ key: string; message: string }>();
  const parameters = new URLSearchParams({
    view,
    query,
    repository,
    sort,
    offset: String(offset),
  });
  if (selected) parameters.set("id", selected);
  const key = parameters.toString();
  useEffect(
    () =>
      pollDashboard(
        async (signal) => {
          const response = await fetch(`../v1/dashboard?${key}`, {
            signal,
            cache: "no-store",
          });
          if (!response.ok)
            throw new Error(
              `Dashboard request failed (HTTP ${response.status}).`,
            );
          return (await response.json()) as DashboardSnapshot;
        },
        (data) => {
          setSaved({ key, data, refreshed: Date.now() });
          setError(undefined);
        },
        (error) =>
          setError({
            key,
            message: error instanceof Error ? error.message : String(error),
          }),
      ),
    [key],
  );

  const data = saved?.key === key ? saved.data : undefined;
  const failure = error?.key === key ? error.message : undefined;
  // Keep overview/filter choices stable while a new page or detail is loading.
  const overview = saved?.data.overview;
  const now = Date.now();
  const current = views.find((v) => v.id === view)!;
  function navigate(next: DashboardView, id?: string) {
    if (next !== view) {
      setView(next);
      setQuery("");
      setRepository("");
      setOffset(0);
    }
    setSelected(id ?? "");
  }
  function filter(setter: (value: string) => void, value: string) {
    setter(value);
    setOffset(0);
  }
  const counts: Record<DashboardView, number | undefined> = {
    findings: overview?.findings,
    groups: overview?.groups,
  };
  return (
    <div className="dashboard-shell">
      <header className="app-header">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            ↗
          </span>
          <strong>Codex Security</strong>
          <span className="header-divider" />
          <span>Findings service</span>
        </div>
        <Badge>Read only</Badge>
      </header>
      <div className="workspace">
        <aside className="sidebar">
          <p className="eyebrow">Explore</p>
          <nav aria-label="Dashboard views">
            {views.map((tab) => (
              <Button
                key={tab.id}
                color="secondary"
                variant="ghost"
                pill={false}
                block
                selected={view === tab.id}
                aria-current={view === tab.id ? "page" : undefined}
                onClick={() => navigate(tab.id)}
              >
                <span>{tab.label}</span>
                <span className="nav-count">{count(counts[tab.id])}</span>
              </Button>
            ))}
          </nav>
        </aside>
        <main>
          <div className="page-heading">
            <div>
              <h1>{current.label}</h1>
              <p className="text-secondary">{current.description}</p>
            </div>
            <div className="refresh-state" role="status">
              <span
                className={
                  failure ? "connection-dot disconnected" : "connection-dot"
                }
                aria-hidden="true"
              />
              <span>
                {failure
                  ? "Refresh unavailable"
                  : saved
                    ? "Refreshes every 5 seconds"
                    : "Connecting…"}
                <small>
                  {saved
                    ? `Last success ${timestamp(new Date(saved.refreshed).toISOString())}`
                    : "Waiting for first response"}
                </small>
              </span>
            </div>
          </div>
          <div className="overview" aria-label="Service overview">
            <div>
              <span>Stored findings</span>
              <strong>{count(overview?.findings)}</strong>
            </div>
            <div>
              <span>Duplicate groups</span>
              <strong>{count(overview?.groups)}</strong>
            </div>
          </div>
          <div className="filters">
            <label className="search-field">
              <span className="sr-only">
                Search {current.label.toLowerCase()}
              </span>
              <Input
                size="lg"
                value={query}
                placeholder={`Search ${current.label.toLowerCase()}…`}
                onChange={(event) => filter(setQuery, event.target.value)}
              />
            </label>
            <label>
              <span>Repository</span>
              <select
                value={repository}
                onChange={(event) => filter(setRepository, event.target.value)}
              >
                <option value="">All repositories</option>
                {(saved?.data.repositories ?? []).map((repo) => (
                  <option key={repo.id} value={repo.id}>
                    {repo.label}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span>Sort</span>
              <select
                value={sort}
                onChange={(event) => filter(setSort, event.target.value)}
              >
                <option value="activity">Recent activity</option>
                <option value="newest">Newest first</option>
              </select>
            </label>
          </div>
          {failure && (
            <div role="alert" className="error-message">
              <strong>Unable to refresh</strong>
              <p>
                {failure}{" "}
                {data
                  ? "Showing the last successful data."
                  : "No current data to show."}{" "}
                Retrying every five seconds.
              </p>
            </div>
          )}
          <div
            className={
              selected ? "content-layout with-inspector" : "content-layout"
            }
          >
            <section
              className="results"
              aria-label={current.label}
              ref={resultsElement}
              tabIndex={-1}
              aria-busy={!data && !failure}
            >
              {!data ? (
                <div className="empty-state">
                  <h2>
                    {failure
                      ? "Data unavailable"
                      : `Loading ${current.label.toLowerCase()}…`}
                  </h2>
                </div>
              ) : data.items.length ? (
                <Results
                  view={view}
                  items={data.items}
                  selected={selected}
                  navigate={navigate}
                  now={now}
                />
              ) : (
                <div className="empty-state">
                  <h2>
                    {query || repository
                      ? "No matching records"
                      : `No ${current.label.toLowerCase()} yet`}
                  </h2>
                  <p>
                    {query || repository
                      ? "Try another search or filter."
                      : view === "findings"
                        ? "Published or imported findings will appear here."
                        : "Accepted duplicate groups will appear here after they are saved."}
                  </p>
                </div>
              )}
              {data && (
                <footer className="pagination">
                  <span>
                    {data.total === 0
                      ? "0 records"
                      : `${data.offset + (data.items.length ? 1 : 0)}–${data.offset + data.items.length} of ${data.total}`}
                  </span>
                  <div className="inline-values">
                    <Button
                      color="secondary"
                      variant="outline"
                      disabled={offset === 0}
                      onClick={() =>
                        setOffset(Math.max(0, offset - data.limit))
                      }
                    >
                      Previous
                    </Button>
                    <Button
                      color="secondary"
                      variant="outline"
                      disabled={data.nextOffset === null}
                      onClick={() => setOffset(data.nextOffset!)}
                    >
                      Next
                    </Button>
                  </div>
                </footer>
              )}
            </section>
            {selected && (
              <aside className="inspector" aria-label="Selected record">
                <div className="inspector-heading">
                  <h2 ref={inspectorHeading} tabIndex={-1}>
                    Details
                  </h2>
                  <Button
                    color="secondary"
                    variant="ghost"
                    onClick={() => {
                      setSelected("");
                      resultsElement.current?.focus();
                    }}
                  >
                    Close
                  </Button>
                </div>
                {data?.detail ? (
                  <Inspector detail={data.detail} navigate={navigate} />
                ) : (
                  <p className="text-secondary">
                    {data
                      ? "This record is not available in this service’s database."
                      : "Loading details…"}
                  </p>
                )}
              </aside>
            )}
          </div>
          <p className="state-note">
            This dashboard only reads findings and duplicate groups stored in
            this service.
          </p>
        </main>
      </div>
    </div>
  );
}
