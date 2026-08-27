import { useEffect, useRef, useState, type ReactNode } from "react";
import { Badge } from "@openai/apps-sdk-ui/components/Badge";
import { Button } from "@openai/apps-sdk-ui/components/Button";
import { Input } from "@openai/apps-sdk-ui/components/Input";
import { Select } from "@openai/apps-sdk-ui/components/Select";
import type {
  DashboardDetail,
  DashboardItem,
  DashboardScan,
  DashboardSnapshot,
  DashboardView,
} from "../src/server/dashboard-types.js";
import type { WorkflowState } from "../src/finding-workflow.js";
import type { CustomPublicationResult } from "../src/custom-publish.js";
import type { DeduplicateScanResult } from "../src/deduplication/scan.js";
import { pollDashboard } from "./polling.js";

const views: { id: DashboardView; label: string; description: string }[] = [
  {
    id: "workflows",
    label: "Workflows",
    description: "Optional scan → publish → dedupe workflows.",
  },
  {
    id: "scans",
    label: "Scans",
    description: "Scan activity and history, with or without a workflow.",
  },
  {
    id: "findings",
    label: "Findings",
    description: "All stored findings, including imports without local scans.",
  },
  {
    id: "groups",
    label: "Duplicate groups",
    description:
      "Reviewed duplicate relationships. Overlapping groups stay separate.",
  },
];
const labels: Record<string, string> = {
  scan: "Scan",
  publish: "Publish",
  dedupe: "Dedupe",
  pending: "Pending",
  running: "Running",
  failed: "Failed",
  completed: "Completed",
  canceled: "Canceled",
  preflight: "Preflight",
  threat_model: "Threat modeling",
  discovery: "Discovery",
  validation: "Validation",
  attack_path: "Attack-path analysis",
  reporting: "Reporting",
};
const label = (value: string) => labels[value] ?? value;
const count = (value: number | null | undefined) =>
  value == null ? "—" : value.toLocaleString();
const timestamp = (value: string | null | undefined) =>
  value ? new Date(value).toLocaleString() : "—";
const total = (counts: Record<string, number>) =>
  Object.values(counts).reduce((sum, n) => sum + n, 0);

function age(value: string | null | undefined, now: number) {
  if (!value) return "—";
  const seconds = Math.max(0, Math.floor((now - Date.parse(value)) / 1_000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3_600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3_600)}h ago`;
  return `${Math.floor(seconds / 86_400)}d ago`;
}

function Status({ value }: { value: string }) {
  return (
    <Badge
      color={
        value === "failed"
          ? "danger"
          : value === "completed"
            ? "success"
            : value === "running"
              ? "info"
              : "secondary"
      }
    >
      {label(value)}
    </Badge>
  );
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

function ScanDetail({
  scan,
  navigate,
}: {
  scan: DashboardScan;
  navigate: Navigate;
}) {
  const { reviewed, total: reviewTotal, reportable, deepPass } = scan.progress;
  return (
    <>
      <section className="detail-section">
        <div className="section-title">
          <h3>Scan progress</h3>
          <Status value={scan.status} />
        </div>
        <p>{label(scan.phase)}</p>
        {reviewTotal != null && reviewTotal > 0 && reviewed != null ? (
          <>
            <progress
              aria-label="Reviewed items"
              value={reviewed}
              max={reviewTotal}
            />
            <p className="text-secondary">
              {count(reviewed)} / {count(reviewTotal)} review items completed
            </p>
          </>
        ) : (
          <p className="text-secondary">Review total not reported</p>
        )}
        <dl>
          <Field name="Reportable findings">{count(reportable)}</Field>
          {deepPass != null && <Field name="Deep-scan pass">{deepPass}</Field>}
          <Field name="Started">{timestamp(scan.startedAt)}</Field>
          <Field name="Finished">{timestamp(scan.completedAt)}</Field>
          <Field name="Last recorded update">{timestamp(scan.updatedAt)}</Field>
        </dl>
        {scan.error && (
          <div className="error-message" role="note">
            <strong>Scan error</strong>
            <p>{scan.error}</p>
          </div>
        )}
      </section>
      <section className="detail-section">
        <h3>Scan identity</h3>
        <dl>
          <Field name="Scan ID">
            <code>{scan.scanId}</code>
          </Field>
          <Field name="Repository">{scan.repositoryPath}</Field>
          <Field name="Repository ID">
            <code>{scan.repositoryId ?? "—"}</code>
          </Field>
          <Field name="Revision">
            <code>{scan.revision}</code>
          </Field>
          <Field name="Mode">{scan.mode}</Field>
          <Field name="Scope">{scan.scope}</Field>
          <Field name="Artifact directory">
            <code>{scan.scanDir}</code>
          </Field>
        </dl>
      </section>
      <section className="detail-section">
        <h3>Scan findings · {scan.findingIds.length}</h3>
        <RecordLinks
          ids={scan.findingIds}
          view="findings"
          navigate={navigate}
          empty="No finding records for this scan."
        />
      </section>
      <section className="detail-section">
        <h3>Linked workflows</h3>
        <RecordLinks
          ids={scan.workflowIds}
          view="workflows"
          navigate={navigate}
          empty="Standalone scan — no workflow required."
        />
      </section>
    </>
  );
}

function WorkflowDetail({
  workflow,
  item,
  scan,
  navigate,
}: {
  workflow: WorkflowState;
  item: DashboardItem;
  scan?: DashboardScan;
  navigate: Navigate;
}) {
  const publication = workflow.stages.publish.result as
    | CustomPublicationResult
    | undefined;
  const result =
    workflow.stages.dedupe.status === "completed"
      ? (workflow.stages.dedupe.result as DeduplicateScanResult)
      : undefined;
  return (
    <>
      <section className="detail-section">
        <h3>Pipeline</h3>
        <ol className="pipeline">
          {(["scan", "publish", "dedupe"] as const).map((stage) => (
            <li key={stage}>
              <span>{label(stage)}</span>
              <Status value={workflow.stages[stage].status} />
            </li>
          ))}
        </ol>
        {Object.entries(workflow.stages).map(([stage, state]) =>
          state.status === "failed" && state.error ? (
            <div key={stage} className="error-message">
              <strong>{label(stage)} error</strong>
              <p>{state.error}</p>
            </div>
          ) : null,
        )}
        <dl>
          <Field name="Workflow ID">
            <code>{workflow.id}</code>
          </Field>
          <Field name="Scan ID">
            <code>{workflow.scanId ?? "—"}</code>
          </Field>
          <Field name="Created">{timestamp(item.createdAt)}</Field>
          <Field name="Last workflow update">{timestamp(item.updatedAt)}</Field>
          {!scan && (
            <Field name="Artifact directory">
              <code>{workflow.scanDir ?? "—"}</code>
            </Field>
          )}
          <Field name="Destination">{workflow.destination}</Field>
          <Field name="Dedupe scope">
            {workflow.scope?.allRepositories
              ? "All repositories"
              : workflow.scope?.repositoryId ?? "Not bound yet"}
          </Field>
        </dl>
      </section>
      <section className="detail-section">
        <h3>Publication</h3>
        <Status value={workflow.stages.publish.status} />
        <dl>
          <Field name="Acknowledged findings">
            {count(publication?.findingCount)}
          </Field>
        </dl>
        {publication && (
          <RecordLinks
            ids={publication.findingIds}
            view="findings"
            navigate={navigate}
            empty="Completed — 0 findings published."
          />
        )}
      </section>
      <section className="detail-section">
        <h3>Deduplication</h3>
        <Status value={workflow.stages.dedupe.status} />
        {result ? (
          <>
            <dl>
              <Field name="Unique findings">
                {count(result.uniqueFindingIds.length)}
              </Field>
              <Field name="Accepted groups">
                {count(result.duplicateGroups.length)}
              </Field>
            </dl>
            <RecordLinks
              ids={result.uniqueFindingIds}
              view="findings"
              navigate={navigate}
              empty="Completed — 0 findings."
            />
            {result.duplicateGroups.map((members, index) => (
              <div className="duplicate-set" key={index}>
                <h4>Group {index + 1}</h4>
                <p className="text-secondary">
                  First member is the representative selected for this run.
                </p>
                <ul className="record-links">
                  {members.map((id, memberIndex) => (
                    <li key={id}>
                      <button
                        className="record-link"
                        onClick={() => navigate("findings", id)}
                      >
                        {id}
                      </button>
                      <span className="text-secondary">
                        {memberIndex === 0 ? " · Representative" : ""}
                        {scan
                          ? scan.findingIds.includes(id)
                            ? " · This scan"
                            : " · Existing finding"
                          : ""}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </>
        ) : (
          <p className="text-secondary">
            Results appear after review and successful group write-back. No
            review completion estimate is available.
          </p>
        )}
      </section>
      {scan ? (
        <ScanDetail scan={scan} navigate={navigate} />
      ) : (
        <section className="detail-section">
          <h3>Local scan</h3>
          <p className="text-secondary">
            {workflow.scanId
              ? "This workflow references a scan that is not in this service’s database."
              : "No scan registered yet."}
          </p>
          {workflow.repositoryPath && <p>{workflow.repositoryPath}</p>}
        </section>
      )}
    </>
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
      {detail.workflow ? (
        <WorkflowDetail
          workflow={detail.workflow}
          item={detail.item}
          scan={detail.scan}
          navigate={navigate}
        />
      ) : detail.scan ? (
        <ScanDetail scan={detail.scan} navigate={navigate} />
      ) : null}
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
            <h3>Recorded scans</h3>
            <RecordLinks
              ids={detail.scanIds ?? []}
              view="scans"
              navigate={navigate}
              empty="Imported finding — no local scan history."
            />
          </section>
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
  const run = view === "scans" || view === "workflows";
  return (
    <div className="table-scroll">
      <table>
        <caption className="sr-only">
          {views.find((v) => v.id === view)!.label}
        </caption>
        <thead>
          <tr>
            <th scope="col">
              {view === "scans"
                ? "Repository / scan"
                : view === "findings"
                  ? "Finding"
                  : view === "groups"
                    ? "Group"
                    : "Workflow"}
            </th>
            {view !== "scans" && <th scope="col">Repository</th>}
            {run && (
              <>
                <th scope="col">Stage / status</th>
                <th scope="col">Mode</th>
                <th scope="col">Findings</th>
              </>
            )}
            {view === "workflows" && (
              <>
                <th scope="col">Published</th>
                <th scope="col">Unique</th>
              </>
            )}
            {view === "findings" && <th scope="col">Severity</th>}
            {view === "groups" && <th scope="col">Members</th>}
            <th scope="col">{run ? "Started" : "Created"}</th>
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
                {view === "workflows" && item.scanId && (
                  <code className="row-subtitle">{item.scanId}</code>
                )}
              </th>
              {view !== "scans" && (
                <td className="repository-cell">
                  {item.repositoryPath ??
                    (item.repositoryIds.join(", ") || "—")}
                </td>
              )}
              {run && (
                <>
                  <td>
                    <div className="cell-stack">
                      <span>{label(item.stage!)}</span>
                      <Status value={item.status!} />
                    </div>
                  </td>
                  <td>{item.mode ?? "—"}</td>
                  <td className="numeric">{count(item.findingCount)}</td>
                </>
              )}
              {view === "workflows" && (
                <>
                  <td className="numeric">{count(item.publishedCount)}</td>
                  <td className="numeric">{count(item.uniqueCount)}</td>
                </>
              )}
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
  const [view, setView] = useState<DashboardView>("workflows");
  const [query, setQuery] = useState("");
  const [repository, setRepository] = useState("");
  const [status, setStatus] = useState("");
  const [stage, setStage] = useState("");
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
    status,
    stage,
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
  const run = view === "scans" || view === "workflows";
  const current = views.find((v) => v.id === view)!;
  function navigate(next: DashboardView, id?: string) {
    if (next !== view) {
      setView(next);
      setQuery("");
      setRepository("");
      setStatus("");
      setStage("");
      setOffset(0);
    }
    setSelected(id ?? "");
  }
  function filter(setter: (value: string) => void, value: string) {
    setter(value);
    setOffset(0);
  }
  const counts: Record<DashboardView, number | undefined> = {
    scans: overview ? total(overview.scans) : undefined,
    workflows: overview ? total(overview.workflows) : undefined,
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
          <div className="sidebar-note">
            Local workbench state
            <br />
            Workflows are optional
          </div>
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
              <span>Scans running</span>
              <strong>
                {count(
                  overview?.scans["running"] ?? (overview ? 0 : undefined),
                )}
              </strong>
            </div>
            <div>
              <span>Publishing</span>
              <strong>
                {count(
                  overview?.workflows["publish"] ?? (overview ? 0 : undefined),
                )}
              </strong>
            </div>
            <div>
              <span>Deduplicating</span>
              <strong>
                {count(
                  overview?.workflows["dedupe"] ?? (overview ? 0 : undefined),
                )}
              </strong>
            </div>
            <div>
              <span>Stored findings</span>
              <strong>{count(overview?.findings)}</strong>
            </div>
            <div>
              <span>Duplicate groups</span>
              <strong>{count(overview?.groups)}</strong>
            </div>
          </div>
          {overview && (
            <p className="history-summary">
              Scans: {overview.scans["completed"] ?? 0} completed ·{" "}
              {overview.scans["failed"] ?? 0} failed ·{" "}
              {overview.scans["canceled"] ?? 0} canceled
              <span>
                Workflows: {overview.workflows["scan"] ?? 0} scanning ·{" "}
                {overview.workflows["completed"] ?? 0} completed ·{" "}
                {overview.workflows["failed"] ?? 0} failed ·{" "}
                {overview.workflows["pending"] ?? 0} pending
              </span>
            </p>
          )}
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
              {/* Select needs nonempty values for arrow-key navigation. */}
              <Select
                size="lg"
                value={`repo:${repository}`}
                options={[
                  { value: "repo:", label: "All repositories" },
                  ...(saved?.data.repositories ?? []).map((repo) => ({
                    value: `repo:${repo.id}`,
                    label: repo.label,
                  })),
                ]}
                onChange={(option) =>
                  filter(setRepository, option.value.slice(5))
                }
              />
            </label>
            {run && (
              <label>
                <span>Status</span>
                <Select
                  size="lg"
                  value={status || "all"}
                  options={[
                    { value: "all", label: "All statuses" },
                    ...[
                      "running",
                      "completed",
                      "failed",
                      ...(view === "scans" ? ["canceled"] : ["pending"]),
                    ].map((value) => ({ value, label: label(value) })),
                  ]}
                  onChange={(option) =>
                    filter(
                      setStatus,
                      option.value === "all" ? "" : option.value,
                    )
                  }
                />
              </label>
            )}
            {view === "workflows" && (
              <label>
                <span>Stage</span>
                <Select
                  size="lg"
                  value={stage || "all"}
                  options={[
                    { value: "all", label: "All stages" },
                    ...["scan", "publish", "dedupe"].map((value) => ({
                      value,
                      label: label(value),
                    })),
                  ]}
                  onChange={(option) =>
                    filter(setStage, option.value === "all" ? "" : option.value)
                  }
                />
              </label>
            )}
            <label>
              <span>Sort</span>
              <Select
                size="lg"
                value={sort}
                options={[
                  { value: "activity", label: "Recent activity" },
                  { value: "newest", label: "Newest first" },
                ]}
                onChange={(option) => filter(setSort, option.value)}
              />
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
                    {query || repository || status || stage
                      ? "No matching records"
                      : `No ${current.label.toLowerCase()} yet`}
                  </h2>
                  <p>
                    {query || repository || status || stage
                      ? "Try another search or filter."
                      : view === "scans"
                        ? "Scans recorded in this service’s state directory appear here. Imported findings are available in Findings, even without local scans."
                        : view === "workflows"
                          ? "Workflows are optional. Browse Scans, Findings, or Duplicate groups without creating one."
                          : view === "findings"
                            ? "Findings from local scans or API imports will appear here."
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
            Statuses are last recorded values, not runner heartbeats. This
            dashboard only reads the service’s configured workbench database.
          </p>
        </main>
      </div>
    </div>
  );
}
