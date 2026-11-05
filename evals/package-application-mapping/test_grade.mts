import assert from "node:assert/strict";
import test from "node:test";
import {
  cases,
  catalogServer,
  catalogTool,
  type CatalogService,
} from "./cases.mts";
import { gradeMapping } from "./grade.mts";

const shared = cases.find((c) => c.id === "shared-project")!;
const empty = cases.find((c) => c.id === "runnable-package")!;
const unavailable = cases.find((c) => c.id === "catalog-unavailable")!;
const file = { kind: "file", name: shared.path };
const directory = { kind: "directory", name: "packages/runner" };
const query = (evidence: unknown[], configured = true) => ({
  node: file,
  service_lookup: configured ? "checked" : undefined,
  service_resolution: {
    revision: 4,
    pending: 0,
    checked: configured ? 1 : 0,
    catalog_configured: configured,
  },
  evidence,
});
function edge(app: CatalogService) {
  return {
    from: {
      kind: "service",
      name: app.name,
      scope: `${catalogServer}:${app.id}`,
    },
    relation: "uses",
    to: file,
    source: `${catalogServer}/${catalogTool}#${app.id}`,
  };
}

test("checks independent catalog identities for the same code and accepts a covering directory mapping", () => {
  const apps = shared.expected.applications;
  const first = edge(apps[0]!);
  const second = { ...edge(apps[1]!), to: directory };
  assert.equal(gradeMapping(shared, [query([first, second])]).pass, true);
  for (const incorrect of [
    [],
    [first],
    [first, { ...second, source: first.source }],
    [first, { ...second, to: { ...directory, name: "packages/run" } }],
    [first, second, { ...first, from: { ...first.from, scope: "unrelated" } }],
  ])
    assert.equal(gradeMapping(shared, [query(incorrect)]).pass, false);
});

test("requires a checked target query at the latest revision", () => {
  const good = query(shared.expected.applications.map(edge));
  for (const snapshots of [
    [],
    [{ ...good, node: { kind: "file", name: "elsewhere" } }],
    [{ ...good, service_lookup: "pending" }],
    [
      {
        ...good,
        service_resolution: { ...good.service_resolution, pending: 1 },
      },
    ],
    [{ ...good, truncated: true }],
    [
      {
        ...good,
        service_resolution: { ...good.service_resolution, truncated: true },
      },
    ],
    [good, { service_resolution: { revision: 5, pending: 0 } }],
    [
      good,
      { services: [{ name: "preview", scope: `${catalogServer}:svc-41` }] },
    ],
  ])
    assert.equal(gradeMapping(shared, snapshots).pass, false);
  assert.deepEqual(
    gradeMapping(shared, [
      good,
      {
        service_resolution: {
          revision: 5,
          pending: 1,
          paths: ["packages/runner/package.json"],
        },
      },
    ]).errors,
    ["Pending service lookups (1) for packages/runner/package.json"],
  );
});

test("distinguishes a cited no-service finding from an empty graph or package owner", () => {
  const none = {
    from: file,
    relation: "no_service_found",
    source: `${catalogServer}/${catalogTool}`,
  };
  assert.equal(gradeMapping(empty, [query([none])]).pass, true);
  for (const incorrect of [
    [],
    [{ ...none, source: "packages/runner/package.json" }],
    [{ ...none, from: { kind: "directory", name: "packages/runner" } }],
    [none, edge(shared.expected.applications[0]!)],
  ])
    assert.equal(gradeMapping(empty, [query(incorrect)]).pass, false);
});

test("requires an unresolved identity when no service catalog is configured", () => {
  assert.equal(gradeMapping(unavailable, [query([], false)]).pass, true);
  for (const incorrect of [
    [query([], true)],
    [query([], false), { services_found: 1 }],
    [query([edge(shared.expected.applications[0]!)], false)],
    [query([{ from: file, relation: "no_service_found" }], false)],
  ])
    assert.equal(gradeMapping(unavailable, incorrect).pass, false);
});
