export interface CatalogService {
  id: string;
  name: string;
}

export interface MappingCase {
  id: string;
  package: string;
  path: string;
  files: Record<string, string>;
  catalog?: Record<string, CatalogService[]>;
  expected: { applications: CatalogService[] };
}

export const catalogServer = "mapping_catalog";
export const catalogTool = "lookup_service_by_path";
const packageName = "@sample/labels";
const consumer = "packages/runner/main.cjs";
const weekly = { id: "svc-18", name: "weekly-delivery" };
const morning = { id: "svc-25", name: "morning-delivery" };
const evening = { id: "svc-76", name: "evening-delivery" };
const bulletin = { id: "svc-92", name: "print-delivery" };

function projectCatalog(
  project: string,
  entry: string,
  ...services: CatalogService[]
) {
  return {
    [project]: services,
    [`${project}/package.json`]: services,
    [entry]: services,
  };
}
const workspace = {
  "package.json": '{"private":true,"workspaces":["packages/*"]}\n',
  "packages/labels/package.json":
    '{"name":"@sample/labels","version":"1.0.0"}\n',
  "packages/labels/index.js": "exports.label = value => String(value);\n",
  "packages/runner/package.json":
    '{"name":"report-runner","private":true,"scripts":{"start":"node main.cjs"},"dependencies":{"@sample/labels":"1.0.0"}}\n',
  [consumer]:
    'const { label } = require("@sample/labels");\nconsole.log(label(process.env.EDITION || "daily"));\n',
};
const dockerfile = `FROM node:22
WORKDIR /app
COPY . .
RUN npm install --offline --ignore-scripts --no-audit
`;

export const cases: MappingCase[] = [
  {
    id: "external-launcher",
    package: packageName,
    path: consumer,
    files: {
      ...workspace,
      Dockerfile: dockerfile,
      "packages/runner-next/package.json":
        '{"name":"report-runner-next","private":true}\n',
      "packages/runner-next/main.cjs": 'console.log("preview");\n',
      ".github/workflows/check.yaml": `name: Check
on: [push]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: node --check packages/runner/main.cjs
`,
      "ops/weekly/compose.yaml": `services:
  digest:
    build: ../..
    command: ["node", "packages/runner/main.cjs"]
  preview:
    build: ../..
    command: ["node", "packages/runner-next/main.cjs"]
`,
    },
    catalog: {
      ...projectCatalog("packages/runner", consumer, weekly),
      ...projectCatalog(
        "packages/runner-next",
        "packages/runner-next/main.cjs",
        {
          id: "svc-41",
          name: "preview-delivery",
        },
      ),
      "ops/weekly/compose.yaml": [weekly],
      ".github/workflows/check.yaml": [],
    },
    expected: { applications: [weekly] },
  },
  {
    id: "shared-project",
    package: packageName,
    path: consumer,
    files: {
      ...workspace,
      Dockerfile: dockerfile,
      "ops/morning/compose.yaml": `name: morning-edition
services:
  digest:
    build: ../..
    command: ["node", "packages/runner/main.cjs"]
    environment:
      EDITION: morning
`,
      "ops/evening/compose.yaml": `name: evening-edition
services:
  digest:
    build: ../..
    command: ["node", "packages/runner/main.cjs"]
    environment:
      EDITION: evening
`,
    },
    catalog: {
      ...projectCatalog("packages/runner", consumer, morning, evening),
      "ops/morning/compose.yaml": [morning],
      "ops/evening/compose.yaml": [evening],
    },
    expected: { applications: [morning, evening] },
  },
  {
    id: "runnable-package",
    package: packageName,
    path: consumer,
    files: { ...workspace },
    catalog: projectCatalog("packages/runner", consumer),
    expected: { applications: [] },
  },
  {
    id: "shared-library-consumer",
    package: packageName,
    path: "packages/format/render.cjs",
    files: {
      "package.json": '{"private":true,"workspaces":["packages/*","jobs/*"]}\n',
      "packages/labels/package.json": workspace["packages/labels/package.json"],
      "packages/labels/index.js": workspace["packages/labels/index.js"],
      "packages/format/package.json":
        '{"name":"@sample/format","version":"1.0.0","main":"render.cjs","dependencies":{"@sample/labels":"1.0.0"}}\n',
      "packages/format/render.cjs":
        'const { label } = require("@sample/labels");\nmodule.exports = value => label(value);\n',
      "jobs/print/package.json":
        '{"name":"print-job","private":true,"dependencies":{"@sample/format":"1.0.0"}}\n',
      "jobs/print/start.cjs":
        'const render = require("@sample/format");\nconsole.log(render("daily"));\n',
      Dockerfile: dockerfile,
      "ops/print/compose.yaml": `services:
  bulletin:
    build: ../..
    command: ["node", "jobs/print/start.cjs"]
`,
    },
    catalog: {
      ...projectCatalog("jobs/print", "jobs/print/start.cjs", bulletin),
      "ops/print/compose.yaml": [bulletin],
    },
    expected: { applications: [bulletin] },
  },
  {
    id: "catalog-unavailable",
    package: packageName,
    path: consumer,
    files: {
      ...workspace,
      "packages/runner/catalog-info.yaml": `apiVersion: backstage.io/v1alpha1
kind: Component
metadata:
  name: report-runner
spec:
  type: service
  lifecycle: production
  owner: examples
`,
      "compose.yaml": `services:
  digest:
    build: .
    command: ["node", "packages/runner/main.cjs"]
`,
      Dockerfile: dockerfile,
    },
    expected: { applications: [] },
  },
];
