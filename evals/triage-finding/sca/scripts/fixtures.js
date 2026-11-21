"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { application, families, cases, ...metadata } =
  require("../fixtures/corpus.json");

function json(value) {
  return JSON.stringify(value, null, 2) + "\n";
}

function snapshot({ source, deployment, ...description }) {
  const { osv, preconditions, dev } = families[description.advisory_family];
  const result = osv.results[0];
  const { package: component, vulnerabilities, groups } = result.packages[0];
  const { name, version, ecosystem } = component;
  const input = {
    input_id: `${description.case_id}-match`,
    source_type: "advisory",
    component: { source: result.source.path, ecosystem, name, version },
    advisory_ids: groups[0].ids,
    advisories: vulnerabilities,
    preconditions,
    scanner_evidence: "osv.json",
  };
  const manifest = {
    name: `sca-synthetic-${description.case_id}`,
    version: "1.0.0",
    private: true,
    type: "module",
    [dev ? "devDependencies" : "dependencies"]: { [name]: version },
  };
  const lockfile = {
    name: manifest.name,
    version: manifest.version,
    lockfileVersion: 3,
    requires: true,
    packages: { "": manifest, [`node_modules/${name}`]: { version, dev } },
  };

  // Only these six files go to the model. Their original digests are pinned per case.
  const files = {
    "APPLICATION.md": [...application, ...deployment].join("\n\n") + "\n",
    "input.json": json(input),
    "osv.json": json(osv),
    "package-lock.json": json(lockfile),
    "package.json": json(manifest),
    "src/application.mjs": source.join("\n") + "\n",
  };
  return { ...description, input, files };
}

function stageCase(root, testCase) {
  const directory = path.resolve(root, testCase.case_id);
  if (path.dirname(directory) !== path.resolve(root))
    throw new Error(`Invalid case directory: ${testCase.case_id}`);
  fs.mkdirSync(path.join(directory, "src"), { recursive: true });
  for (const [name, content] of Object.entries(testCase.files)) {
    fs.writeFileSync(path.join(directory, name), content);
  }
  return directory;
}

const CORPUS = { ...metadata, cases: cases.map(snapshot) };
module.exports = { CORPUS, stageCase };
