import type { ReachabilityCase, StageFile } from "./cases.mts";

function bundleCase(id: string, byName: boolean): ReachabilityCase {
  const source = (file: string, name = file): StageFile => ({
    kind: "fixture",
    source: `fixtures/zip/${file}`,
    destination: `bundle/${name}`,
  });
  const stage: StageFile[] = [
    source("gateway.py"),
    source(byName ? "catalog_a.py" : "catalog_b.py", "catalog.py"),
    source("worker.py"),
    {
      kind: "fixture",
      source: "fixtures/services/index-mail.cjs",
      destination: "bundle/index-mail.cjs",
    },
    {
      kind: "git",
      repository: "nodemailer/nodemailer",
      revision: "4175e4baf92ffc4e20791a11fc0886025228a2ac",
      source: "package.json",
      destination: "node_modules/nodemailer/package.json",
    },
  ];
  return {
    id,
    suite: "mailparser",
    repository: "nodemailer/mailparser",
    revision: "3e1e0291d7757501d334d19fe6553a78b45cc1eb",
    question:
      "A caller submits a ZIP mail bundle to gateway.submit in bundle/. Only that service can enqueue jobs. " +
      "The separate worker receives the queued bytes intact, and its mail index uses this checkout and its locked dependencies. " +
      "CVE-2025-14874 in Nodemailer requires a sender-controlled address header to reach the parser. " +
      "Assess that input-reachability prerequisite: can a caller-selected To address outside the permitted envelope " +
      "reach the worker's installed address parser? Report the installed Nodemailer version. " +
      "Treat code for both services as deployed and assume standard CPython zipfile behavior.",
    verdict: byName ? "exploitable" : "ruled_out",
    version: "7.0.10",
    stage,
    evidenceGroups: [
      [
        {
          path: "bundle/catalog.py",
          contains: byName
            ? "archive.read(member.filename)"
            : "archive.read(member)",
        },
      ],
      [
        { path: "bundle/gateway.py", contains: "headers != ENVELOPE" },
        { path: "bundle/gateway.py", contains: "To: archive@example.invalid" },
      ],
      [{ path: "bundle/gateway.py", contains: "jobs.put(upload)" }],
      [{ path: "bundle/worker.py", contains: "input=archive.read(member)" }],
      [{ path: "bundle/index-mail.cjs", contains: "simpleParser(input)" }],
      [{ path: "lib/mail-parser.js", contains: "addressparser(value)" }],
      [
        {
          path: "node_modules/nodemailer/package.json",
          contains: '"version": "7.0.10"',
        },
        { path: "package.json", contains: '"nodemailer": "7.0.10"' },
        { path: "package-lock.json", contains: "nodemailer-7.0.10.tgz" },
        { path: "package-lock.json", contains: '"nodemailer": "7.0.10"' },
      ],
    ],
  };
}

export const zipCases = [
  bundleCase("zip-import-alpha", true),
  bundleCase("zip-import-beta", false),
];
