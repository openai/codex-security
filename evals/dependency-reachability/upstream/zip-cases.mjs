import {
  skillOnly,
  excerpts,
  installedNodemailerVersion,
  mail390,
  nodemailerFile,
} from "./case-data.mjs";

import { mimeReceiverSources } from "./receiver-data.mjs";

const bundleCaller =
  "An external caller can submit a ZIP mail bundle and controls only its contents.";

const envelope = [
  excerpts("bundle/gateway.py", "From: relay@example.invalid"),
  excerpts("bundle/gateway.py", "To: archive@example.invalid"),
  excerpts("bundle/gateway.py", "Content-Type: text/plain; charset=us-ascii"),
];

function bundleCase(variant, byName) {
  const source = (file, name = file) => ({
    kind: "fixture",
    source: `fixtures/zip/${file}`,
    destination: `bundle/${name}`,
  });
  const stage = [
    source("submit_bundle.py"),
    source("gateway.py"),
    source(byName ? "catalog_a.py" : "catalog_b.py", "catalog.py"),
    source("worker.py"),
    {
      kind: "fixture",
      source: "fixtures/services/index-mail.cjs",
      destination: "bundle/index-mail.cjs",
    },
    nodemailerFile("package.json"),
    nodemailerFile("lib/addressparser/index.js"),
    ...mimeReceiverSources,
  ];
  const selection = excerpts(
    "bundle/catalog.py",
    byName ? "archive.read(member.filename)" : "archive.read(member)",
  );
  const worker = excerpts(
    "bundle/submit_bundle.py",
    "target=import_next, args=(jobs,)",
  );
  const parse = excerpts("bundle/index-mail.cjs", "simpleParser(input)");
  return {
    id: `zip-import-${variant}`,
    target: `zip-bundle-${variant}-address-parser`,
    identityEvidence: [selection, worker, parse],
    cve: "CVE-2025-14874",
    component: "nodemailer",
    suite: "mailparser",
    repository: "nodemailer/mailparser",
    revision: mail390,
    callerScope: bundleCaller,
    verdict: byName ? "potentially_exploitable" : "ruled_out",
    version: "7.0.10",
    stage,
    evidenceGroups: [
      excerpts(
        "bundle/submit_bundle.py",
        "submit(sys.stdin.buffer.read(), jobs)",
      ),
      worker,
      selection,
      excerpts("bundle/gateway.py", "headers != ENVELOPE"),
      excerpts(
        "bundle/gateway.py",
        'raise ValueError("expected an archive notification")',
      ),
      ...(byName ? [skillOnly(...envelope)] : envelope),
      excerpts("bundle/gateway.py", "jobs.put(upload)"),
      excerpts("bundle/worker.py", "input=archive.read(member)"),
      excerpts("bundle/index-mail.cjs", 'require("../index.js")'),
      parse,
      excerpts("lib/mail-parser.js", "addressparser(value)"),
      ...(byName
        ? [
            excerpts(
              "node_modules/nodemailer/lib/addressparser/index.js",
              "addressparser(data.group.join(','))",
            ),
          ]
        : []),
      installedNodemailerVersion,
    ],
  };
}

export const zipCases = [bundleCase("alpha", true), bundleCase("beta", false)];
