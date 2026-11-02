import {
  declaredNodemailerVersion,
  excerpts,
  installedNodemailerVersion,
  mail390,
  nodemailerFile,
} from "./case-data.mts";
import type { ReachabilityCase, StageFile } from "./cases.mts";

function bundleCase(id: string, byName: boolean): ReachabilityCase {
  const source = (file: string, name = file): StageFile => ({
    kind: "fixture",
    source: `fixtures/zip/${file}`,
    destination: `bundle/${name}`,
  });
  const stage: StageFile[] = [
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
  ];
  return {
    id,
    suite: "mailparser",
    repository: "nodemailer/mailparser",
    revision: mail390,
    question:
      "An external caller can submit a ZIP mail bundle and controls only its contents. " +
      "CVE-2025-14874 in Nodemailer requires a sender-controlled address header to reach the parser. " +
      "Can an arbitrary To address chosen by this caller reach the installed address parser through this feature? " +
      "Assess this input prerequisite and report the installed Nodemailer version.",
    verdict: byName ? "exploitable" : "ruled_out",
    version: "7.0.10",
    stage,
    evidenceGroups: [
      excerpts(
        "bundle/submit_bundle.py",
        "submit(sys.stdin.buffer.read(), jobs)",
      ),
      excerpts("bundle/submit_bundle.py", "target=import_next, args=(jobs,)"),
      excerpts(
        "bundle/catalog.py",
        byName ? "archive.read(member.filename)" : "archive.read(member)",
      ),
      excerpts(
        "bundle/gateway.py",
        "headers != ENVELOPE",
        "To: archive@example.invalid",
      ),
      excerpts("bundle/gateway.py", "jobs.put(upload)"),
      excerpts("bundle/worker.py", "input=archive.read(member)"),
      excerpts("bundle/index-mail.cjs", "simpleParser(input)"),
      excerpts("lib/mail-parser.js", "addressparser(value)"),
      [...installedNodemailerVersion, ...declaredNodemailerVersion],
    ],
  };
}

export const zipCases = [
  bundleCase("zip-import-alpha", true),
  bundleCase("zip-import-beta", false),
];
