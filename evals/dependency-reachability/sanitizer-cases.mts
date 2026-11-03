import {
  declaredNodemailerVersion,
  excerpts,
  installedNodemailerVersion,
  mail390,
  nodemailerFile,
} from "./case-data.mts";
import type { ReachabilityCase } from "./cases.mts";
const installed = "node_modules/nodemailer/";
const qp = installed + "lib/qp/index.js";
function archiveCase(
  id: string,
  boundary: string,
  verdict: "exploitable" | "ruled_out",
): ReachabilityCase {
  return {
    id,
    cve: "CVE-2025-14874",
    component: "nodemailer",
    suite: "mailparser",
    repository: "nodemailer/mailparser",
    revision: mail390,
    version: "7.0.10",
    verdict,
    question:
      "Assess CVE-2025-14874 in Nodemailer. " +
      "An unauthenticated caller controls the bytes of an uploaded file in POST /archive. " +
      "The finding concerns unbounded recursion on nested groups in an address header in " +
      "Nodemailer 3.0.0 through 7.0.10. Determine whether this caller can reach the vulnerable " +
      "operation through the service as deployed, and report the installed Nodemailer version.",
    stage: [
      nodemailerFile("package.json"),
      nodemailerFile("lib/addressparser/index.js"),
      nodemailerFile("lib/qp/index.js"),
      {
        kind: "fixture",
        source: "fixtures/sanitizer/server.cjs",
        destination: "service/server.cjs",
      },
      {
        kind: "json",
        value: { boundary },
        destination: "service/archive.json",
      },
    ],
    evidenceGroups: [
      [...installedNodemailerVersion, ...declaredNodemailerVersion],
      excerpts("service/archive.json", boundary),
      excerpts("service/server.cjs", "qp.wrap(qp.encode("),
      excerpts(qp, "ord.toString(16).toUpperCase()", "[0x20, 0x3c]"),
      ...(verdict === "exploitable"
        ? [
            [
              ...excerpts(
                "lib/mail-parser.js",
                "this.processHeaders(node.headers.getList())",
                "addressparser(value)",
              ),
              ...excerpts(
                installed + "lib/addressparser/index.js",
                "addressparser(data.group.join(','))",
              ),
            ],
          ]
        : []),
    ],
  };
}

// Quoted-printable encoding turns "=" into "=3D". It cannot emit "=_" within a line.
export const sanitizerCases = [
  archiveCase("archive-east", "archive=3Dpart", "exploitable"),
  archiveCase("archive-west", "archive=_part", "ruled_out"),
];
