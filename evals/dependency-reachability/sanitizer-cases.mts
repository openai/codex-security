import type { ReachabilityCase, StageFile } from "./cases.mts";

const nodemailer = "4175e4baf92ffc4e20791a11fc0886025228a2ac";
const installed = "node_modules/nodemailer/";
const qp = installed + "lib/qp/index.js";
const files: StageFile[] = [
  "package.json",
  "lib/addressparser/index.js",
  "lib/qp/index.js",
].map((source) => ({
  kind: "git",
  repository: "nodemailer/nodemailer",
  revision: nodemailer,
  source,
  destination: installed + source,
}));

function archiveCase(
  id: string,
  boundary: string,
  verdict: "exploitable" | "ruled_out",
): ReachabilityCase {
  return {
    id,
    suite: "mailparser",
    repository: "nodemailer/mailparser",
    revision: "3e1e0291d7757501d334d19fe6553a78b45cc1eb",
    version: "7.0.10",
    verdict,
    question:
      "Assess CVE-2025-14874 in Nodemailer for the deployed archive service under service/. " +
      "An unauthenticated caller controls the bytes of an uploaded file in POST /archive. " +
      "The finding concerns unbounded recursion on nested groups in an address header in " +
      "Nodemailer 3.0.0 through 7.0.10. Determine whether this caller can reach the vulnerable " +
      "operation through the service as deployed, and report the installed Nodemailer version.",
    stage: [
      ...files,
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
      [
        { path: installed + "package.json", contains: '"version": "7.0.10"' },
        { path: "package.json", contains: '"nodemailer": "7.0.10"' },
        { path: "package-lock.json", contains: "nodemailer-7.0.10.tgz" },
        { path: "package-lock.json", contains: '"nodemailer": "7.0.10"' },
      ],
      [{ path: "service/archive.json", contains: boundary }],
      [{ path: "service/server.cjs", contains: "qp.wrap(qp.encode(" }],
      [
        { path: qp, contains: "ord.toString(16).toUpperCase()" },
        { path: qp, contains: "[0x20, 0x3c]" },
      ],
      ...(verdict === "exploitable"
        ? [
            [
              {
                path: "lib/mail-parser.js",
                contains: "this.processHeaders(node.headers.getList())",
              },
              { path: "lib/mail-parser.js", contains: "addressparser(value)" },
              {
                path: installed + "lib/addressparser/index.js",
                contains: "addressparser(data.group.join(','))",
              },
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
