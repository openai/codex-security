import type { ReachabilityCase, StageFile } from "./cases.mts";
import type { EvidenceGroup } from "./grade.mts";

function at(path: string, ...contains: string[]): EvidenceGroup {
  return contains.map((marker) => ({ path, contains: marker }));
}

const revision = "3e1e0291d7757501d334d19fe6553a78b45cc1eb";
const dependencyRevision = "4175e4baf92ffc4e20791a11fc0886025228a2ac";
const source = "lib/addressparser/index.js";
const api = "archive/ingest.py";
const worker = "archive/importer.py";

function archiveCase(
  id: string,
  status: "Enabled" | "Suspended",
  forwardContentType = false,
): ReachabilityCase {
  const stage: StageFile[] = ["ingest.py", "importer.py", "index-mail.cjs"].map(
    (name) => ({
      kind: "fixture",
      source: `fixtures/services/${name}`,
      destination: `archive/${name}`,
    }),
  );
  stage.push({
    kind: "json",
    destination: "archive/media.json",
    value: { forwardContentType },
  });
  stage.push({
    kind: "json",
    destination: "archive/stack.json",
    value: {
      Resources: {
        Archive: {
          Type: "AWS::S3::Bucket",
          Properties: { VersioningConfiguration: { Status: status } },
        },
        ImportQueue: { Type: "AWS::SQS::Queue" },
      },
      Outputs: {
        ArchiveBucket: { Value: { Ref: "Archive" } },
        ImportQueueUrl: { Value: { Ref: "ImportQueue" } },
      },
    },
  });
  for (const path of [source, "package.json"]) {
    stage.push({
      kind: "git",
      repository: "nodemailer/nodemailer",
      revision: dependencyRevision,
      source: path,
      destination: `node_modules/nodemailer/${path}`,
    });
  }
  return {
    id,
    suite: "mailparser",
    repository: "nodemailer/mailparser",
    revision,
    question:
      "The deployed gateway in archive/ accepts unauthenticated RFC 5322 uploads at POST /messages. " +
      "A separate import service consumes jobs. Both use ARCHIVE_BUCKET and IMPORT_QUEUE_URL " +
      "from the deployed CloudFormation stack in that directory. The worker image contains this " +
      "checkout and the staged dependency. The sender controls the uploaded message but cannot write " +
      "the bucket or queue directly. Assess CVE-2025-14874 for this endpoint through completion " +
      "of the import. This Nodemailer advisory concerns unbounded recursion on nested address groups " +
      "in a message header in versions through 7.0.10. Report the installed worker dependency version.",
    verdict:
      status === "Enabled" || forwardContentType ? "exploitable" : "ruled_out",
    version: "7.0.10",
    evidenceGroups: [
      at("archive/stack.json", `"Status": "${status}"`),
      at(api, "receipt = objects.put_object(Bucket=bucket, Key=key, Body=raw)"),
      at(api, "Body=envelope + parts[1]"),
      at(api, 'receipt.get("VersionId") or "null"'),
      at(worker, 'VersionId=locator["generation"]'),
      at("archive/index-mail.cjs", "simpleParser(input)"),
      ...(forwardContentType
        ? [
            at("archive/media.json", '"forwardContentType": true'),
            at(
              api,
              'SMTP.fold_binary("Content-Type", original_headers["Content-Type"])',
            ),
            at(
              "lib/mail-parser.js",
              "this.processHeaders(node.headers.getList())",
            ),
            at("lib/mail-parser.js", "value = addressparser(value)"),
          ]
        : []),
      [
        ...at("package.json", '"nodemailer": "7.0.10"'),
        ...at(
          "package-lock.json",
          "nodemailer-7.0.10.tgz",
          '"nodemailer": "7.0.10"',
        ),
        ...at("node_modules/nodemailer/package.json", '"version": "7.0.10"'),
      ],
    ],
    stage,
  };
}

export const serviceCases = [
  archiveCase("archive-worker-pinned-original", "Enabled"),
  archiveCase("archive-worker-pinned-normalized", "Suspended"),
  archiveCase("archive-worker-mime-parts", "Suspended", true),
];
