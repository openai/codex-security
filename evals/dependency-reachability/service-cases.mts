import {
  declaredNodemailerVersion,
  excerpts,
  installedNodemailerVersion,
  mail390,
  nodemailerFile,
} from "./case-data.mts";
import type { ReachabilityCase, StageFile } from "./cases.mts";

const api = "archive/ingest.py";
const worker = "archive/importer.py";
const compose = "deploy/compose.yaml";

function archiveCase(
  id: string,
  status: "Enabled" | "Suspended",
  forwardContentType = false,
): ReachabilityCase {
  const stage: StageFile[] = [
    ["ingest.py", api],
    ["importer.py", worker],
    ["index-mail.cjs", "archive/index-mail.cjs"],
    ["preview.py", "preview/consumer.py"],
    ["compose.yaml", compose],
  ].map(([name, destination]) => ({
    kind: "fixture",
    source: `fixtures/services/${name}`,
    destination,
  }));
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
          Properties: {
            BucketName: { "Fn::Sub": "${AWS::StackName}-messages" },
            VersioningConfiguration: { Status: status },
          },
        },
        ImportQueue: {
          Type: "AWS::SQS::Queue",
          Properties: { QueueName: { "Fn::Sub": "${AWS::StackName}-imports" } },
        },
        PreviewQueue: {
          Type: "AWS::SQS::Queue",
          Properties: {
            QueueName: { "Fn::Sub": "${AWS::StackName}-previews" },
          },
        },
      },
    },
  });
  stage.push(
    nodemailerFile("lib/addressparser/index.js"),
    nodemailerFile("package.json"),
  );
  return {
    id,
    cve: "CVE-2025-14874",
    component: "nodemailer",
    suite: "mailparser",
    repository: "nodemailer/mailparser",
    revision: mail390,
    question:
      "An unauthenticated sender can submit an RFC 5322 message to POST /messages and has no other access. " +
      "Can that sender trigger CVE-2025-14874 in this deployment? The advisory concerns unbounded " +
      "recursion on nested address groups in a message header in Nodemailer through 7.0.10. " +
      "Report the installed Nodemailer version.",
    verdict:
      status === "Enabled" || forwardContentType ? "exploitable" : "ruled_out",
    version: "7.0.10",
    evidenceGroups: [
      ...["archive.ingest", "archive.importer"].map((module) =>
        excerpts(
          compose,
          `command: python3 -m ${module}\n    environment: *imports`,
        ),
      ),
      excerpts("archive/stack.json", `"Status": "${status}"`),
      excerpts(
        api,
        "receipt = objects.put_object(Bucket=bucket, Key=key, Body=raw)",
      ),
      excerpts(api, "Body=envelope + parts[1]"),
      excerpts(api, 'receipt.get("VersionId") or "null"'),
      excerpts(worker, 'VersionId=locator["generation"]'),
      excerpts("archive/index-mail.cjs", "simpleParser(input)"),
      ...(forwardContentType
        ? [
            excerpts("archive/media.json", '"forwardContentType": true'),
            excerpts(
              api,
              'SMTP.fold_binary("Content-Type", original_headers["Content-Type"])',
            ),
            excerpts(
              "lib/mail-parser.js",
              "this.processHeaders(node.headers.getList())",
            ),
            excerpts("lib/mail-parser.js", "value = addressparser(value)"),
          ]
        : []),
      [...declaredNodemailerVersion, ...installedNodemailerVersion],
    ],
    stage,
  };
}

export const serviceCases = [
  archiveCase("archive-worker-pinned-original", "Enabled"),
  archiveCase("archive-worker-pinned-normalized", "Suspended"),
  archiveCase("archive-worker-mime-parts", "Suspended", true),
];
