import {
  skillOnly,
  excerpts,
  installedNodemailerVersion,
  mail390,
  nodemailerFile,
} from "./case-data.mjs";

import {
  mimePromotionEvidence,
  mimeReceiverSources,
} from "./receiver-data.mjs";

const api = "archive/ingest.py";
const worker = "archive/importer.py";
const compose = "deploy/compose.yaml";
const intakeCaller =
  "An unauthenticated sender can submit an RFC 5322 message to POST /messages and has no other access.";

const selectedRelease = excerpts(
  "package-lock.json",
  '"node_modules/nodemailer": {\n' +
    '            "version": "7.0.10",\n' +
    '            "resolved": "https://registry.npmjs.org/nodemailer/-/nodemailer-7.0.10.tgz",\n' +
    '            "integrity": "sha512-Us/Se1WtT0ylXgNFfyFSx4LElllVLJXQjWi2Xz17xWw7amDKO2MLtFnVp1WACy7GkVGs+oBlRopVNUzlrGSw1w=="',
);
const selectedImports = [
  excerpts("index.js", "const simpleParser = require('./lib/simple-parser');"),
  excerpts(
    "lib/simple-parser.js",
    "const MailParser = require('./mail-parser.js');",
  ),
  excerpts("lib/simple-parser.js", "let parser = new MailParser(options);"),
  excerpts("lib/mail-parser.js", "require('nodemailer/lib/addressparser')"),
];
// Either the installed manifest or the locked package and its complete import chain.
const selectedParser = [selectedRelease, ...selectedImports].map((group) => [
  ...installedNodemailerVersion,
  ...group,
]);
const indexWorker = excerpts(compose, "command: python3 -m archive.importer");
const queue = excerpts(compose, "QUEUE_NAME: ${STACK_NAME:?}-imports");
const parser = excerpts("archive/index-mail.cjs", "simpleParser(input)");

function archiveCase(id, target, status, forwardContentType = false) {
  const versioning = excerpts("archive/stack.json", `"Status": "${status}"`);
  const mediaPolicy = excerpts(
    "archive/media.json",
    `"forwardContentType": ${forwardContentType}`,
  );
  const stage = [
    ["ingest.py", api],
    ["importer.py", worker],
    ["index-mail.cjs", "archive/index-mail.cjs"],
    ["preview.py", "preview/consumer.py"],
    ["compose.yaml", compose],
    ["Dockerfile", "deploy/Dockerfile"],
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
    ...mimeReceiverSources,
  );
  return {
    id,
    target,
    identityEvidence: [
      indexWorker,
      queue,
      parser,
      forwardContentType ? mediaPolicy : versioning,
    ],
    cve: "CVE-2025-14874",
    component: "nodemailer",
    suite: "mailparser",
    repository: "nodemailer/mailparser",
    revision: mail390,
    callerScope:
      intakeCaller +
      " Assess jobs produced by this endpoint under the deployment configuration supplied in the checkout.",
    verdict:
      status === "Enabled" || forwardContentType
        ? "potentially_exploitable"
        : "ruled_out",
    version: "7.0.10",
    evidenceGroups: [
      skillOnly(excerpts(compose, "context: ..")),
      excerpts(compose, "dockerfile: deploy/Dockerfile"),
      skillOnly(excerpts("deploy/Dockerfile", "WORKDIR /opt/mail")),
      excerpts("deploy/Dockerfile", "COPY package.json package-lock.json ./"),
      excerpts("deploy/Dockerfile", "npm ci --omit=dev --ignore-scripts"),
      excerpts("package-lock.json", "nodemailer-7.0.10.tgz"),
      skillOnly(
        excerpts("deploy/Dockerfile", "COPY index.js ./"),
        excerpts("deploy/Dockerfile", "COPY lib/ ./lib/"),
        excerpts("deploy/Dockerfile", "COPY archive/ ./archive/"),
      ),
      excerpts(compose, "command: python3 -m archive.ingest"),
      indexWorker,
      excerpts(compose, "environment: *imports"),
      queue,
      versioning,
      excerpts(
        api,
        "receipt = objects.put_object(Bucket=bucket, Key=key, Body=raw)",
      ),
      excerpts(api, "Body=envelope + parts[1]"),
      excerpts(api, 'receipt.get("VersionId") or "null"'),
      excerpts(worker, 'VersionId=locator["generation"]'),
      excerpts(worker, 'input=obj["Body"].read()'),
      excerpts("archive/index-mail.cjs", 'require("../index.js")'),
      parser,
      ...(forwardContentType ? mimePromotionEvidence("child") : []),
      ...(status === "Suspended"
        ? [
            mediaPolicy,
            excerpts(api, 'if media_policy["forwardContentType"]:'),
            ...(forwardContentType
              ? [
                  excerpts(
                    api,
                    'SMTP.fold_binary("Content-Type", original_headers["Content-Type"])',
                  ),
                ]
              : [
                  excerpts(api, 'content_type = b"Content-Type: text/plain'),
                  excerpts(api, "From: relay@example.invalid"),
                  excerpts(api, "To: archive@example.invalid"),
                ]),
          ]
        : []),
      ...(status === "Enabled" || forwardContentType
        ? [
            excerpts(
              "lib/mail-parser.js",
              "this.processHeaders(node.headers.getList())",
            ),
            excerpts("lib/mail-parser.js", "value = addressparser(value)"),
            excerpts(
              "node_modules/nodemailer/lib/addressparser/index.js",
              "addressparser(data.group.join(','))",
            ),
          ]
        : []),
      skillOnly(...selectedParser),
    ],
    stage,
  };
}

export const serviceCases = [
  archiveCase(
    "archive-worker-pinned-original",
    "archive-original-worker",
    "Enabled",
  ),
  archiveCase(
    "archive-worker-pinned-normalized",
    "archive-normalized-worker",
    "Suspended",
  ),
  archiveCase(
    "archive-worker-mime-parts",
    "archive-mime-worker",
    "Suspended",
    true,
  ),
];
