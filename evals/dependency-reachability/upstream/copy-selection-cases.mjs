import {
  excerpts,
  mail390,
  nodemailer7011,
  nodemailerFile,
} from "./case-data.mjs";

const app = "address-book";
const plugin = `${app}/plugins/contacts`;
const compose = `${app}/compose.yaml`;
const server = `${app}/server.cjs`;
const parser = "lib/addressparser/index.js";
const version = "7.0.10";

function installation(project, parserRevision) {
  return [
    {
      kind: "json",
      destination: `${project}/package.json`,
      value: { private: true, dependencies: { nodemailer: version } },
    },
    ...[
      nodemailerFile("package.json"),
      nodemailerFile(parser, parserRevision),
    ].map((file) => ({
      ...file,
      destination: `${project}/${file.destination}`,
    })),
  ];
}

const mainCopy = `${app}/node_modules/nodemailer`;
const pluginCopy = `${plugin}/node_modules/nodemailer`;
const versionLine = `"version": "${version}"`;
const mainEvidence = [
  excerpts(server, '["main", require.resolve("./package.json")]'),
  excerpts(`${mainCopy}/package.json`, versionLine),
  excerpts(`${mainCopy}/${parser}`, "addressparser(data.group.join(','))"),
];
const pluginEvidence = [
  excerpts(
    server,
    '["contacts", require.resolve("./plugins/contacts/package.json")]',
  ),
  excerpts(`${pluginCopy}/package.json`, versionLine),
  excerpts(
    `${pluginCopy}/${parser}`,
    "addressparser(data.group.join(','), { _depth: depth + 1 })",
  ),
  excerpts(
    `${pluginCopy}/${parser}`,
    "if (depth > MAX_NESTED_GROUP_DEPTH) {\n        return [];",
  ),
];

function loaderCase(id, profile, verdict, copyEvidence) {
  return {
    id,
    target: "address-book-parser",
    suite: "resolution",
    repository: "nodemailer/mailparser",
    revision: mail390,
    cve: "CVE-2025-14874",
    component: "nodemailer",
    version,
    verdict,
    needsDecidingGap: verdict === "unknown",
    callerScope:
      "An unauthenticated caller can submit arbitrary address text to POST /addresses. " +
      "Assess the address-book service launched by its Compose file, including the installed " +
      "Nodemailer version for that handler. The caller controls only the request body.",
    stage: [
      ...installation(app),
      ...installation(plugin, nodemailer7011),
      {
        kind: "fixture",
        source: "fixtures/address-book/server.cjs",
        destination: server,
      },
      {
        kind: "json",
        destination: compose,
        value: {
          services: {
            "address-book": {
              image: "node:22",
              working_dir: "/app",
              volumes: [".:/app:ro"],
              command: "node server.cjs",
              ports: ["8080:8080"],
              environment: { ADDRESS_BOOK_PROFILE: profile },
            },
          },
        },
      },
    ],
    identityEvidence: [
      excerpts(compose, `"ADDRESS_BOOK_PROFILE": "${profile}"`),
      excerpts(server, "profiles.get(process.env.ADDRESS_BOOK_PROFILE)"),
    ],
    evidenceGroups: [
      excerpts(server, "createRequire(anchor)"),
      excerpts(server, 'load("nodemailer/lib/addressparser")'),
      excerpts(server, 'parse(Buffer.concat(chunks).toString("utf8"))'),
      ...copyEvidence,
    ],
  };
}

export const copySelectionCases = [
  loaderCase(
    "address-loader-main",
    "main",
    "potentially_exploitable",
    mainEvidence,
  ),
  loaderCase("address-loader-plugin", "contacts", "ruled_out", pluginEvidence),
  loaderCase("address-loader-setting", "${ADDRESS_BOOK_PROFILE:?}", "unknown", [
    ...mainEvidence,
    ...pluginEvidence,
  ]),
];
