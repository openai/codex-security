import {
  skillOnly,
  originalRubric,
  excerpts,
  installedNodemailerVersion,
  mail390,
  nodemailer7010,
  nodemailer7011,
  nodemailerFile,
} from "./case-data.mjs";
import { sanitizerCases } from "./sanitizer-cases.mjs";
import { serviceCases } from "./service-cases.mjs";
import { rolloutCases } from "./rollout-cases.mjs";
import { zipCases } from "./zip-cases.mjs";
import { mimeReceiverSources } from "./receiver-data.mjs";
import { applicationCases } from "./application-cases.mjs";
import { copySelectionCases } from "./copy-selection-cases.mjs";

const pillowAffected = "6e28ed1f36d0eb74053af54e1eddc9c29db698cd";
const pillowFixed = "e34d346f10c0b1c814661e662a3e0c1ef084cf1c";
const webpPlugin = "src/PIL/WebPImagePlugin.py";
const webpNative = "src/_webp.c";
const wheelRecipe = "pillow-wheels/config.sh";

function pillowCase(id, revision, operation, verdict) {
  const fixed = revision === pillowFixed;
  const version = fixed ? "1.3.2" : "1.3.1";
  const release = fixed ? "10.0.1" : "10.0.0";
  const filename = `Pillow-${release}-cp312-cp312-manylinux_2_28_x86_64.whl`;
  const wheelSha256 = fixed
    ? "4ce90f8a24e1c15465048959f1e94309dfef93af272633e8f37361b824532e91"
    : "d72e2ecc68a942e8cf9739619b7f408cc7b272b279b56b2c83c6123fcfa5cdff";
  const downloadPath = fixed
    ? "0c/ce/3cceae2fab54118a5fcdfd9a2ddd0167c21169446c05378c5dc10b0d5093"
    : "5f/82/39a266a0626d2c0dd4ee341639fe7749268fc871429b90006eeb1583f24b";
  const artifact = "service/wheel-artifact.json";
  const bundledLibrary = fixed
    ? "libwebp-850e2bec.so.7.1.8"
    : "libwebp-8b6d8948.so.7.1.7";
  const selectedWheel = [
    excerpts("service/deployment.json", wheelSha256),
    excerpts(artifact, wheelSha256),
  ];
  const versionEvidence = [
    ...selectedWheel,
    excerpts(artifact, `"version": "${version}"`),
    excerpts(artifact, `"neededLibrary": "${bundledLibrary}"`),
  ];
  const handler = excerpts(
    "service/media.py",
    operation === "decode"
      ? 'Image.open(BytesIO(environ["wsgi.input"].read()))'
      : 'Image.frombytes("RGB", (64, 64), pixels)',
  );
  return {
    id,
    target:
      operation === "decode"
        ? "thumbnail-webp-decoder"
        : "thumbnail-webp-encoder",
    identityEvidence: [...selectedWheel, handler],
    cve: "CVE-2023-4863",
    component: "libwebp",
    suite: "pillow",
    repository: "python-pillow/Pillow",
    revision,
    verdict,
    version,
    callerScope:
      "An unauthenticated caller can supply the request-body bytes in POST /thumbnail. " +
      "Assess that request in the supplied configured deployment, using the official Linux CPython 3.12 x86_64 " +
      "manylinux_2_28 wheel declared there. Include all image formats and native backends reachable from that request. " +
      "Report the bundled libwebp version where the selected artifact establishes it.",
    evidenceGroups:
      operation === "decode"
        ? [
            handler,
            excerpts("service/media.py", "image.load()"),
            ...versionEvidence,
            ...(fixed
              ? []
              : [
                  excerpts(webpPlugin, "_webp.WebPAnimDecoder(self.fp.read())"),
                  excerpts(webpPlugin, "self._decoder.get_next()"),
                  excerpts(webpNative, "WebPAnimDecoderGetNext(decp->dec"),
                ]),
          ]
        : [
            handler,
            excerpts("service/media.py", "size = 64 * 64 * 3"),
            excerpts("service/media.py", "if len(pixels) != size:"),
            ...versionEvidence,
            excerpts(webpPlugin, "data = _webp.WebPEncode("),
            excerpts(webpNative, "WebPEncode(&config, &pic)"),
          ],
    stage: [
      {
        kind: "fixture",
        source:
          operation === "decode"
            ? "fixtures/rollout/app.py"
            : "fixtures/media/encode.py",
        destination: "service/media.py",
      },
      {
        kind: "json",
        destination: "service/deployment.json",
        value: {
          command: ["gunicorn", "--chdir", "service", "media:application"],
          wheels: [
            {
              filename,
              url: `https://files.pythonhosted.org/packages/${downloadPath}/${filename}`,
              sha256: wheelSha256,
              metadata: artifact,
            },
          ],
        },
      },
      {
        kind: "fixture",
        source: `fixtures/media/pillow-${release}-wheel.json`,
        destination: artifact,
      },
      {
        kind: "git",
        repository: "python-pillow/pillow-wheels",
        revision: fixed
          ? "deb384b86e39beec75bd0b52027faf784fb17625"
          : "b2eed6e689596fefacf5bcbec10193a23ba5df12",
        source: "config.sh",
        destination: wheelRecipe,
      },
    ],
  };
}

const mail392 = "bb325f156d35c28d78a18c7f61c0f2a54a2b7854";
const addressSource = "lib/addressparser/index.js";
const installedAddress = "node_modules/nodemailer/" + addressSource;

const inboxCallerScope =
  "An unauthenticated caller can attempt POST /inbox with raw email they control. " +
  "Assess that request in the configured deployment supplied in the checkout.";

const direct = { routes: { "/inbox": "direct" } };
const queue = { routes: { "/inbox": "queue" } };
const deployment = "service/deploy.json";
const server = "service/server.cjs";
const parse = "service/parse.cjs";
const mail = "lib/mail-parser.js";
const linkVersion = [
  ...excerpts("package.json", '"linkify-it": "5.0.0"'),
  ...excerpts(
    "package-lock.json",
    '"linkify-it": "5.0.0"',
    '"node_modules/linkify-it": {\n            "version": "5.0.0"',
    "linkify-it-5.0.0.tgz",
  ),
];
const directRoute = excerpts(deployment, '"/inbox": "direct"');
const queueRoute = excerpts(deployment, '"/inbox": "queue"');
const parseInbox = excerpts(
  server,
  "if (delivery === 'direct') {\n    const mail = await parse(raw);",
);
const disabledLinks = excerpts(deployment, '"skipTextLinks": true');
const localWorker = excerpts(deployment, '"worker": "local"');
const workerParse = excerpts("service/worker.cjs", "await parse(raw)");
const remoteFetch = excerpts(
  server,
  "fetch(config.workerUrl, { method: 'POST', body: raw })",
);
const externalReceiver = "http://mail-worker:8080/jobs";
const routeGuard = [
  excerpts(deployment, '"routes": {}'),
  excerpts(server, "config.routes[req.url]"),
];
const stripHeaders = excerpts(deployment, '"stripHeaders": true');
const charsetConversion = [
  excerpts(deployment, '"nativeCharset": true'),
  excerpts(parse, "options.Iconv = require('iconv').Iconv"),
  excerpts(mail, "new Iconv(charset, 'UTF-8"),
];
const parseBody = excerpts(parse, "return simpleParser(");
const parserSelection = [
  excerpts(parse, "require('../index.js')"),
  excerpts("lib/simple-parser.js", "new MailParser(options)"),
  skillOnly(excerpts("lib/simple-parser.js", "parser.end(input)")),
];
const directParsing = [
  directRoute,
  skillOnly(excerpts(server, "require('./parse.cjs')")),
  excerpts(server, "config.routes[req.url]"),
  excerpts(server, "for await (const chunk of req) chunks.push(chunk)"),
  skillOnly(excerpts(server, "const raw = Buffer.concat(chunks)")),
  parseInbox,
  parseBody,
  ...parserSelection,
];
const linkText = excerpts(mail, "text.map(part => this.textToHtml(part))");
const matchLinks = excerpts(mail, "linkify.match(str)");
const addressSelection = excerpts(
  mail,
  "require('nodemailer/lib/addressparser')",
);
const parseAddress = excerpts(mail, "addressparser(value)");

function mailFiles(profile, addressRevision) {
  const files = ["server.cjs", "parse.cjs", "worker.cjs"].map((name) => ({
    kind: "fixture",
    source: `fixtures/mail-service/${name}`,
    destination: `service/${name}`,
  }));
  files.push({ kind: "json", destination: deployment, value: profile });
  if (addressRevision) {
    // The downstream parser may be patched while its package metadata remains unchanged.
    files.push(
      nodemailerFile("package.json"),
      nodemailerFile(addressSource, addressRevision),
      ...mimeReceiverSources,
    );
  }
  if (profile.nativeCharset) {
    files.push({
      kind: "json",
      destination: "service/runtime.json",
      value: {
        glibc: { version: "2.39", distribution_patches: [] },
        iconv: {
          version: "3.0.1",
          node_iconv_use_system_libiconv: 1,
          linked_library: "glibc",
        },
      },
    });
  }
  return files;
}

const mailSource = {
  suite: "mailparser",
  repository: "nodemailer/mailparser",
  callerScope: inboxCallerScope,
};
const linkCase = {
  ...mailSource,
  cve: "CVE-2026-48801",
  component: "linkify-it",
  revision: mail392,
  version: "5.0.0",
};
const addressCase = {
  ...mailSource,
  cve: "CVE-2025-14874",
  component: "nodemailer",
  revision: mail390,
  version: "7.0.10",
  identityEvidence: [directRoute, parseInbox, parseAddress],
};
const scaffolder = "plugins/scaffolder-backend/src/";
const selectedSteps = excerpts(
  scaffolder + "service/router.ts",
  "steps: template.spec.steps",
);

export const originalCases = [
  pillowCase(
    "affected-decode",
    pillowAffected,
    "decode",
    "potentially_exploitable",
  ),
  pillowCase("fixed-decode", pillowFixed, "decode", "ruled_out"),
  pillowCase("affected-encode-only", pillowAffected, "encode", "ruled_out"),
  {
    ...linkCase,
    id: "direct-links",
    target: "inbox-direct-linkifier",
    identityEvidence: [directRoute, parseInbox, matchLinks],
    verdict: "potentially_exploitable",
    stage: mailFiles(direct),
    evidenceGroups: [...directParsing, linkText, matchLinks, linkVersion],
  },
  {
    ...linkCase,
    id: "disabled-links",
    target: "inbox-disabled-linkifier",
    identityEvidence: [directRoute, parseInbox, disabledLinks],
    verdict: "ruled_out",
    stage: mailFiles({ ...direct, skipTextLinks: true }),
    evidenceGroups: [
      ...directParsing,
      disabledLinks,
      excerpts(parse, "skipTextLinks: config.skipTextLinks"),
      excerpts(mail, "if (!this.options.skipTextLinks)"),
      linkVersion,
    ],
  },
  {
    ...linkCase,
    id: "queued-links",
    target: "inbox-local-queued-linkifier",
    identityEvidence: [queueRoute, localWorker, workerParse],
    verdict: "potentially_exploitable",
    stage: mailFiles({ ...queue, worker: "local" }),
    evidenceGroups: [
      queueRoute,
      localWorker,
      excerpts(server, "config.routes[req.url]"),
      excerpts(server, "config.worker === 'local'"),
      excerpts(
        server,
        "fork(require.resolve('./worker.cjs'), [], { serialization: 'advanced' })",
      ),
      excerpts(server, "for await (const chunk of req) chunks.push(chunk)"),
      skillOnly(excerpts(server, "const raw = Buffer.concat(chunks)")),
      excerpts(server, "if (worker) {\n    worker.send(raw);"),
      excerpts("service/worker.cjs", "process.on('message'"),
      excerpts("service/worker.cjs", "require('./parse.cjs')"),
      workerParse,
      parseBody,
      ...parserSelection,
      linkText,
      matchLinks,
      linkVersion,
    ],
  },
  {
    ...linkCase,
    id: "unmounted-route",
    target: "inbox-unmounted-route",
    identityEvidence: routeGuard,
    verdict: "ruled_out",
    // The route guard excludes this caller before any dependency copy is used.
    commandVersion: [null, "5.0.0"],
    stage: mailFiles({ routes: {} }),
    evidenceGroups: [
      ...routeGuard,
      excerpts(
        server,
        "if (req.method !== 'POST' || !delivery) {\n    res.writeHead(404).end();\n    return;",
      ),
    ],
  },
  {
    ...linkCase,
    id: "external-worker",
    target: "inbox-external-worker",
    identityEvidence: [
      queueRoute,
      excerpts(deployment, `"workerUrl": "${externalReceiver}"`),
      remoteFetch,
    ],
    needsDecidingGap: true,
    verdict: "unknown",
    // The selected HTTP receiver is absent; the local 5.0.0 is not its version.
    commandVersion: null,
    stage: mailFiles({
      ...queue,
      worker: "external",
      workerUrl: externalReceiver,
    }),
    evidenceGroups: [
      queueRoute,
      excerpts(deployment, '"worker": "external"'),
      skillOnly(excerpts(deployment, '"workerUrl":')),
      excerpts(server, "config.worker === 'local'"),
      remoteFetch,
    ],
  },
  {
    ...addressCase,
    id: "address-groups",
    target: "inbox-installed-address-parser",
    verdict: "potentially_exploitable",
    stage: mailFiles(direct, nodemailer7010),
    evidenceGroups: [
      ...directParsing,
      addressSelection,
      parseAddress,
      installedNodemailerVersion,
      excerpts(installedAddress, "addressparser(data.group.join(','))"),
    ],
  },
  {
    ...addressCase,
    id: "address-backport",
    target: "inbox-backported-address-parser",
    verdict: "ruled_out",
    stage: mailFiles(direct, nodemailer7011),
    evidenceGroups: [
      ...directParsing,
      addressSelection,
      parseAddress,
      installedNodemailerVersion,
      excerpts(installedAddress, "const MAX_NESTED_GROUP_DEPTH = 50"),
      skillOnly(
        excerpts(installedAddress, "let depth = options._depth || 0"),
        excerpts(installedAddress, "_handleAddress(address, depth)"),
      ),
      excerpts(
        installedAddress,
        "addressparser(data.group.join(','), { _depth: depth + 1 })",
      ),
      excerpts(
        installedAddress,
        "if (depth > MAX_NESTED_GROUP_DEPTH) {\n        return [];",
      ),
    ],
  },
  {
    ...addressCase,
    id: "stripped-headers",
    target: "inbox-filtered-address-parser",
    identityEvidence: [directRoute, stripHeaders, parseAddress],
    verdict: "ruled_out",
    stage: mailFiles({ ...direct, stripHeaders: true }, nodemailer7010),
    evidenceGroups: [
      ...directParsing,
      stripHeaders,
      excerpts(
        parse,
        "simpleParser(config.stripHeaders ? replaceHeaders(raw) : raw, options)",
      ),
      excerpts(parse, "From: sender@example.invalid"),
      excerpts(parse, "To: archive@example.invalid"),
      excerpts(parse, "Content-Type: text/plain; charset=utf-8"),
      excerpts(parse, "  '',\n  '',\n].join('\\r\\n')"),
      skillOnly(excerpts(parse, "const lf = raw.indexOf(0x0a, start)")),
      excerpts(
        parse,
        "lf === start || (lf === start + 1 && raw[start] === 0x0d)",
      ),
      excerpts(parse, "Buffer.concat([envelope, raw.subarray(lf + 1)])"),
      skillOnly(
        excerpts(parse, "throw new Error('Missing end of message headers')"),
      ),
      addressSelection,
      parseAddress,
      installedNodemailerVersion,
    ],
  },
  {
    ...mailSource,
    id: "native-charset",
    target: "inbox-native-charset-conversion",
    identityEvidence: charsetConversion.slice(0, 2),
    cve: "CVE-2024-2961",
    component: "glibc",
    revision: mail392,
    verdict: "ruled_out",
    version: "2.39",
    // The runtime declaration is not bound to a selected native implementation.
    commandVersion: null,
    stage: mailFiles({ ...direct, nativeCharset: true }),
    evidenceGroups: charsetConversion,
  },
  {
    id: "task-parameter",
    largeRepo: true,
    target: "starter-template-task",
    identityEvidence: [
      excerpts("portal/app-config.yaml", "target: /app/catalog/template.yaml"),
      excerpts("portal/template.yaml", "name: example-nodejs-template"),
      selectedSteps,
    ],
    cve: "CVE-2023-37466",
    component: "vm2",
    suite: "backstage",
    repository: "backstage/backstage",
    revision: "99d7a6f42d71e86578c89c0669a3d962088ed8ae",
    verdict: "ruled_out",
    version: "3.9.19",
    commandCallSite: {
      path: "plugins/scaffolder-backend/src/lib/templating/SecureTemplater.ts",
      line: 170,
    },
    stage: [
      "compose.yaml",
      "app-config.yaml",
      "portal.conf",
      "template.yaml",
    ].map((name) => ({
      kind: "fixture",
      source: `fixtures/backstage/${name}`,
      destination: `portal/${name}`,
    })),
    callerScope:
      "An authenticated user may submit a normal POST /v2/tasks request for the starter app's example-nodejs-template " +
      "and controls the name parameter. The user cannot choose the repository destination or edit the registered template or its skeleton. " +
      "Assess server-side task execution in the configured deployment supplied in the checkout. " +
      "Assume the backend and its dependencies are built from this checkout and its lockfile. " +
      "Report the resolved vm2 version.",
    evidenceGroups: [
      excerpts(
        "yarn.lock",
        "vm2@npm:3.9.19",
        '"vm2@npm:^3.9.18":\n  version: 3.9.19',
      ),
      skillOnly(
        ...[
          "catalog:",
          "  readonly: true",
          "  locations:",
          "    - type: file",
          "      target: /app/catalog/template.yaml",
          "      rules:",
          "        - allow: [Template]",
        ].map((line) => excerpts("portal/app-config.yaml", line)),
      ),
      excerpts("portal/compose.yaml", "/app/catalog/template.yaml:ro"),
      excerpts("portal/compose.yaml", "/app/catalog/content:ro"),
      skillOnly(
        excerpts(
          "portal/compose.yaml",
          "dockerfile: packages/backend/Dockerfile",
        ),
        excerpts(
          "portal/compose.yaml",
          "--config, app-config.yaml, --config, portal.yaml",
        ),
        excerpts(
          "packages/backend/package.json",
          '"@backstage/plugin-scaffolder-backend": "workspace:^"',
        ),
        excerpts(
          "packages/backend/Dockerfile",
          "yarn.lock package.json packages/backend/dist/skeleton.tar.gz",
        ),
        excerpts(
          "packages/backend/Dockerfile",
          "packages/backend/dist/bundle.tar.gz",
        ),
        excerpts("portal/template.yaml", "additionalProperties: false"),
      ),
      excerpts("portal/template.yaml", "parameters.name"),
      excerpts("portal/template.yaml", "url: ./content"),
      skillOnly(
        ...["catalog-info.yaml", "index.js", "package.json"].map((name) => [
          {
            path:
              "packages/create-app/templates/default-app/examples/template/content/" +
              name,
            contains: "${{ values.name",
            completeFile: true,
          },
        ]),
      ),
      excerpts(scaffolder + "service/router.ts", "values = req.body.values"),
      skillOnly(
        excerpts(
          scaffolder + "service/router.ts",
          "validate(values, parameters)",
        ),
      ),
      excerpts(scaffolder + "service/router.ts", "parameters: values"),
      selectedSteps,
      excerpts(
        scaffolder + "scaffolder/tasks/NunjucksWorkflowRunner.ts",
        "parameters: task.spec.parameters",
      ),
      excerpts(
        scaffolder + "scaffolder/tasks/NunjucksWorkflowRunner.ts",
        "renderTemplate(value, context)",
        "renderTemplate(wrappedDumped, context)",
      ),
      excerpts(
        scaffolder + "scaffolder/actions/builtin/fetch/template.ts",
        "renderTemplate(inputFileContents, context)",
      ),
      excerpts(
        scaffolder + "scaffolder/actions/builtin/fetch/template.ts",
        "'values']: values",
        "ctx.input.values",
      ),
      excerpts(
        scaffolder + "lib/templating/SecureTemplater.ts",
        "env.renderString(str, JSON.parse(values))",
      ),
      excerpts(
        scaffolder + "lib/templating/SecureTemplater.ts",
        "vm.setGlobal('templateValues', JSON.stringify(values))",
      ),
      excerpts(
        scaffolder + "lib/templating/SecureTemplater.ts",
        "vm.run(`render(templateStr, templateValues)`)",
      ),
    ],
  },
  ...sanitizerCases,
  ...serviceCases,
  ...rolloutCases,
  ...zipCases,
].map(originalRubric);

export const cases = [
  ...originalCases,
  ...copySelectionCases,
  ...applicationCases,
];
