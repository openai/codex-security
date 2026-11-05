import type { EvidenceGroup, Verdict } from "./grade.mts";
import {
  excerpts,
  installedNodemailerVersion,
  mail390,
  nodemailer7010,
  nodemailerFile,
} from "./case-data.mts";
import { sanitizerCases } from "./sanitizer-cases.mts";
import { serviceCases } from "./service-cases.mts";
import { rolloutCases } from "./rollout-cases.mts";
import { zipCases } from "./zip-cases.mts";
import { mimeReceiverSources } from "./receiver-data.mts";

export type CommandVerdict = Verdict | "potentially_exploitable";
export type Suite = "pillow" | "mailparser" | "backstage";
export type Repository =
  | "alpinelinux/aports"
  | "python-pillow/Pillow"
  | "python-pillow/pillow-wheels"
  | "nodemailer/mailparser"
  | "nodemailer/nodemailer"
  | "backstage/backstage";

export type StageFile =
  | {
      kind: "git";
      repository: Repository;
      revision: string;
      source: string;
      destination: string;
    }
  | { kind: "fixture"; source: string; destination: string }
  | { kind: "json"; value: unknown; destination: string };

export interface ReachabilityCase {
  id: string;
  cve: string;
  component: string;
  suite: Suite;
  repository: Repository;
  revision: string;
  question: string;
  verdict: CommandVerdict;
  version: string;
  // CLI-only copy override; null explicitly requires an unresolved version.
  commandVersion?: string | null;
  versionAliases?: readonly string[];
  evidenceGroups: readonly EvidenceGroup[];
  stage: readonly StageFile[];
}

const pillowAffected = "6e28ed1f36d0eb74053af54e1eddc9c29db698cd";
const pillowFixed = "e34d346f10c0b1c814661e662a3e0c1ef084cf1c";
const webpPlugin = "src/PIL/WebPImagePlugin.py";
const webpNative = "src/_webp.c";
const wheelRecipe = "pillow-wheels/config.sh";
const decode =
  "An attacker supplies the bytes in request_body to Image.open(BytesIO(request_body)).load().";
const encode =
  "An attacker controls raw RGB pixel values in a validated, fixed-length 64x64 buffer. " +
  "The only image operation is Image.frombytes('RGB', (64, 64), pixels).save(output, format='WEBP', lossless=True).";

function pillowCase(
  id: string,
  revision: string,
  operation: string,
  verdict: CommandVerdict,
): ReachabilityCase {
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
  const versionEvidence = [
    excerpts("service/deployment.json", wheelSha256),
    excerpts(artifact, wheelSha256),
    excerpts(artifact, `"version": "${version}"`),
    excerpts(artifact, `"neededLibrary": "${bundledLibrary}"`),
  ];
  return {
    id,
    cve: "CVE-2023-4863",
    component: "libwebp",
    suite: "pillow",
    repository: "python-pillow/Pillow",
    revision,
    verdict,
    version,
    question:
      "Assess CVE-2023-4863 in libwebp for this Pillow checkout. The flaw is a heap overflow " +
      "when decoding Huffman tables in a crafted lossless WebP. Upstream fixed it in 1.3.2. Assume the official Linux " +
      `CPython 3.12 x86_64 manylinux_2_28 wheel built for this release. ${operation} ` +
      "Can this caller trigger the advisory? Report the bundled libwebp version.",
    evidenceGroups:
      operation === decode
        ? [
            excerpts(
              "service/media.py",
              'Image.open(BytesIO(environ["wsgi.input"].read()))',
            ),
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
            excerpts(
              "service/media.py",
              'Image.frombytes("RGB", (64, 64), pixels)',
            ),
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
          operation === decode
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
const nodemailer7011 = "3d17dbec49ab3e3f0e13e62871e5534be5b99994";
const addressSource = "lib/addressparser/index.js";
const installedAddress = "node_modules/nodemailer/" + addressSource;

const surface =
  "An unauthenticated caller controls the raw email submitted to POST /inbox. " +
  "Can this caller trigger the advisory through that endpoint as deployed? " +
  "Report the dependency version in the supplied image.";
const links =
  surface +
  " The finding is CVE-2026-48801 in linkify-it. In versions through 5.0.0, " +
  "match() takes quadratic time on text containing many fuzzy links or email addresses.";
const addresses =
  surface +
  " The finding is CVE-2025-14874 in Nodemailer 3.0.0 through 7.0.10. " +
  "Its address parser can exhaust the stack by recursing without a depth limit on nested address " +
  "groups in a mail header. Upstream added a depth limit in 7.0.11.";
const charset =
  surface +
  " The finding is CVE-2024-2961 in glibc iconv. In unpatched glibc versions " +
  "through 2.39, certain conversions to ISO-2022-CN-EXT can overflow the output buffer.";

type MailProfile = {
  routes: Record<string, "direct" | "queue">;
  skipTextLinks?: boolean;
  stripHeaders?: boolean;
  worker?: "local" | "external";
  workerUrl?: string;
  nativeCharset?: boolean;
};
const direct: MailProfile = { routes: { "/inbox": "direct" } };
const queue: MailProfile = { routes: { "/inbox": "queue" } };
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
const addressVersion = installedNodemailerVersion;
const directRoute = excerpts(deployment, '"/inbox": "direct"');
const parseBody = excerpts(parse, "return simpleParser(");
const parserSelection = [
  excerpts(parse, "require('../index.js')"),
  excerpts("lib/simple-parser.js", "new MailParser(options)"),
  excerpts("lib/simple-parser.js", "parser.end(input)"),
];
const directParsing = [
  directRoute,
  excerpts(server, "require('./parse.cjs')"),
  excerpts(server, "config.routes[req.url]"),
  excerpts(server, "for await (const chunk of req) chunks.push(chunk)"),
  excerpts(server, "const raw = Buffer.concat(chunks)"),
  excerpts(
    server,
    "if (delivery === 'direct') {\n    const mail = await parse(raw);",
  ),
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

function mailFiles(
  profile: MailProfile,
  addressRevision?: string,
): StageFile[] {
  const files: StageFile[] = ["server.cjs", "parse.cjs", "worker.cjs"].map(
    (name) => ({
      kind: "fixture",
      source: `fixtures/mail-service/${name}`,
      destination: `service/${name}`,
    }),
  );
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
} as const;
const linkCase = {
  ...mailSource,
  cve: "CVE-2026-48801",
  component: "linkify-it",
  revision: mail392,
  question: links,
  version: "5.0.0",
};
const addressCase = {
  ...mailSource,
  cve: "CVE-2025-14874",
  component: "nodemailer",
  revision: mail390,
  question: addresses,
  version: "7.0.10",
};
const scaffolder = "plugins/scaffolder-backend/src/";

export const challengeCases: readonly ReachabilityCase[] = [
  ...sanitizerCases,
  ...serviceCases,
  ...rolloutCases,
  ...zipCases,
];

export const cases: readonly ReachabilityCase[] = [
  pillowCase(
    "affected-decode",
    pillowAffected,
    decode,
    "potentially_exploitable",
  ),
  pillowCase("fixed-decode", pillowFixed, decode, "ruled_out"),
  pillowCase("affected-encode-only", pillowAffected, encode, "ruled_out"),
  {
    ...linkCase,
    id: "direct-links",
    verdict: "potentially_exploitable",
    stage: mailFiles(direct),
    evidenceGroups: [...directParsing, linkText, matchLinks, linkVersion],
  },
  {
    ...linkCase,
    id: "disabled-links",
    verdict: "ruled_out",
    stage: mailFiles({ ...direct, skipTextLinks: true }),
    evidenceGroups: [
      ...directParsing,
      excerpts(deployment, '"skipTextLinks": true'),
      excerpts(parse, "skipTextLinks: config.skipTextLinks"),
      excerpts(mail, "if (!this.options.skipTextLinks)"),
      linkVersion,
    ],
  },
  {
    ...linkCase,
    id: "queued-links",
    verdict: "potentially_exploitable",
    stage: mailFiles({ ...queue, worker: "local" }),
    evidenceGroups: [
      excerpts(deployment, '"/inbox": "queue"'),
      excerpts(deployment, '"worker": "local"'),
      excerpts(server, "config.routes[req.url]"),
      excerpts(server, "config.worker === 'local'"),
      excerpts(
        server,
        "fork(require.resolve('./worker.cjs'), [], { serialization: 'advanced' })",
      ),
      excerpts(server, "for await (const chunk of req) chunks.push(chunk)"),
      excerpts(server, "const raw = Buffer.concat(chunks)"),
      excerpts(server, "if (worker) {\n    worker.send(raw);"),
      excerpts("service/worker.cjs", "process.on('message'"),
      excerpts("service/worker.cjs", "require('./parse.cjs')"),
      excerpts("service/worker.cjs", "await parse(raw)"),
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
    verdict: "ruled_out",
    stage: mailFiles({ routes: {} }),
    evidenceGroups: [
      excerpts(deployment, '"routes": {}'),
      excerpts(server, "config.routes[req.url]"),
      excerpts(
        server,
        "if (req.method !== 'POST' || !delivery) {\n    res.writeHead(404).end();\n    return;",
      ),
      linkVersion,
    ],
  },
  {
    ...linkCase,
    id: "external-worker",
    verdict: "unknown",
    // The selected HTTP receiver is absent; the local 5.0.0 is not its version.
    commandVersion: null,
    stage: mailFiles({
      ...queue,
      worker: "external",
      workerUrl: "http://mail-worker:8080/jobs",
    }),
    evidenceGroups: [
      excerpts(deployment, '"/inbox": "queue"'),
      excerpts(deployment, '"worker": "external"'),
      excerpts(deployment, '"workerUrl":'),
      excerpts(server, "config.worker === 'local'"),
      excerpts(
        server,
        "fetch(config.workerUrl, { method: 'POST', body: raw })",
      ),
      excerpts("service/worker.cjs", "process.on('message'"),
    ],
  },
  {
    ...addressCase,
    id: "address-groups",
    verdict: "potentially_exploitable",
    stage: mailFiles(direct, nodemailer7010),
    evidenceGroups: [
      ...directParsing,
      addressSelection,
      parseAddress,
      addressVersion,
      excerpts(installedAddress, "addressparser(data.group.join(','))"),
    ],
  },
  {
    ...addressCase,
    id: "address-backport",
    verdict: "ruled_out",
    stage: mailFiles(direct, nodemailer7011),
    evidenceGroups: [
      ...directParsing,
      addressSelection,
      parseAddress,
      addressVersion,
      excerpts(installedAddress, "const MAX_NESTED_GROUP_DEPTH = 50"),
      excerpts(installedAddress, "let depth = options._depth || 0"),
      excerpts(installedAddress, "_handleAddress(address, depth)"),
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
    verdict: "ruled_out",
    stage: mailFiles({ ...direct, stripHeaders: true }, nodemailer7010),
    evidenceGroups: [
      ...directParsing,
      excerpts(deployment, '"stripHeaders": true'),
      excerpts(
        parse,
        "simpleParser(config.stripHeaders ? replaceHeaders(raw) : raw, options)",
      ),
      excerpts(parse, "From: sender@example.invalid"),
      excerpts(parse, "To: archive@example.invalid"),
      excerpts(parse, "Content-Type: text/plain; charset=utf-8"),
      excerpts(parse, "  '',\n  '',\n].join('\\r\\n')"),
      excerpts(parse, "const lf = raw.indexOf(0x0a, start)"),
      excerpts(
        parse,
        "lf === start || (lf === start + 1 && raw[start] === 0x0d)",
      ),
      excerpts(parse, "Buffer.concat([envelope, raw.subarray(lf + 1)])"),
      excerpts(parse, "throw new Error('Missing end of message headers')"),
      addressSelection,
      parseAddress,
      addressVersion,
    ],
  },
  {
    ...mailSource,
    id: "native-charset",
    cve: "CVE-2024-2961",
    component: "glibc",
    revision: mail392,
    question: charset,
    verdict: "ruled_out",
    version: "2.39",
    stage: mailFiles({ ...direct, nativeCharset: true }),
    evidenceGroups: [
      excerpts(deployment, '"nativeCharset": true'),
      excerpts(parse, "options.Iconv = require('iconv').Iconv"),
      excerpts(mail, "new Iconv(charset, 'UTF-8"),
      excerpts("service/runtime.json", '"version": "2.39"'),
    ],
  },
  {
    id: "task-parameter",
    cve: "CVE-2023-37466",
    component: "vm2",
    suite: "backstage",
    repository: "backstage/backstage",
    revision: "99d7a6f42d71e86578c89c0669a3d962088ed8ae",
    verdict: "ruled_out",
    version: "3.9.19",
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
    question:
      "Assess CVE-2023-37466 in vm2 for the starter app's example-nodejs-template. " +
      "Assume the backend and its dependencies are built from this checkout and its lockfile. " +
      "An authenticated user may submit a normal POST /v2/tasks request and controls the name parameter. " +
      "The repository destination is fixed. The user cannot edit the registered template or its skeleton. " +
      "Scope this to server-side task execution. The advisory describes a sandbox escape in vm2 through " +
      "3.9.19 that requires attacker-controlled JavaScript execution inside the VM. Can this requester " +
      "meet that precondition? Report the resolved vm2 version.",
    evidenceGroups: [
      excerpts(
        "yarn.lock",
        "vm2@npm:3.9.19",
        '"vm2@npm:^3.9.18":\n  version: 3.9.19',
      ),
      excerpts("portal/portal.conf", "location = /api/scaffolder/v2/tasks"),
      excerpts("portal/portal.conf", "limit_except POST { deny all; }"),
      excerpts("portal/portal.conf", "location / { return 404; }"),
      [
        {
          path: "portal/app-config.yaml",
          contains: "readonly: true",
          completeFile: true,
        },
      ],
      excerpts("portal/compose.yaml", "/app/catalog/template.yaml:ro"),
      excerpts("portal/compose.yaml", "/app/catalog/content:ro"),
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
      excerpts("app-config.yaml", "connection: ':memory:'"),
      excerpts("portal/template.yaml", "additionalProperties: false"),
      excerpts("portal/template.yaml", "parameters.name"),
      excerpts("portal/template.yaml", "url: ./content"),
      ...["catalog-info.yaml", "index.js", "package.json"].map((name) => [
        {
          path:
            "packages/create-app/templates/default-app/examples/template/content/" +
            name,
          contains: "${{ values.name",
          completeFile: true,
        },
      ]),
      excerpts(scaffolder + "service/router.ts", "values = req.body.values"),
      excerpts(
        scaffolder + "service/router.ts",
        "validate(values, parameters)",
      ),
      excerpts(scaffolder + "service/router.ts", "parameters: values"),
      excerpts(scaffolder + "service/router.ts", "steps: template.spec.steps"),
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
        "vm.setGlobal('templateValues'",
      ),
      excerpts(
        scaffolder + "lib/templating/SecureTemplater.ts",
        "vm.run(`render(templateStr, templateValues)`)",
      ),
    ],
  },
  ...challengeCases,
];
