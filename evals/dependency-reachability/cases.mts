import type { EvidenceGroup, Verdict } from "./grade.mts";
import { sanitizerCases } from "./sanitizer-cases.mts";
import { serviceCases } from "./service-cases.mts";
import { rolloutCases } from "./rollout-cases.mts";
import { zipCases } from "./zip-cases.mts";

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
  suite: Suite;
  repository: Repository;
  revision: string;
  question: string;
  verdict: Verdict;
  version: string;
  evidenceGroups: readonly EvidenceGroup[];
  stage: readonly StageFile[];
}

// Each group accepts any of its source excerpts. All groups are required.
function excerpts(path: string, ...markers: string[]): EvidenceGroup {
  return markers.map((contains) => ({ path, contains }));
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
  "The only image operation is Image.frombytes('RGB', (64, 64), pixels).save(output, format='WEBP', lossless=True). " +
  "No encoded image is accepted or opened.";

function pillowCase(
  id: string,
  revision: string,
  operation: string,
  verdict: Verdict,
): ReachabilityCase {
  const fixed = revision === pillowFixed;
  const version = fixed ? "1.3.2" : "1.3.1";
  const versionSources = [
    ...excerpts(wheelRecipe, `LIBWEBP_VERSION=${version}`),
    ...(fixed
      ? excerpts(
          "docs/releasenotes/10.0.1.rst",
          "wheels to include libwebp 1.3.2",
        )
      : []),
  ];
  return {
    id,
    suite: "pillow",
    repository: "python-pillow/Pillow",
    revision,
    verdict,
    version,
    question:
      "Assess CVE-2023-4863 in libwebp for this Pillow checkout. The flaw is a heap overflow " +
      "when decoding Huffman tables in a crafted lossless WebP. Upstream fixed it in 1.3.2. Assume the official Linux " +
      "CPython 3.12 x86_64 manylinux_2_28 wheel built for this release. Its public wheel build " +
      `recipe is staged under pillow-wheels/. ${operation} Use the checkout to trace this specific ` +
      "operation through the Python and native code and establish the bundled libwebp version.",
    evidenceGroups:
      operation === decode
        ? [
            versionSources,
            excerpts(
              webpPlugin,
              "_webp.WebPAnimDecoder(self.fp.read())",
              "self._decoder.get_next()",
            ),
            excerpts(
              webpNative,
              "WebPAnimDecoderGetNext(decp->dec",
              "WebPAnimDecoderNew(&(decp->data)",
            ),
          ]
        : [
            versionSources,
            excerpts(
              webpPlugin,
              "data = _webp.WebPEncode(",
              "register_save(WebPImageFile.format, _save)",
            ),
            excerpts(webpNative, "WebPEncode(&config, &pic)"),
          ],
    stage: [
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
const mail390 = "3e1e0291d7757501d334d19fe6553a78b45cc1eb";
const nodemailer7010 = "4175e4baf92ffc4e20791a11fc0886025228a2ac";
const nodemailer7011 = "3d17dbec49ab3e3f0e13e62871e5534be5b99994";
const addressSource = "lib/addressparser/index.js";
const installedAddress = "node_modules/nodemailer/" + addressSource;

const surface =
  "Assess the deployed mail service in service/ for an unauthenticated caller who controls " +
  "the raw email body of POST /inbox. Scope the verdict to requests through this endpoint and give " +
  "evidence for the decisive step in the path. Report the dependency version in the supplied image. " +
  "If later processing occurs in another image, distinguish what is known about that worker.";
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
const addressVersion = [
  ...excerpts("package.json", '"nodemailer": "7.0.10"'),
  ...excerpts(
    "package-lock.json",
    '"nodemailer": "7.0.10"',
    "nodemailer-7.0.10.tgz",
    '"node_modules/nodemailer": {\n            "version": "7.0.10"',
  ),
  ...excerpts("node_modules/nodemailer/package.json", '"version": "7.0.10"'),
];
const directRoute = excerpts(deployment, '"/inbox": "direct"');
const parseBody = excerpts(
  parse,
  "simpleParser(",
  "skipTextLinks: config.skipTextLinks",
);
const matchLinks = excerpts(mail, "linkify.match(str)");
const parseAddress = excerpts(
  mail,
  "addressparser(value)",
  "case 'from':",
  "case 'to':",
);

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
    for (const [source, revision] of [
      ["package.json", nodemailer7010],
      [addressSource, addressRevision],
    ] as const) {
      files.push({
        kind: "git",
        repository: "nodemailer/nodemailer",
        revision,
        source,
        destination: `node_modules/nodemailer/${source}`,
      });
    }
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
  revision: mail392,
  question: links,
  version: "5.0.0",
};
const addressCase = {
  ...mailSource,
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
  pillowCase("affected-decode", pillowAffected, decode, "exploitable"),
  pillowCase("fixed-decode", pillowFixed, decode, "ruled_out"),
  pillowCase("affected-encode-only", pillowAffected, encode, "ruled_out"),
  {
    ...linkCase,
    id: "direct-links",
    verdict: "exploitable",
    stage: mailFiles(direct),
    evidenceGroups: [directRoute, parseBody, matchLinks, linkVersion],
  },
  {
    ...linkCase,
    id: "disabled-links",
    verdict: "ruled_out",
    stage: mailFiles({ ...direct, skipTextLinks: true }),
    evidenceGroups: [
      excerpts(deployment, '"skipTextLinks": true'),
      excerpts(parse, "skipTextLinks: config.skipTextLinks"),
      excerpts(mail, "if (!this.options.skipTextLinks)"),
      linkVersion,
    ],
  },
  {
    ...linkCase,
    id: "queued-links",
    verdict: "exploitable",
    stage: mailFiles({ ...queue, worker: "local" }),
    evidenceGroups: [
      excerpts(deployment, '"/inbox": "queue"', '"worker": "local"'),
      excerpts(
        server,
        "worker.send(raw)",
        "fork(require.resolve('./worker.cjs')",
      ),
      excerpts(
        "service/worker.cjs",
        "process.on('message'",
        "await parse(raw)",
      ),
      parseBody,
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
      excerpts(
        server,
        "!delivery",
        "res.writeHead(404)",
        "config.routes[req.url]",
      ),
      linkVersion,
    ],
  },
  {
    ...linkCase,
    id: "external-worker",
    verdict: "unknown",
    stage: mailFiles({
      ...queue,
      worker: "external",
      workerUrl: "http://mail-worker:8080/jobs",
    }),
    evidenceGroups: [
      excerpts(deployment, '"worker": "external"', '"workerUrl":'),
      excerpts(server, "fetch(config.workerUrl"),
      linkVersion,
    ],
  },
  {
    ...addressCase,
    id: "address-groups",
    verdict: "exploitable",
    stage: mailFiles(direct, nodemailer7010),
    evidenceGroups: [
      directRoute,
      parseBody,
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
      addressVersion,
      excerpts(installedAddress, "depth > MAX_NESTED_GROUP_DEPTH"),
    ],
  },
  {
    ...addressCase,
    id: "stripped-headers",
    verdict: "ruled_out",
    stage: mailFiles({ ...direct, stripHeaders: true }, nodemailer7010),
    evidenceGroups: [
      excerpts(deployment, '"stripHeaders": true'),
      excerpts(parse, "replaceHeaders(raw) : raw"),
      excerpts(
        parse,
        "From: sender@example.invalid",
        "To: archive@example.invalid",
        "Buffer.concat([envelope, raw.subarray(",
      ),
      addressVersion,
    ],
  },
  {
    ...mailSource,
    id: "native-charset",
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
    suite: "backstage",
    repository: "backstage/backstage",
    revision: "99d7a6f42d71e86578c89c0669a3d962088ed8ae",
    verdict: "ruled_out",
    version: "3.9.19",
    stage: [],
    question:
      "Assess CVE-2023-37466 in vm2 for the starter app's example-nodejs-template. " +
      "Assume the backend and its dependencies are built from this checkout and its lockfile. " +
      "An authenticated user may submit a normal POST /v2/tasks request and controls the name parameter. " +
      "The repository destination is fixed. The user cannot edit the registered template or its skeleton. " +
      "Scope this to server-side task execution. The advisory describes a sandbox escape in vm2 through " +
      "3.9.19 that requires attacker-controlled JavaScript execution inside the VM. Can this requester " +
      "meet that precondition? Trace the name from submission through the background task and file " +
      "rendering. Report the resolved vm2 version.",
    evidenceGroups: [
      excerpts(
        "yarn.lock",
        "vm2@npm:3.9.19",
        '"vm2@npm:^3.9.18":\n  version: 3.9.19',
      ),
      excerpts(
        "packages/create-app/templates/default-app/examples/template/template.yaml",
        "parameters.name",
        "url: ./content",
      ),
      excerpts(
        scaffolder + "service/router.ts",
        "values = req.body.values",
        "parameters: values",
        "steps: template.spec.steps",
        "await taskBroker.dispatch",
      ),
      excerpts(
        scaffolder + "scaffolder/tasks/NunjucksWorkflowRunner.ts",
        "parameters: task.spec.parameters",
        "this.render(\n            step.input,",
        "renderTemplate(value, context)",
        "renderTemplate(wrappedDumped, context)",
      ),
      excerpts(
        scaffolder + "scaffolder/actions/builtin/fetch/template.ts",
        "renderTemplate(inputFileContents, context)",
        "'values']: values",
        "ctx.input.values",
      ),
      excerpts(
        scaffolder + "lib/templating/SecureTemplater.ts",
        "env.renderString(str, JSON.parse(values))",
        "vm.setGlobal('templateValues'",
        "vm.run(`render(templateStr, templateValues)`)",
      ),
    ],
  },
  ...challengeCases,
];
