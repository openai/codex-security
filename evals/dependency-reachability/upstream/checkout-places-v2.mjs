import { excerpts } from "./case-data.mjs";

const mailConfig = "service/deploy.json";
const mailParser = "lib/mail-parser.js";
const directInbox = excerpts(mailConfig, '"/inbox": "direct"');
const queuedInbox = excerpts(mailConfig, '"/inbox": "queue"');
const parseInbox = excerpts("service/server.cjs", "await parse(raw)");
const addressParser = excerpts(mailParser, "addressparser(value)");
const mountedAddressParser = [directInbox, parseInbox, addressParser];

function wheelIdentity(release, operation) {
  const digest =
    release === "10.0.0"
      ? "d72e2ecc68a942e8cf9739619b7f408cc7b272b279b56b2c83c6123fcfa5cdff"
      : "4ce90f8a24e1c15465048959f1e94309dfef93af272633e8f37361b824532e91";
  return [
    excerpts("service/deployment.json", digest),
    excerpts("service/wheel-artifact.json", digest),
    excerpts("service/media.py", operation),
  ];
}

function capturedWorker(port) {
  const [pid, inode] = port === 9100 ? [431, 3741] : [692, 8930];
  return [
    excerpts("edge/caddy.json", `127.0.0.1:${port}`),
    excerpts("incident/workers.txt", `127.0.0.1:${port}`),
    excerpts("incident/workers.txt", `pid=${pid},fd=3`),
    excerpts("incident/workers.txt", `# /proc/${pid}/maps`),
    excerpts("incident/workers.txt", `08:01 ${inode} /usr/lib/libwebp.so`),
  ];
}

function zipWorker(catalogSelection) {
  return [
    excerpts("bundle/catalog.py", catalogSelection),
    excerpts("bundle/submit_bundle.py", "target=import_next, args=(jobs,)"),
    excerpts("bundle/index-mail.cjs", "simpleParser(input)"),
  ];
}

const imageDecode = 'Image.open(BytesIO(environ["wsgi.input"].read()))';
const configuredArchiveWorker = [
  excerpts("deploy/compose.yaml", "command: python3 -m archive.importer"),
  excerpts("deploy/compose.yaml", "QUEUE_NAME: ${STACK_NAME:?}-imports"),
  excerpts("archive/index-mail.cjs", "simpleParser(input)"),
];

// Frozen identities for the original 23 targets. The fixture's expected source
// conditions and version still apply. The published wheel evidence binds _webp;
// it does not bind a separately loaded TIFF codec or establish a second target.
export const checkoutPlacesV2 = {
  "affected-decode": {
    id: "thumbnail-webp-decoder",
    verdict: "potentially_exploitable",
    identityEvidence: wheelIdentity("10.0.0", imageDecode),
  },
  "fixed-decode": {
    id: "thumbnail-webp-decoder",
    verdict: "ruled_out",
    identityEvidence: wheelIdentity("10.0.1", imageDecode),
  },
  "affected-encode-only": {
    id: "thumbnail-webp-encoder",
    verdict: "ruled_out",
    identityEvidence: wheelIdentity(
      "10.0.0",
      'Image.frombytes("RGB", (64, 64), pixels)',
    ),
  },
  "direct-links": {
    id: "inbox-direct-linkifier",
    verdict: "potentially_exploitable",
    identityEvidence: [
      directInbox,
      parseInbox,
      excerpts(mailParser, "linkify.match(str)"),
    ],
  },
  "disabled-links": {
    id: "inbox-disabled-linkifier",
    verdict: "ruled_out",
    identityEvidence: [
      directInbox,
      parseInbox,
      excerpts(mailConfig, '"skipTextLinks": true'),
    ],
  },
  "queued-links": {
    id: "inbox-local-queued-linkifier",
    verdict: "potentially_exploitable",
    identityEvidence: [
      queuedInbox,
      excerpts(mailConfig, '"worker": "local"'),
      excerpts("service/worker.cjs", "await parse(raw)"),
    ],
  },
  "unmounted-route": {
    id: "inbox-unmounted-route",
    verdict: "ruled_out",
    identityEvidence: [
      excerpts(mailConfig, '"routes": {}'),
      excerpts("service/server.cjs", "config.routes[req.url]"),
    ],
  },
  "external-worker": {
    id: "inbox-external-worker",
    verdict: "unknown",
    identityEvidence: [
      queuedInbox,
      excerpts(mailConfig, '"workerUrl": "http://mail-worker:8080/jobs"'),
      excerpts("service/server.cjs", "fetch(config.workerUrl"),
    ],
    needsDecidingGap: true,
    unsupportedExpectation:
      "The checked-out code identifies the selected external receiver but does not contain its installed dependency or implementation.",
  },
  "address-groups": {
    id: "inbox-installed-address-parser",
    verdict: "potentially_exploitable",
    identityEvidence: mountedAddressParser,
  },
  "address-backport": {
    id: "inbox-backported-address-parser",
    verdict: "ruled_out",
    identityEvidence: mountedAddressParser,
  },
  "stripped-headers": {
    id: "inbox-filtered-address-parser",
    verdict: "ruled_out",
    identityEvidence: [
      directInbox,
      excerpts(mailConfig, '"stripHeaders": true'),
      addressParser,
    ],
  },
  "native-charset": {
    id: "inbox-native-charset-conversion",
    verdict: "ruled_out",
    identityEvidence: [
      excerpts(mailConfig, '"nativeCharset": true'),
      excerpts("service/parse.cjs", "options.Iconv = require('iconv').Iconv"),
      excerpts(mailParser, "new Iconv(charset, 'UTF-8"),
    ],
  },
  "task-parameter": {
    id: "starter-template-task",
    verdict: "ruled_out",
    identityEvidence: [
      excerpts("portal/app-config.yaml", "target: /app/catalog/template.yaml"),
      excerpts("portal/template.yaml", "name: example-nodejs-template"),
      excerpts(
        "plugins/scaffolder-backend/src/service/router.ts",
        "steps: template.spec.steps",
      ),
    ],
    callSite: {
      path: "plugins/scaffolder-backend/src/lib/templating/SecureTemplater.ts",
      line: 170,
    },
  },
  "archive-east": {
    id: "archive-east-address-parser",
    verdict: "potentially_exploitable",
    identityEvidence: [
      excerpts("service/archive.json", "archive=3Dpart"),
      excerpts("service/server.cjs", "simpleParser(message)"),
    ],
  },
  "archive-west": {
    id: "archive-west-address-parser",
    verdict: "ruled_out",
    identityEvidence: [
      excerpts("service/archive.json", "archive=_part"),
      excerpts("service/server.cjs", "simpleParser(message)"),
    ],
  },
  "archive-worker-pinned-original": {
    id: "archive-original-worker",
    verdict: "potentially_exploitable",
    identityEvidence: [
      ...configuredArchiveWorker,
      excerpts("archive/stack.json", '"Status": "Enabled"'),
    ],
  },
  "archive-worker-pinned-normalized": {
    id: "archive-normalized-worker",
    verdict: "ruled_out",
    identityEvidence: [
      ...configuredArchiveWorker,
      excerpts("archive/stack.json", '"Status": "Suspended"'),
    ],
  },
  "archive-worker-mime-parts": {
    id: "archive-mime-worker",
    verdict: "potentially_exploitable",
    identityEvidence: [
      ...configuredArchiveWorker,
      excerpts("archive/media.json", '"forwardContentType": true'),
    ],
  },
  "thumbnail-blue": {
    id: "thumbnail-blue-captured-worker",
    verdict: "ruled_out",
    identityEvidence: capturedWorker(9100),
    observedBySource: true,
  },
  "thumbnail-green": {
    id: "thumbnail-green-captured-worker",
    verdict: "potentially_exploitable",
    identityEvidence: capturedWorker(9101),
    observedBySource: true,
  },
  "thumbnail-receipt-window": {
    id: "thumbnail-unresolved-loaded-copy",
    verdict: "unknown",
    identityEvidence: capturedWorker(9100),
    observedBySource: true,
    needsDecidingGap: true,
    unsupportedExpectation:
      "The staged package receipts do not identify the older inode still mapped by the selected captured worker.",
  },
  "zip-import-alpha": {
    id: "zip-bundle-alpha-address-parser",
    verdict: "potentially_exploitable",
    identityEvidence: zipWorker("archive.read(member.filename)"),
  },
  "zip-import-beta": {
    id: "zip-bundle-beta-address-parser",
    verdict: "ruled_out",
    identityEvidence: zipWorker("archive.read(member)"),
  },
};
