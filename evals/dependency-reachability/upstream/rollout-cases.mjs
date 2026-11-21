import { skillOnly, excerpts } from "./case-data.mjs";

const before = "985238ce5b8f999edccd3c4ba83fba636db51272";
const after = "29a91ff19585ca3eebd4bf53d275f600a093a73d";
const root = "image/ports/";
const patch = root + "1.3.1-r1/CVE-2023-4863.patch";
const workers = "incident/workers.txt";
const packages = "incident/packages.tsv";

function port(revision, source, destination) {
  return {
    kind: "git",
    repository: "alpinelinux/aports",
    revision,
    source,
    destination,
  };
}

const stage = [
  port(before, "main/libwebp/APKBUILD", root + "1.3.1-r0/APKBUILD"),
  port(after, "main/libwebp/APKBUILD", root + "1.3.1-r1/APKBUILD"),
  port(after, "main/libwebp/CVE-2023-4863.patch", patch),
  port(after, "community/py3-pillow/APKBUILD", root + "py3-pillow/APKBUILD"),
  {
    kind: "fixture",
    source: "fixtures/rollout/app.py",
    destination: "app/thumbnail.py",
  },
  {
    kind: "fixture",
    source: "fixtures/rollout/workers.txt",
    destination: workers,
  },
];

const decodeEvidence = [
  excerpts(
    "app/thumbnail.py",
    'Image.open(BytesIO(environ["wsgi.input"].read()))',
  ),
  excerpts("app/thumbnail.py", "image.load()"),
  excerpts(
    "src/PIL/WebPImagePlugin.py",
    "_webp.WebPAnimDecoder(self.fp.read())",
  ),
  excerpts("src/PIL/WebPImagePlugin.py", "self._decoder.get_next()"),
  excerpts("src/_webp.c", "WebPAnimDecoderGetNext(decp->dec"),
];

function rolloutCase(id, portNumber, verdict) {
  const prior = portNumber === 9100;
  const missing = verdict === "unknown";
  const receipts = missing ? "packages-current.tsv" : "packages.tsv";
  const dial = `127.0.0.1:${portNumber}`;
  const revision = prior ? "1.3.1-r1" : "1.3.1-r0";
  const inode = prior ? "3741" : "8930";
  const pid = prior ? "431" : "692";
  const endpoint = "edge/caddy.json";
  const listener = [
    excerpts(endpoint, dial),
    excerpts(workers, dial),
    excerpts(workers, `pid=${pid},fd=3`),
  ];
  const loadedLibrary = [
    excerpts(workers, `# /proc/${pid}/maps`),
    excerpts(workers, `08:01 ${inode} /usr/lib/libwebp.so`),
  ];
  return {
    id,
    target: missing
      ? "thumbnail-unresolved-loaded-copy"
      : `${id}-captured-worker`,
    identityEvidence: [...listener, ...loadedLibrary],
    observedBySource: true,
    needsDecidingGap: missing,
    cve: "CVE-2023-4863",
    component: "libwebp",
    suite: "pillow",
    repository: "python-pillow/Pillow",
    revision: "6e28ed1f36d0eb74053af54e1eddc9c29db698cd",
    callerScope:
      "An anonymous caller supplies the image bytes in the next POST /thumbnail. " +
      "Assess the supplied captured deployment, assuming it stays in effect. " +
      "The application uses Alpine's py3-pillow built from this checkout. " +
      "Report the upstream libwebp version used for that request.",
    version: "1.3.1",
    versionAliases: missing ? [] : [revision],
    verdict,
    stage: [
      ...stage,
      {
        kind: "fixture",
        source: "fixtures/rollout/" + receipts,
        destination: packages,
      },
      {
        kind: "json",
        destination: endpoint,
        value: {
          apps: {
            http: {
              servers: {
                api: {
                  listen: [":80"],
                  routes: [
                    {
                      match: [{ path: ["/thumbnail"] }],
                      handle: [
                        { handler: "reverse_proxy", upstreams: [{ dial }] },
                      ],
                    },
                  ],
                },
              },
            },
          },
        },
      },
    ],
    evidenceGroups: [
      ...listener,
      excerpts(workers, `${pid} gunicorn: worker [app.thumbnail:application]`),
      ...loadedLibrary,
      excerpts(
        workers,
        `pillow_webp_version_info{pid="${pid}",version="1.3.1"}`,
      ),
      ...(missing
        ? [
            [
              {
                path: packages,
                contains: "transaction\tdevice\tinode\tpath\tpackage",
                completeFile: true,
              },
            ],
          ]
        : [
            excerpts(packages, `08:01\t${inode}\t/usr/lib/libwebp.so`),
            excerpts(packages, `libwebp-${revision}`),
            excerpts(
              root + revision + "/APKBUILD",
              prior ? "CVE-2023-4863.patch" : "libwebp-$pkgver.tar.gz",
            ),
          ]),
      ...(verdict === "ruled_out"
        ? []
        : missing
          ? [skillOnly(...decodeEvidence)]
          : decodeEvidence),
      ...(verdict === "ruled_out"
        ? [
            excerpts(
              patch,
              "+      BuildHuffmanTable(NULL, root_bits, code_lengths, code_lengths_size, NULL);",
            ),
            excerpts(
              patch,
              "+  if (root_table->curr_segment->curr_table + total_size >=",
            ),
            excerpts(patch, "+    next->size = total_size > segment_size"),
            skillOnly(
              excerpts(
                patch,
                "+        (HuffmanCode*)WebPSafeMalloc(next->size, sizeof(*next->start));",
              ),
            ),
          ]
        : []),
    ],
  };
}

export const rolloutCases = [
  rolloutCase("thumbnail-blue", 9100, "ruled_out"),
  // The running worker is observed, but the edge route is only configuration.
  rolloutCase("thumbnail-green", 9101, "potentially_exploitable"),
  rolloutCase("thumbnail-receipt-window", 9100, "unknown"),
];
