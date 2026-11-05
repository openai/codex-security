import type { StageFile } from "./cases.mts";
import { excerpts } from "./case-data.mts";
import type { EvidenceGroup } from "./grade.mts";

// Exact published source from the lockfile's integrity-verified artifacts.
// Retain original package bytes and licenses; these are evidence, not an install.
const packages = [
  {
    name: "@zone-eu/mailsplit",
    directory: "mailsplit-5.4.7",
    files: [
      "LICENSE.EUPL-1.2",
      "lib/chunked-passthrough.js",
      "lib/flowed-decoder.js",
      "lib/headers.js",
      "index.js",
      "lib/message-joiner.js",
      "lib/message-splitter.js",
      "lib/mime-node.js",
      "lib/node-rewriter.js",
      "lib/node-streamer.js",
      "package.json",
      "README.md",
      "LICENSE.MIT",
    ],
  },
  {
    name: "libmime",
    directory: "libmime-5.3.7",
    files: [
      "LICENSE",
      "lib/charset.js",
      "lib/charsets.js",
      "lib/get-charset-name.js",
      "lib/libmime.js",
      "lib/mimetypes.js",
      "package.json",
      "CHANGELOG.md",
      "README.md",
    ],
  },
];

export const mimeReceiverSources: StageFile[] = [
  ...packages.flatMap(({ name, directory, files }) =>
    files.map((file): StageFile => ({
      kind: "fixture",
      source: `fixtures/mime-receiver/${directory}/${file}`,
      destination: `node_modules/${name}/${file}`,
    })),
  ),
  {
    kind: "fixture",
    source: "fixtures/mime-receiver/artifacts.json",
    destination: "dependency-artifacts/mime-receiver.json",
  },
];

const splitter = "node_modules/@zone-eu/mailsplit/lib/message-splitter.js";

const boundarySelection = excerpts(
  "node_modules/@zone-eu/mailsplit/lib/mime-node.js",
  "Buffer.from(this._parsedContentType.params.boundary)",
);
const boundaryComparison = excerpts(
  splitter,
  "if (line[i + 2 + startpos] !== boundary[i])",
);
export const mimeBoundaryEvidence = [boundarySelection, boundaryComparison];

export function mimePromotionEvidence(
  relation: "child" | "sibling",
): EvidenceGroup[] {
  return [
    boundarySelection,
    // The encoded-boundary case depends on byte-exact recognition. A sender
    // choosing both the multipart header and body only needs child promotion.
    ...(relation === "sibling" ? [boundaryComparison] : []),
    excerpts(
      splitter,
      relation === "child"
        ? "this.newNode(this.node)"
        : "this.newNode(parentNode)",
    ),
    excerpts(splitter, "return next(null, currentNode, flush)"),
    excerpts(
      "node_modules/libmime/lib/libmime.js",
      "match = line.match(/^\\s*([^:]+):(.*)$/)",
    ),
    ...(relation === "sibling"
      ? [
          excerpts(
            "node_modules/@zone-eu/mailsplit/lib/headers.js",
            "lines[i - 1] += '\\r\\n' + lines[i]",
          ),
        ]
      : []),
  ];
}
