import { bedrockOssPricing } from "./bedrock-oss-pricing.js";

// AWS Bedrock Standard prices, in USD per million tokens. Each route lists
// the source regions of the request (not cross-region routing destinations).
type Prices = readonly [
  input: number,
  read: number,
  write: number,
  output: number,
];
type Route = "regional" | "us" | "us-gov" | "in" | "global";
type Origins = Partial<Record<Route, readonly string[]>>;

const usEast = ["us-east-1", "us-east-2"];
const usMantle = [...usEast, "us-west-2"];
const usGeo = [...usMantle, "us-west-1", "ca-central-1", "ca-west-1"];
const gov = ["us-gov-east-1", "us-gov-west-1"];
const india = ["ap-south-1", "ap-south-2"];
const astraGlobal = [
  ...usGeo,
  "eu-central-1",
  "eu-north-1",
  "eu-west-1",
  "eu-west-2",
  "eu-west-3",
  "ap-northeast-1",
  "ap-northeast-2",
  "ap-northeast-3",
  "ap-south-1",
  "ap-southeast-1",
  "ap-southeast-2",
  "sa-east-1",
];
const commonGlobal = [
  ...astraGlobal,
  "eu-central-2",
  "eu-south-1",
  "eu-south-2",
  "ap-east-2",
  "ap-south-2",
  "ap-southeast-3",
  "ap-southeast-4",
  "ap-southeast-5",
  "ap-southeast-6",
  "ap-southeast-7",
  "il-central-1",
  "af-south-1",
];
const gpt56Global = [...commonGlobal, "me-central-1", "me-south-1"];
// GPT-6.1 Sol links here for its global source regions:
// https://docs.aws.amazon.com/bedrock/latest/userguide/models-region-compatibility.html#model-regions-openai
const gpt6Global = [...commonGlobal, "mx-central-1"];

function perToken([input, read, write, output]: Prices, scale: number): Prices {
  return [
    Math.round(input * scale),
    Math.round(read * scale),
    Math.round(write * scale),
    Math.round(output * scale),
  ];
}

function offer(
  origins: Origins,
  short: Prices,
  long?: Prices,
  source?: string,
) {
  return { origins, short, long, source };
}

function card(slug: string, ...offers: ReturnType<typeof offer>[]) {
  return {
    source: `https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-openai-gpt-${slug}.html`,
    offers,
  };
}

// Prefer AWS's route-specific model card, including its GovCloud prices.
// GPT-5.4 and GPT-5.5 list no separate write fee for their implicit cache.
// Their cards publish regional rates. AWS prices geographic inference at the
// source region's Standard rate, and does not specify the Global rate here:
// https://docs.aws.amazon.com/bedrock/latest/userguide/models-region-compatibility.html
const cards: Readonly<Record<string, ReturnType<typeof card>>> = {
  "openai.gpt-5.4": card(
    "54",
    offer(
      { regional: usMantle, us: usGeo },
      [2.75, 0.275, 2.75, 16.5],
      [5.5, 0.55, 5.5, 24.75],
    ),
    offer({ regional: ["us-gov-west-1"] }, [3.375, 0.3375, 3.375, 20.25]),
    offer(
      { regional: ["us-gov-east-1"] },
      [3.3, 0.33, 3.3, 19.8],
      undefined,
      "https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonBedrock/20261102165015/us-gov-east-1/index.json",
    ),
  ),
  "openai.gpt-5.5": card(
    "55",
    offer(
      { regional: usEast, us: usGeo },
      [5.5, 0.55, 5.5, 33],
      [11, 1.1, 11, 49.5],
    ),
  ),
  "openai.gpt-daybreak-blue-5.6-sol": card(
    "daybreak-blue-56-sol",
    offer(
      { regional: ["us-east-2"] },
      [4.4, 0.44, 5.5, 22],
      [8.8, 0.88, 11, 33],
    ),
  ),
  "openai.gpt-5.6-cyber": card(
    "56-cyber",
    offer({ regional: ["us-east-2"] }, [13.75, 1.375, 17.1875, 82.5]),
    offer({ regional: ["us-gov-east-1"] }, [16.875, 1.6875, 21.09375, 101.25]),
  ),
  "openai.gpt-5.6-luna": card(
    "56-luna",
    offer(
      { regional: usMantle, us: usGeo, in: india },
      [0.22, 0.022, 0.275, 1.32],
      [0.44, 0.044, 0.55, 1.98],
    ),
    offer(
      { global: gpt56Global },
      [0.2, 0.02, 0.25, 1.2],
      [0.4, 0.04, 0.5, 1.8],
    ),
    offer(
      { regional: gov, "us-gov": gov },
      [0.27, 0.027, 0.3375, 1.62],
      [0.54, 0.054, 0.675, 2.43],
    ),
  ),
  "openai.gpt-5.6-terra": card(
    "56-terra",
    offer(
      { regional: usMantle, us: usGeo, in: india },
      [2.2, 0.22, 2.75, 13.2],
      [4.4, 0.44, 5.5, 19.8],
    ),
    offer({ global: gpt56Global }, [2, 0.2, 2.5, 12], [4, 0.4, 5, 18]),
    offer(
      { regional: gov, "us-gov": gov },
      [2.7, 0.27, 3.375, 16.2],
      [5.4, 0.54, 6.75, 24.3],
    ),
  ),
  "openai.gpt-5.6-sol": card(
    "56-sol",
    offer(
      { regional: usEast, us: usGeo },
      [4.4, 0.44, 5.5, 22],
      [8.8, 0.88, 11, 33],
    ),
    offer({ global: gpt56Global }, [4, 0.4, 5, 20], [8, 0.8, 10, 30]),
  ),
  "openai.gpt-6-astra": card(
    "6-astra",
    offer(
      { regional: ["us-east-1", "us-west-2"], us: usGeo },
      [11, 1.1, 13.75, 55],
      [22, 2.2, 27.5, 82.5],
    ),
    offer({ global: astraGlobal }, [10, 1, 12.5, 50], [20, 2, 25, 75]),
  ),
  "openai.gpt-6-luna": card(
    "6-luna",
    offer(
      { regional: ["us-east-1"], us: usGeo },
      [0.11, 0.011, 0.1375, 0.55],
      [0.22, 0.022, 0.275, 0.825],
    ),
    offer(
      { global: gpt6Global },
      [0.1, 0.01, 0.125, 0.5],
      [0.2, 0.02, 0.25, 0.75],
    ),
  ),
  "openai.gpt-6-sol": card(
    "6-sol",
    offer(
      { regional: ["us-east-1"], us: usGeo },
      [2.2, 0.22, 2.75, 11],
      [4.4, 0.44, 5.5, 16.5],
    ),
    offer({ global: gpt6Global }, [2, 0.2, 2.5, 10], [4, 0.4, 5, 15]),
  ),
  "openai.gpt-6.1-sol": card(
    "6-1-sol",
    offer(
      { regional: ["us-east-1"], us: usGeo },
      [2.2, 0.11, 2.75, 11],
      [4.4, 0.22, 5.5, 16.5],
    ),
    offer({ global: gpt6Global }, [2, 0.1, 2.5, 10], [4, 0.2, 5, 15]),
  ),
  "openai.gpt-6.1-terra": card(
    "6-1-terra",
    offer(
      { regional: ["us-east-1"], us: usGeo },
      [1.1, 0.055, 1.375, 5.5],
      [2.2, 0.11, 2.75, 8.25],
    ),
    offer({ global: gpt6Global }, [1, 0.05, 1.25, 5], [2, 0.1, 2.5, 7.5]),
  ),
};

function frontierPricing(model: string, region?: string | null) {
  const match = /^(?:(us|us-gov|in|global)\.)?(openai\.gpt-[\w.-]+)$/.exec(
    model,
  );
  if (!match) return undefined;
  const modelCard = cards[match[2]!];
  if (!modelCard) return undefined;
  const route = (match[1] ?? "regional") as Route;
  // The first regional offer is the model-only SDK's commercial default.
  // A live scan with an unresolved region (null) needs an unambiguous rate.
  const offers = modelCard.offers.filter(
    ({ origins }) =>
      origins[route] && (region == null || origins[route].includes(region)),
  );
  if (region === null && offers.length > 1) return undefined;
  const rate = offers[0];
  if (!rate) return undefined;
  return {
    short: rate.short,
    long: rate.long,
    source: rate.source ?? modelCard.source,
  };
}

export function bedrockModelPricing(model: string, region?: string | null) {
  const rate =
    frontierPricing(model, region) ?? bedrockOssPricing(model, region);
  if (!rate) return undefined;

  // Keep nanodollar arithmetic where possible. GovCloud Cyber cache writes
  // require quarter-nanodollars, and Sydney OSS prices need tenths.
  const prices = [...rate.short, ...(rate.long ?? [])];
  const scale = [1_000, 2_000, 4_000, 10_000].find((scale) =>
    prices.every((price) => Math.round(price * scale) / scale === price),
  );
  if (!scale) throw new Error("Bedrock price exceeds supported precision");
  return {
    short: perToken(rate.short, scale),
    long: rate.long && perToken(rate.long, scale),
    unitsPerUsd: scale * 1_000_000,
    source: rate.source,
    asOf: "2026-11-05",
  };
}
