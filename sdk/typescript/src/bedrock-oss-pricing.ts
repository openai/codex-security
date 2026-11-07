// Standard on-demand input and output in USD per million tokens (AWS quotes
// 1K-token units in the bulk catalog). The four OSS models have a 128K context
// window and one input/output rate for the whole request.
type Prices = readonly [input: number, output: number];
type ModelRates = Readonly<Record<string, Prices | undefined>>;

function models(
  base20b: Prices,
  base120b: Prices,
  safeguard20b?: Prices,
  safeguard120b?: Prices,
): ModelRates {
  return {
    "openai.gpt-oss-20b": base20b,
    "openai.gpt-oss-120b": base120b,
    "openai.gpt-oss-20b-1:0": base20b,
    "openai.gpt-oss-120b-1:0": base120b,
    "openai.gpt-oss-safeguard-20b": safeguard20b,
    "openai.gpt-oss-safeguard-120b": safeguard120b,
  };
}

const us = models([0.07, 0.3], [0.15, 0.6], [0.07, 0.2], [0.15, 0.6]);
const gov = models([0.084, 0.36], [0.18, 0.72]);
const tokyo = models([0.08, 0.36], [0.18, 0.73], [0.08, 0.24], [0.18, 0.73]);

const regions: Readonly<Record<string, ModelRates>> = {
  "us-east-1": us,
  "us-east-2": us,
  "us-west-2": us,
  "us-gov-east-1": gov,
  "us-gov-west-1": gov,
  "ap-northeast-1": tokyo,
  "ap-south-1": models([0.08, 0.35], [0.18, 0.71], [0.08, 0.24], [0.18, 0.71]),
  // The Standard table on AWS's pricing page explicitly lists Sydney, where
  // the bulk catalog only has Mantle SKUs.
  "ap-southeast-2": models(
    [0.0721, 0.309],
    [0.1545, 0.618],
    [0.0721, 0.206],
    [0.1545, 0.618],
  ),
  "ap-southeast-3": models(
    [0.07, 0.31],
    [0.16, 0.62],
    [0.084, 0.24],
    [0.18, 0.72],
  ),
  "eu-central-1": models([0.09, 0.4], [0.2, 0.79], [0.084, 0.24], [0.18, 0.72]),
  "eu-north-1": models([0.07, 0.3], [0.15, 0.6], [0.084, 0.24], [0.18, 0.72]),
  "eu-south-1": models([0.09, 0.4], [0.2, 0.79], [0.08, 0.23], [0.18, 0.7]),
  "eu-west-1": models([0.08, 0.35], [0.18, 0.7], [0.08, 0.23], [0.18, 0.7]),
  "eu-west-2": models([0.11, 0.47], [0.23, 0.93], [0.11, 0.31], [0.23, 0.93]),
  "sa-east-1": tokyo,
};

export function bedrockOssPricing(model: string, region?: string | null) {
  const govProfile =
    model === "us-gov.openai.gpt-oss-20b-1:0" ||
    model === "us-gov.openai.gpt-oss-120b-1:0";
  // Both possible source regions of these inference profiles have the same
  // rates. A bare model ID requires the billing region to resolve its price.
  const origin = region ?? (govProfile ? "us-gov-east-1" : undefined);
  if (origin === undefined || !Object.hasOwn(regions, origin)) return undefined;
  if (govProfile && origin !== "us-gov-east-1" && origin !== "us-gov-west-1")
    return undefined;
  const rates = regions[origin]!;
  const id = govProfile ? model.slice("us-gov.".length) : model;
  const price = Object.hasOwn(rates, id) ? rates[id] : undefined;
  if (!price) return undefined;
  const [input, output] = price;
  const tokens = [input, input, input, output] as const;
  return {
    short: tokens,
    long: tokens,
    source:
      origin === "ap-southeast-2" && model.endsWith("-1:0")
        ? "https://aws.amazon.com/bedrock/pricing/#OpenAI"
        : "https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonBedrock/20261102165015/index.json",
  };
}
