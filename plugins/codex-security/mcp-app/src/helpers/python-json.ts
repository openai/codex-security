import { decodeUtf8 } from "./utf8";

// Preserve Python's integer/float distinction and arbitrary-size JSON integers.
export class JsonFloat {
  constructor(readonly source: string) {}
}

type Row = Record<string, unknown>;
const keyOrder = new WeakMap<Row, string[]>();
export function object(value: unknown): value is Row {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    !(value instanceof JsonFloat)
  );
}
export function objectEntries(value: Row): [string, unknown][] {
  return (keyOrder.get(value) ?? Object.keys(value)).map((key) => [
    key,
    value[key],
  ]);
}

export class JsonSyntaxError extends Error {}

// Detect UTF-8/16/32 JSON bytes; UTF-8 input uses the shared strict decoder.
export function parseJsonBytes(bytes: Buffer): unknown {
  let width = 1;
  let little = true;
  let offset = 0;
  const prefix = bytes.subarray(0, 4).toString("hex");
  if (prefix === "fffe0000" || prefix === "0000feff") {
    width = 4;
    little = prefix === "fffe0000";
    offset = 4;
  } else if (prefix.startsWith("fffe") || prefix.startsWith("feff")) {
    width = 2;
    little = prefix.startsWith("fffe");
    offset = 2;
  } else if (prefix.startsWith("efbbbf")) {
    offset = 3;
  } else if (bytes.length >= 4) {
    if (bytes[0] === 0) {
      width = bytes[1] === 0 ? 4 : 2;
      little = false;
    } else if (bytes[1] === 0) {
      width = bytes[2] || bytes[3] ? 2 : 4;
    }
  } else if (bytes.length === 2 && (bytes[0] === 0 || bytes[1] === 0)) {
    width = 2;
    little = bytes[0] !== 0;
  }
  let text = "";
  if (width === 1) {
    text = decodeUtf8(bytes.subarray(offset));
  } else {
    if ((bytes.length - offset) % width !== 0)
      throw new Error(`Truncated UTF-${width * 8} JSON input`);
    for (let index = offset; index < bytes.length; index += width) {
      const point =
        width === 2
          ? little
            ? bytes.readUInt16LE(index)
            : bytes.readUInt16BE(index)
          : little
            ? bytes.readUInt32LE(index)
            : bytes.readUInt32BE(index);
      text += String.fromCodePoint(point);
    }
  }
  return parseJson(text);
}

export function parseJson(source: string, rejectDuplicates = false): unknown {
  const tokens = [
    ...source.matchAll(
      /"(?:\\[\s\S]|[^"\\])*"|[{}\[\]:,]|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null|-?Infinity|NaN|[^ \t\r\n]/gu,
    ),
  ];
  let index = 0;
  const position = () => tokens[index]?.index ?? source.length;
  function error(message: string, offset = position()): never {
    const before = source.slice(0, offset);
    const line = before.split("\n").length;
    const column =
      Array.from(before.slice(before.lastIndexOf("\n") + 1)).length + 1;
    throw new JsonSyntaxError(
      `${message}: line ${line} column ${column} (char ${Array.from(before).length})`,
    );
  }
  if (source.startsWith("\ufeff"))
    error("Unexpected UTF-8 BOM (decode using utf-8-sig)", 0);
  const take = () => tokens[index++]?.[0];
  function expect(token: string): void {
    if (tokens[index]?.[0] !== token) error(`Expecting '${token}' delimiter`);
    index++;
  }
  function string(token: string, start: number): string {
    try {
      return JSON.parse(token) as string;
    } catch (cause) {
      return error((cause as Error).message, start);
    }
  }
  function value(): unknown {
    const start = position();
    const token = take();
    if (token === "{") {
      const row = Object.create(null) as Row;
      const keys: string[] = [];
      function finish(): Row {
        index++;
        const unique = new Set<string>();
        for (const key of keys) {
          if (rejectDuplicates && unique.has(key))
            throw new Error(`duplicate JSON object key: ${key}`);
          unique.add(key);
        }
        keyOrder.set(row, [...unique]);
        return row;
      }
      if (tokens[index]?.[0] === "}") return finish();
      while (true) {
        const keyStart = position();
        const key = take();
        if (!key?.startsWith('"'))
          error("Expecting property name enclosed in double quotes", keyStart);
        const name = string(key, keyStart);
        expect(":");
        row[name] = value();
        keys.push(name);
        if (tokens[index]?.[0] === "}") return finish();
        expect(",");
      }
    }
    if (token === "[") {
      const values: unknown[] = [];
      if (tokens[index]?.[0] === "]") {
        index++;
        return values;
      }
      while (true) {
        values.push(value());
        if (tokens[index]?.[0] === "]") {
          index++;
          return values;
        }
        expect(",");
      }
    }
    if (token?.startsWith('"')) return string(token, start);
    if (token === "true") return true;
    if (token === "false") return false;
    if (token === "null") return null;
    if (token !== undefined && /^-?[0-9]+$/u.test(token)) return BigInt(token);
    if (
      token !== undefined &&
      (/^-?(?:[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|Infinity)$/u.test(
        token,
      ) ||
        token === "NaN")
    )
      return new JsonFloat(token);
    return error("Expecting value", start);
  }
  const result = value();
  if (index !== tokens.length) error("Extra data");
  return result;
}

export function pythonRepr(value: unknown): string {
  if (typeof value === "string") {
    const quote = value.includes("'") && !value.includes('"') ? '"' : "'";
    return (
      quote +
      Array.from(value, (character) => {
        if (character === quote || character === "\\") return `\\${character}`;
        if (character === "\n") return "\\n";
        if (character === "\r") return "\\r";
        if (character === "\t") return "\\t";
        if (character !== " " && /[\p{C}\p{Z}]/u.test(character)) {
          const point = character.codePointAt(0)!;
          return point <= 0xff
            ? `\\x${point.toString(16).padStart(2, "0")}`
            : point <= 0xffff
              ? `\\u${point.toString(16).padStart(4, "0")}`
              : `\\U${point.toString(16).padStart(8, "0")}`;
        }
        return character;
      }).join("") +
      quote
    );
  }
  if (value === null) return "None";
  if (value === true) return "True";
  if (value === false) return "False";
  if (value instanceof JsonFloat) {
    const number = Number(value.source);
    if (Number.isNaN(number)) return "nan";
    if (!Number.isFinite(number)) return number < 0 ? "-inf" : "inf";
    if (Object.is(number, -0)) return "-0.0";
    const magnitude = Math.abs(number);
    if (magnitude !== 0 && (magnitude < 0.0001 || magnitude >= 1e16))
      return number.toExponential().replace(/e([+-])([0-9])$/u, "e$10$2");
    return number.toString() + (Number.isInteger(number) ? ".0" : "");
  }
  if (Array.isArray(value)) return `[${value.map(pythonRepr).join(", ")}]`;
  if (object(value))
    return `{${objectEntries(value)
      .map(([key, item]) => `${pythonRepr(key)}: ${pythonRepr(item)}`)
      .join(", ")}}`;
  return String(value);
}
