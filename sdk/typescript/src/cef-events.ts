import { z } from "zod";

/** Check CEF framing without interpreting or rewriting extension values. */
function isCefRecord(record: string): boolean {
  if (/[\r\n]/.test(record)) return false;
  // CEF may follow a syslog prefix. Transport-prefix validation belongs to
  // the producer; the original prefix is retained as evidence.
  const start = /(?:^|\s)CEF:[01]\|/.exec(record);
  if (!start) return false;
  const offset = start.index + start[0].indexOf("CEF:");
  const fields: string[] = [];
  let field = "";
  for (let index = offset; index < record.length; index++) {
    const char = record[index]!;
    if (char === "\\") {
      if (++index === record.length) return false;
      field += record[index];
    } else if (char === "|") {
      fields.push(field);
      field = "";
      if (fields.length === 7) {
        return (
          fields.every((value) => value.length > 0) &&
          /^(?:[0-9]|10|Unknown|Low|Medium|High|Very-High)$/i.test(fields[6]!)
        );
      }
    } else {
      field += char;
    }
  }
  return false;
}

/** A complete CEF 0 or 1 record, optionally prefixed by syslog, unchanged. */
export const cefEventSchema = z.string().refine(isCefRecord, {
  message:
    "Expected one CEF 0 or 1 record with seven header fields and a valid severity.",
});
