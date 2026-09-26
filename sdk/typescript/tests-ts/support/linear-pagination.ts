import { Connection, PageInfo, type LinearRequest } from "@linear/sdk";

/** Replace page transport while retaining the SDK's pagination behavior. */
export function paginated<Value>(values: Value[]) {
  const cursors: string[] = [];
  const request: LinearRequest = async () => {
    throw new Error("Unexpected request outside the synthetic page transport.");
  };
  const page = (offset: number): Connection<Value> =>
    new Connection(
      request,
      async (variables) => {
        cursors.push(variables!.after!);
        return page(Number(variables!.after));
      },
      values.slice(offset, offset + 50),
      new PageInfo(request, {
        __typename: "PageInfo",
        hasNextPage: offset + 50 < values.length,
        hasPreviousPage: offset > 0,
        endCursor: String(Math.min(offset + 50, values.length)),
      }),
    );
  return { connection: page(0), cursors };
}
