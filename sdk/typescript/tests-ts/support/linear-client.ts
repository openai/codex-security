import { GraphQLClientError, LinearSdk, parseLinearError } from "@linear/sdk";
import type { LinearClientFactory } from "../../src/linear-api.js";

export function mockLinearClient(fetchImpl: typeof fetch): LinearClientFactory {
  return ({ apiKey, redirect, signal }) => {
    const request = async <Result, Variables extends Record<string, unknown>>(
      document: string,
      variables?: Variables,
    ): Promise<Result> => {
      const response = await fetchImpl("https://api.linear.app/graphql", {
        method: "POST",
        headers: {
          Authorization: apiKey ?? "",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ query: document, variables }),
        redirect,
        ...(signal === null || signal === undefined ? {} : { signal }),
      });
      let payload: {
        data?: Result;
        errors?: Array<Record<string, unknown>>;
        error?: string;
      };
      try {
        payload = (await response.json()) as typeof payload;
      } catch {
        if (response.ok) throw new Error("Invalid synthetic Linear response");
        payload = {};
      }
      if (!response.ok || payload.errors !== undefined) {
        throw parseLinearError(
          new GraphQLClientError(
            {
              ...payload,
              headers: response.headers,
              status: response.status,
            },
            { query: document, variables },
          ),
        );
      }
      if (payload.data === undefined) {
        throw new Error("Invalid synthetic Linear response");
      }
      return payload.data;
    };
    return new LinearSdk(request);
  };
}
