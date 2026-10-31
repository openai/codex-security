import { decode } from "@sca-fixtures/depth-parser";

export function handle(request, deployment) {
  return decode(request.body, { maxDepth: 32 });
}
