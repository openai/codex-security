import { filter } from "@sca-fixtures/pattern-filter";

export function handle(request, deployment) {
  return filter(request.pattern, { bounded: deployment.bounded });
}
