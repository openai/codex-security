import { lookup } from "@sca-fixtures/shared-cache";

export function handle(request, deployment) {
  return lookup(request.query, { isolateTenants: false });
}
