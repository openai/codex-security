import { render } from "@sca-fixtures/template-view";

export function handle(request, deployment) {
  return render(request.values, { escapeValues: deployment.escapeValues });
}
