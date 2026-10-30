export function rubricConfigResponse(
  value: unknown,
  name = "codex_security_default_severity_rubric",
): Response {
  return Response.json({ name, value });
}
