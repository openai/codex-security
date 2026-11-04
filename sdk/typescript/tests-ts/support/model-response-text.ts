export function modelResponseText(response: unknown) {
  return typeof response === "string" ? response : JSON.stringify(response);
}
