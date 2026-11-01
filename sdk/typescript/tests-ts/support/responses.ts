export const responding = (body: string, status: number) => async () =>
  new Response(body, { status });
