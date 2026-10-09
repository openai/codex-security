import assert from "node:assert/strict";

globalThis.fetch = async (url, init) => {
  assert.equal(url, "https://api.openai.com/v1/embeddings");
  assert.equal(init.headers.Authorization, "Bearer synthetic-container-key");
  const { input, model, dimensions } = JSON.parse(init.body);
  assert.equal(model, "text-embedding-3-large");
  assert.equal(dimensions, 1536);
  const embedding = Array(dimensions).fill(0);
  embedding[0] = 1;
  return Response.json({
    model,
    data: input.map((_, index) => ({ index, embedding })),
  });
};
