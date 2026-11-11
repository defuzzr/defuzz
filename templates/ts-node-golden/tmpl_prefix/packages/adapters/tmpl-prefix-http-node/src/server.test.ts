import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { NodeHttpServer } from "./index.js";

describe("NodeHttpServer", () => {
  it("serves registered GET routes as JSON and returns 404 for unknown routes", async () => {
    const server = new NodeHttpServer({
      "/health": async () => ({ status: 200, body: { status: "healthy" } }),
    });

    const bound = await server.listen(0, "127.0.0.1");
    try {
      const okRes = await fetch(`http://127.0.0.1:${bound.port}/health`);
      assert.equal(okRes.status, 200);
      const okBody = (await okRes.json()) as Record<string, unknown>;
      assert.deepEqual(okBody, { status: "healthy" });

      const missingRes = await fetch(`http://127.0.0.1:${bound.port}/unknown`);
      assert.equal(missingRes.status, 404);
    } finally {
      await server.close();
    }
  });
});
