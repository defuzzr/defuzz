import type {
  // Workspace API.
  HttpServer,
  Routes,
} from "tmpl-prefix-core";
import { NodeHttpServer } from "tmpl-prefix-http-node";
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { HonoHttpServer } from "./index.js";

const contractRoutes: Routes = {
  "/health": async () => ({
    status: 200,
    body: { status: "healthy", serving: true },
  }),
  "/live": () => ({
    status: 200,
    body: { live: true },
  }),
  "/ready": async () => ({
    status: 503,
    body: { ready: false, reason: "warming_up" },
  }),
};

interface ProbedEndpointResult {
  readonly status: number;
  readonly body: Record<string, unknown>;
}

async function exerciseAdapter(server: HttpServer): Promise<Record<string, ProbedEndpointResult>> {
  const bound = await server.listen(0, "127.0.0.1");
  const baseUrl = `http://127.0.0.1:${bound.port}`;
  const results: Record<string, ProbedEndpointResult> = {};

  try {
    for (const path of ["/health", "/live", "/ready", "/missing"]) {
      const response = await fetch(`${baseUrl}${path}`);
      const body = (await response.json()) as Record<string, unknown>;
      results[path] = {
        status: response.status,
        body,
      };
    }
  } finally {
    await server.close();
  }

  return results;
}

describe("HttpServer adapter contract (HonoHttpServer vs NodeHttpServer)", () => {
  it("boots both adapters on port 0, hits every route, and returns identical responses", async () => {
    const honoResults = await exerciseAdapter(new HonoHttpServer(contractRoutes));
    const nodeResults = await exerciseAdapter(new NodeHttpServer(contractRoutes));

    assert.deepEqual(honoResults, nodeResults);
    assert.equal(honoResults["/health"]?.status, 200);
    assert.equal(honoResults["/live"]?.status, 200);
    assert.equal(honoResults["/ready"]?.status, 503);
    assert.equal(honoResults["/missing"]?.status, 404);
  });
});
