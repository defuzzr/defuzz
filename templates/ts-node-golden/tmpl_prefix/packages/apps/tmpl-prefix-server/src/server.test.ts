import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildApplication, parseServerCliArgs } from "./index.js";

describe("tmpl-prefix-server", () => {
  it("parses --check and --http CLI flags and validates adapter choice", () => {
    const parsed = parseServerCliArgs(["--check", "--http", "node"]);
    assert.equal(parsed.check, true);
    assert.equal(parsed.httpAdapter, "node");

    assert.throws(() => parseServerCliArgs(["--http", "invalid"]), /Invalid --http adapter/);
  });

  it("wires components, starts registry, and serves health routes", async () => {
    const res = buildApplication({
      env: {
        TMPL_PREFIX_ENVIRONMENT: "test",
        TMPL_PREFIX_HTTP_PORT: "0",
        TMPL_PREFIX_HTTP_ADAPTER: "node",
      },
      logSink: () => {},
    });
    assert.equal(res.ok, true);
    if (!res.ok) {
      return;
    }

    const wiring = res.value;
    await wiring.registry.start(wiring.context);
    const bound = await wiring.httpServer.listen(0, "127.0.0.1");
    try {
      const healthRes = await fetch(`http://127.0.0.1:${bound.port}/health`);
      assert.equal(healthRes.status, 200);
      const body = (await healthRes.json()) as Record<string, unknown>;
      assert.equal(body["status"], "healthy");
      assert.equal(body["serving"], true);
    } finally {
      await wiring.httpServer.close();
      await wiring.registry.stop();
    }
  });
});
