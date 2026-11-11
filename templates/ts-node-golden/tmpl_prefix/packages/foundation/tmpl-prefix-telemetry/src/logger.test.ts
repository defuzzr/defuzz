import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createLogger } from "./index.js";

describe("tmpl-prefix-telemetry", () => {
  it("formats structured JSON logs, filters below level, and binds child fields", () => {
    const lines: string[] = [];
    const service = "tmpl-prefix-svc";
    const logger = createLogger("info", service, {
      sink: (line) => lines.push(line),
      clock: () => "2026-11-06T00:00:00.000Z",
    });

    logger.debug("ignored debug", { seq: 1 });
    logger.info("server started", { port: 3000 });

    const child = logger.child({ requestId: "req-123" });
    child.warn("slow query", { durationMs: 250 });

    assert.equal(lines.length, 2);

    const first = JSON.parse(lines[0] ?? "{}") as Record<string, unknown>;
    assert.equal(first["level"], "info");
    assert.equal(first["service"], service);
    assert.equal(first["message"], "server started");
    assert.equal(first["port"], 3000);

    const second = JSON.parse(lines[1] ?? "{}") as Record<string, unknown>;
    assert.equal(second["level"], "warn");
    assert.equal(second["requestId"], "req-123");
    assert.equal(second["durationMs"], 250);
  });
});
