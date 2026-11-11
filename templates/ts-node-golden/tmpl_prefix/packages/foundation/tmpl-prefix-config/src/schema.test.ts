import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { defaultConfig, fromVars, parseConfig } from "./index.js";

describe("tmpl-prefix-config", () => {
  it("returns defaultConfig when environment variables are empty", () => {
    const res = fromVars({});
    assert.equal(res.ok, true);
    if (res.ok) {
      assert.deepEqual(res.value, defaultConfig);
    }
  });

  it("overrides configuration fields from TMPL_PREFIX_* variables", () => {
    const res = fromVars({
      TMPL_PREFIX_ENVIRONMENT: "production",
      TMPL_PREFIX_SERVICE_NAME: "billing-api",
      TMPL_PREFIX_HTTP_HOST: "0.0.0.0",
      TMPL_PREFIX_HTTP_PORT: "8080",
      TMPL_PREFIX_HTTP_ADAPTER: "node",
      TMPL_PREFIX_LOG_LEVEL: "warn",
    });

    assert.equal(res.ok, true);
    if (res.ok) {
      assert.equal(res.value.environment, "production");
      assert.equal(res.value.serviceName, "billing-api");
      assert.equal(res.value.http.host, "0.0.0.0");
      assert.equal(res.value.http.port, 8080);
      assert.equal(res.value.http.adapter, "node");
      assert.equal(res.value.logLevel, "warn");
    }
  });

  it("produces an AppError of kind config listing every invalid field", () => {
    const res = fromVars({
      TMPL_PREFIX_ENVIRONMENT: "mars",
      TMPL_PREFIX_HTTP_PORT: "99999",
      TMPL_PREFIX_HTTP_ADAPTER: "express",
      TMPL_PREFIX_LOG_LEVEL: "trace",
    });

    assert.equal(res.ok, false);
    if (!res.ok) {
      assert.equal(res.error.kind, "config");
      assert.match(res.error.message, /environment/);
      assert.match(res.error.message, /http\.port/);
      assert.match(res.error.message, /http\.adapter/);
      assert.match(res.error.message, /logLevel/);
    }

    const direct = parseConfig({
      environment: "development",
      serviceName: "",
      http: { host: "", port: -5, adapter: "hono" },
      logLevel: "info",
    });
    assert.equal(direct.ok, false);
    if (!direct.ok) {
      assert.equal(direct.error.kind, "config");
      assert.match(direct.error.message, /serviceName/);
      assert.match(direct.error.message, /http\.host/);
      assert.match(direct.error.message, /http\.port/);
    }
  });
});
