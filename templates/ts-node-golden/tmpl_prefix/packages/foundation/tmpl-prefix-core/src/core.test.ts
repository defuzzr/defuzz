import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  AppError,
  type Component,
  type Context,
  err,
  isAppError,
  type Logger,
  ok,
  Registry,
} from "./index.js";

function createNoopLogger(): Logger {
  const logger: Logger = {
    debug: () => {},
    info: () => {},
    warn: () => {},
    error: () => {},
    child: () => logger,
  };
  return logger;
}

function createTestContext(signal?: AbortSignal): Context {
  const base: Context = {
    environment: "test",
    serviceName: "tmpl-prefix-test",
    logger: createNoopLogger(),
  };
  if (signal !== undefined) {
    return { ...base, signal };
  }
  return base;
}

describe("AppError and Result", () => {
  it("constructs AppError with cause chaining and discriminates Results", () => {
    const rootCause = new Error("socket hang up");
    const appErr = new AppError("unavailable", "Database unreachable", {
      cause: rootCause,
      details: { host: "localhost" },
    });

    assert.equal(isAppError(appErr), true);
    assert.equal(isAppError(rootCause), false);
    assert.equal(appErr.kind, "unavailable");
    assert.equal(appErr.cause, rootCause);
    assert.deepEqual(appErr.details, { host: "localhost" });

    const success = ok(42);
    assert.equal(success.ok, true);
    assert.equal(success.value, 42);

    const failure = err(appErr);
    assert.equal(failure.ok, false);
    assert.equal(failure.error.kind, "unavailable");
  });
});

describe("Registry lifecycle", () => {
  it("starts components in registration order and stops them in reverse order", async () => {
    const events: string[] = [];
    const makeComponent = (name: string): Component => ({
      name,
      start: async () => {
        events.push(`start:${name}`);
      },
      stop: async () => {
        events.push(`stop:${name}`);
      },
      health: async () => ({ status: "healthy" }),
    });

    const registry = new Registry();
    registry.register(makeComponent("first"));
    registry.register(makeComponent("second"));
    registry.register(makeComponent("third"));

    await registry.start(createTestContext());
    assert.equal(await registry.isServing(), true);

    const report = await registry.report();
    assert.equal(report.status, "healthy");
    assert.equal(report.serving, true);
    assert.equal(report.components.length, 3);

    await registry.stop();
    assert.equal(await registry.isServing(), false);
    assert.deepEqual(events, [
      "start:first",
      "start:second",
      "start:third",
      "stop:third",
      "stop:second",
      "stop:first",
    ]);
  });

  it("rolls back already-started components in reverse order when a component fails to start", async () => {
    const events: string[] = [];
    const registry = new Registry();

    registry.register({
      name: "alpha",
      start: async () => {
        events.push("start:alpha");
      },
      stop: async () => {
        events.push("stop:alpha");
      },
      health: async () => ({ status: "healthy" }),
    });

    registry.register({
      name: "beta",
      start: async () => {
        events.push("start:beta");
      },
      stop: async () => {
        events.push("stop:beta");
      },
      health: async () => ({ status: "healthy" }),
    });

    registry.register({
      name: "gamma",
      start: async () => {
        events.push("start:gamma");
        throw new Error("gamma boom");
      },
      stop: async () => {
        events.push("stop:gamma");
      },
      health: async () => ({ status: "healthy" }),
    });

    await assert.rejects(async () => {
      await registry.start(createTestContext());
    }, /gamma boom/);

    assert.equal(await registry.isServing(), false);
    assert.deepEqual(events, [
      "start:alpha",
      "start:beta",
      "start:gamma",
      "stop:beta",
      "stop:alpha",
    ]);
  });

  it("rejects duplicate component names and respects AbortSignal", async () => {
    const registry = new Registry();
    const comp: Component = {
      name: "unique",
      start: async () => {},
      stop: async () => {},
      health: async () => ({ status: "healthy" }),
    };
    registry.register(comp);
    assert.throws(() => registry.register(comp), /Duplicate component name/);

    const abortController = new AbortController();
    abortController.abort();
    await assert.rejects(async () => {
      await registry.start(createTestContext(abortController.signal));
    }, /Startup aborted/);
  });
});
