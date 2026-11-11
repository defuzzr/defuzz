import {
  // Workspace API.
  type HttpAdapter,
  HttpAdapterValues,
} from "tmpl-prefix-config";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { buildApplication } from "./wiring.js";

export interface ParsedServerCliArgs {
  readonly check: boolean;
  readonly httpAdapter?: HttpAdapter;
}

export function parseServerCliArgs(argv: readonly string[]): ParsedServerCliArgs {
  const { values } = parseArgs({
    args: [...argv],
    options: {
      check: { type: "boolean", default: false },
      http: { type: "string" },
    },
    strict: true,
    allowPositionals: false,
  });

  const check = values.check ?? false;
  const rawHttp = values.http;
  if (rawHttp === undefined) {
    return { check };
  }
  if (!HttpAdapterValues.includes(rawHttp as HttpAdapter)) {
    throw new Error(
      `Invalid --http adapter "${rawHttp}". Expected one of: ${HttpAdapterValues.join(", ")}`,
    );
  }
  return {
    check,
    httpAdapter: rawHttp as HttpAdapter,
  };
}

export async function runServer(
  argv: readonly string[],
  env?: Readonly<Record<string, string | undefined>>,
  externalSignal?: AbortSignal,
): Promise<number> {
  let cliArgs: ParsedServerCliArgs;
  try {
    cliArgs = parseServerCliArgs(argv);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`${msg}\n`);
    return 1;
  }

  const abortController = new AbortController();
  const onExternalAbort = (): void => {
    abortController.abort();
  };
  externalSignal?.addEventListener("abort", onExternalAbort, { once: true });

  const logLines: string[] = [];
  const wiringRes = buildApplication({
    ...(env !== undefined ? { env } : {}),
    ...(cliArgs.httpAdapter !== undefined ? { httpAdapterOverride: cliArgs.httpAdapter } : {}),
    ...(cliArgs.check ? { logSink: (line: string) => logLines.push(line) } : {}),
    signal: abortController.signal,
  });

  if (!wiringRes.ok) {
    process.stderr.write(`${wiringRes.error.message}\n`);
    return 1;
  }

  const wiring = wiringRes.value;

  if (cliArgs.check) {
    await wiring.registry.start(wiring.context);
    const report = await wiring.registry.report();
    const output = {
      ...report,
      service: wiring.config.serviceName,
      environment: wiring.config.environment,
      adapter: wiring.config.http.adapter,
    };
    process.stdout.write(`${JSON.stringify(output)}\n`);
    await wiring.registry.stop();
    return report.serving ? 0 : 1;
  }

  await wiring.registry.start(wiring.context);
  const bound = await wiring.httpServer.listen(wiring.config.http.port, wiring.config.http.host);
  wiring.logger.info("HTTP server listening", {
    host: wiring.config.http.host,
    port: bound.port,
    adapter: wiring.config.http.adapter,
  });

  await new Promise<void>((resolve) => {
    const onSigint = (): void => {
      abortController.abort();
    };
    const onSigterm = (): void => {
      abortController.abort();
    };
    const cleanup = (): void => {
      process.off("SIGINT", onSigint);
      process.off("SIGTERM", onSigterm);
      resolve();
    };

    if (abortController.signal.aborted) {
      cleanup();
      return;
    }

    process.once("SIGINT", onSigint);
    process.once("SIGTERM", onSigterm);
    abortController.signal.addEventListener("abort", cleanup, { once: true });
  });

  wiring.logger.info("Shutting down HTTP server");
  await wiring.httpServer.close();
  await wiring.registry.stop();
  return 0;
}

export function isDirectExecution(metaUrl: string, argv1: string | undefined): boolean {
  if (argv1 === undefined) {
    return false;
  }
  try {
    return realpathSync(fileURLToPath(metaUrl)) === realpathSync(argv1);
  } catch {
    return false;
  }
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  runServer(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`${msg}\n`);
      process.exitCode = 1;
    },
  );
}
