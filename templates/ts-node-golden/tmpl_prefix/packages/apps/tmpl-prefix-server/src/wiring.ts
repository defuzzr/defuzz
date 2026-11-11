import {
  // Workspace API.
  AccountService,
  AccountsComponent,
} from "tmpl-prefix-accounts";
import {
  // Workspace API.
  type Config,
  fromEnv,
  fromVars,
  type HttpAdapter,
} from "tmpl-prefix-config";
import {
  type AppError,
  type Context,
  type HttpServer,
  ok,
  Registry,
  type Result,
  type Routes,
} from "tmpl-prefix-core";
import { HonoHttpServer } from "tmpl-prefix-http-hono";
import { NodeHttpServer } from "tmpl-prefix-http-node";
import { InMemoryAccountRepository } from "tmpl-prefix-storage-memory";
import {
  // Workspace API.
  createLogger,
  type Logger,
  type LogSink,
} from "tmpl-prefix-telemetry";

export interface BuildApplicationOptions {
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly httpAdapterOverride?: HttpAdapter;
  readonly logSink?: LogSink;
  readonly signal?: AbortSignal;
}

export interface ApplicationWiring {
  readonly config: Config;
  readonly logger: Logger;
  readonly context: Context;
  readonly registry: Registry;
  readonly accountService: AccountService;
  readonly httpServer: HttpServer;
  readonly routes: Routes;
}

export function createRoutes(registry: Registry, config: Config): Routes {
  return {
    "/health": async () => {
      const report = await registry.report();
      return {
        status: report.serving ? 200 : 503,
        body: {
          status: report.status,
          serving: report.serving,
          service: config.serviceName,
          environment: config.environment,
          adapter: config.http.adapter,
          components: report.components,
        },
      };
    },
    "/live": () => ({
      status: 200,
      body: {
        live: true,
        service: config.serviceName,
      },
    }),
    "/ready": async () => {
      const serving = await registry.isServing();
      return {
        status: serving ? 200 : 503,
        body: {
          ready: serving,
          service: config.serviceName,
        },
      };
    },
  };
}

export function selectHttpServer(adapter: HttpAdapter, routes: Routes): HttpServer {
  if (adapter === "node") {
    return new NodeHttpServer(routes);
  }
  return new HonoHttpServer(routes);
}

export function buildApplication(
  options?: BuildApplicationOptions,
): Result<ApplicationWiring, AppError> {
  const baseConfigRes = options?.env !== undefined ? fromVars(options.env) : fromEnv();
  if (!baseConfigRes.ok) {
    return baseConfigRes;
  }

  const config: Config =
    options?.httpAdapterOverride !== undefined
      ? {
          ...baseConfigRes.value,
          http: {
            ...baseConfigRes.value.http,
            adapter: options.httpAdapterOverride,
          },
        }
      : baseConfigRes.value;

  const logger = createLogger(
    config.logLevel,
    config.serviceName,
    options?.logSink !== undefined ? { sink: options.logSink } : undefined,
  );

  const context: Context =
    options?.signal !== undefined
      ? {
          environment: config.environment,
          serviceName: config.serviceName,
          logger,
          signal: options.signal,
        }
      : {
          environment: config.environment,
          serviceName: config.serviceName,
          logger,
        };

  const accountRepository = new InMemoryAccountRepository();
  const accountService = new AccountService(accountRepository);

  const registry = new Registry();
  registry.register(new AccountsComponent(accountService));
  // @xtask:register-components

  const routes = createRoutes(registry, config);
  const httpServer = selectHttpServer(config.http.adapter, routes);

  return ok({
    config,
    logger,
    context,
    registry,
    accountService,
    httpServer,
    routes,
  });
}
