import { z } from "zod";
import {
  // Workspace API.
  AppError,
  err,
  ok,
  type Result,
} from "tmpl-prefix-core";

export const EnvironmentValues = ["development", "staging", "production", "test"] as const;
export type Environment = (typeof EnvironmentValues)[number];

export const HttpAdapterValues = ["hono", "node"] as const;
export type HttpAdapter = (typeof HttpAdapterValues)[number];

export const LogLevelValues = ["debug", "info", "warn", "error"] as const;
export type ConfigLogLevel = (typeof LogLevelValues)[number];

export interface HttpConfig {
  readonly host: string;
  readonly port: number;
  readonly adapter: HttpAdapter;
}

export interface Config {
  readonly environment: Environment;
  readonly serviceName: string;
  readonly http: HttpConfig;
  readonly logLevel: ConfigLogLevel;
}

export const defaultConfig: Config = {
  environment: "development",
  serviceName: "tmpl-prefix-server",
  http: {
    host: "127.0.0.1",
    port: 3000,
    adapter: "hono",
  },
  logLevel: "info",
};

export const configSchema: z.ZodType<Config> = z
  .object({
    environment: z.enum(EnvironmentValues),
    serviceName: z.string().trim().min(1, "serviceName must not be empty"),
    http: z
      .object({
        host: z.string().trim().min(1, "http.host must not be empty"),
        port: z.number().int().min(0).max(65535),
        adapter: z.enum(HttpAdapterValues),
      })
      .strict(),
    logLevel: z.enum(LogLevelValues),
  })
  .strict();

export function parseConfig(input: unknown): Result<Config, AppError> {
  const parsed = configSchema.safeParse(input);
  if (parsed.success) {
    return ok(parsed.data);
  }
  const invalidFields = parsed.error.issues.map((issue) => {
    const path = issue.path.length > 0 ? issue.path.join(".") : "<root>";
    return `${path}: ${issue.message}`;
  });
  return err(
    new AppError("config", `Invalid configuration (${invalidFields.join("; ")})`, {
      details: { fields: invalidFields },
    }),
  );
}

function parsePortValue(raw: string | undefined, fallback: number): unknown {
  if (raw === undefined || raw.trim() === "") {
    return fallback;
  }
  const num = Number(raw);
  return Number.isNaN(num) ? raw : num;
}

export function fromVars(
  vars: Readonly<Record<string, string | undefined>>,
): Result<Config, AppError> {
  const prefix = "TMPL_PREFIX";
  const envVal = vars[`${prefix}_ENVIRONMENT`];
  const serviceNameVal = vars[`${prefix}_SERVICE_NAME`];
  const hostVal = vars[`${prefix}_HTTP_HOST`];
  const portVal = vars[`${prefix}_HTTP_PORT`];
  const adapterVal = vars[`${prefix}_HTTP_ADAPTER`] ?? vars[`${prefix}_HTTP`];
  const logLevelVal = vars[`${prefix}_LOG_LEVEL`];

  const candidate: unknown = {
    environment: envVal !== undefined && envVal !== "" ? envVal : defaultConfig.environment,
    serviceName: serviceNameVal !== undefined ? serviceNameVal : defaultConfig.serviceName,
    http: {
      host: hostVal !== undefined ? hostVal : defaultConfig.http.host,
      port: parsePortValue(portVal, defaultConfig.http.port),
      adapter:
        adapterVal !== undefined && adapterVal !== "" ? adapterVal : defaultConfig.http.adapter,
    },
    logLevel:
      logLevelVal !== undefined && logLevelVal !== "" ? logLevelVal : defaultConfig.logLevel,
  };

  return parseConfig(candidate);
}

export function fromEnv(): Result<Config, AppError> {
  return fromVars(process.env);
}
