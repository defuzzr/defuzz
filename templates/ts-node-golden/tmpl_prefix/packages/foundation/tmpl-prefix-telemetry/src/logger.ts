import type {
  // Workspace API.
  LogFields,
  Logger,
} from "tmpl-prefix-core";

export const LogLevels = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
} as const;

export type LogLevel = keyof typeof LogLevels;

export type LogSink = (line: string) => void;

export interface CreateLoggerOptions {
  readonly sink?: LogSink;
  readonly boundFields?: LogFields;
  readonly clock?: () => string;
}

const defaultSink: LogSink = (line: string): void => {
  process.stdout.write(`${line}\n`);
};

const defaultClock = (): string => new Date().toISOString();

export function createLogger(
  level: LogLevel,
  serviceName: string,
  options?: CreateLoggerOptions,
): Logger {
  const threshold = LogLevels[level];
  const sink = options?.sink ?? defaultSink;
  const bound = options?.boundFields ?? {};
  const clock = options?.clock ?? defaultClock;

  const emit = (entryLevel: LogLevel, message: string, fields?: LogFields): void => {
    if (LogLevels[entryLevel] < threshold) {
      return;
    }
    const payload: Record<string, unknown> = {
      timestamp: clock(),
      level: entryLevel,
      service: serviceName,
      message,
      ...bound,
      ...fields,
    };
    sink(JSON.stringify(payload));
  };

  return {
    debug(message: string, fields?: LogFields): void {
      emit("debug", message, fields);
    },
    info(message: string, fields?: LogFields): void {
      emit("info", message, fields);
    },
    warn(message: string, fields?: LogFields): void {
      emit("warn", message, fields);
    },
    error(message: string, fields?: LogFields): void {
      emit("error", message, fields);
    },
    child(childFields: LogFields): Logger {
      return createLogger(level, serviceName, {
        sink,
        boundFields: { ...bound, ...childFields },
        clock,
      });
    },
  };
}

export type {
  // Workspace API.
  LogFields,
  Logger,
} from "tmpl-prefix-core";
