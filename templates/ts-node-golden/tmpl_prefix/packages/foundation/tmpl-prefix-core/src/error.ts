export const ErrorKindValues = [
  "invalid_input",
  "not_found",
  "conflict",
  "config",
  "unavailable",
  "internal",
] as const;

export type ErrorKind = (typeof ErrorKindValues)[number];

export interface AppErrorOptions {
  readonly cause?: unknown;
  readonly details?: Readonly<Record<string, unknown>>;
}

export class AppError extends Error {
  public readonly kind: ErrorKind;
  public readonly details: Readonly<Record<string, unknown>>;

  public constructor(kind: ErrorKind, message: string, options?: AppErrorOptions) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = "TmplPrefixAppError";
    this.kind = kind;
    this.details = options?.details ?? {};
  }

  public toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      kind: this.kind,
      message: this.message,
      details: this.details,
    };
  }
}

export function isAppError(value: unknown): value is AppError {
  return value instanceof AppError;
}

export type OkResult<T> = {
  readonly ok: true;
  readonly value: T;
};

export type ErrResult<E> = {
  readonly ok: false;
  readonly error: E;
};

export type Result<T, E = AppError> = OkResult<T> | ErrResult<E>;

export function ok<T>(value: T): OkResult<T> {
  return { ok: true, value };
}

export function err<E = AppError>(error: E): ErrResult<E> {
  return { ok: false, error };
}
