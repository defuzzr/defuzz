import {
  // Workspace API.
  AppError,
  err,
  ok,
  type Result,
} from "tmpl-prefix-core";

export type AccountId = string & {
  // Keep brands distinct across workspaces.
  readonly __brand: "TmplPrefixAccountId";
};
export type Email = string & {
  // Keep brands distinct across workspaces.
  readonly __brand: "TmplPrefixEmail";
};

export const AccountStatusValues = ["active", "deactivated"] as const;
export type AccountStatus = (typeof AccountStatusValues)[number];

export interface Account {
  readonly id: AccountId;
  readonly email: Email;
  readonly displayName: string;
  readonly status: AccountStatus;
  readonly createdAt: string;
}

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function parseAccountId(raw: string): Result<AccountId, AppError> {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    return err(new AppError("invalid_input", "Account id must not be empty"));
  }
  return ok(trimmed as AccountId);
}

export function parseEmail(raw: string): Result<Email, AppError> {
  const normalized = raw.trim().toLowerCase();
  if (!EMAIL_PATTERN.test(normalized)) {
    return err(
      new AppError("invalid_input", `Invalid email address: ${raw}`, {
        details: { email: raw },
      }),
    );
  }
  return ok(normalized as Email);
}
