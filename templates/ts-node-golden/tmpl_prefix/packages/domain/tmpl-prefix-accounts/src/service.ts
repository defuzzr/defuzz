import {
  // Workspace API.
  AppError,
  err,
  ok,
  type Result,
} from "tmpl-prefix-core";
import { type Account, type AccountId, parseAccountId, parseEmail } from "./model.js";
import type { AccountRepository } from "./port.js";

export interface RegisterAccountInput {
  readonly id?: string;
  readonly email: string;
  readonly displayName: string;
  readonly now?: () => string;
}

export class AccountService {
  private readonly repository: AccountRepository;
  private nextSequence = 1;

  public constructor(repository: AccountRepository) {
    this.repository = repository;
  }

  public async register(input: RegisterAccountInput): Promise<Result<Account, AppError>> {
    const emailRes = parseEmail(input.email);
    if (!emailRes.ok) {
      return emailRes;
    }

    const displayName = input.displayName.trim();
    if (displayName.length === 0) {
      return err(new AppError("invalid_input", "Account displayName must not be empty"));
    }

    const rawId = input.id ?? `acct_${String(this.nextSequence).padStart(4, "0")}`;
    this.nextSequence += 1;
    const idRes = parseAccountId(rawId);
    if (!idRes.ok) {
      return idRes;
    }

    const existing = await this.repository.findByEmail(emailRes.value);
    if (!existing.ok) {
      return existing;
    }
    if (existing.value !== undefined) {
      return err(
        new AppError("conflict", `Account with email ${emailRes.value} already exists`, {
          details: { email: emailRes.value },
        }),
      );
    }

    const account: Account = {
      id: idRes.value,
      email: emailRes.value,
      displayName,
      status: "active",
      createdAt: (input.now ?? (() => new Date().toISOString()))(),
    };

    return this.repository.save(account);
  }

  public async get(id: AccountId): Promise<Result<Account, AppError>> {
    const found = await this.repository.findById(id);
    if (!found.ok) {
      return found;
    }
    if (found.value === undefined) {
      return err(
        new AppError("not_found", `Account ${id} not found`, {
          details: { id },
        }),
      );
    }
    return ok(found.value);
  }

  public async deactivate(id: AccountId): Promise<Result<Account, AppError>> {
    const current = await this.get(id);
    if (!current.ok) {
      return current;
    }
    if (current.value.status === "deactivated") {
      return ok(current.value);
    }
    const updated: Account = {
      ...current.value,
      status: "deactivated",
    };
    return this.repository.save(updated);
  }

  public async listActive(): Promise<Result<readonly Account[], AppError>> {
    const all = await this.repository.list();
    if (!all.ok) {
      return all;
    }
    return ok(all.value.filter((acct) => acct.status === "active"));
  }
}
