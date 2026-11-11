import type {
  // Workspace API.
  Account,
  AccountId,
  AccountRepository,
  Email,
} from "tmpl-prefix-accounts";
import {
  // Workspace API.
  AppError,
  err,
  ok,
  type Result,
} from "tmpl-prefix-core";

/**
 * In-memory implementation of `AccountRepository` backed by a `Map`.
 *
 * Production Postgres replacement:
 * Scaffold `packages/adapters/tmpl-prefix-storage-postgres` (`pnpm xtask new-package adapters storage-postgres`),
 * opt into `"postgres": "catalog:"` and `"drizzle-orm": "catalog:"` in its `package.json`,
 * implement `AccountRepository`, and select it in `packages/apps/tmpl-prefix-server/src/wiring.ts`.
 */
export class InMemoryAccountRepository implements AccountRepository {
  private readonly byId = new Map<AccountId, Account>();
  private readonly byEmail = new Map<Email, AccountId>();

  public async save(account: Account): Promise<Result<Account, AppError>> {
    const existingOwner = this.byEmail.get(account.email);
    if (existingOwner !== undefined && existingOwner !== account.id) {
      return err(
        new AppError("conflict", `Email ${account.email} is already bound to another account`, {
          details: { email: account.email, accountId: existingOwner },
        }),
      );
    }
    this.byId.set(account.id, account);
    this.byEmail.set(account.email, account.id);
    return ok(account);
  }

  public async findById(id: AccountId): Promise<Result<Account | undefined, AppError>> {
    return ok(this.byId.get(id));
  }

  public async findByEmail(email: Email): Promise<Result<Account | undefined, AppError>> {
    const id = this.byEmail.get(email);
    if (id === undefined) {
      return ok(undefined);
    }
    return ok(this.byId.get(id));
  }

  public async list(): Promise<Result<readonly Account[], AppError>> {
    return ok([...this.byId.values()]);
  }
}
