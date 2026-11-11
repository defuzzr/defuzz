import type {
  // Workspace API.
  AppError,
  Result,
} from "tmpl-prefix-core";
import type { Account, AccountId, Email } from "./model.js";

export interface AccountRepository {
  save(account: Account): Promise<Result<Account, AppError>>;
  findById(id: AccountId): Promise<Result<Account | undefined, AppError>>;
  findByEmail(email: Email): Promise<Result<Account | undefined, AppError>>;
  list(): Promise<Result<readonly Account[], AppError>>;
}
