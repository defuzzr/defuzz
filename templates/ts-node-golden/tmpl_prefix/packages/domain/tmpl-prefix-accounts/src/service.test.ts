import {
  // Workspace API.
  type AppError,
  ok,
  type Result,
} from "tmpl-prefix-core";
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  type Account,
  type AccountId,
  type AccountRepository,
  AccountService,
  AccountsComponent,
  type Email,
  parseEmail,
} from "./index.js";

class FakeAccountRepository implements AccountRepository {
  private readonly items = new Map<AccountId, Account>();

  public async save(account: Account): Promise<Result<Account, AppError>> {
    this.items.set(account.id, account);
    return ok(account);
  }

  public async findById(id: AccountId): Promise<Result<Account | undefined, AppError>> {
    return ok(this.items.get(id));
  }

  public async findByEmail(email: Email): Promise<Result<Account | undefined, AppError>> {
    for (const acct of this.items.values()) {
      if (acct.email === email) {
        return ok(acct);
      }
    }
    return ok(undefined);
  }

  public async list(): Promise<Result<readonly Account[], AppError>> {
    return ok([...this.items.values()]);
  }
}

describe("AccountService and AccountsComponent", () => {
  it("validates email addresses, registers accounts, prevents duplicates, and deactivates", async () => {
    const badEmail = parseEmail("not-an-email");
    assert.equal(badEmail.ok, false);

    const repo = new FakeAccountRepository();
    const service = new AccountService(repo);

    const created = await service.register({
      email: "Ada@Example.com",
      displayName: "Ada Lovelace",
      now: () => "2026-11-06T00:00:00.000Z",
    });
    assert.equal(created.ok, true);
    if (!created.ok) {
      return;
    }
    assert.equal(created.value.email, "ada@example.com");
    assert.equal(created.value.status, "active");

    const duplicate = await service.register({
      email: "ada@example.com",
      displayName: "Duplicate Ada",
    });
    assert.equal(duplicate.ok, false);
    if (!duplicate.ok) {
      assert.equal(duplicate.error.kind, "conflict");
    }

    const fetched = await service.get(created.value.id);
    assert.equal(fetched.ok, true);

    const deactivated = await service.deactivate(created.value.id);
    assert.equal(deactivated.ok, true);
    if (deactivated.ok) {
      assert.equal(deactivated.value.status, "deactivated");
    }

    const active = await service.listActive();
    assert.equal(active.ok, true);
    if (active.ok) {
      assert.equal(active.value.length, 0);
    }

    const component = new AccountsComponent(service);
    const beforeStart = await component.health();
    assert.equal(beforeStart.status, "unhealthy");
  });
});
