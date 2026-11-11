import {
  // Workspace API.
  type Account,
  parseAccountId,
  parseEmail,
} from "tmpl-prefix-accounts";
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { InMemoryAccountRepository } from "./index.js";

function mustAccount(id: string, email: string, displayName: string): Account {
  const parsedId = parseAccountId(id);
  const parsedEmail = parseEmail(email);
  if (!parsedId.ok || !parsedEmail.ok) {
    throw new Error("Invalid test fixture");
  }
  return {
    id: parsedId.value,
    email: parsedEmail.value,
    displayName,
    status: "active",
    createdAt: "2026-11-06T00:00:00.000Z",
  };
}

describe("InMemoryAccountRepository", () => {
  it("stores, retrieves, updates, and rejects duplicate emails across accounts", async () => {
    const repo = new InMemoryAccountRepository();
    const first = mustAccount("acct_1", "grace@example.com", "Grace Hopper");

    const saved = await repo.save(first);
    assert.equal(saved.ok, true);

    const byId = await repo.findById(first.id);
    assert.equal(byId.ok, true);
    if (byId.ok) {
      assert.deepEqual(byId.value, first);
    }

    const byEmail = await repo.findByEmail(first.email);
    assert.equal(byEmail.ok, true);
    if (byEmail.ok) {
      assert.deepEqual(byEmail.value, first);
    }

    const updatedSameId: Account = { ...first, status: "deactivated" };
    const reSaved = await repo.save(updatedSameId);
    assert.equal(reSaved.ok, true);

    const conflicting = mustAccount("acct_2", "grace@example.com", "Another Grace");
    const dupRes = await repo.save(conflicting);
    assert.equal(dupRes.ok, false);
    if (!dupRes.ok) {
      assert.equal(dupRes.error.kind, "conflict");
    }

    const listRes = await repo.list();
    assert.equal(listRes.ok, true);
    if (listRes.ok) {
      assert.equal(listRes.value.length, 1);
    }
  });
});
