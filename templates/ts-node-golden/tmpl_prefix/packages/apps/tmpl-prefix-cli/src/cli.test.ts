import { AccountService } from "tmpl-prefix-accounts";
import { InMemoryAccountRepository } from "tmpl-prefix-storage-memory";
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { runCli } from "./index.js";

describe("tmpl-prefix-cli", () => {
  it("runs health, accounts register, and accounts list commands", async () => {
    const out: string[] = [];
    const errOut: string[] = [];
    const service = new AccountService(new InMemoryAccountRepository());

    const healthCode = await runCli(["health"], {
      stdout: (line) => out.push(line),
      stderr: (line) => errOut.push(line),
      accountService: service,
    });
    assert.equal(healthCode, 0);
    assert.equal(errOut.length, 0);
    const healthReport = JSON.parse(out[0] ?? "{}") as Record<string, unknown>;
    assert.equal(healthReport["status"], "healthy");

    out.length = 0;
    const regCode = await runCli(["accounts", "register", "alan@example.com", "Alan Turing"], {
      stdout: (line) => out.push(line),
      stderr: (line) => errOut.push(line),
      accountService: service,
    });
    assert.equal(regCode, 0);
    const registered = JSON.parse(out[0] ?? "{}") as Record<string, unknown>;
    assert.equal(registered["email"], "alan@example.com");

    out.length = 0;
    const listCode = await runCli(["accounts", "list"], {
      stdout: (line) => out.push(line),
      stderr: (line) => errOut.push(line),
      accountService: service,
    });
    assert.equal(listCode, 0);
    const listed = JSON.parse(out[0] ?? "[]") as unknown[];
    assert.equal(listed.length, 1);

    const badCode = await runCli(["unknown"], {
      stdout: (line) => out.push(line),
      stderr: (line) => errOut.push(line),
      accountService: service,
    });
    assert.equal(badCode, 1);
  });
});
