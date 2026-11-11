import {
  // Workspace API.
  AccountService,
  AccountsComponent,
} from "tmpl-prefix-accounts";
import {
  // Workspace API.
  fromEnv,
  fromVars,
} from "tmpl-prefix-config";
import {
  // Workspace API.
  type Context,
  Registry,
} from "tmpl-prefix-core";
import { InMemoryAccountRepository } from "tmpl-prefix-storage-memory";
import { createLogger } from "tmpl-prefix-telemetry";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

export interface CliEnvironment {
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly stdout?: (line: string) => void;
  readonly stderr?: (line: string) => void;
  readonly accountService?: AccountService;
}

export async function runCli(argv: readonly string[], cliEnv?: CliEnvironment): Promise<number> {
  const writeOut =
    cliEnv?.stdout ??
    ((line: string): void => {
      process.stdout.write(`${line}\n`);
    });
  const writeErr =
    cliEnv?.stderr ??
    ((line: string): void => {
      process.stderr.write(`${line}\n`);
    });

  let positionals: string[];
  try {
    const parsed = parseArgs({
      args: [...argv],
      options: {},
      strict: true,
      allowPositionals: true,
    });
    positionals = parsed.positionals;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    writeErr(msg);
    return 1;
  }

  const configRes = cliEnv?.env !== undefined ? fromVars(cliEnv.env) : fromEnv();
  if (!configRes.ok) {
    writeErr(configRes.error.message);
    return 1;
  }
  const config = configRes.value;
  const service = cliEnv?.accountService ?? new AccountService(new InMemoryAccountRepository());

  const cmd = positionals[0];
  if (cmd === "health") {
    const logger = createLogger(config.logLevel, config.serviceName, {
      sink: () => {},
    });
    const ctx: Context = {
      environment: config.environment,
      serviceName: config.serviceName,
      logger,
    };
    const registry = new Registry();
    registry.register(new AccountsComponent(service));
    await registry.start(ctx);
    const report = await registry.report();
    await registry.stop();
    writeOut(JSON.stringify(report));
    return report.serving ? 0 : 1;
  }

  if (cmd === "accounts") {
    const sub = positionals[1];
    if (sub === "register") {
      const email = positionals[2];
      const displayName = positionals[3];
      if (email === undefined || displayName === undefined) {
        const program = "tmpl-prefix";
        const usage = `Usage: ${program} accounts register <email> <name>`;
        writeErr(usage);
        return 1;
      }
      const created = await service.register({ email, displayName });
      if (!created.ok) {
        writeErr(created.error.message);
        return 1;
      }
      writeOut(JSON.stringify(created.value));
      return 0;
    }

    if (sub === "list") {
      const listed = await service.listActive();
      if (!listed.ok) {
        writeErr(listed.error.message);
        return 1;
      }
      writeOut(JSON.stringify(listed.value));
      return 0;
    }

    const program = "tmpl-prefix";
    const usage = `Usage: ${program} accounts <register|list>`;
    writeErr(usage);
    return 1;
  }

  const program = "tmpl-prefix";
  const usage = `Usage: ${program} <accounts|health>`;
  writeErr(usage);
  return 1;
}

export function isDirectExecution(metaUrl: string, argv1: string | undefined): boolean {
  if (argv1 === undefined) {
    return false;
  }
  try {
    return realpathSync(fileURLToPath(metaUrl)) === realpathSync(argv1);
  } catch {
    return false;
  }
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  runCli(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`${msg}\n`);
      process.exitCode = 1;
    },
  );
}
