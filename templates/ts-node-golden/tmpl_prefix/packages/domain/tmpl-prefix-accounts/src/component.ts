import type {
  // Workspace API.
  Component,
  Context,
  Health,
} from "tmpl-prefix-core";
import type { AccountService } from "./service.js";

export class AccountsComponent implements Component {
  public readonly name = "accounts";
  private readonly service: AccountService;
  private started = false;

  public constructor(service: AccountService) {
    this.service = service;
  }

  public async start(ctx: Context): Promise<void> {
    ctx.logger.info("Starting accounts domain component", { component: this.name });
    this.started = true;
  }

  public async stop(): Promise<void> {
    this.started = false;
  }

  public async health(): Promise<Health> {
    if (!this.started) {
      return { status: "unhealthy", reason: "AccountsComponent is not started" };
    }
    const active = await this.service.listActive();
    if (!active.ok) {
      return { status: "degraded", reason: active.error.message };
    }
    return { status: "healthy" };
  }
}
