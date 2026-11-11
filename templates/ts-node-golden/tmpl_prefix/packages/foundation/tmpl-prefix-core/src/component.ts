export type LogFields = Readonly<Record<string, unknown>>;

export interface Logger {
  debug(message: string, fields?: LogFields): void;
  info(message: string, fields?: LogFields): void;
  warn(message: string, fields?: LogFields): void;
  error(message: string, fields?: LogFields): void;
  child(boundFields: LogFields): Logger;
}

export type Health =
  | { readonly status: "healthy" }
  | { readonly status: "degraded"; readonly reason: string }
  | { readonly status: "unhealthy"; readonly reason: string };

export interface Context {
  readonly environment: string;
  readonly serviceName: string;
  readonly logger: Logger;
  readonly signal?: AbortSignal;
}

export interface Component {
  readonly name: string;
  start(ctx: Context): Promise<void>;
  stop(): Promise<void>;
  health(): Promise<Health>;
}

export interface ComponentReportEntry {
  readonly name: string;
  readonly health: Health;
}

export interface HealthReport {
  readonly status: "healthy" | "degraded" | "unhealthy";
  readonly serving: boolean;
  readonly components: readonly ComponentReportEntry[];
}

export class Registry {
  private readonly components: Component[] = [];
  private readonly names = new Set<string>();
  private started: Component[] = [];
  private running = false;

  public register(component: Component): void {
    if (this.names.has(component.name)) {
      throw new Error(`Duplicate component name registered: ${component.name}`);
    }
    this.names.add(component.name);
    this.components.push(component);
  }

  public listNames(): readonly string[] {
    return this.components.map((c) => c.name);
  }

  public async start(ctx: Context): Promise<void> {
    if (this.running) {
      throw new Error("Registry is already started");
    }
    const newlyStarted: Component[] = [];
    try {
      for (const component of this.components) {
        if (ctx.signal?.aborted === true) {
          throw new Error(`Startup aborted before starting component ${component.name}`);
        }
        await component.start(ctx);
        newlyStarted.push(component);
      }
      this.started = newlyStarted;
      this.running = true;
    } catch (startErr: unknown) {
      for (let i = newlyStarted.length - 1; i >= 0; i -= 1) {
        const comp = newlyStarted[i];
        if (comp !== undefined) {
          try {
            await comp.stop();
          } catch (stopErr: unknown) {
            ctx.logger.error("Failed to roll back component during startup failure", {
              component: comp.name,
              error: stopErr instanceof Error ? stopErr.message : String(stopErr),
            });
          }
        }
      }
      this.started = [];
      this.running = false;
      throw startErr;
    }
  }

  public async stop(): Promise<void> {
    const toStop = [...this.started].reverse();
    this.started = [];
    this.running = false;
    const errors: unknown[] = [];
    for (const component of toStop) {
      try {
        await component.stop();
      } catch (err: unknown) {
        errors.push(err);
      }
    }
    if (errors.length > 0) {
      throw new AggregateError(errors, "One or more components failed to stop cleanly");
    }
  }

  public async isServing(): Promise<boolean> {
    if (!this.running) {
      return false;
    }
    const currentReport = await this.report();
    return currentReport.serving;
  }

  public async report(): Promise<HealthReport> {
    if (!this.running) {
      return {
        status: "unhealthy",
        serving: false,
        components: this.components.map((c) => ({
          name: c.name,
          health: { status: "unhealthy", reason: "Registry not started" },
        })),
      };
    }

    const entries: ComponentReportEntry[] = [];
    let overall: "healthy" | "degraded" | "unhealthy" = "healthy";

    for (const component of this.started) {
      let health: Health;
      try {
        health = await component.health();
      } catch (err: unknown) {
        health = {
          status: "unhealthy",
          reason: err instanceof Error ? err.message : String(err),
        };
      }
      entries.push({ name: component.name, health });
      if (health.status === "unhealthy") {
        overall = "unhealthy";
      } else if (health.status === "degraded" && overall === "healthy") {
        overall = "degraded";
      }
    }

    return {
      status: overall,
      serving: overall !== "unhealthy",
      components: entries,
    };
  }
}
