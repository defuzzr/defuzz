import { Hono } from "hono";
import type {
  // Workspace API.
  BoundServerAddress,
  HttpServer,
  Routes,
} from "tmpl-prefix-core";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { serve } from "@hono/node-server";

export class HonoHttpServer implements HttpServer {
  private readonly routes: Routes;
  private server: Server | undefined;

  public constructor(routes: Routes) {
    this.routes = routes;
  }

  public async listen(port: number, host: string): Promise<BoundServerAddress> {
    if (this.server !== undefined) {
      throw new Error("HonoHttpServer is already listening");
    }

    const app = new Hono();

    for (const [routePath, handler] of Object.entries(this.routes)) {
      app.get(routePath, async () => {
        try {
          const result = await handler();
          return new Response(JSON.stringify(result.body), {
            status: result.status,
            headers: {
              "content-type": "application/json; charset=utf-8",
            },
          });
        } catch (err: unknown) {
          return new Response(
            JSON.stringify({
              error: "internal",
              message: err instanceof Error ? err.message : String(err),
            }),
            {
              status: 500,
              headers: {
                "content-type": "application/json; charset=utf-8",
              },
            },
          );
        }
      });
    }

    app.all("*", (ctx) => {
      const pathname = new URL(ctx.req.url, "http://localhost").pathname;
      return new Response(JSON.stringify({ error: "not_found", path: pathname }), {
        status: 404,
        headers: {
          "content-type": "application/json; charset=utf-8",
        },
      });
    });

    const bound = await new Promise<{ readonly server: Server; readonly port: number }>(
      (resolve, reject) => {
        try {
          const srv = serve(
            {
              fetch: app.fetch,
              port,
              hostname: host,
            },
            (info: AddressInfo) => {
              resolve({ server: srv as Server, port: info.port });
            },
          );
          srv.once("error", reject);
        } catch (err: unknown) {
          reject(err);
        }
      },
    );

    this.server = bound.server;
    return { port: bound.port };
  }

  public async close(): Promise<void> {
    const srv = this.server;
    this.server = undefined;
    if (srv === undefined) {
      return;
    }
    await new Promise<void>((resolve, reject) => {
      srv.close((err) => {
        if (err !== undefined && err !== null) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }
}
