import type {
  // Workspace API.
  BoundServerAddress,
  HttpServer,
  Routes,
} from "tmpl-prefix-core";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

export class NodeHttpServer implements HttpServer {
  private readonly routes: Routes;
  private server: Server | undefined;

  public constructor(routes: Routes) {
    this.routes = routes;
  }

  public async listen(port: number, host: string): Promise<BoundServerAddress> {
    if (this.server !== undefined) {
      throw new Error("NodeHttpServer is already listening");
    }

    const srv = createServer((req: IncomingMessage, res: ServerResponse) => {
      void this.handleRequest(req, res);
    });

    const boundPort = await new Promise<number>((resolve, reject) => {
      srv.once("error", reject);
      srv.listen(port, host, () => {
        srv.removeListener("error", reject);
        const addr = srv.address();
        if (addr !== null && typeof addr === "object") {
          resolve(addr.port);
        } else {
          reject(new Error("Failed to resolve bound port for NodeHttpServer"));
        }
      });
    });

    this.server = srv;
    return { port: boundPort };
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

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const method = req.method ?? "GET";
    const rawUrl = req.url ?? "/";
    const pathname = new URL(rawUrl, "http://localhost").pathname;

    if (method !== "GET") {
      this.sendJson(res, 404, { error: "not_found", path: pathname });
      return;
    }

    const handler = this.routes[pathname];
    if (handler === undefined) {
      this.sendJson(res, 404, { error: "not_found", path: pathname });
      return;
    }

    try {
      const result = await handler();
      this.sendJson(res, result.status, result.body);
    } catch (err: unknown) {
      this.sendJson(res, 500, {
        error: "internal",
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  private sendJson(
    res: ServerResponse,
    status: number,
    body: Readonly<Record<string, unknown>>,
  ): void {
    const payload = JSON.stringify(body);
    res.writeHead(status, {
      "content-type": "application/json; charset=utf-8",
      "content-length": String(Buffer.byteLength(payload)),
    });
    res.end(payload);
  }
}
