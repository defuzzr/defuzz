export interface HttpResponse {
  readonly status: number;
  readonly body: Readonly<Record<string, unknown>>;
}

export type RouteHandler = () => Promise<HttpResponse> | HttpResponse;

export type Routes = Readonly<Record<string, RouteHandler>>;

export interface BoundServerAddress {
  readonly port: number;
}

export interface HttpServer {
  listen(port: number, host: string): Promise<BoundServerAddress>;
  close(): Promise<void>;
}
