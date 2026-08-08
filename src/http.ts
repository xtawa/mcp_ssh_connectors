import type { OAuthTokenVerifier } from "@modelcontextprotocol/express";
import { createMcpExpressApp, requireBearerAuth } from "@modelcontextprotocol/express";
import { toNodeHandler } from "@modelcontextprotocol/node";
import type { AuthInfo } from "@modelcontextprotocol/server";
import { createMcpHandler, OAuthError, OAuthErrorCode } from "@modelcontextprotocol/server";
import { verifyApiKey } from "./auth.js";
import { isLoopbackHost, loadConfig } from "./config.js";
import { createMcpServer } from "./mcp.js";

export interface HttpOverrides {
  host?: string;
  port?: number;
}

export async function serveHttp(configPath?: string, overrides: HttpOverrides = {}): Promise<void> {
  const config = await loadConfig(configPath);
  const host = overrides.host ?? config.http.host;
  const port = overrides.port ?? config.http.port;
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error("HTTP port must be from 1 to 65535");
  if (!isLoopbackHost(host) && config.http.allowedHosts.length === 0) {
    throw new Error("http.allowedHosts is required when binding HTTP MCP beyond loopback");
  }

  const verifier: OAuthTokenVerifier = {
    async verifyAccessToken(token): Promise<AuthInfo> {
      const record = await verifyApiKey(config.authKeyStore, token);
      if (!record) throw new OAuthError(OAuthErrorCode.InvalidToken, "unknown, expired, or revoked API key");
      return {
        token,
        clientId: record.id,
        scopes: [...record.scopes, ...record.targets.map((target) => `target:${target}`)],
        expiresAt: Math.floor(Date.parse(record.expiresAt) / 1_000),
      };
    },
  };

  const handler = createMcpHandler(({ authInfo }) => createMcpServer(config, {
    transport: "http",
    clientId: authInfo?.clientId,
    scopes: authInfo?.scopes ?? [],
  }));
  const node = toNodeHandler(handler);
  const app = createMcpExpressApp({
    host,
    ...(config.http.allowedHosts.length > 0 ? { allowedHosts: config.http.allowedHosts } : {}),
    ...(config.http.allowedOrigins.length > 0 ? { allowedOrigins: config.http.allowedOrigins } : {}),
  });
  const auth = requireBearerAuth({ verifier, requiredScopes: ["mcp"] });
  app.all("/mcp", auth, (request, response) => void node(request, response, request.body));

  await new Promise<void>((resolvePromise, rejectPromise) => {
    const listener = app.listen(port, host, () => {
      console.error(`mcp-ssh-connectors listening with Bearer authentication: host=${host} port=${port} path=/mcp`);
    });
    listener.once("error", rejectPromise);
    let closing = false;
    const shutdown = (): void => {
      if (closing) return;
      closing = true;
      void handler.close().finally(() => listener.close(() => resolvePromise()));
    };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
  });
}
