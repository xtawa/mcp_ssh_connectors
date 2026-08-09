import { McpServer } from "@modelcontextprotocol/server";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";
import { authorizeAccess, LOCAL_ACCESS, visibleTargets } from "./access.js";
import { commandFingerprint } from "./audit.js";
import { loadConfig } from "./config.js";
import { evaluateCommand, evaluateDynamicCommand, getTarget } from "./policy.js";
import { checkConnection, checkDynamicConnection, runDynamicCommand, runRemoteCommand } from "./ssh.js";
import type { McpAccessContext, ResolvedConfig } from "./types.js";

function textResult(value: unknown, isError = false) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }],
    ...(isError ? { isError: true } : {}),
  };
}

function errorResult(error: unknown) {
  return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
}

function listTargets(config: ResolvedConfig, access: McpAccessContext) {
  const visible = new Set(visibleTargets(access, Object.keys(config.targets)));
  return Object.entries(config.targets)
    .filter(([name]) => visible.has(name))
    .map(([name, target]) => ({
      name,
      destination: target.destination,
      description: target.description,
      tags: target.tags,
      disabled: target.disabled,
      requireReason: target.requireReason,
    }));
}

const dynamicAuthenticationSchema = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("password"),
    password: z.string().min(1).max(4_096).describe("Sensitive SSH password; never logged or returned"),
  }),
  z.object({
    type: z.literal("privateKey"),
    privateKey: z.string().min(1).max(262_144).describe("Sensitive OpenSSH or PEM private-key content; never logged or returned"),
    passphrase: z.string().min(1).max(4_096).optional().describe("Optional sensitive private-key passphrase; never logged or returned"),
  }),
]);

const dynamicConnectionSchema = z.object({
  host: z.string().min(1).max(253).describe("SSH hostname or IP address"),
  username: z.string().min(1).max(128).describe("Remote SSH username"),
  port: z.number().int().min(1).max(65_535).optional().describe("SSH port; defaults to 22"),
  authentication: dynamicAuthenticationSchema,
});

function requireExactlyOneConnection(
  value: { target?: string; connection?: unknown },
  context: z.core.$RefinementCtx,
): void {
  if ((value.target === undefined) === (value.connection === undefined)) {
    context.addIssue({ code: "custom", message: "Provide exactly one of target or connection" });
  }
}

export function createMcpServer(config: ResolvedConfig, access: McpAccessContext = LOCAL_ACCESS): McpServer {
  const source = access.transport === "http" ? "mcp-http" : "mcp";
  const server = new McpServer(
    { name: "mcp-ssh-connectors", version: "0.3.0" },
    {
      instructions:
        "ssh_check and ssh_exec accept either a configured target or an arbitrary dynamic connection with a password/private key. Dynamic commands are unrestricted after single-line and size validation. Never repeat credentials in output.",
    },
  );

  server.registerTool(
    "ssh_list_targets",
    {
      title: "List configured SSH targets",
      description: "List the SSH targets visible to the authenticated caller. Requires ssh:read over HTTP.",
      inputSchema: z.object({}),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async () => {
      const accessDecision = authorizeAccess(access, "ssh:read");
      if (!accessDecision.allowed) return textResult(accessDecision, true);
      return textResult({ actor: access.clientId, config: config.path, targets: listTargets(config, access) });
    },
  );

  server.registerTool(
    "ssh_preview",
    {
      title: "Preview an SSH command",
      description: "Check a command against API-key target scope and host policy without executing it. Requires ssh:read.",
      inputSchema: z.object({
        target: z.string().describe("Named target from ssh_list_targets"),
        command: z.string().describe("Exact single-line remote shell command"),
        reason: z.string().max(500).optional().describe("Human-readable purpose for the audit log"),
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ target, command, reason }) => {
      const accessDecision = authorizeAccess(access, "ssh:read", target);
      if (!accessDecision.allowed) return textResult(accessDecision, true);
      const decision = evaluateCommand(config, target, command, reason);
      return textResult({ target, destination: config.targets[target]?.destination, commandHash: commandFingerprint(command), access: accessDecision, ...decision });
    },
  );

  server.registerTool(
    "ssh_check",
    {
      title: "Check SSH connectivity",
      description: "Connect to a configured target or any SSH server and run the no-op command 'true'. Requires ssh:read.",
      inputSchema: z.object({
        target: z.string().optional().describe("Configured target from ssh_list_targets"),
        connection: dynamicConnectionSchema.optional().describe("Arbitrary SSH server and request-scoped credential"),
      }).superRefine(requireExactlyOneConnection),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ target, connection }) => {
      const accessDecision = authorizeAccess(access, "ssh:read", target);
      if (!accessDecision.allowed) return textResult(accessDecision, true);
      try {
        if (connection) return textResult(await checkDynamicConnection(config, connection, source, access.clientId));
        return textResult(await checkConnection(config, target!, source, access.clientId));
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  server.registerTool(
    "ssh_exec",
    {
      title: "Execute an SSH command",
      description:
        "Run one exact non-interactive command on a configured target or any SSH server. Dynamic connections accept any validated single-line command. Requires ssh:exec.",
      inputSchema: z.object({
        target: z.string().optional().describe("Configured target from ssh_list_targets"),
        connection: dynamicConnectionSchema.optional().describe("Arbitrary SSH server and request-scoped credential"),
        command: z.string().describe("Exact single-line remote shell command"),
        reason: z.string().max(500).optional().describe("Human-readable purpose for the audit log"),
        timeoutMs: z.number().int().min(100).max(600_000).optional().describe("May shorten but never extend the target timeout"),
      }).superRefine(requireExactlyOneConnection),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    async ({ target, connection, command, reason, timeoutMs }) => {
      const accessDecision = authorizeAccess(access, "ssh:exec", target);
      if (!accessDecision.allowed) return textResult(accessDecision, true);
      try {
        if (connection) {
          const decision = evaluateDynamicCommand(config, command);
          if (!decision.allowed) return textResult({ destination: `${connection.username}@${connection.host}:${connection.port ?? 22}`, access: accessDecision, ...decision }, true);
          const result = await runDynamicCommand(config, connection, command, {
            source,
            actor: access.clientId,
            reason,
            timeoutMs: Math.min(timeoutMs ?? config.dynamicDefaults.timeoutMs, config.dynamicDefaults.timeoutMs),
          });
          return textResult({ access: accessDecision, policy: decision, result }, !result.ok);
        }
        const configuredTarget = target!;
        const decision = evaluateCommand(config, configuredTarget, command, reason);
        if (!decision.allowed) return textResult({ target: configuredTarget, command, access: accessDecision, ...decision }, true);
        const resolvedTarget = getTarget(config, configuredTarget);
        const result = await runRemoteCommand(config, configuredTarget, command, {
          source,
          actor: access.clientId,
          reason,
          timeoutMs: Math.min(timeoutMs ?? resolvedTarget.timeoutMs, resolvedTarget.timeoutMs),
        });
        return textResult({ access: accessDecision, policy: decision, result }, !result.ok);
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  return server;
}

export async function serveMcp(configPath?: string): Promise<void> {
  const config = await loadConfig(configPath);
  const server = createMcpServer(config, LOCAL_ACCESS);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`mcp-ssh-connectors serving ${Object.keys(config.targets).length} target(s) over stdio`);
}
