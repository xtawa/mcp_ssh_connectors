import { McpServer } from "@modelcontextprotocol/server";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";
import { authorizeAccess, LOCAL_ACCESS, visibleTargets } from "./access.js";
import { commandFingerprint } from "./audit.js";
import { loadConfig } from "./config.js";
import { evaluateCommand, getTarget } from "./policy.js";
import { checkConnection, runRemoteCommand } from "./ssh.js";
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

export function createMcpServer(config: ResolvedConfig, access: McpAccessContext = LOCAL_ACCESS): McpServer {
  const source = access.transport === "http" ? "mcp-http" : "mcp";
  const server = new McpServer(
    { name: "mcp-ssh-connectors", version: "0.2.0" },
    {
      instructions:
        "Use only named targets. Preview commands when uncertain. HTTP callers need ssh:read or ssh:exec plus an allowed target. ssh_exec always re-checks host policy.",
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
      description: "Connect to an allowed target and run the no-op command 'true'. Requires ssh:read.",
      inputSchema: z.object({ target: z.string().describe("Named target from ssh_list_targets") }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ target }) => {
      const accessDecision = authorizeAccess(access, "ssh:read", target);
      if (!accessDecision.allowed) return textResult(accessDecision, true);
      try {
        return textResult(await checkConnection(config, target, source, access.clientId));
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  server.registerTool(
    "ssh_exec",
    {
      title: "Execute a policy-approved SSH command",
      description:
        "Run one exact, non-interactive command through host OpenSSH. Requires ssh:exec and target access; host deny/allow rules are then enforced.",
      inputSchema: z.object({
        target: z.string().describe("Named target from ssh_list_targets"),
        command: z.string().describe("Exact single-line remote shell command"),
        reason: z.string().max(500).optional().describe("Human-readable purpose for the audit log"),
        timeoutMs: z.number().int().min(100).max(600_000).optional().describe("May shorten but never extend the target timeout"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    async ({ target, command, reason, timeoutMs }) => {
      const accessDecision = authorizeAccess(access, "ssh:exec", target);
      if (!accessDecision.allowed) return textResult(accessDecision, true);
      try {
        const decision = evaluateCommand(config, target, command, reason);
        if (!decision.allowed) return textResult({ target, command, access: accessDecision, ...decision }, true);
        const resolvedTarget = getTarget(config, target);
        const result = await runRemoteCommand(config, target, command, {
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
