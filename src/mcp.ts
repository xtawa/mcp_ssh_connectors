import { McpServer } from "@modelcontextprotocol/server";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";
import { loadConfig } from "./config.js";
import { evaluateCommand, getTarget } from "./policy.js";
import { checkConnection, runRemoteCommand } from "./ssh.js";
import type { ResolvedConfig } from "./types.js";

function textResult(value: unknown, isError = false) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }],
    ...(isError ? { isError: true } : {}),
  };
}

function errorResult(error: unknown) {
  return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
}

function listTargets(config: ResolvedConfig) {
  return Object.entries(config.targets).map(([name, target]) => ({
    name,
    destination: target.destination,
    description: target.description,
    tags: target.tags,
    disabled: target.disabled,
    requireReason: target.requireReason,
  }));
}

export function createMcpServer(config: ResolvedConfig): McpServer {
  const server = new McpServer(
    { name: "mcp-ssh-connectors", version: "0.1.0" },
    {
      instructions:
        "Use only named targets. Preview commands when uncertain. ssh_exec is non-interactive and always re-checks host policy before using the host OpenSSH client.",
    },
  );

  server.registerTool(
    "ssh_list_targets",
    {
      title: "List configured SSH targets",
      description: "List the named SSH targets exposed by the host configuration. No connection is opened.",
      inputSchema: z.object({}),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async () => textResult({ config: config.path, targets: listTargets(config) }),
  );

  server.registerTool(
    "ssh_preview",
    {
      title: "Preview an SSH command",
      description: "Check a command against the target allow/deny policy without connecting or executing it.",
      inputSchema: z.object({
        target: z.string().describe("Named target from ssh_list_targets"),
        command: z.string().describe("Exact single-line remote shell command"),
        reason: z.string().max(500).optional().describe("Human-readable purpose for the audit log"),
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ target, command, reason }) => {
      const decision = evaluateCommand(config, target, command, reason);
      return textResult({
        target,
        destination: config.targets[target]?.destination,
        commandHash: command,
        ...decision,
      });
    },
  );

  server.registerTool(
    "ssh_check",
    {
      title: "Check SSH connectivity",
      description: "Open a non-interactive SSH connection to a named target and run the no-op command 'true'.",
      inputSchema: z.object({ target: z.string().describe("Named target from ssh_list_targets") }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ target }) => {
      try {
        return textResult(await checkConnection(config, target, "mcp"));
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
        "Run one exact, non-interactive command on a configured target through the host OpenSSH client. Deny rules are evaluated before allow rules. Input cannot select arbitrary hosts, SSH options, or key material.",
      inputSchema: z.object({
        target: z.string().describe("Named target from ssh_list_targets"),
        command: z.string().describe("Exact single-line remote shell command"),
        reason: z.string().max(500).optional().describe("Human-readable purpose for the audit log"),
        timeoutMs: z.number().int().min(100).max(600_000).optional().describe("May shorten but never extend the target timeout"),
      }),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    async ({ target, command, reason, timeoutMs }) => {
      try {
        const decision = evaluateCommand(config, target, command, reason);
        if (!decision.allowed) return textResult({ target, command, ...decision }, true);
        const resolvedTarget = getTarget(config, target);
        const effectiveTimeout = Math.min(timeoutMs ?? resolvedTarget.timeoutMs, resolvedTarget.timeoutMs);
        const result = await runRemoteCommand(config, target, command, "mcp", reason, effectiveTimeout);
        return textResult({ policy: decision, result }, !result.ok);
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  return server;
}

export async function serveMcp(configPath?: string): Promise<void> {
  const config = await loadConfig(configPath);
  const server = createMcpServer(config);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`mcp-ssh-connectors serving ${Object.keys(config.targets).length} target(s)`);
}
