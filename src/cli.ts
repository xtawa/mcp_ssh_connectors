#!/usr/bin/env node
import { createApiKey, listApiKeys, parseExpiry, revokeApiKey } from "./auth.js";
import { defaultConfigPath, initializeConfig, loadConfig } from "./config.js";
import { serveHttp } from "./http.js";
import { serveMcp } from "./mcp.js";
import { evaluateCommand } from "./policy.js";
import { checkConnection, connectInteractive, runRemoteCommand } from "./ssh.js";

const HELP = `mcp-ssh - host-side OpenSSH bridge for MCP and humans

Usage:
  mcp-ssh init [--config PATH]
  mcp-ssh targets [--config PATH]
  mcp-ssh preview TARGET [--reason TEXT] -- COMMAND
  mcp-ssh check TARGET [--config PATH]
  mcp-ssh exec TARGET [--reason TEXT] -- COMMAND
  mcp-ssh connect TARGET [--config PATH]
  mcp-ssh mcp [--config PATH]
  mcp-ssh http [--host HOST] [--port PORT] [--config PATH]
  mcp-ssh key create NAME [--targets LIST] [--scopes LIST] [--expires 30d]
  mcp-ssh key list
  mcp-ssh key revoke KEY_ID

API key scopes: mcp, ssh:read, ssh:exec. New keys default to mcp,ssh:read.
New keys default to target '*' so their SSH scopes can use dynamic connections.
`;

function takeOption(args: string[], name: string): string | undefined {
  const separator = args.indexOf("--");
  const searchEnd = separator === -1 ? args.length : separator;
  const index = args.slice(0, searchEnd).indexOf(name);
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (!value) throw new Error(`${name} requires a value`);
  args.splice(index, 2);
  return value;
}

function takeReason(args: string[]): string | undefined {
  return takeOption(args, "--reason");
}

function csv(value: string): string[] {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}

function shellQuote(value: string): string {
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(value)) return value;
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function commandFrom(parts: string[]): string {
  if (parts[0] === "--") parts = parts.slice(1);
  if (parts.length === 0) throw new Error("A remote command is required after --");
  return parts.length === 1 ? parts[0]! : parts.map(shellQuote).join(" ");
}

async function manageKeys(configPath: string | undefined, args: string[]): Promise<void> {
  const action = args.shift();
  const config = await loadConfig(configPath);
  if (action === "list") {
    process.stdout.write(`${JSON.stringify(await listApiKeys(config.authKeyStore), null, 2)}\n`);
    return;
  }
  if (action === "revoke") {
    const id = args.shift();
    if (!id) throw new Error("key revoke requires a key id");
    const record = await revokeApiKey(config.authKeyStore, id);
    process.stdout.write(`Revoked ${record.id} (${record.name})\n`);
    return;
  }
  if (action === "create") {
    const name = args.shift();
    if (!name) throw new Error("key create requires a name");
    const targets = csv(takeOption(args, "--targets") ?? "*");
    const scopes = csv(takeOption(args, "--scopes") ?? "mcp,ssh:read");
    const expiresAt = parseExpiry(takeOption(args, "--expires") ?? "30d");
    if (!targets.includes("*")) {
      const unknown = targets.filter((target) => !config.targets[target]);
      if (unknown.length > 0) throw new Error(`Unknown target(s): ${unknown.join(", ")}`);
    }
    const created = await createApiKey(config.authKeyStore, { name, targets, scopes, expiresAt });
    process.stdout.write(
      `API key created. Save it now; it will not be shown again.\n` +
      `id: ${created.record.id}\nname: ${created.record.name}\nexpires: ${created.record.expiresAt}\n` +
      `scopes: ${created.record.scopes.join(",")}\ntargets: ${created.record.targets.join(",")}\n` +
      `token: ${created.token}\n`,
    );
    return;
  }
  throw new Error("Usage: mcp-ssh key create|list|revoke");
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const configPath = takeOption(args, "--config");
  const command = args.shift();

  if (!command || command === "help" || command === "--help" || command === "-h") {
    process.stdout.write(HELP);
    return;
  }
  if (command === "init") {
    const path = await initializeConfig(configPath ?? defaultConfigPath());
    process.stdout.write(`Created ${path}\nDynamic MCP connections are ready; configured targets remain optional.\n`);
    return;
  }
  if (command === "mcp") {
    await serveMcp(configPath);
    return;
  }
  if (command === "http") {
    const host = takeOption(args, "--host");
    const rawPort = takeOption(args, "--port");
    const port = rawPort === undefined ? undefined : Number(rawPort);
    await serveHttp(configPath, { host, port });
    return;
  }
  if (command === "key") {
    await manageKeys(configPath, args);
    return;
  }

  const config = await loadConfig(configPath);
  if (command === "targets") {
    const targets = Object.entries(config.targets).map(([name, target]) => ({
      name,
      destination: target.destination,
      description: target.description,
      tags: target.tags,
      disabled: target.disabled,
      requireReason: target.requireReason,
    }));
    process.stdout.write(`${JSON.stringify(targets, null, 2)}\n`);
    return;
  }

  const target = args.shift();
  if (!target) throw new Error(`${command} requires a target name`);
  if (command === "check") {
    const result = await checkConnection(config, target, "cli");
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.exitCode = result.ok ? 0 : result.exitCode ?? 1;
    return;
  }
  if (command === "connect") {
    process.exitCode = connectInteractive(config, target);
    return;
  }
  if (command === "preview" || command === "exec") {
    const reason = takeReason(args);
    const remoteCommand = commandFrom(args);
    const decision = evaluateCommand(config, target, remoteCommand, reason);
    if (command === "preview" || !decision.allowed) {
      process.stdout.write(`${JSON.stringify({ target, command: remoteCommand, ...decision }, null, 2)}\n`);
      process.exitCode = decision.allowed ? 0 : 2;
      return;
    }
    const result = await runRemoteCommand(config, target, remoteCommand, { source: "cli", reason });
    process.stdout.write(`${JSON.stringify({ policy: decision, result }, null, 2)}\n`);
    process.exitCode = result.ok ? 0 : result.exitCode ?? 1;
    return;
  }

  throw new Error(`Unknown command ${JSON.stringify(command)}\n\n${HELP}`);
}

void main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
