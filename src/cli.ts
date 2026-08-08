#!/usr/bin/env node
import { defaultConfigPath, initializeConfig, loadConfig } from "./config.js";
import { evaluateCommand } from "./policy.js";
import { checkConnection, connectInteractive, runRemoteCommand } from "./ssh.js";
import { serveMcp } from "./mcp.js";

const HELP = `mcp-ssh - host-side OpenSSH bridge for MCP and humans

Usage:
  mcp-ssh init [--config PATH]
  mcp-ssh targets [--config PATH]
  mcp-ssh preview TARGET [--reason TEXT] -- COMMAND
  mcp-ssh check TARGET [--config PATH]
  mcp-ssh exec TARGET [--reason TEXT] -- COMMAND
  mcp-ssh connect TARGET [--config PATH]
  mcp-ssh mcp [--config PATH]

Examples:
  mcp-ssh init
  mcp-ssh check staging
  mcp-ssh exec staging -- uname -a
  mcp-ssh exec prod --reason "inspect service" -- "systemctl status nginx"
  mcp-ssh connect staging
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
  const separator = args.indexOf("--");
  const searchEnd = separator === -1 ? args.length : separator;
  const index = args.slice(0, searchEnd).indexOf("--reason");
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (!value) throw new Error("--reason requires a value");
  args.splice(index, 2);
  return value;
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
    process.stdout.write(`Created ${path}\nEdit the target and policy before use.\n`);
    return;
  }
  if (command === "mcp") {
    await serveMcp(configPath);
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
    const result = await runRemoteCommand(config, target, remoteCommand, "cli", reason);
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
