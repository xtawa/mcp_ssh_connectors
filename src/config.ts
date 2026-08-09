import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { ResolvedConfig, TargetConfig } from "./types.js";

const TARGET_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/;

const EXAMPLE_CONFIG = {
  version: 1,
  sshBinary: "ssh",
  auth: { keyStore: "~/.config/mcp-ssh/keys.json" },
  http: { host: "127.0.0.1", port: 3000, allowedHosts: [], allowedOrigins: [] },
  audit: { required: true, logCommands: false },
  defaults: {
    timeoutMs: 30_000,
    connectTimeoutSeconds: 10,
    maxOutputBytes: 1_048_576,
    knownHostsFile: "~/.ssh/known_hosts",
  },
  policy: {
    maxCommandLength: 4_096,
    deniedCommands: [
      "(?:^|[;&|]\\s*)rm\\s+-rf(?:\\s|$)",
      "(?:^|\\s)sudo(?:\\s|$)",
      "(?:^|\\s)(?:shutdown|reboot|poweroff)(?:\\s|$)",
    ],
  },
  targets: {},
};

export const CONFIG_EXAMPLE = `${JSON.stringify(EXAMPLE_CONFIG, null, 2)}\n`;

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

function objectOrEmpty(value: unknown, label: string): Record<string, unknown> {
  return value === undefined ? {} : asObject(value, label);
}

function stringValue(value: unknown, fallback: string, label: string): string {
  if (value === undefined) return fallback;
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function optionalString(value: unknown, label: string): string | undefined {
  if (value === undefined) return undefined;
  return stringValue(value, "", label);
}

function booleanValue(value: unknown, fallback: boolean, label: string): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
  return value;
}

function integerValue(
  value: unknown,
  fallback: number,
  label: string,
  minimum: number,
  maximum: number,
): number {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new Error(`${label} must be an integer from ${minimum} to ${maximum}`);
  }
  return value as number;
}

function stringArray(value: unknown, label: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || item === "")) {
    throw new Error(`${label} must be an array of non-empty strings`);
  }
  return [...value] as string[];
}

export function expandUserPath(value: string): string {
  if (value === "~") return homedir();
  if (value.startsWith("~/") || value.startsWith("~\\")) {
    return join(homedir(), value.slice(2));
  }
  return value;
}

export function defaultConfigPath(): string {
  if (process.env.MCP_SSH_CONFIG) return resolve(expandUserPath(process.env.MCP_SSH_CONFIG));
  if (process.env.XDG_CONFIG_HOME) return join(process.env.XDG_CONFIG_HOME, "mcp-ssh", "config.json");
  if (process.platform === "win32" && process.env.APPDATA) {
    return join(process.env.APPDATA, "mcp-ssh", "config.json");
  }
  return join(homedir(), ".config", "mcp-ssh", "config.json");
}

function defaultAuditPath(): string {
  if (process.env.XDG_STATE_HOME) return join(process.env.XDG_STATE_HOME, "mcp-ssh", "audit.jsonl");
  if (process.platform === "win32" && process.env.LOCALAPPDATA) {
    return join(process.env.LOCALAPPDATA, "mcp-ssh", "audit.jsonl");
  }
  return join(homedir(), ".local", "state", "mcp-ssh", "audit.jsonl");
}

export function isLoopbackHost(host: string): boolean {
  return host === "127.0.0.1" || host === "localhost" || host === "::1";
}

function validateEndpoint(value: string, label: string): void {
  if (value.startsWith("-") || CONTROL_CHARACTER.test(value)) {
    throw new Error(`${label} may not start with '-' or contain control characters`);
  }
}

function validatePatterns(patterns: string[], label: string): void {
  for (const pattern of patterns) {
    try {
      new RegExp(pattern, "u");
    } catch (error) {
      throw new Error(`${label} contains invalid regular expression ${JSON.stringify(pattern)}: ${String(error)}`);
    }
  }
}

export async function loadConfig(configPath = defaultConfigPath()): Promise<ResolvedConfig> {
  const path = resolve(expandUserPath(configPath));
  const rawText = await readFile(path, "utf8").catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") {
      throw new Error(`SSH connector config not found at ${path}. Run: mcp-ssh init --config ${path}`);
    }
    throw error;
  });

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch (error) {
    throw new Error(`Invalid JSON in ${path}: ${String(error)}`);
  }

  const root = asObject(parsed, "config");
  if (root.version !== undefined && root.version !== 1) throw new Error("config.version must be 1");

  const defaults = objectOrEmpty(root.defaults, "defaults");
  const policy = objectOrEmpty(root.policy, "policy");
  const audit = objectOrEmpty(root.audit, "audit");
  const auth = objectOrEmpty(root.auth, "auth");
  const http = objectOrEmpty(root.http, "http");
  const rawTargets = objectOrEmpty(root.targets, "targets");

  const defaultTimeout = integerValue(defaults.timeoutMs, 30_000, "defaults.timeoutMs", 100, 600_000);
  const defaultConnectTimeout = integerValue(defaults.connectTimeoutSeconds, 10, "defaults.connectTimeoutSeconds", 1, 120);
  const defaultMaxOutput = integerValue(defaults.maxOutputBytes, 1_048_576, "defaults.maxOutputBytes", 1_024, 10_485_760);
  const defaultKnownHosts = optionalString(defaults.knownHostsFile, "defaults.knownHostsFile");
  const globalDeniedCommands = stringArray(policy.deniedCommands, "policy.deniedCommands");
  validatePatterns(globalDeniedCommands, "policy.deniedCommands");

  const targets: Record<string, TargetConfig> = {};
  for (const [name, value] of Object.entries(rawTargets)) {
    if (!TARGET_NAME.test(name)) {
      throw new Error(`Invalid target name ${JSON.stringify(name)}; use letters, numbers, '.', '_' or '-'`);
    }
    const raw = asObject(value, `targets.${name}`);
    const destination = stringValue(raw.destination, "", `targets.${name}.destination`);
    validateEndpoint(destination, `targets.${name}.destination`);

    const proxyJump = optionalString(raw.proxyJump, `targets.${name}.proxyJump`);
    if (proxyJump) validateEndpoint(proxyJump, `targets.${name}.proxyJump`);

    const allowedCommands = stringArray(raw.allowedCommands, `targets.${name}.allowedCommands`);
    const targetDeniedCommands = stringArray(raw.deniedCommands, `targets.${name}.deniedCommands`);
    validatePatterns(allowedCommands, `targets.${name}.allowedCommands`);
    validatePatterns(targetDeniedCommands, `targets.${name}.deniedCommands`);

    const identityFile = optionalString(raw.identityFile, `targets.${name}.identityFile`);
    const knownHostsFile = optionalString(raw.knownHostsFile, `targets.${name}.knownHostsFile`) ?? defaultKnownHosts;
    const description = optionalString(raw.description, `targets.${name}.description`);
    const port = raw.port === undefined ? undefined : integerValue(raw.port, 22, `targets.${name}.port`, 1, 65_535);

    targets[name] = {
      destination,
      description,
      port,
      identityFile: identityFile ? resolve(expandUserPath(identityFile)) : undefined,
      proxyJump,
      knownHostsFile: knownHostsFile ? resolve(expandUserPath(knownHostsFile)) : undefined,
      tags: stringArray(raw.tags, `targets.${name}.tags`),
      allowedCommands,
      deniedCommands: [...globalDeniedCommands, ...targetDeniedCommands],
      disabled: booleanValue(raw.disabled, false, `targets.${name}.disabled`),
      timeoutMs: integerValue(raw.timeoutMs, defaultTimeout, `targets.${name}.timeoutMs`, 100, 600_000),
      connectTimeoutSeconds: integerValue(raw.connectTimeoutSeconds, defaultConnectTimeout, `targets.${name}.connectTimeoutSeconds`, 1, 120),
      maxOutputBytes: integerValue(raw.maxOutputBytes, defaultMaxOutput, `targets.${name}.maxOutputBytes`, 1_024, 10_485_760),
      requireReason: booleanValue(raw.requireReason, false, `targets.${name}.requireReason`),
    };
  }

  const host = stringValue(http.host, "127.0.0.1", "http.host");
  const allowedHosts = stringArray(http.allowedHosts, "http.allowedHosts");
  if (!isLoopbackHost(host) && allowedHosts.length === 0) {
    throw new Error("http.allowedHosts is required when http.host is not loopback");
  }
  const keyStore = optionalString(auth.keyStore, "auth.keyStore") ?? join(dirname(path), "keys.json");
  const auditPath = stringValue(audit.path, defaultAuditPath(), "audit.path");

  return {
    path,
    sshBinary: expandUserPath(stringValue(root.sshBinary, "ssh", "sshBinary")),
    authKeyStore: resolve(expandUserPath(keyStore)),
    http: {
      host,
      port: integerValue(http.port, 3_000, "http.port", 1, 65_535),
      allowedHosts,
      allowedOrigins: stringArray(http.allowedOrigins, "http.allowedOrigins"),
    },
    auditLog: resolve(expandUserPath(auditPath)),
    auditRequired: booleanValue(audit.required, true, "audit.required"),
    logCommands: booleanValue(audit.logCommands, false, "audit.logCommands"),
    maxCommandLength: integerValue(policy.maxCommandLength, 4_096, "policy.maxCommandLength", 1, 65_536),
    dynamicDefaults: {
      timeoutMs: defaultTimeout,
      connectTimeoutSeconds: defaultConnectTimeout,
      maxOutputBytes: defaultMaxOutput,
      knownHostsFile: defaultKnownHosts ? resolve(expandUserPath(defaultKnownHosts)) : undefined,
    },
    targets,
  };
}

export async function initializeConfig(configPath = defaultConfigPath()): Promise<string> {
  const path = resolve(expandUserPath(configPath));
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, CONFIG_EXAMPLE, { encoding: "utf8", flag: "wx", mode: 0o600 }).catch(
    (error: NodeJS.ErrnoException) => {
      if (error.code === "EEXIST") throw new Error(`Refusing to overwrite existing config at ${path}`);
      throw error;
    },
  );
  return path;
}
