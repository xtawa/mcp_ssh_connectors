export interface TargetConfig {
  destination: string;
  description?: string;
  port?: number;
  identityFile?: string;
  proxyJump?: string;
  knownHostsFile?: string;
  tags: string[];
  allowedCommands: string[];
  deniedCommands: string[];
  disabled: boolean;
  timeoutMs: number;
  connectTimeoutSeconds: number;
  maxOutputBytes: number;
  requireReason: boolean;
}

export interface HttpConfig {
  host: string;
  port: number;
  allowedHosts: string[];
  allowedOrigins: string[];
}

export interface ResolvedConfig {
  path: string;
  sshBinary: string;
  authKeyStore: string;
  http: HttpConfig;
  auditLog: string;
  auditRequired: boolean;
  logCommands: boolean;
  maxCommandLength: number;
  targets: Record<string, TargetConfig>;
}

export type ExecutionSource = "mcp" | "mcp-http" | "cli";

export interface RemoteCommandOptions {
  source: ExecutionSource;
  reason?: string;
  timeoutMs?: number;
  eventType?: "exec" | "check";
  actor?: string;
}

export interface McpAccessContext {
  transport: "stdio" | "http";
  clientId?: string;
  scopes: string[];
}

export interface PolicyDecision {
  allowed: boolean;
  reason: string;
  matchedPattern?: string;
}

export interface ExecResult {
  requestId: string;
  target: string;
  destination: string;
  ok: boolean;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  timedOut: boolean;
  truncated: boolean;
  durationMs: number;
  stdout: string;
  stderr: string;
}
