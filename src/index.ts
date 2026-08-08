export { CONFIG_EXAMPLE, defaultConfigPath, initializeConfig, loadConfig } from "./config.js";
export { createMcpServer, serveMcp } from "./mcp.js";
export { evaluateCommand, getTarget } from "./policy.js";
export { checkConnection, connectInteractive, runRemoteCommand } from "./ssh.js";
export type { ExecResult, ExecutionSource, PolicyDecision, ResolvedConfig, TargetConfig } from "./types.js";
