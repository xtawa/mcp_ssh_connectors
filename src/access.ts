import type { McpAccessContext } from "./types.js";

export interface AccessDecision {
  allowed: boolean;
  reason: string;
}

export const LOCAL_ACCESS: McpAccessContext = {
  transport: "stdio",
  clientId: "local-stdio",
  scopes: ["mcp", "ssh:read", "ssh:exec", "target:*"],
};

export function authorizeAccess(
  access: McpAccessContext,
  requiredScope: "ssh:read" | "ssh:exec",
  target?: string,
): AccessDecision {
  if (access.transport === "stdio") return { allowed: true, reason: "Local stdio transport" };
  if (!access.scopes.includes(requiredScope)) {
    return { allowed: false, reason: `insufficient_scope: requires ${requiredScope}` };
  }
  if (target && !access.scopes.includes("target:*") && !access.scopes.includes(`target:${target}`)) {
    return { allowed: false, reason: `target_forbidden: API key cannot access ${target}` };
  }
  return { allowed: true, reason: "API key scope permits the operation" };
}

export function visibleTargets(access: McpAccessContext, targetNames: string[]): string[] {
  if (access.transport === "stdio" || access.scopes.includes("target:*")) return targetNames;
  return targetNames.filter((target) => access.scopes.includes(`target:${target}`));
}
