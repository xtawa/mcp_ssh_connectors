import type { PolicyDecision, ResolvedConfig, TargetConfig } from "./types.js";

function match(patterns: string[], command: string): string | undefined {
  return patterns.find((pattern) => new RegExp(pattern, "u").test(command));
}

export function getTarget(config: ResolvedConfig, targetName: string): TargetConfig {
  const target = config.targets[targetName];
  if (!target) throw new Error(`Unknown target ${JSON.stringify(targetName)}`);
  return target;
}

export function evaluateCommand(
  config: ResolvedConfig,
  targetName: string,
  command: string,
  reason?: string,
): PolicyDecision {
  const target = config.targets[targetName];
  if (!target) return { allowed: false, reason: `Unknown target ${JSON.stringify(targetName)}` };
  if (target.disabled) return { allowed: false, reason: `Target ${targetName} is disabled` };
  if (command.trim() === "") return { allowed: false, reason: "Command may not be empty" };
  if (command.includes("\0") || command.includes("\n") || command.includes("\r")) {
    return { allowed: false, reason: "NUL and multi-line commands are not accepted" };
  }
  if (Buffer.byteLength(command, "utf8") > config.maxCommandLength) {
    return { allowed: false, reason: `Command exceeds the ${config.maxCommandLength}-byte limit` };
  }
  if (target.requireReason && !reason?.trim()) {
    return { allowed: false, reason: `Target ${targetName} requires a non-empty reason` };
  }

  const deniedPattern = match(target.deniedCommands, command);
  if (deniedPattern) {
    return { allowed: false, reason: "Command matched a deny rule", matchedPattern: deniedPattern };
  }
  if (target.allowedCommands.length === 0) {
    return { allowed: false, reason: "Target has no allowedCommands rules; default deny is active" };
  }

  const allowedPattern = match(target.allowedCommands, command);
  if (!allowedPattern) return { allowed: false, reason: "Command did not match an allow rule" };
  return { allowed: true, reason: "Command matched an allow rule", matchedPattern: allowedPattern };
}
