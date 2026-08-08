import assert from "node:assert/strict";
import test from "node:test";
import { evaluateCommand } from "../dist/policy.js";

function config(overrides = {}) {
  return {
    path: "/tmp/config.json",
    sshBinary: "ssh",
    auditLog: "/tmp/audit.jsonl",
    auditRequired: true,
    logCommands: false,
    maxCommandLength: 100,
    targets: {
      demo: {
        destination: "demo.example",
        tags: [],
        allowedCommands: ["^(?:hostname|uname -a)$"],
        deniedCommands: ["sudo"],
        disabled: false,
        timeoutMs: 1000,
        connectTimeoutSeconds: 1,
        maxOutputBytes: 1024,
        requireReason: false,
        ...overrides,
      },
    },
  };
}

test("allows commands that match the target allowlist", () => {
  assert.equal(evaluateCommand(config(), "demo", "uname -a").allowed, true);
});

test("deny rules take precedence over allow rules", () => {
  const decision = evaluateCommand(
    config({ allowedCommands: [".*"] }),
    "demo",
    "sudo uname -a",
  );
  assert.equal(decision.allowed, false);
  assert.match(decision.reason, /deny rule/);
});

test("default deny applies when no allow rule exists", () => {
  const decision = evaluateCommand(config({ allowedCommands: [] }), "demo", "hostname");
  assert.equal(decision.allowed, false);
  assert.match(decision.reason, /default deny/);
});

test("rejects multi-line commands", () => {
  assert.equal(evaluateCommand(config(), "demo", "hostname\nuname -a").allowed, false);
});

test("enforces a required reason", () => {
  const secured = config({ requireReason: true });
  assert.equal(evaluateCommand(secured, "demo", "hostname").allowed, false);
  assert.equal(evaluateCommand(secured, "demo", "hostname", "diagnostics").allowed, true);
});
