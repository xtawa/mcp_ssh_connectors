#!/usr/bin/env node
import { serveMcp } from "./mcp.js";

void serveMcp().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
