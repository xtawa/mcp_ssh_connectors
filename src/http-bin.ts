#!/usr/bin/env node
import { serveHttp } from "./http.js";

void serveHttp().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
