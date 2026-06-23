#!/usr/bin/env node
"use strict";

// Thin launcher: ensures the native binary exists (downloading it on first run if a
// postinstall was skipped), then forwards all arguments to it and mirrors its exit code.

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const bin = path.join(
  __dirname,
  process.platform === "win32" ? "envo.exe" : "envo"
);

if (!fs.existsSync(bin)) {
  const install = spawnSync(process.execPath, [path.join(__dirname, "install.js")], {
    stdio: "inherit",
  });
  if (install.status !== 0) {
    process.exit(install.status || 1);
  }
}

const run = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
if (run.error) {
  console.error(`[envo] failed to run binary: ${run.error.message}`);
  process.exit(1);
}
process.exit(run.status === null ? 1 : run.status);
