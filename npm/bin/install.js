#!/usr/bin/env node
"use strict";

// Downloads the correct prebuilt envo binary from GitHub Releases and places it
// next to this script. Runs on `npm install` (postinstall) and, as a fallback,
// is invoked by cli.js the first time the binary is missing.

const fs = require("fs");
const path = require("path");
const https = require("https");
const { execFileSync } = require("child_process");

const pkg = require("../package.json");
const REPO = "horiastanxd/envo";
const VERSION = pkg.version;

const TARGETS = {
  "linux-x64": "x86_64-unknown-linux-musl",
  "linux-arm64": "aarch64-unknown-linux-musl",
  "darwin-x64": "x86_64-apple-darwin",
  "darwin-arm64": "aarch64-apple-darwin",
  "win32-x64": "x86_64-pc-windows-msvc",
};

function resolveTarget() {
  const key = `${process.platform}-${process.arch}`;
  const target = TARGETS[key];
  if (!target) {
    throw new Error(
      `unsupported platform "${key}". Install with: cargo install envo-cli`
    );
  }
  return target;
}

function binName() {
  return process.platform === "win32" ? "envo.exe" : "envo";
}

function download(url, dest) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { "User-Agent": "envo-installer" } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          return download(res.headers.location, dest).then(resolve, reject);
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        }
        const file = fs.createWriteStream(dest);
        res.pipe(file);
        file.on("finish", () => file.close(() => resolve()));
        file.on("error", reject);
      })
      .on("error", reject);
  });
}

async function main() {
  const target = resolveTarget();
  const ext = process.platform === "win32" ? "zip" : "tar.gz";
  const asset = `envo-${target}.${ext}`;
  const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${asset}`;
  const dir = __dirname;
  const archive = path.join(dir, asset);

  await download(url, archive);
  // bsdtar (default `tar` on Linux, macOS and Windows 10+) extracts both .tar.gz and .zip.
  execFileSync("tar", ["-xf", archive, "-C", dir], { stdio: "inherit" });
  fs.unlinkSync(archive);

  const bin = path.join(dir, binName());
  if (!fs.existsSync(bin)) {
    throw new Error("binary not found in archive after extraction");
  }
  if (process.platform !== "win32") {
    fs.chmodSync(bin, 0o755);
  }
}

main().catch((err) => {
  console.error(`[envo] could not install the prebuilt binary: ${err.message}`);
  console.error("[envo] alternative: cargo install envo-cli");
  process.exit(1);
});
