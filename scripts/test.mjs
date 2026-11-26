#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TEST_DIR = join(ROOT, "test");
const testFiles = readdirSync(TEST_DIR)
  .filter((name) => name.endsWith(".test.mjs"))
  .sort()
  .map((name) => join(TEST_DIR, name));

const extraArgs = process.argv.slice(2);
const res = spawnSync(process.execPath, ["--test", ...extraArgs, ...testFiles], {
  cwd: ROOT,
  stdio: "inherit",
});

process.exit(res.status ?? 1);
