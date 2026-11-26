#!/usr/bin/env node
/**
 * Zero-dependency repository quality & security invariant gate (`npm run check`).
 * Pure Node.js built-ins only — fast (<200ms), offline, cross-platform.
 */
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const errors = [];

function fail(msg) {
  errors.push(msg);
}

function walkFiles(dir, result = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === ".git" || entry.name === "node_modules") continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      walkFiles(full, result);
    } else {
      result.push(full);
    }
  }
  return result;
}

const allFiles = walkFiles(ROOT);
const mjsFiles = allFiles.filter((f) => extname(f) === ".mjs");

// 1. Zero-dependency package.json invariant
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
for (const field of [
  "dependencies",
  "optionalDependencies",
  "peerDependencies",
  "bundleDependencies",
  "bundledDependencies",
  "devDependencies",
]) {
  if (pkg[field] && Object.keys(pkg[field]).length > 0) {
    fail(`package.json must stay zero-dependency: found non-empty "${field}"`);
  }
}

// 2. Syntax check every .mjs file with `node --check`
for (const file of mjsFiles) {
  try {
    execFileSync(process.execPath, ["--check", file], { stdio: "pipe" });
  } catch (err) {
    fail(`Syntax error in ${relative(ROOT, file)}: ${err.stderr?.toString("utf8") || err.message}`);
  }
}

// 3. Strict stdout discipline across src/** (never corrupt MCP JSON-RPC frames)
const FORBIDDEN_STDOUT_RE =
  /\bconsole\.(?:log|info|debug|dir|table|count|timeEnd)\s*\(|\bwriteSync\s*\(\s*1\b/;
for (const file of mjsFiles) {
  const rel = relative(ROOT, file).replace(/\\/g, "/");
  if (!rel.startsWith("src/")) continue;
  const content = readFileSync(file, "utf8");
  const stripped = content
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\n]*/g, "");

  if (FORBIDDEN_STDOUT_RE.test(stripped)) {
    fail(`Forbidden stdout call in ${rel} (MCP JSON-RPC stdout must never be polluted; use stderr)`);
  }
  if (rel !== "src/proxy.mjs" && /\bprocess\.stdout\b/.test(stripped)) {
    fail(`Forbidden process.stdout reference in ${rel} (only src/proxy.mjs may own stdout framing)`);
  }
}

// 4. Executable bin shebang (LF) + cross-platform executable mode check
const binPath = join(ROOT, "bin/mcp-guard.mjs");
const binContent = readFileSync(binPath, "utf8");
if (!binContent.startsWith("#!/usr/bin/env node\n")) {
  fail("bin/mcp-guard.mjs must start with `#!/usr/bin/env node\\n` (LF line ending)");
}
try {
  const stageLine = execFileSync("git", ["ls-files", "--stage", "bin/mcp-guard.mjs"], {
    cwd: ROOT,
    stdio: ["ignore", "pipe", "pipe"],
  })
    .toString("utf8")
    .trim();
  if (stageLine && !stageLine.startsWith("100755 ")) {
    fail(`bin/mcp-guard.mjs must have git mode 100755 (got: ${stageLine.split(" ")[0]})`);
  }
} catch {
  if (process.platform !== "win32") {
    const mode = statSync(binPath).mode;
    if ((mode & 0o111) === 0) {
      fail("bin/mcp-guard.mjs must be executable (chmod +x)");
    }
  }
}

// 5. Dynamic export parity between src/index.mjs and src/index.d.ts
const mod = await import("../src/index.mjs");
const runtimeExports = Object.keys(mod).sort();
const dtsContent = readFileSync(join(ROOT, "src/index.d.ts"), "utf8");
const dtsExports = [
  ...dtsContent.matchAll(/export\s+declare\s+(?:const|let|var|function|class)\s+([A-Za-z0-9_$]+)/g),
]
  .map((m) => m[1])
  .sort();

for (const name of runtimeExports) {
  if (!dtsExports.includes(name)) {
    fail(`Missing TypeScript declaration in src/index.d.ts for export "${name}"`);
  }
}
for (const name of dtsExports) {
  if (!runtimeExports.includes(name)) {
    fail(`Stale TypeScript declaration "${name}" in src/index.d.ts not exported by src/index.mjs`);
  }
}

// 6. Rule-table security invariants (unique IDs, /g flags, valid severity/tier/groups)
const validSeverities = new Set(Object.keys(mod.SEVERITY_RANK));
const validTiers = new Set(["high-confidence", "heuristic"]);

function checkRedactRuleTable(tableName, rules) {
  const seen = new Set();
  for (const rule of rules) {
    if (!rule.id || typeof rule.id !== "string") {
      fail(`${tableName}: rule missing string id`);
      continue;
    }
    if (seen.has(rule.id)) {
      fail(`${tableName}: duplicate rule id "${rule.id}"`);
    }
    seen.add(rule.id);

    if (!(rule.pattern instanceof RegExp)) {
      fail(`${tableName}.${rule.id}: pattern must be a RegExp`);
    } else if (!rule.pattern.global) {
      fail(`${tableName}.${rule.id}: pattern MUST include /g flag (otherwise 2nd secret in string leaks)`);
    }
    if (!validSeverities.has(rule.severity)) {
      fail(`${tableName}.${rule.id}: invalid severity "${rule.severity}"`);
    }
    if (rule.valueGroup !== undefined && (!Number.isInteger(rule.valueGroup) || rule.valueGroup < 1)) {
      fail(`${tableName}.${rule.id}: invalid valueGroup "${rule.valueGroup}"`);
    }
    if (rule.prefixGroup !== undefined && (!Number.isInteger(rule.prefixGroup) || rule.prefixGroup < 1)) {
      fail(`${tableName}.${rule.id}: invalid prefixGroup "${rule.prefixGroup}"`);
    }
  }
}

checkRedactRuleTable("SECRET_RULES", mod.SECRET_RULES);
checkRedactRuleTable("PII_RULES", mod.PII_RULES);

const seenInjectionIds = new Set();
for (const rule of mod.INJECTION_PATTERNS) {
  if (!rule.id || seenInjectionIds.has(rule.id)) {
    fail(`INJECTION_PATTERNS: missing or duplicate rule id "${rule.id}"`);
  }
  seenInjectionIds.add(rule.id);
  if (!(rule.pattern instanceof RegExp)) {
    fail(`INJECTION_PATTERNS.${rule.id}: pattern must be a RegExp`);
  } else if (rule.pattern.global) {
    fail(`INJECTION_PATTERNS.${rule.id}: pattern must NOT include /g flag (breaks .match() capture groups)`);
  }
  if (!validSeverities.has(rule.severity)) {
    fail(`INJECTION_PATTERNS.${rule.id}: invalid severity "${rule.severity}"`);
  }
  if (!validTiers.has(rule.tier)) {
    fail(`INJECTION_PATTERNS.${rule.id}: invalid tier "${rule.tier}"`);
  }
}

// 7. Formatting & whitespace hygiene (LF, no tabs, no trailing spaces, final newline)
const CHECKED_EXTS = new Set([".mjs", ".js", ".ts", ".json", ".yml", ".yaml", ".md"]);
for (const file of allFiles) {
  const rel = relative(ROOT, file).replace(/\\/g, "/");
  if (rel.startsWith("test/fixtures/")) continue;
  if (!CHECKED_EXTS.has(extname(file))) continue;

  const text = readFileSync(file, "utf8");
  if (text.includes("\r\n")) {
    fail(`${rel}: contains CRLF line endings (expected LF)`);
  }
  if (text.length > 0 && !text.endsWith("\n")) {
    fail(`${rel}: missing trailing newline`);
  }
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.includes("\t")) {
      fail(`${rel}:${i + 1}: contains tab character (use 2 spaces)`);
      break;
    }
    if (/[ ]+$/.test(line)) {
      fail(`${rel}:${i + 1}: contains trailing whitespace`);
      break;
    }
  }
}

if (errors.length > 0) {
  console.error(`\n[mcp-guard check] FAILED with ${errors.length} issue(s):\n`);
  for (const err of errors) {
    console.error(`  - ${err}`);
  }
  process.exit(1);
}

console.log(
  `[mcp-guard check] OK — ${mjsFiles.length} ESM files, ${runtimeExports.length} typed exports, ${mod.SECRET_RULES.length + mod.PII_RULES.length} redaction rules, ${mod.INJECTION_PATTERNS.length} injection rules verified.`
);
