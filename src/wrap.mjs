/**
 * Safe, idempotent `mcp-guard wrap` / `unwrap` config transformer for
 * Cursor (.cursor/mcp.json), Claude Desktop (claude_desktop_config.json),
 * Claude Code (.mcp.json), and VS Code (.vscode/mcp.json).
 */
import { copyFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";

const DEFAULT_WRAPPER_CMD = "npx";
const DEFAULT_WRAPPER_ARGS = ["-y", "@4sails/mcp-guard"];

function findServersKey(config) {
  if (!config || typeof config !== "object" || Array.isArray(config)) {
    throw new Error("Invalid MCP config: root must be a JSON object.");
  }
  if (config.mcpServers && typeof config.mcpServers === "object" && !Array.isArray(config.mcpServers)) {
    return "mcpServers";
  }
  if (config.servers && typeof config.servers === "object" && !Array.isArray(config.servers)) {
    return "servers";
  }
  throw new Error('Invalid MCP config: expected a top-level "mcpServers" or "servers" object.');
}

/**
 * Detects whether a stdio server entry is already wrapped by `mcp-guard proxy`.
 */
export function isWrappedServer(entry) {
  if (!entry || typeof entry !== "object") return false;
  if (typeof entry.command !== "string" || !Array.isArray(entry.args)) return false;

  const sepIdx = entry.args.indexOf("--");
  if (sepIdx === -1 || sepIdx + 1 >= entry.args.length) return false;

  const beforeSep = entry.args.slice(0, sepIdx);
  if (!beforeSep.includes("proxy")) return false;

  const cmd = entry.command.toLowerCase();
  if (cmd.endsWith("mcp-guard") || cmd.endsWith("mcp-guard.mjs")) return true;
  if (
    beforeSep.some(
      (a) =>
        typeof a === "string" &&
        (a === "@4sails/mcp-guard" ||
          a.startsWith("@4sails/mcp-guard@") ||
          a.endsWith("mcp-guard.mjs") ||
          a.endsWith("mcp-guard"))
    )
  ) {
    return true;
  }
  return false;
}

/**
 * Purely transforms an MCP config object by wrapping stdio server entries with `mcp-guard proxy`.
 * Idempotent: already-wrapped entries and remote HTTP/SSE (`url`) entries are left untouched.
 */
export function wrapMcpConfig(config, options = {}) {
  const {
    wrapperCommand = DEFAULT_WRAPPER_CMD,
    wrapperArgs = DEFAULT_WRAPPER_ARGS,
    proxyFlags = [],
    servers = null,
  } = options;

  const serversKey = findServersKey(config);
  const filterSet = servers && servers.length > 0 ? new Set(servers) : null;

  const wrapped = [];
  const alreadyWrapped = [];
  const skipped = [];
  const nextServers = {};

  for (const [name, entry] of Object.entries(config[serversKey])) {
    if (filterSet && !filterSet.has(name)) {
      nextServers[name] = entry;
      continue;
    }
    if (!entry || typeof entry !== "object" || typeof entry.command !== "string") {
      skipped.push({ name, reason: "non_stdio_server" });
      nextServers[name] = entry;
      continue;
    }
    if (isWrappedServer(entry)) {
      alreadyWrapped.push(name);
      nextServers[name] = entry;
      continue;
    }

    const origArgs = Array.isArray(entry.args) ? entry.args : [];
    nextServers[name] = {
      ...entry,
      command: wrapperCommand,
      args: [...wrapperArgs, "proxy", ...proxyFlags, "--", entry.command, ...origArgs],
    };
    wrapped.push(name);
  }

  return {
    config: {
      ...config,
      [serversKey]: nextServers,
    },
    serversKey,
    wrapped,
    alreadyWrapped,
    skipped,
    changed: wrapped.length > 0,
  };
}

/**
 * Purely reverts wrapped `mcp-guard proxy` entries back to their original `command` and `args`.
 */
export function unwrapMcpConfig(config, options = {}) {
  const { servers = null } = options;
  const serversKey = findServersKey(config);
  const filterSet = servers && servers.length > 0 ? new Set(servers) : null;

  const unwrapped = [];
  const notWrapped = [];
  const skipped = [];
  const nextServers = {};

  for (const [name, entry] of Object.entries(config[serversKey])) {
    if (filterSet && !filterSet.has(name)) {
      nextServers[name] = entry;
      continue;
    }
    if (!entry || typeof entry !== "object" || typeof entry.command !== "string") {
      skipped.push({ name, reason: "non_stdio_server" });
      nextServers[name] = entry;
      continue;
    }
    if (!isWrappedServer(entry)) {
      notWrapped.push(name);
      nextServers[name] = entry;
      continue;
    }

    const sepIdx = entry.args.indexOf("--");
    const origCmd = entry.args[sepIdx + 1];
    const origArgs = entry.args.slice(sepIdx + 2);
    nextServers[name] = {
      ...entry,
      command: origCmd,
      args: origArgs,
    };
    unwrapped.push(name);
  }

  return {
    config: {
      ...config,
      [serversKey]: nextServers,
    },
    serversKey,
    unwrapped,
    notWrapped,
    skipped,
    changed: unwrapped.length > 0,
  };
}

/**
 * Produces a concise readable line diff between two formatted JSON strings (zero deps).
 */
export function formatJsonDiff(beforeText, afterText, label = "mcp.json") {
  if (beforeText === afterText) return "";
  const a = beforeText.replace(/\r\n/g, "\n").split("\n");
  const b = afterText.replace(/\r\n/g, "\n").split("\n");

  const lines = [`--- a/${label}`, `+++ b/${label}`];
  let i = 0;
  let j = 0;

  while (i < a.length || j < b.length) {
    if (i < a.length && j < b.length && a[i] === b[j]) {
      lines.push(`  ${a[i]}`);
      i++;
      j++;
      continue;
    }

    // Look ahead within a small window to resynchronize cleanly
    let foundA = -1;
    let foundB = -1;
    for (let look = 1; look <= 16; look++) {
      if (foundB === -1 && j + look < b.length && i < a.length && a[i] === b[j + look]) {
        foundB = j + look;
      }
      if (foundA === -1 && i + look < a.length && j < b.length && a[i + look] === b[j]) {
        foundA = i + look;
      }
      if (foundA !== -1 || foundB !== -1) break;
    }

    if (foundB !== -1 && (foundA === -1 || foundB - j <= foundA - i)) {
      while (j < foundB) {
        lines.push(`+ ${b[j]}`);
        j++;
      }
    } else if (foundA !== -1) {
      while (i < foundA) {
        lines.push(`- ${a[i]}`);
        i++;
      }
    } else {
      if (i < a.length) {
        lines.push(`- ${a[i]}`);
        i++;
      }
      if (j < b.length) {
        lines.push(`+ ${b[j]}`);
        j++;
      }
    }
  }

  return `${lines.join("\n")}\n`;
}

function chooseBackupPath(filePath) {
  const simple = `${filePath}.bak`;
  if (!existsSync(simple)) return simple;
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  return `${filePath}.${stamp}.bak`;
}

/**
 * Reads an MCP config file, computes wrap/unwrap transformation + diff,
 * and if `options.apply` is true, creates a `.bak` backup before writing.
 */
export function applyMcpConfigTransform(filePath, mode, options = {}) {
  const { apply = false, ...transformOpts } = options;
  const rawBefore = readFileSync(filePath, "utf8");
  let parsed;
  try {
    parsed = JSON.parse(rawBefore);
  } catch (err) {
    throw new Error(`Invalid JSON in ${filePath}: ${err.message}`);
  }

  const result =
    mode === "wrap"
      ? wrapMcpConfig(parsed, transformOpts)
      : unwrapMcpConfig(parsed, transformOpts);

  const formattedBefore = `${JSON.stringify(parsed, null, 2)}\n`;
  const formattedAfter = `${JSON.stringify(result.config, null, 2)}\n`;
  const diff = formatJsonDiff(formattedBefore, formattedAfter, filePath);

  let backupPath = null;
  if (apply && result.changed) {
    backupPath = chooseBackupPath(filePath);
    copyFileSync(filePath, backupPath);
    writeFileSync(filePath, formattedAfter, "utf8");
  }

  return {
    ...result,
    applied: Boolean(apply && result.changed),
    backupPath,
    diff,
  };
}
