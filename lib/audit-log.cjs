'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { redact, makeScrubber } = require('./redact.cjs');

function defaultStateDir(env = process.env) {
  if (env.UNIFI_MCP_RW_STATE_DIR) return env.UNIFI_MCP_RW_STATE_DIR;
  return path.join(os.homedir(), '.local', 'state', 'unifi-mcp-rw');
}

function pad(n, w = 2) {
  return String(Math.abs(n)).padStart(w, '0');
}

// ISO 8601 in local time with explicit offset, e.g. 2026-10-18T16:30:00.000-04:00
function formatLocalIso(d) {
  const offMin = -d.getTimezoneOffset();
  const sign = offMin >= 0 ? '+' : '-';
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
    `T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}` +
    `${sign}${pad(Math.trunc(offMin / 60))}:${pad(offMin % 60)}`
  );
}

function ensurePrivateDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = fs.statSync(dir);
  if ((st.mode & 0o077) !== 0) fs.chmodSync(dir, 0o700);
}

// Scrubbed before truncation, so a cut can never leave a partial secret behind.
function shortError(err, scrub) {
  if (err === undefined || err === null) return undefined;
  const msg = scrub(typeof err === 'string' ? err : (err && err.message) || String(err));
  return msg.length > 300 ? msg.slice(0, 300) + '...' : msg;
}

/**
 * @param {object} [o]
 * @param {string[]} [o.secrets]  values (API key, bearer token) scrubbed from every line
 */
function createAuditLog({ stateDir = defaultStateDir(), now = () => new Date(), secrets = [] } = {}) {
  const file = path.join(stateDir, 'writes.log');
  const scrub = makeScrubber(secrets);

  function write(entry) {
    ensurePrivateDir(stateDir);
    const d = now();
    const line = {
      ts_utc: d.toISOString(),
      ts_local: formatLocalIso(d),
      tool: entry.tool ?? null,
      args: redact(entry.args ?? null),
      backend: entry.backend ?? null,
      method: entry.method ?? null,
      // Canonical path ("/integration/v1/..." or "/api/s/..."), never the full URL or headers.
      endpoint: entry.endpoint ?? null,
      dry_run: Boolean(entry.dry_run),
      status: entry.status,
    };
    const e = shortError(entry.error, scrub);
    if (e) line.error = e;
    const text = scrub(JSON.stringify(line));
    const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT, 0o600);
    try {
      const st = fs.fstatSync(fd);
      if ((st.mode & 0o077) !== 0) fs.fchmodSync(fd, 0o600);
      fs.writeSync(fd, text + '\n');
    } finally {
      fs.closeSync(fd);
    }
    return JSON.parse(text);
  }

  return { write, file, stateDir };
}

module.exports = { createAuditLog, formatLocalIso, defaultStateDir };
