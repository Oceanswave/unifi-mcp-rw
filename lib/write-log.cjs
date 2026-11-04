'use strict';

/**
 * UNIFI_WRITE_LOG: one JSON line per write tool call, so an operator can see
 * what an agent changed (or tried to) without trusting its account of it.
 *
 * A line holds the time, the tool, its arguments with secrets redacted, the
 * canonical request (method and path, never host, console id or headers),
 * whether it was a dry run, the outcome (ok | dry_run | refused | error), the
 * HTTP status and a short error summary. Request and response bodies are
 * never logged: the arguments are what the caller sent, not the body the
 * server built from the controller's current object.
 *
 * This is separate from the audit log (lib/audit-log.cjs), which is always on,
 * lives in the state directory and records each controller write request. The
 * write log is opt-in, goes where the operator points it, and is opened once
 * at startup with stricter checks, so a bad path stops the server instead of
 * failing on the first write.
 */

const fs = require('node:fs');
const path = require('node:path');
const { redact, makeScrubber } = require('./redact.cjs');
const { formatLocalIso } = require('./audit-log.cjs');

const OUTCOMES = Object.freeze(['ok', 'dry_run', 'refused', 'error']);
const MAX_ERROR = 300;

// Scrubbed before truncation, so a cut can never leave a partial secret behind.
function shortError(err, scrub) {
  if (err === undefined || err === null) return undefined;
  const msg = scrub(typeof err === 'string' ? err : (err && err.message) || String(err));
  return msg.length > MAX_ERROR ? msg.slice(0, MAX_ERROR) + '...' : msg;
}

/**
 * Refuse a log directory that someone else could use to swap the file: one
 * reached through a symlink anywhere along the path, one that group or others
 * can write to without the sticky bit (they could rename or replace the
 * file), or one owned by anyone but us or root. Each existing ancestor is
 * checked with lstat before the missing ones are created, so mkdir never
 * follows a symlink; the parent is then compared with its realpath, which
 * also catches a link swapped in after the walk.
 */
function checkLogDir(dir) {
  const parts = dir.split(path.sep).filter(Boolean);
  let cur = path.parse(dir).root;
  for (const part of parts) {
    cur = path.join(cur, part);
    let st;
    try {
      st = fs.lstatSync(cur);
    } catch (e) {
      if (e.code === 'ENOENT') break;
      throw e;
    }
    if (st.isSymbolicLink()) throw new Error(`a directory on its path (${cur}) is a symlink; use the real path`);
    if (!st.isDirectory()) throw new Error(`a component of its path (${cur}) is not a directory`);
  }
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (fs.realpathSync(dir) !== dir) throw new Error(`its directory ${dir} goes through a symlink; use the real path`);
  if (process.platform === 'win32') return;
  const st = fs.lstatSync(dir);
  if ((st.mode & 0o022) !== 0 && (st.mode & 0o1000) === 0) {
    throw new Error(`its directory ${dir} is group- or world-writable without the sticky bit (mode 0${(st.mode & 0o7777).toString(8)})`);
  }
  const uid = process.getuid();
  if (st.uid !== uid && st.uid !== 0) throw new Error(`its directory ${dir} is owned by uid ${st.uid}, not by this user or root`);
}

/**
 * Open `file` for appending, creating it with mode 0600 (and its directory
 * 0700) if needed. Throws for a relative path, a directory that fails
 * checkLogDir, a symlink, anything but a regular file (a FIFO would block the
 * open), a file with other hard links (lines could land elsewhere), or a
 * file that group or others can write to (it could be truncated or filled
 * with lies). A wider but read-only mode is left as the operator set it, as
 * upstream does.
 *
 * On Windows there is no O_NOFOLLOW or O_NONBLOCK and modes and owners say
 * nothing about access, so only the path, symlink and regular-file checks
 * apply there.
 */
function openWriteLogFd(file) {
  if (typeof file !== 'string' || !path.isAbsolute(file)) throw new Error('it must be an absolute path');
  file = path.resolve(file);
  const windows = process.platform === 'win32';
  checkLogDir(path.dirname(file));
  let existing;
  try {
    existing = fs.lstatSync(file);
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }
  if (existing && existing.isSymbolicLink()) throw new Error('it is a symlink; point it at the file itself');
  if (existing && !existing.isFile()) throw new Error('it is not a regular file');
  // O_NOFOLLOW closes the gap between the check above and the open; O_NONBLOCK
  // keeps a FIFO swapped in during that gap from hanging startup.
  const extra = windows ? 0 : fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK;
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT | extra, 0o600);
  const st = fs.fstatSync(fd);
  const problem = !st.isFile()
    ? 'it is not a regular file'
    : windows
      ? undefined
      : st.nlink > 1
        ? 'it has other hard links, so lines could land in another file'
        : (st.mode & 0o022) !== 0
          ? `it is group- or world-writable (mode 0${(st.mode & 0o777).toString(8)}); chmod 600 it`
          : undefined;
  if (problem) {
    fs.closeSync(fd);
    throw new Error(problem);
  }
  return fd;
}

/**
 * @param {object} o
 * @param {Function} o.sink           (line) => void; appends one line, may throw
 * @param {string[]} [o.secrets]      values (API key, bearer token) scrubbed from every line
 * @param {Function} [o.now]
 * @param {Function} [o.onError]      called once with a message when the first append fails
 */
function createWriteLog({ sink, secrets = [], now = () => new Date(), onError = (m) => process.stderr.write(`unifi-mcp-rw: ${m}\n`), file = null }) {
  const scrub = makeScrubber(secrets);
  let failed = false;

  /**
   * Append one line. Never throws: a failure is reported once and the call
   * that was being logged goes on.
   */
  function record({ tool, args, method = null, endpoint = null, dryRun = false, outcome, status, reason, error, startedAt, durationMs }) {
    try {
      if (!OUTCOMES.includes(outcome)) throw new Error(`unknown outcome ${JSON.stringify(outcome)}`);
      const d = startedAt instanceof Date ? startedAt : now();
      const line = {
        ts: d.toISOString(),
        ts_local: formatLocalIso(d),
        tool: tool ?? null,
        args: redact(args ?? null),
        method,
        // Canonical path, without its query.
        endpoint: typeof endpoint === 'string' ? endpoint.split('?')[0] : null,
        dry_run: dryRun === true,
        outcome,
      };
      if (status !== undefined) line.status = status;
      if (reason !== undefined) line.reason = reason;
      const e = shortError(error, scrub);
      if (e) line.error = e;
      if (durationMs !== undefined) line.duration_ms = durationMs;
      // Arguments are the model's; if it ever pasted a secret into one, keep it out.
      sink(scrub(JSON.stringify(line)) + '\n');
    } catch (e) {
      if (failed) return;
      failed = true;
      onError(`write log: cannot append (${scrub((e && e.message) || String(e))}); tool calls continue, but are not being logged`);
    }
  }

  return Object.freeze({ record, file });
}

/** Open UNIFI_WRITE_LOG at startup. Throws (with the reason) if the file cannot be used. */
function openWriteLog(file, { secrets = [], onError } = {}) {
  const fd = openWriteLogFd(file);
  return createWriteLog({ sink: (line) => fs.writeSync(fd, line), secrets, onError, file });
}

module.exports = { openWriteLog, createWriteLog, openWriteLogFd, OUTCOMES };
