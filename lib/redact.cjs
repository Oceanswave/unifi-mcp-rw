'use strict';

// Keys whose values are always replaced. Over-redaction is acceptable
// (e.g. "keyId"); under-redaction is not.
const SECRET_KEY_RE = /pass(word|phrase)?|secret|token|key|psk|x_passphrase|radius.*secret|authorization|cookie/i;
const REDACTED = '[REDACTED]';

function redact(value, depth = 0) {
  if (depth > 64) return REDACTED;
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = SECRET_KEY_RE.test(k) ? REDACTED : redact(v, depth + 1);
    }
    return out;
  }
  return value;
}

/**
 * Final scrubber for strings sent to MCP output or the write log: replaces
 * every occurrence of the given secret values (API key, bearer token), also in
 * JSON-escaped and URL-encoded form. Values shorter than 8 chars are ignored
 * (secret files enforce much longer minimums).
 */
function makeScrubber(secrets = []) {
  const forms = new Set();
  for (const s of secrets) {
    if (typeof s !== 'string' || s.length < 8) continue;
    forms.add(s);
    forms.add(JSON.stringify(s).slice(1, -1));
    forms.add(encodeURIComponent(s));
  }
  const list = [...forms].sort((a, b) => b.length - a.length);
  return function scrub(str) {
    if (typeof str !== 'string') return str;
    let out = str;
    for (const f of list) out = out.split(f).join(REDACTED);
    return out;
  };
}

module.exports = { redact, makeScrubber, REDACTED, SECRET_KEY_RE };
