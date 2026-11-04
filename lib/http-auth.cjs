'use strict';

// Pure request-gate functions for the HTTP layer. No I/O, no network.

const crypto = require('node:crypto');

const DEFAULT_PORT = 18778;
const BODY_CAP_BYTES = 256 * 1024;

// The reverse proxy's public name (e.g. a `tailscale serve` host), from MCP_PUBLIC_HOST. A bare DNS name only.
const PUBLIC_HOST_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
function parsePublicHost(v) {
  if (v === undefined || v === '') return null;
  const h = String(v).toLowerCase();
  if (!PUBLIC_HOST_RE.test(h)) throw new Error('MCP_PUBLIC_HOST must be a DNS name without scheme, port or path');
  return h;
}

function defaultAllowedHosts(port = DEFAULT_PORT, publicHost = null) {
  const hosts = [`localhost:${port}`, `127.0.0.1:${port}`];
  if (publicHost) hosts.push(publicHost, `${publicHost}:443`);
  return hosts;
}

function defaultAllowedOrigins(port = DEFAULT_PORT, publicHost = null) {
  return [...(publicHost ? [`https://${publicHost}`] : []), `http://localhost:${port}`, `http://127.0.0.1:${port}`];
}

const DEFAULT_PATHS = Object.freeze(['/mcp', '/unifi-mcp-rw']);

/** Exact, case-insensitive match. Missing/duplicated/odd header -> false. */
function isAllowedHost(hostHeader, allowedHosts) {
  if (typeof hostHeader !== 'string' || hostHeader.length === 0 || hostHeader.length > 255) return false;
  const h = hostHeader.toLowerCase();
  return allowedHosts.some((a) => a.toLowerCase() === h);
}

/** Absent Origin is allowed (non-browser clients); present must match exactly. */
function isAllowedOrigin(originHeader, allowedOrigins) {
  if (originHeader === undefined) return true;
  if (typeof originHeader !== 'string') return false;
  const o = originHeader.toLowerCase();
  return allowedOrigins.some((a) => a.toLowerCase() === o);
}

/** Strip query string, accept one trailing slash, exact match otherwise. */
function isAllowedPath(rawUrl, allowedPaths = DEFAULT_PATHS) {
  if (typeof rawUrl !== 'string' || !rawUrl.startsWith('/')) return false;
  let p = rawUrl;
  const q = p.search(/[?#]/);
  if (q !== -1) p = p.slice(0, q);
  if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1);
  return allowedPaths.includes(p);
}

function isAllowedMethod(method) {
  return method === 'POST';
}

/** application/json with optional parameters (e.g. charset). */
function isJsonContentType(ct) {
  if (typeof ct !== 'string') return false;
  const type = ct.split(';')[0].trim().toLowerCase();
  return type === 'application/json';
}

/** Returns 'ok' | 'too_large' | 'invalid'. Absent header is 'ok' (chunked; capped while streaming). */
function checkContentLength(header, cap = BODY_CAP_BYTES) {
  if (header === undefined) return 'ok';
  if (typeof header !== 'string' || !/^\d{1,15}$/.test(header)) return 'invalid';
  return Number(header) > cap ? 'too_large' : 'ok';
}

function sha256(s) {
  return crypto.createHash('sha256').update(String(s), 'utf8').digest();
}

/**
 * Compare a bearer token against the expected token's sha256 digest.
 * Digests are always 32 bytes so timingSafeEqual never throws on length.
 * The scheme name is case-insensitive (RFC 7235).
 */
function checkBearer(authHeader, expectedDigest) {
  if (!Buffer.isBuffer(expectedDigest) || expectedDigest.length !== 32) return false;
  const m = typeof authHeader === 'string' ? /^Bearer +([^\s]+) *$/i.exec(authHeader) : null;
  const presented = sha256(m ? m[1] : '');
  const equal = crypto.timingSafeEqual(presented, expectedDigest);
  return Boolean(m) && equal;
}

const ERR = Object.freeze({
  host: { status: 403, body: { error: 'Forbidden' } },
  origin: { status: 403, body: { error: 'Forbidden' } },
  path: { status: 404, body: { error: 'Not found' } },
  method: { status: 405, body: { error: 'Method not allowed' }, headers: { Allow: 'POST' } },
  auth: { status: 401, body: { error: 'Authentication required' }, headers: { 'WWW-Authenticate': 'Bearer' } },
  contentType: { status: 415, body: { error: 'Unsupported media type' } },
  tooLarge: { status: 413, body: { error: 'Payload too large' } },
  badLength: { status: 400, body: { error: 'Bad request' } },
  badJson: { status: 400, body: { error: 'Invalid JSON' } },
});

/**
 * Run header checks in the required order:
 * host, origin, path, method, auth, content-type, size.
 * (JSON parsing happens after the body is read.)
 * Returns null when OK or one of ERR.
 */
function evaluateHeaders({ method, url, headers }, opts) {
  const h = headers || {};
  if (!isAllowedHost(h.host, opts.allowedHosts)) return ERR.host;
  if (!isAllowedOrigin(h.origin, opts.allowedOrigins)) return ERR.origin;
  if (!isAllowedPath(url, opts.paths || DEFAULT_PATHS)) return ERR.path;
  if (!isAllowedMethod(method)) return ERR.method;
  if (!checkBearer(h.authorization, opts.tokenDigest)) return ERR.auth;
  if (!isJsonContentType(h['content-type'])) return ERR.contentType;
  const cl = checkContentLength(h['content-length'], opts.bodyCap || BODY_CAP_BYTES);
  if (cl === 'too_large') return ERR.tooLarge;
  if (cl === 'invalid') return ERR.badLength;
  return null;
}

module.exports = {
  DEFAULT_PORT,
  BODY_CAP_BYTES,
  DEFAULT_PATHS,
  ERR,
  defaultAllowedHosts,
  parsePublicHost,
  defaultAllowedOrigins,
  isAllowedHost,
  isAllowedOrigin,
  isAllowedPath,
  isAllowedMethod,
  isJsonContentType,
  checkContentLength,
  checkBearer,
  sha256,
  evaluateHeaders,
};
