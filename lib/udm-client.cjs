'use strict';

/**
 * HTTPS client to the UniFi Network application, via one of two backends:
 *
 *   local  https://{local_host}/proxy/network/...                     (UDM on the LAN)
 *   cloud  https://api.ui.com/v1/connector/consoles/{id}/proxy/network/... (Site Manager connector)
 *
 * Tools and the guard only ever see CANONICAL paths ("/integration/v1/...",
 * "/api/s/..."). Every request goes through request(), which
 *   0. refuses every non-GET method unless the client was created with
 *      allowWrites: true (config allow_writes), and after beginShutdown(),
 *   1. runs guard.checkRequest() on the canonical path,
 *   2. (cloud) refuses classic /api/s/ paths whose capability (firewallrule,
 *      fixed_ip, radio) is not enabled by cloud_allow_classic, and classic
 *      paths that map to no capability,
 *   3. prepends the backend's constant prefix and re-checks the result with
 *      guard.checkFinalPath(),
 * all before any socket is opened. The transport is private to the closure;
 * there is no other exported way to send bytes.
 *
 * TLS: a TLS socket is opened and fully verified first (CA/system chain, or
 * SHA-256 certificate pin compared with timingSafeEqual). Only after that is
 * an HTTP request (incl. X-API-KEY) written onto that same socket. The cloud
 * backend always connects to api.ui.com:443 with system-CA verification and
 * servername api.ui.com; nothing about that is configurable.
 */

const tls = require('node:tls');
const http = require('node:http');
const fs = require('node:fs');
const crypto = require('node:crypto');
const {
  checkRequest,
  checkFinalPath,
  cloudPrefix,
  LOCAL_PREFIX,
  CONSOLE_ID_RE,
  GuardError,
  CLASSIC_CAPABILITIES,
  classicCapabilityOf,
  normalizeClassicCapabilities,
} = require('./guard.cjs');
const { redact, makeScrubber } = require('./redact.cjs');
const { normalizeFingerprint } = require('./config.cjs');

const TIMEOUT_MS = 15_000;
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;
// Site Manager connector: 25 s per proxied request, 10 MB response cap.
const CLOUD_TIMEOUT_MS = 30_000;
const CLOUD_MAX_RESPONSE_BYTES = 10 * 1024 * 1024;
const CLOUD_TARGET = Object.freeze({ host: 'api.ui.com', port: 443, isIp: false, hostHeader: 'api.ui.com' });

/**
 * Test-only injection point. Only reachable with this Symbol as an object key,
 * which JSON (and therefore config.json) cannot produce, and main() builds the
 * client options field by field. Value: { connect(opts) } replacing tls.connect.
 */
const TEST_OVERRIDES = Symbol('unifi-mcp-rw.test-overrides');

/**
 * Probe-only option (scripts/probe-classic.cjs). Same reachability as
 * TEST_OVERRIDES: a Symbol key, which JSON/config cannot express and main()
 * never passes. A client created with { [PROBE_READ_ONLY]: true } refuses
 * every method except GET (before the guard and again right before the
 * transport), and may GET classic paths even if their capability is not
 * enabled by cloud_allow_classic. Everything else (guard allowlist, final
 * path check, TLS, prefixing, unmapped classic paths) applies unchanged.
 */
const PROBE_READ_ONLY = Symbol('unifi-mcp-rw.probe-read-only');

/**
 * Upstream HTTP/API error. Never carries the upstream body: `summary` is a
 * fixed text chosen by status, `code` only a token-shaped `code` (or classic
 * `meta.msg`) from a JSON body. toJSON() is what tools return to the caller.
 */
class UdmHttpError extends Error {
  constructor(status, summary, { code, retryAfter, label = 'UDM' } = {}) {
    super(`${label}: ${summary}${code ? ` [code ${code}]` : ''}`);
    this.name = 'UdmHttpError';
    this.status = status;
    this.summary = summary;
    if (code !== undefined) this.code = code;
    if (retryAfter !== undefined) this.retryAfter = retryAfter;
  }

  toJSON() {
    const out = { status: this.status };
    if (this.code !== undefined) out.code = this.code;
    out.message = this.summary;
    return out;
  }
}

class PinMismatchError extends Error {
  constructor() {
    super('UDM TLS certificate fingerprint does not match local_tls_cert_sha256; nothing was sent');
    this.name = 'PinMismatchError';
  }
}

function pinMatches(fingerprint256, pinHex) {
  const got = normalizeFingerprint(fingerprint256 || '');
  if (!got) return false;
  const a = Buffer.from(got, 'hex');
  const b = Buffer.from(pinHex, 'hex');
  return a.length === 32 && b.length === 32 && crypto.timingSafeEqual(a, b);
}

/** Open a TLS socket and resolve only once it is verified. */
function connectVerified({ target, tlsConf, ca, timeoutMs, connect = tls.connect, label = 'UDM' }) {
  return new Promise((resolve, reject) => {
    const opts = { host: target.host, port: target.port };
    if (!target.isIp) opts.servername = target.host;
    if (tlsConf.mode === 'pin') {
      // Self-signed UDM cert: chain verification is replaced by the pin check
      // below, which runs before any application data is written.
      opts.rejectUnauthorized = false;
    } else {
      opts.rejectUnauthorized = true;
      if (tlsConf.mode === 'ca') opts.ca = ca;
    }
    let settled = false;
    const sock = connect(opts);
    const timer = setTimeout(() => fail(new Error(`${label} TLS connect timed out`)), timeoutMs);
    function fail(err) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.destroy();
      reject(err);
    }
    sock.once('error', fail);
    sock.once('secureConnect', () => {
      if (settled) return;
      if (tlsConf.mode === 'pin') {
        const cert = sock.getPeerCertificate();
        if (!pinMatches(cert && cert.fingerprint256, tlsConf.pin)) return fail(new PinMismatchError());
      } else if (!sock.authorized) {
        return fail(new Error(`${label} TLS verification failed: ${sock.authorizationError || 'unauthorized'}`));
      }
      settled = true;
      clearTimeout(timer);
      sock.removeListener('error', fail);
      resolve(sock);
    });
  });
}

/** Default transport: verified TLS socket, then HTTP/1.1 over it. */
function makeTlsTransport({ target, tlsConf, timeoutMs = TIMEOUT_MS, maxBytes = MAX_RESPONSE_BYTES, connect, label = 'UDM' }) {
  const ca = tlsConf.mode === 'ca' ? fs.readFileSync(tlsConf.caFile) : undefined;
  return async function send({ method, path, headers, body }) {
    const sock = await connectVerified({ target, tlsConf, ca, timeoutMs, connect, label });
    return new Promise((resolve, reject) => {
      let done = false;
      const finish = (fn, v) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        fn(v);
      };
      const req = http.request({
        method,
        path,
        headers: { ...headers, Host: target.hostHeader, Connection: 'close' },
        createConnection: () => sock,
      });
      const timer = setTimeout(() => {
        req.destroy(new Error(`${label} request timed out after ${Math.round(timeoutMs / 1000)} s`));
      }, timeoutMs);
      req.on('error', (e) => {
        sock.destroy();
        finish(reject, e);
      });
      req.on('response', (res) => {
        const chunks = [];
        let size = 0;
        res.on('data', (c) => {
          size += c.length;
          if (size > maxBytes) {
            req.destroy();
            sock.destroy();
            finish(reject, new Error(`${label} response exceeded ${Math.round(maxBytes / (1024 * 1024))} MiB cap`));
            return;
          }
          chunks.push(c);
        });
        res.on('end', () => {
          sock.end();
          finish(resolve, { status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8') });
        });
        res.on('error', (e) => finish(reject, e));
      });
      if (body !== undefined) req.write(body);
      req.end();
    });
  };
}

const NON_JSON = Symbol('non-JSON body');

/** Parsed JSON, null for an empty body, or NON_JSON. Raw text is never returned. */
function parseBody(text) {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return NON_JSON;
  }
}

const CODE_RE = /^[a-z0-9._-]{1,100}$/i;

/**
 * A machine-readable error code from a JSON body: `code`, or classic
 * `meta.msg`, taken from the REDACTED body and only if token-shaped and
 * unchanged by the secret scrubber. Nothing else of the body is used.
 */
function upstreamCode(parsed, scrub) {
  if (!parsed || typeof parsed !== 'object' || parsed === NON_JSON) return undefined;
  const r = redact(parsed);
  for (const c of [r.code, r.meta && typeof r.meta === 'object' ? r.meta.msg : undefined]) {
    if (typeof c === 'string' && CODE_RE.test(c) && scrub(c) === c) return c;
  }
  return undefined;
}

const STATUS_TEXT = Object.freeze({
  400: 'request rejected as invalid (400)',
  401: 'authentication failed (401): API key rejected',
  403: 'forbidden (403)',
  404: 'not found (404)',
  405: 'method not allowed (405)',
  408: 'request timed out (408)',
  409: 'conflict (409)',
  413: 'request too large (413)',
  422: 'validation failed (422)',
  429: 'rate limited (429)',
  500: 'internal server error (500)',
  502: 'bad gateway (502)',
  503: 'service unavailable (503)',
  504: 'gateway timeout (504)',
});
const statusText = (status) => STATUS_TEXT[status] || `HTTP error ${Number.isInteger(status) ? status : 'unknown'}`;

function retryAfterOf(headers) {
  const v = headers && headers['retry-after'];
  if (typeof v !== 'string') return undefined;
  // delta-seconds or an HTTP-date only
  const clean = v.trim();
  return /^[0-9A-Za-z ,:]{1,64}$/.test(clean) ? clean : undefined;
}

/**
 * Map Site Manager connector statuses to clear, fixed errors. A status may
 * also come from the Network application behind the connector (e.g. 404 for
 * an unknown object); only its token-shaped code is passed on.
 */
function cloudHttpError(status, headers, code) {
  const retryAfter = retryAfterOf(headers);
  let what;
  switch (status) {
    case 401:
      what = 'Site Manager API key rejected (401): the key in cloud_rw_key_file is invalid, expired or revoked';
      break;
    case 403:
      what = "Site Manager API key cannot access this console (403): check console_id and that the key's account has admin rights on it";
      break;
    case 404:
      what = code === 'device_offline'
        ? 'console is offline (404 device_offline)'
        : 'not found (404): console_id unknown/not visible to this key, console offline, or the resource does not exist';
      break;
    case 408:
      what = "console did not answer within the connector's 25 s limit (408)";
      break;
    case 429:
      what = `rate limited by Site Manager (429; 100 requests/min per console)${retryAfter ? `; Retry-After: ${retryAfter}` : ''}`;
      break;
    case 502:
      what = 'connector could not reach the console or got an invalid answer (502 bad gateway)';
      break;
    default:
      what = statusText(status);
  }
  return new UdmHttpError(status, what, { code, retryAfter, label: 'Cloud connector' });
}

/** Local/classic: fixed per-status text plus the token-shaped code. */
function localHttpError(status, code) {
  return new UdmHttpError(status, statusText(status), { code, label: 'UDM' });
}

/**
 * @param {object} o
 * @param {'local'|'cloud'} o.backend
 * @param {object} [o.target]        local: parsed local_host {host, port, isIp, hostHeader}
 * @param {object} [o.tls]           local: {mode:'system'|'ca'|'pin', caFile?, pin?}
 * @param {string} [o.consoleId]     cloud: Site Manager console id
 * @param {boolean|string[]} [o.allowClassic] cloud: classic capabilities (false/true/subset of firewallrule, fixed_ip, radio)
 * @param {string} o.apiKey
 * @param {string} [o.siteName]
 * @param {string} [o.siteId]
 * @param {object} [o.auditLog]      {write(entry)}
 * @param {string[]} [o.firewallInternalZoneIds] config firewall_internal_zone_ids (guard context)
 * @param {string[]} [o.firewallWanZoneIds]      config firewall_wan_zone_ids (guard context)
 * @param {boolean} [o.allowWrites] config allow_writes; anything but true = read-only client
 * @param {Function} [o.transport]   injectable sink (tests); called only after the guard
 */
function createUdmClient(o) {
  const { apiKey } = o;
  if (!apiKey) throw new Error('createUdmClient: apiKey is required');
  const backend = o.backend;
  const testOverrides = o[TEST_OVERRIDES] || {};
  const probeReadOnly = o[PROBE_READ_ONLY] === true;
  // Strictly boolean true; the probe client is always read-only.
  const writesEnabled = o.allowWrites === true && !probeReadOnly;
  let shuttingDown = false;
  const pendingWrites = new Set();
  let target, prefix, tlsConf, classicCapabilities, defaults, label;
  if (backend === 'local') {
    if (!o.target) throw new Error('createUdmClient: local backend requires target');
    target = o.target;
    prefix = LOCAL_PREFIX;
    tlsConf = o.tls || { mode: 'system' };
    classicCapabilities = Object.freeze([...CLASSIC_CAPABILITIES]);
    defaults = { timeoutMs: TIMEOUT_MS, maxBytes: MAX_RESPONSE_BYTES };
    label = 'UDM';
  } else if (backend === 'cloud') {
    if (typeof o.consoleId !== 'string' || !CONSOLE_ID_RE.test(o.consoleId)) throw new Error('createUdmClient: cloud backend requires a valid consoleId');
    // Never configurable: api.ui.com:443, system CA, servername api.ui.com.
    target = CLOUD_TARGET;
    prefix = cloudPrefix(o.consoleId);
    tlsConf = { mode: 'system' };
    try {
      classicCapabilities = normalizeClassicCapabilities(o.allowClassic);
    } catch (e) {
      throw new Error(`createUdmClient: allowClassic ${e.message}`);
    }
    defaults = { timeoutMs: CLOUD_TIMEOUT_MS, maxBytes: CLOUD_MAX_RESPONSE_BYTES };
    label = 'Cloud connector';
  } else {
    throw new Error('createUdmClient: backend must be "local" or "cloud"');
  }
  const origin = `https://${target.hostHeader}`;
  const siteName = o.siteName || 'default';
  const transport =
    o.transport ||
    makeTlsTransport({
      target,
      tlsConf,
      timeoutMs: o.timeoutMs ?? defaults.timeoutMs,
      maxBytes: o.maxBytes ?? defaults.maxBytes,
      connect: testOverrides.connect,
      label,
    });
  const audit = o.auditLog || null;
  let siteId = o.siteId || null;
  const scrub = makeScrubber([apiKey]);
  // Zone classification comes from configuration only. It overrides whatever
  // a tool puts into the guard context; the guard validates the values.
  const zoneIds = (v) => (Array.isArray(v) ? Object.freeze([...v]) : v === undefined ? Object.freeze([]) : v);
  const internalZoneIds = zoneIds(o.firewallInternalZoneIds);
  const wanZoneIds = zoneIds(o.firewallWanZoneIds);

  function logWrite(auditCtx, fields) {
    if (!auditCtx) return;
    // What the tool layer's write log (UNIFI_WRITE_LOG) reports for this call.
    auditCtx.request = { method: fields.method, endpoint: fields.endpoint, status: fields.status };
    if (!audit) return;
    auditCtx.logged = true;
    try {
      audit.write({ tool: auditCtx.tool, args: auditCtx.args, backend, ...fields });
    } catch {
      process.stderr.write('unifi-mcp-rw: audit log write failed\n');
    }
  }

  /** Guard + backend checks; returns the full request path. Throws GuardError. */
  function resolvePath({ method, path, body, context }) {
    const ctx = context === undefined || context === null ? {} : context;
    if (typeof ctx !== 'object' || Array.isArray(ctx)) throw new GuardError('context must be an object');
    if (probeReadOnly && method !== 'GET') throw new GuardError(`probe client is read-only: ${String(method)} refused`);
    if (!writesEnabled && method !== 'GET') throw new GuardError(`server is in read-only mode (allow_writes is not true): ${String(method)} refused`);
    if (shuttingDown && method !== 'GET') throw new GuardError(`server is shutting down: ${String(method)} refused`);
    checkRequest({ method, path, body, context: { ...ctx, internalZoneIds, wanZoneIds } });
    if (backend === 'cloud' && path.startsWith('/api/s/')) {
      const cap = classicCapabilityOf(path);
      if (cap === null) throw new GuardError('classic /api/s/ path maps to no classic capability; refused for the cloud backend (fail closed)');
      if (!classicCapabilities.includes(cap) && !(probeReadOnly && method === 'GET')) {
        throw new GuardError(`classic /api/s/ endpoints are disabled for the cloud backend: capability "${cap}" is not enabled (cloud_allow_classic; experimental)`);
      }
    }
    const full = prefix + path;
    checkFinalPath({ prefix, canonical: path, full });
    return full;
  }

  /**
   * @param {object} r
   * @param {string} r.path canonical path ("/integration/v1/..." or "/api/s/...")
   * @param {boolean} [r.withStatus] return {status, data} instead of the parsed body (probe)
   * @returns {Promise<any>} parsed response, or a dry-run descriptor
   */
  async function performRequest({ method, path, body, context, dryRun = false, audit: auditCtx, withStatus = false }) {
    const isWrite = method !== 'GET';
    let full;
    try {
      full = resolvePath({ method, path, body, context });
    } catch (e) {
      if (isWrite) {
        logWrite(auditCtx, { method, endpoint: path, dry_run: dryRun, status: e instanceof GuardError ? 'refused' : 'error', error: e.message });
      }
      throw e;
    }
    const headers = { 'X-API-KEY': apiKey, Accept: 'application/json' };
    let payload;
    if (body !== undefined && body !== null) {
      payload = JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = String(Buffer.byteLength(payload));
    }
    if (dryRun && isWrite) {
      logWrite(auditCtx, { method, endpoint: path, dry_run: true, status: 'dry_run' });
      return {
        dry_run: true,
        backend,
        request: {
          method,
          url: `${origin}${full}`,
          headers: { ...headers, 'X-API-KEY': '[REDACTED]' },
          body: body === undefined ? null : redact(body),
        },
      };
    }
    // Second, independent checks right before any byte could be sent.
    if (probeReadOnly && method !== 'GET') throw new GuardError('probe client is read-only');
    if (!writesEnabled && method !== 'GET') throw new GuardError('server is in read-only mode (allow_writes is not true)');
    let res;
    try {
      res = await transport({ method, path: full, headers, body: payload });
    } catch (e) {
      // Local transport errors (TLS, timeout, size cap); scrubbed all the same.
      if (e && typeof e.message === 'string') e.message = scrub(e.message);
      if (isWrite) logWrite(auditCtx, { method, endpoint: path, dry_run: false, status: 'error', error: e.message });
      throw e;
    }
    const parsed = parseBody(res.text);
    const code = upstreamCode(parsed, scrub);
    let err = null;
    if (res.status >= 400) {
      err = backend === 'cloud' ? cloudHttpError(res.status, res.headers, code) : localHttpError(res.status, code);
    } else if (parsed && typeof parsed === 'object' && parsed !== NON_JSON && parsed.meta && parsed.meta.rc && parsed.meta.rc !== 'ok') {
      err = new UdmHttpError(res.status, 'classic API reported an error', { code, label: 'UDM' });
    }
    if (isWrite) {
      logWrite(auditCtx, { method, endpoint: path, dry_run: false, status: res.status, error: err ? err.message : undefined });
    }
    if (err) throw err;
    const data = parsed === NON_JSON ? { status: res.status, note: 'non-JSON response omitted' } : parsed;
    return withStatus ? { status: res.status, data } : data;
  }

  function request(req) {
    const pending = performRequest(req);
    if (req.method !== 'GET') {
      pendingWrites.add(pending);
      const finished = () => pendingWrites.delete(pending);
      pending.then(finished, finished);
    }
    return pending;
  }

  const integration = (p) => `/integration/v1${p}`;

  async function getSiteId() {
    if (siteId) return siteId;
    const page = await request({ method: 'GET', path: integration('/sites?limit=200') });
    const data = page && Array.isArray(page.data) ? page.data : [];
    if (data.length !== 1) {
      throw new Error(`expected exactly one site from /v1/sites, found ${data.length}; set site_id in config`);
    }
    siteId = String(data[0].id).toLowerCase();
    return siteId;
  }

  async function sitePath(p) {
    return integration(`/sites/${await getSiteId()}${p}`);
  }

  const classicPath = (p) => `/api/s/${siteName}${p}`;

  return {
    request,
    getSiteId,
    sitePath,
    integration,
    classicPath,
    siteName,
    target,
    backend,
    prefix,
    origin,
    classicCapabilities,
    classicEnabled: classicCapabilities.length > 0,
    probeReadOnly,
    writesEnabled,
    /** Refuse new writes and resolve after in-flight writes have finished and been audited. */
    beginShutdown() {
      shuttingDown = true;
      return Promise.allSettled([...pendingWrites]);
    },
    scrub,
  };
}

module.exports = {
  createUdmClient,
  UdmHttpError,
  PinMismatchError,
  pinMatches,
  TEST_OVERRIDES,
  PROBE_READ_ONLY,
  CLOUD_TARGET,
  TIMEOUT_MS,
  MAX_RESPONSE_BYTES,
  CLOUD_TIMEOUT_MS,
  CLOUD_MAX_RESPONSE_BYTES,
};
