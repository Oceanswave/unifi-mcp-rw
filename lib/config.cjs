'use strict';

const { parsePublicHost } = require('./http-auth.cjs');

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { CONSOLE_ID_RE, normalizeClassicCapabilities } = require('./guard.cjs');
const { WRITE_TOOLS, parseWriteTools } = require('./tool-names.cjs');

const CONFIG_DIR = path.join(os.homedir(), '.config', 'unifi-connectivity');
const DEFAULTS = Object.freeze({
  listenHost: '127.0.0.1',
  listenPort: 18778,
  tokenFile: path.join(CONFIG_DIR, 'mcp-rw-token'),
  keyFile: path.join(CONFIG_DIR, 'local-rw-key'),
  cloudKeyFile: path.join(CONFIG_DIR, 'cloud-rw-key'),
  siteName: 'default',
  backend: 'cloud',
});

const BACKENDS = Object.freeze(['cloud', 'local']);
// The cloud host is hardcoded (api.ui.com:443). Keys that look like an attempt
// to point the cloud backend (and its key) elsewhere are refused outright.
const CLOUD_OVERRIDE_KEY_RE = /^cloud_(host|port|url|base_url|api_host|api_url|tls_.*)$/;

class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
  }
}

function expandHome(p) {
  if (typeof p !== 'string') return p;
  if (p === '~') return os.homedir();
  if (p.startsWith('~/')) return path.join(os.homedir(), p.slice(2));
  return p;
}

const HOSTNAME_RE = /^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

// "host" or "host:port"; hostname or IPv4 only; no scheme, path, userinfo.
function parseLocalHost(value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new ConfigError('local_host is required (UDM hostname or IPv4, no scheme)');
  }
  const m = /^([^:/?#@\s]+)(?::(\d{1,5}))?$/.exec(value);
  if (!m) throw new ConfigError('local_host must be "host" or "host:port" without scheme or path');
  const host = m[1];
  const port = m[2] === undefined ? 443 : Number(m[2]);
  if (!(port >= 1 && port <= 65535)) throw new ConfigError('local_host port out of range');
  const isIp = IPV4_RE.test(host);
  if (!isIp && (/^[\d.]+$/.test(host) || !HOSTNAME_RE.test(host))) {
    throw new ConfigError('local_host is not a valid hostname or IPv4 address');
  }
  return { host, port, isIp, hostHeader: m[2] === undefined ? host : `${host}:${port}` };
}

function normalizeFingerprint(fp) {
  if (typeof fp !== 'string') return null;
  const hex = fp.replace(/:/g, '').trim().toLowerCase();
  return /^[0-9a-f]{64}$/.test(hex) ? hex : null;
}

function isLoopbackAddress(h) {
  if (h === '::1') return true;
  return net.isIPv4(h) && h.startsWith('127.');
}

/**
 * A secret file must be a regular file (not a symlink), owned by the current
 * uid, mode exactly 0600, with trimmed content of at least minLength chars.
 * Returns the trimmed content.
 */
function readSecretFile(file, { label = 'secret file', minLength = 32 } = {}) {
  let st;
  try {
    st = fs.lstatSync(file);
  } catch (e) {
    throw new ConfigError(`${label} ${file} is not readable (${e.code || 'error'})`);
  }
  if (!st.isFile()) throw new ConfigError(`${label} ${file} must be a regular file (symlinks are refused)`);
  if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
    throw new ConfigError(`${label} ${file} must be owned by uid ${process.getuid()}`);
  }
  const mode = st.mode & 0o777;
  if (mode !== 0o600) {
    throw new ConfigError(`${label} ${file} must have mode 0600 (found 0${mode.toString(8)}); run: chmod 600 ${file}`);
  }
  const content = fs.readFileSync(file, 'utf8').trim();
  if (content.length < minLength) throw new ConfigError(`${label} ${file} must contain at least ${minLength} characters`);
  if (/\s/.test(content)) throw new ConfigError(`${label} ${file} must contain a single value without whitespace`);
  return content;
}

function defaultConfigPath(env = process.env) {
  return env.UNIFI_MCP_RW_CONFIG ? expandHome(env.UNIFI_MCP_RW_CONFIG) : path.join(CONFIG_DIR, 'config.json');
}

const present = (v) => v !== undefined && v !== null && v !== '';

/** Optional path-valued key: absent -> fallback, else a non-empty string (with ~ expanded). */
function pathKey(raw, key, fallback) {
  const v = raw[key];
  if (v === undefined || v === null || v === '') return fallback;
  if (typeof v !== 'string') throw new ConfigError(`${key} must be a file path (string)`);
  return expandHome(v);
}

/**
 * Write mode. config allow_writes (boolean, default false) and env
 * UNIFI_ALLOW_WRITES:
 *   env "true" / "1"   -> writes on (whatever the config says)
 *   env "false" / "0"  -> writes off (whatever the config says)
 *   env unset / empty  -> config allow_writes
 *   env anything else  -> config allow_writes, with a startup warning
 * (case-insensitive, surrounding whitespace ignored).
 */
function resolveAllowWrites(raw, env, warnings) {
  const cfgValue = raw.allow_writes;
  if (cfgValue !== undefined && cfgValue !== null && typeof cfgValue !== 'boolean') {
    throw new ConfigError('allow_writes must be true or false');
  }
  const fromConfig = cfgValue === true;
  const e = typeof env.UNIFI_ALLOW_WRITES === 'string' ? env.UNIFI_ALLOW_WRITES.trim().toLowerCase() : '';
  if (e === 'true' || e === '1') return { allowWrites: true, allowWritesSource: 'env UNIFI_ALLOW_WRITES' };
  if (e === 'false' || e === '0') return { allowWrites: false, allowWritesSource: 'env UNIFI_ALLOW_WRITES' };
  if (e !== '') warnings.push('UNIFI_ALLOW_WRITES has an unrecognised value (use true/1 or false/0); using allow_writes from the config');
  return { allowWrites: fromConfig, allowWritesSource: cfgValue === undefined || cfgValue === null ? 'default' : 'config allow_writes' };
}

/** Neutral key (site_id) or legacy local_ key (local_site_id); both must agree if both are set. */
function pickAlias(raw, neutral, legacy) {
  const a = present(raw[neutral]) ? raw[neutral] : undefined;
  const b = present(raw[legacy]) ? raw[legacy] : undefined;
  if (a !== undefined && b !== undefined && a !== b) throw new ConfigError(`${neutral} and ${legacy} are both set but differ`);
  return { value: a ?? b, key: a !== undefined ? neutral : legacy };
}

function validateConsoleId(v) {
  if (typeof v !== 'string' || v.length === 0) {
    throw new ConfigError('console_id is required in cloud mode (the host "id" from GET https://api.ui.com/v1/hosts)');
  }
  if (!CONSOLE_ID_RE.test(v)) {
    throw new ConfigError('console_id must match [A-Za-z0-9]{8,128} with an optional ":digits" suffix (no "/", ".", "?", "%")');
  }
  return v;
}

/** Local backend: UDM host and TLS verification (pin / CA file / system CA). */
function validateLocal(raw) {
  const target = parseLocalHost(raw.local_host);
  const tls = { mode: 'system' };
  const hasCa = present(raw.local_tls_ca_file);
  const hasPin = present(raw.local_tls_cert_sha256);
  if (hasCa && hasPin) throw new ConfigError('set either local_tls_ca_file or local_tls_cert_sha256, not both');
  if (hasCa) {
    if (typeof raw.local_tls_ca_file !== 'string') throw new ConfigError('local_tls_ca_file must be a file path (string)');
    tls.mode = 'ca';
    tls.caFile = expandHome(raw.local_tls_ca_file);
  } else if (hasPin) {
    const pin = normalizeFingerprint(raw.local_tls_cert_sha256);
    if (!pin) throw new ConfigError('local_tls_cert_sha256 must be a SHA-256 fingerprint (64 hex chars, colons optional)');
    tls.mode = 'pin';
    tls.pin = pin;
  }
  return { target, tls, keyFile: pathKey(raw, 'local_rw_key_file', DEFAULTS.keyFile) };
}

/** Cloud backend: fixed host api.ui.com:443 with system-CA verification; only the console id is configurable. */
function validateCloud(raw, warnings) {
  for (const k of Object.keys(raw)) {
    if (CLOUD_OVERRIDE_KEY_RE.test(k)) throw new ConfigError(`${k} is not supported: the cloud backend always uses https://api.ui.com with system-CA verification`);
  }
  const consoleId = validateConsoleId(raw.console_id);
  let classicCapabilities;
  try {
    classicCapabilities = normalizeClassicCapabilities(raw.cloud_allow_classic);
  } catch (e) {
    throw new ConfigError(`cloud_allow_classic ${e.message}`);
  }
  const ignored = ['local_host', 'local_tls_ca_file', 'local_tls_cert_sha256', 'local_rw_key_file'].filter((k) => present(raw[k]));
  if (ignored.length) warnings.push(`backend "cloud": ${ignored.join(', ')} ignored (local backend only)`);
  if (classicCapabilities.length) {
    warnings.push(`cloud_allow_classic: classic /api/s/ tools enabled through the cloud connector for ${classicCapabilities.join(', ')} (experimental, unverified)`);
  }
  return {
    cloud: { consoleId, classicCapabilities },
    target: null,
    tls: { mode: 'system' },
    keyFile: pathKey(raw, 'cloud_rw_key_file', DEFAULTS.cloudKeyFile),
  };
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Optional array of zone UUIDs (lower-cased, de-duplicated); anything else is a ConfigError. */
function zoneIdList(raw, key) {
  const v = raw[key];
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) throw new ConfigError(`${key} must be an array of firewall zone UUIDs`);
  if (v.length > 256) throw new ConfigError(`${key} has too many entries (max 256)`);
  for (const id of v) {
    if (typeof id !== 'string' || !UUID_RE.test(id)) throw new ConfigError(`${key} entries must be UUIDs (zone ids from unifi_rw_list_firewall_zones)`);
  }
  return [...new Set(v.map((id) => id.toLowerCase()))];
}

/**
 * Zone-based firewall classification. Zone names are user-editable and the
 * API exposes no semantic zone type, so internal zones are configured by id.
 */
function validateFirewallZones(raw, warnings) {
  const internal = zoneIdList(raw, 'firewall_internal_zone_ids');
  const wan = zoneIdList(raw, 'firewall_wan_zone_ids');
  const both = internal.filter((id) => wan.includes(id));
  if (both.length) throw new ConfigError(`zone ${both[0]} is in both firewall_internal_zone_ids and firewall_wan_zone_ids`);
  if (internal.length === 0) warnings.push('firewall_internal_zone_ids not set: zone-based ALLOW policies will be refused, and every BLOCK/REJECT policy is treated as WAN-side (cosmetic changes only)');
  return { internalZoneIds: internal, wanZoneIds: wan };
}

/**
 * UNIFI_WRITE_TOOLS: unset -> null (every write tool, as upstream); set ->
 * comma-separated write tool names, "" or "none" for none. Read tool names
 * and unknown names are a ConfigError listing the valid names. Validated even
 * in read-only mode, so a typo shows before writes are turned on.
 */
function resolveWriteTools(env) {
  const v = env.UNIFI_WRITE_TOOLS;
  if (v === undefined) return null;
  const { tools, unknown, readTools } = parseWriteTools(v);
  const problems = [];
  if (readTools.length) problems.push(`${readTools.join(', ')} ${readTools.length === 1 ? 'is a read tool' : 'are read tools'} (read tools are always registered and cannot be listed)`);
  if (unknown.length) problems.push(`unknown ${unknown.length === 1 ? 'name' : 'names'} ${unknown.join(', ')}`);
  if (problems.length) {
    throw new ConfigError(`UNIFI_WRITE_TOOLS: ${problems.join('; ')}. Valid write tool names: ${WRITE_TOOLS.join(', ')}. Use "none" for no write tools, or leave it unset for all.`);
  }
  return tools;
}

/** UNIFI_WRITE_LOG: unset or empty -> null; otherwise an absolute path (MCP hosts and systemd do not expand ~). */
function resolveWriteLog(env) {
  const v = env.UNIFI_WRITE_LOG;
  if (v === undefined || v === '') return null;
  if (!path.isAbsolute(v)) throw new ConfigError(`UNIFI_WRITE_LOG must be an absolute path (got ${JSON.stringify(v)}; ~ is not expanded)`);
  return path.normalize(v);
}

/**
 * WAN-exposure refusals: on unless UNIFI_ALLOW_WAN_EXPOSURE is "true"
 * (case-insensitive, as upstream). "false" or empty keep them on; anything
 * else keeps them on with a startup warning. UNIFI_WAN_ZONE_IDS adds zone ids
 * to treat as the WAN, on top of config firewall_wan_zone_ids.
 */
function resolveWanExposure(env, firewall, warnings) {
  const raw = typeof env.UNIFI_ALLOW_WAN_EXPOSURE === 'string' ? env.UNIFI_ALLOW_WAN_EXPOSURE.trim().toLowerCase() : '';
  const allowExposure = raw === 'true';
  if (raw !== '' && raw !== 'true' && raw !== 'false') warnings.push('UNIFI_ALLOW_WAN_EXPOSURE has an unrecognised value (only "true" turns the refusals off); WAN-exposure refusals stay on');
  const ids = typeof env.UNIFI_WAN_ZONE_IDS === 'string' ? env.UNIFI_WAN_ZONE_IDS.split(',').map((x) => x.trim()).filter((x) => x !== '') : [];
  for (const id of ids) {
    if (!UUID_RE.test(id)) throw new ConfigError('UNIFI_WAN_ZONE_IDS must be a comma-separated list of firewall zone UUIDs (from unifi_rw_list_firewall_zones)');
  }
  const envIds = ids.map((id) => id.toLowerCase());
  const both = envIds.filter((id) => firewall.internalZoneIds.includes(id));
  if (both.length) throw new ConfigError(`zone ${both[0]} is in both UNIFI_WAN_ZONE_IDS and firewall_internal_zone_ids`);
  return { allowExposure, zoneIds: [...new Set([...firewall.wanZoneIds, ...envIds])] };
}

/**
 * Validate the raw (shared) config object, picking only the keys we own.
 * `env` is consulted for UNIFI_ALLOW_WRITES, UNIFI_WRITE_TOOLS,
 * UNIFI_WRITE_LOG, UNIFI_ALLOW_WAN_EXPOSURE and UNIFI_WAN_ZONE_IDS.
 */
// MCP_PUBLIC_HOST: the reverse proxy's name (e.g. a tailscale serve host), added to the Host/Origin allowlists.
function resolvePublicHost(env) {
  try {
    return parsePublicHost(env.MCP_PUBLIC_HOST);
  } catch (e) {
    throw new ConfigError(e.message);
  }
}

function validateConfig(raw, { env = process.env } = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new ConfigError('config must be a JSON object');
  const backend = raw.backend ?? DEFAULTS.backend;
  if (!BACKENDS.includes(backend)) throw new ConfigError('backend must be "cloud" (default) or "local"');
  const warnings = [];
  const writes = resolveAllowWrites(raw, env, warnings);
  const be = backend === 'cloud' ? validateCloud(raw, warnings) : { cloud: null, ...validateLocal(raw) };

  let siteId = null;
  const sid = pickAlias(raw, 'site_id', 'local_site_id');
  if (sid.value !== undefined) {
    if (typeof sid.value !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(sid.value)) {
      throw new ConfigError(`${sid.key} must be a UUID`);
    }
    siteId = sid.value.toLowerCase();
  }
  const sname = pickAlias(raw, 'site_name', 'local_site_name');
  const siteName = sname.value ?? DEFAULTS.siteName;
  if (typeof siteName !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(siteName)) {
    throw new ConfigError(`${sname.key} must match [A-Za-z0-9_-]{1,64}`);
  }

  const listenHost = raw.rw_listen_host ?? DEFAULTS.listenHost;
  if (typeof listenHost !== 'string' || !isLoopbackAddress(listenHost)) {
    throw new ConfigError('rw_listen_host must be a loopback address (127.0.0.0/8 or ::1)');
  }
  const listenPort = raw.rw_listen_port ?? DEFAULTS.listenPort;
  if (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535) {
    throw new ConfigError('rw_listen_port must be an integer 1-65535');
  }

  const firewall = validateFirewallZones(raw, warnings);
  let writeTools = resolveWriteTools(env);
  let writeLog = resolveWriteLog(env);
  const wanExposure = resolveWanExposure(env, firewall, warnings);
  if (!writes.allowWrites) {
    // Validated above all the same, so a mistake shows before writes are turned on.
    if (writeTools !== null) warnings.push('UNIFI_WRITE_TOOLS ignored: the server is read-only, so no write tools are registered');
    if (writeLog !== null) warnings.push('UNIFI_WRITE_LOG ignored: the server is read-only, so there are no write calls to log');
    writeTools = null;
    writeLog = null;
  }

  return {
    backend,
    ...be,
    ...writes,
    firewall,
    writeTools,
    writeLog,
    wanExposure,
    siteId,
    siteName,
    warnings,
    tokenFile: pathKey(raw, 'rw_token_file', DEFAULTS.tokenFile),
    listenHost,
    listenPort,
    publicHost: resolvePublicHost(env),
  };
}

function loadConfig({ configPath = defaultConfigPath(), env = process.env } = {}) {
  let text;
  try {
    text = fs.readFileSync(configPath, 'utf8');
  } catch (e) {
    throw new ConfigError(`cannot read config ${configPath} (${e.code || 'error'})`);
  }
  let raw;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new ConfigError(`config ${configPath} is not valid JSON`);
  }
  return { ...validateConfig(raw, { env }), configPath };
}

/** Read the bearer token and the backend's API key with the secret-file checks. */
function loadSecrets(cfg) {
  const token = readSecretFile(cfg.tokenFile, { label: 'MCP bearer token file', minLength: 32 });
  const label = cfg.backend === 'cloud' ? 'Site Manager API key file (cloud_rw_key_file)' : 'UDM API key file (local_rw_key_file)';
  const apiKey = readSecretFile(cfg.keyFile, { label, minLength: 16 });
  return { token, apiKey };
}

module.exports = {
  ConfigError,
  BACKENDS,
  loadSecrets,
  validateConsoleId,
  DEFAULTS,
  loadConfig,
  validateConfig,
  resolveAllowWrites,
  resolveWriteTools,
  resolveWriteLog,
  resolveWanExposure,
  readSecretFile,
  parseLocalHost,
  normalizeFingerprint,
  isLoopbackAddress,
  defaultConfigPath,
  expandHome,
};
