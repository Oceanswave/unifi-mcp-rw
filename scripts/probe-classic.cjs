#!/usr/bin/env node
'use strict';

/**
 * Read-only probe: which classic /api/s/ and integration endpoints answer
 * through the configured backend (cloud connector or local UDM)?
 *
 *   node scripts/probe-classic.cjs [--config PATH]      (npm run probe -- --config PATH)
 *
 * Uses the server's config loader and secret-file checks (lib/config.cjs)
 * and its udm-client, so the guard allowlist, final-path check, TLS rules and
 * cloud/local prefixing all apply. The client is created with the probe-only
 * PROBE_READ_ONLY option: it refuses every method except GET, and may GET
 * classic paths even when cloud_allow_classic does not enable them.
 *
 * Output: one line per request: method, canonical path, HTTP status (or
 * error kind/code), and a SHAPE summary built only from key names, counts and
 * a few enum values (ruleset, action, network purpose, group type, device
 * type, radio band). No values
 * (names, MACs, IPs, passphrases, ...) are printed; every line is passed
 * through the secret scrubber and an IPv4/MAC mask as a last layer.
 *
 * Exit: 0 every request got an HTTP response (any status), 1 a request failed
 * (transport/guard/site resolution), 2 configuration or secret-file error.
 */

const { loadConfig, loadSecrets, defaultConfigPath, expandHome, ConfigError } = require('../lib/config.cjs');
const { createUdmClient, PROBE_READ_ONLY, UdmHttpError } = require('../lib/udm-client.cjs');
const { GuardError, LEGACY_RULESETS, LEGACY_ACTIONS, RADIO_BANDS, UUID_RE, INTERNAL_NETWORK_PURPOSES } = require('../lib/guard.cjs');
const { redact, makeScrubber } = require('../lib/redact.cjs');

const KEY_CAP = 40;
const SAFE_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const DEVICE_TYPE_RE = /^u[a-z]{1,4}$/;
const NETWORK_PURPOSES = Object.freeze([...INTERNAL_NETWORK_PURPOSES, 'wan', 'vpn-client']);
const GROUP_TYPES = Object.freeze(['address-group', 'ipv6-address-group', 'port-group']);
const IPV4_ANY_RE = /\b\d{1,3}(\.\d{1,3}){3}\b/g;
const MAC_ANY_RE = /\b[0-9a-f]{2}([:-][0-9a-f]{2}){5}\b/gi;

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function parseArgs(argv) {
  let configPath = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--config' && typeof argv[i + 1] === 'string' && argv[i + 1] !== '') configPath = expandHome(argv[++i]);
    else throw new ConfigError('usage: node scripts/probe-classic.cjs [--config PATH]');
  }
  return { configPath: configPath || defaultConfigPath() };
}

/** Read-only client for the configured backend. `extra` is for tests (injected transport). */
function buildProbeClient(cfg, { apiKey }, extra = {}) {
  const common = {
    apiKey,
    siteName: cfg.siteName,
    siteId: cfg.siteId,
    firewallInternalZoneIds: cfg.firewall.internalZoneIds,
    firewallWanZoneIds: cfg.firewall.wanZoneIds,
    ...extra,
    [PROBE_READ_ONLY]: true,
  };
  const client =
    cfg.backend === 'cloud'
      ? createUdmClient({ backend: 'cloud', consoleId: cfg.cloud.consoleId, allowClassic: cfg.cloud.classicCapabilities, ...common })
      : createUdmClient({ backend: 'local', target: cfg.target, tls: cfg.tls, ...common });
  if (client.probeReadOnly !== true) throw new Error('probe client is not read-only');
  return client;
}

// --- shape summaries (keys, counts, enum values only) -------------------------

/** Sorted union of printable top-level keys of the objects in `items`, capped. */
function keyUnion(items) {
  const keys = new Set();
  let unprintable = 0;
  for (const it of items) {
    if (!isPlainObject(it)) continue;
    for (const k of Object.keys(it)) {
      if (SAFE_KEY_RE.test(k)) keys.add(k);
      else unprintable++;
    }
  }
  const sorted = [...keys].sort();
  const shown = sorted.slice(0, KEY_CAP);
  if (sorted.length > KEY_CAP) shown.push(`+${sorted.length - KEY_CAP} more`);
  if (unprintable) shown.push(`+${unprintable} unprintable`);
  return `[${shown.join(',')}]`;
}

const tally = (values) => {
  const m = new Map();
  for (const v of values) m.set(v, (m.get(v) || 0) + 1);
  return `{${[...m.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([k, n]) => `${k}=${n}`).join(',')}}`;
};
const enumOr = (v, allowed) => (allowed.includes(v) ? v : 'other');
const typeOf = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v);

function summarize(kind, data) {
  const parts = [];
  let items = null;
  if (Array.isArray(data)) items = data;
  else if (isPlainObject(data) && Array.isArray(data.data)) items = data.data;
  if (isPlainObject(data) && isPlainObject(data.meta)) parts.push(`meta.rc=${enumOr(data.meta.rc, ['ok', 'error'])}`);
  if (items === null) {
    parts.push(`${typeOf(data)}`);
    if (isPlainObject(data)) parts.push(`keys=${keyUnion([data])}`);
    return parts.join(' ');
  }
  parts.push(`count=${items.length}`);
  if (isPlainObject(data) && Number.isSafeInteger(data.totalCount)) parts.push(`totalCount=${data.totalCount}`);
  const nonObjects = items.filter((x) => !isPlainObject(x)).length;
  if (nonObjects) parts.push(`non_objects=${nonObjects}`);
  parts.push(`keys=${keyUnion(items)}`);
  const objs = items.filter(isPlainObject);
  if (kind === 'firewallrule') {
    parts.push(`rules=${tally(objs.map((r) => `${enumOr(r.ruleset, LEGACY_RULESETS)}:${enumOr(r.action, LEGACY_ACTIONS)}`))}`);
  } else if (kind === 'networkconf') {
    parts.push(`purposes=${tally(objs.map((n) => enumOr(n.purpose, NETWORK_PURPOSES)))}`);
  } else if (kind === 'firewallgroup') {
    parts.push(`group_types=${tally(objs.map((g) => enumOr(g.group_type, GROUP_TYPES)))}`);
  } else if (kind === 'user') {
    parts.push(`use_fixedip=${objs.filter((u) => u.use_fixedip === true).length}`);
  } else if (kind === 'device') {
    parts.push(`types=${tally(objs.map((d) => (typeof d.type === 'string' && DEVICE_TYPE_RE.test(d.type) ? d.type : 'other')))}`);
    const aps = objs.filter((d) => d.type === 'uap');
    const radios = aps.flatMap((d) => (Array.isArray(d.radio_table) ? d.radio_table : []));
    if (aps.length) {
      parts.push(`uap_radio_table_keys=${keyUnion(radios)}`);
      parts.push(`uap_radios=${tally(radios.filter(isPlainObject).map((r) => enumOr(r.radio, RADIO_BANDS)))}`);
      parts.push(`uap_without_radio_table=${aps.filter((d) => !Array.isArray(d.radio_table)).length}`);
    }
  }
  return parts.join(' ');
}

// --- probe ----------------------------------------------------------------------

/** Last output layer: configured secrets (raw/JSON/URL forms), then any IPv4- or MAC-shaped text. */
function makeSanitizer(secrets) {
  const scrub = makeScrubber(secrets);
  return (str) => scrub(String(str)).replace(IPV4_ANY_RE, '[REDACTED]').replace(MAC_ANY_RE, '[REDACTED]');
}

/**
 * Run all probe GETs. `write(line)` receives each sanitized line. `siteId`:
 * config site_id; otherwise the single site from GET /integration/v1/sites.
 * Returns { complete } (true if every request got an HTTP response).
 */
async function runProbe(client, { siteId: configSiteId = null, secrets = [], write = (l) => process.stdout.write(`${l}\n`) } = {}) {
  const sanitize = makeSanitizer(secrets);
  const emit = (str) => write(sanitize(client.scrub(String(str))));
  let complete = true;

  async function probe(path, kind) {
    try {
      const { status, data } = await client.request({ method: 'GET', path, withStatus: true });
      emit(`GET ${path} ${status} ${summarize(kind, redact(data))}`);
      return data;
    } catch (e) {
      if (e instanceof UdmHttpError) {
        emit(`GET ${path} ${e.status}${e.code !== undefined ? ` code=${e.code}` : ''}`);
      } else if (e instanceof GuardError) {
        complete = false;
        emit(`GET ${path} REFUSED ${e.reason}`);
      } else {
        complete = false;
        emit(`GET ${path} ERROR ${(e && e.message) || 'unknown error'}`);
      }
      return undefined;
    }
  }

  emit(`probe-classic: backend=${client.backend} site_name=${client.siteName} classic_capabilities=${client.classicCapabilities.length ? client.classicCapabilities.join(',') : 'none'} (read-only probe client)`);

  const sites = await probe(client.integration('/sites?limit=200'), 'sites');
  let siteId = configSiteId;
  if (siteId === null && isPlainObject(sites) && Array.isArray(sites.data) && sites.data.length === 1 && isPlainObject(sites.data[0])) {
    siteId = typeof sites.data[0].id === 'string' ? sites.data[0].id.toLowerCase() : null;
  }
  if (siteId !== null && !UUID_RE.test(siteId)) siteId = null;
  if (siteId === null && sites !== undefined) emit('site: could not resolve exactly one integration site (set site_id in config)');

  for (const [p, kind] of [['/rest/firewallrule', 'firewallrule'], ['/rest/firewallgroup', 'firewallgroup'], ['/rest/networkconf', 'networkconf'], ['/rest/user', 'user'], ['/stat/device', 'device']]) {
    await probe(client.classicPath(p), kind);
  }

  const scoped = [['/firewall/policies?limit=200'], ['/firewall/zones?limit=200'], ['/acl-rules?limit=200'], ['/devices?limit=200'], ['/clients?limit=5']];
  for (const [p] of scoped) {
    if (siteId === null) {
      complete = false;
      emit(`GET ${client.integration(`/sites/{siteId}${p}`)} SKIPPED site id unresolved`);
      continue;
    }
    await probe(client.integration(`/sites/${siteId}${p}`), 'generic');
  }
  emit(`probe-classic: ${complete ? 'all requests completed' : 'some requests did not complete'}`);
  return { complete };
}

async function main(argv = process.argv.slice(2)) {
  let cfg, secrets;
  try {
    cfg = loadConfig(parseArgs(argv));
    secrets = loadSecrets(cfg);
  } catch (e) {
    if (e instanceof ConfigError) {
      process.stderr.write(`probe-classic: ${e.message}\n`);
      return 2;
    }
    throw e;
  }
  const all = [secrets.token, secrets.apiKey];
  try {
    const client = buildProbeClient(cfg, secrets);
    const { complete } = await runProbe(client, { siteId: cfg.siteId, secrets: all });
    return complete ? 0 : 1;
  } catch (e) {
    process.stderr.write(`probe-classic: fatal: ${makeSanitizer(all)((e && e.message) || e)}\n`);
    return 1;
  }
}

module.exports = { runProbe, buildProbeClient, summarize, parseArgs, makeSanitizer, main };

if (require.main === module) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (e) => {
      process.stderr.write(`probe-classic: fatal: ${makeSanitizer([])((e && e.message) || e)}\n`);
      process.exitCode = 1;
    }
  );
}
