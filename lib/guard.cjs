'use strict';

/**
 * Second-layer request allowlist. Pure: no I/O.
 *
 * checkRequest({ method, path, body, context }) -> { ok: true, rule } or throws GuardError.
 *
 * `path` is the CANONICAL path, relative to the Network application prefix:
 * it must begin with exactly "/integration/v1/" or "/api/s/". The backend
 * adapter (udm-client) prepends its own constant prefix ("/proxy/network" for
 * local, "/v1/connector/consoles/{id}/proxy/network" for cloud) only after the
 * guard has passed, and then re-checks the full path with checkFinalPath().
 * Decisions are therefore identical for both backends.
 *
 * Order of evaluation:
 *   1. method / path normalization checks (DELETE never allowed), canonical
 *      prefix, no smuggled proxy/connector prefix or other app
 *   2. explicit deny list (defense in depth, clear reasons)
 *   3. hardcoded allowlist (anchored regexes, default deny)
 *   4. generic write-body checks (deep key scan)
 *   5. per-endpoint bodyCheck (WAN-exposure inspection etc.), fail closed
 *
 * `context` (writes only) carries data the guard cannot fetch itself:
 *   existing         the object being updated, fetched right before the write
 *                    (required for every PUT/PATCH except rest/user)
 *   zones            GET firewall/zones result (zone-based policy writes)
 *   networks         classic GET rest/networkconf data   } legacy firewall rule
 *   firewallGroups   classic GET rest/firewallgroup data } writes (accept rules)
 *   lookupErrors     {networks?, firewallGroups?}: why a lookup failed (message only)
 *   internalZoneIds  config firewall_internal_zone_ids  } always set by the
 *   wanZoneIds       config firewall_wan_zone_ids       } udm-client from config
 */

class GuardError extends Error {
  constructor(message) {
    super(`Refused by guard: ${message}`);
    this.name = 'GuardError';
    this.reason = message;
  }
}

const refuse = (msg) => {
  throw new GuardError(msg);
};

const UUID = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
const HEX24 = '[0-9a-f]{24}';
const SITE = '[A-Za-z0-9_-]{1,64}';
const MAC = '[0-9a-f]{2}(?::[0-9a-f]{2}){5}';
const I = `/integration/v1`;
const IS = `${I}/sites/${UUID}`;
const C = `/api/s/${SITE}`;

// ---------------------------------------------------------------------------
// Backend prefixes. Only these two forms can ever precede a canonical path.
// ---------------------------------------------------------------------------
const LOCAL_PREFIX = '/proxy/network';
// Site Manager console id, e.g. "942A…873F:9999999999". Only [A-Za-z0-9] and
// one optional ":digits" suffix, so it can never contain "/", ".", "?", "%".
const CONSOLE_ID_RE = /^[A-Za-z0-9]{8,128}(:[0-9]{1,20})?$/;
const CLOUD_PREFIX_RE = /^\/v1\/connector\/consoles\/[A-Za-z0-9]{8,128}(:[0-9]{1,20})?\/proxy\/network$/;

/**
 * Cloud connector prefix for a console id. The id is URL-encoded with
 * encodeURIComponent, except that ":" is kept literal (a valid path character
 * per RFC 3986, and the form used in Ubiquiti's examples). Because the id is
 * validated against CONSOLE_ID_RE first, the encoded form equals the input.
 */
function cloudPrefix(consoleId) {
  if (typeof consoleId !== 'string' || !CONSOLE_ID_RE.test(consoleId)) refuse('invalid console id');
  const enc = encodeURIComponent(consoleId).replace(/%3A/g, ':');
  if (enc !== consoleId) refuse('invalid console id');
  return `/v1/connector/consoles/${enc}${LOCAL_PREFIX}`;
}

const isKnownPrefix = (prefix) => prefix === LOCAL_PREFIX || (typeof prefix === 'string' && CLOUD_PREFIX_RE.test(prefix));

const UUID_RE = new RegExp(`^${UUID}$`);
const HEX24_RE = new RegExp(`^${HEX24}$`);
const MAC_RE = new RegExp(`^${MAC}$`);
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

const ALLOWED_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH']);
const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH']);

// ---------------------------------------------------------------------------
// Explicit deny list. Checked before the allowlist. `writes: true` limits an
// entry to non-GET methods (so that reads the tools need keep working).
// ---------------------------------------------------------------------------
const DENY = [
  { re: /\/cmd\/devmgr/i, reason: 'device manager commands (firmware upgrade, restart, adopt, forget, provision, power-cycle) are not allowed' },
  { re: /\/cmd\/sitemgr/i, reason: 'site/admin management commands are not allowed' },
  { re: /\/cmd\/backup|\/backup|\/restore|autobackup/i, reason: 'backup/restore operations are not allowed' },
  { re: /\/cmd(\/|$)/i, reason: 'classic /cmd/ endpoints are never allowed' },
  { re: /upgrade|firmware/i, reason: 'firmware/upgrade operations are not allowed' },
  { re: /delete|forget/i, reason: 'delete/forget operations are not allowed' },
  { re: /\/integration\/v1\/pending-devices/i, writes: true, reason: 'device adoption is not allowed' },
  { re: /\/integration\/v1\/sites\/[^/]+\/devices(\/|$)/i, writes: true, reason: 'device writes/actions (adopt, restart, power-cycle, port actions) are not allowed' },
  { re: /\/interfaces\/ports\/.*\/actions/i, reason: 'port actions are not allowed' },
  { re: /portforward|port-forward|port_forward|\/nat(\/|$)/i, reason: 'port forwarding / NAT is not allowed' },
  { re: /\/rest\/networkconf/i, writes: true, reason: 'classic network configuration writes (incl. WAN) are not allowed' },
  { re: /\/integration\/v1\/sites\/[^/]+\/wans/i, writes: true, reason: 'WAN configuration writes are not allowed' },
  { re: /dynamicdns|upnp/i, reason: 'dynamic DNS / UPnP settings are not allowed' },
  { re: /\/api\/self|\/stat\/admin|\/admin(\/|$)|\/proxy\/users|\/users(\/|$)|\/role/i, reason: 'admin/user management is not allowed' },
  { re: /\/rest\/setting|\/set\/setting|\/get\/setting/i, reason: 'controller settings writes are not allowed' },
  { re: /\/mgmt|ssh|remote[-_]?access|cloud[-_]?access|\/cloud(\/|$)/i, reason: 'remote access / SSH / management settings are not allowed' },
  { re: /\/firewall\/zones/i, writes: true, reason: 'firewall zone writes are not allowed (moving a network into the External zone exposes it)' },
  { re: /\/firewall\/policies\/ordering/i, reason: 'firewall policy ordering is not allowed' },
  { re: /voucher/i, writes: true, reason: 'hotspot voucher writes are not allowed' },
  { re: /\/acl-rules/i, writes: true, reason: 'ACL rule writes are not allowed' },
  { re: /\/dns\/policies/i, writes: true, reason: 'DNS policy writes are not allowed' },
  { re: /\/traffic-matching-lists/i, writes: true, reason: 'traffic matching list writes are not allowed' },
  { re: /\/vpn\//i, writes: true, reason: 'VPN writes are not allowed' },
  { re: /\/rest\/account|\/radius/i, writes: true, reason: 'RADIUS account writes are not allowed' },
];

// ---------------------------------------------------------------------------
// Body checks
// ---------------------------------------------------------------------------
const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// Keys refused anywhere in any write body (deep scan).
const DENY_BODY_KEYS = [
  /^x_ssh/i,
  /^ssh_?/i,
  /^mgmt_?/i,
  /^remote_?access/i,
  /^firmware/i,
  /^upgrade/i,
  /^port_?forward/i,
  /^fwd_?port$/i,
  /^upnp/i,
  /^nat_?pmp/i,
];

function deepScan(value, path = '$', depth = 0) {
  if (depth > 32) refuse('request body nested too deeply');
  if (Array.isArray(value)) {
    value.forEach((v, i) => deepScan(v, `${path}[${i}]`, depth + 1));
    return;
  }
  if (isPlainObject(value)) {
    for (const [k, v] of Object.entries(value)) {
      if (k === '__proto__' || k === 'constructor' || k === 'prototype') refuse(`forbidden key "${k}" in body`);
      const hit = DENY_BODY_KEYS.find((re) => re.test(k));
      if (hit) refuse(`body key "${path}.${k}" is not allowed (SSH/management/firmware/port-forward settings)`);
      deepScan(v, `${path}.${k}`, depth + 1);
    }
    return;
  }
  // Never write a redaction placeholder back to the controller (would e.g. set a passphrase to "[REDACTED]").
  if (value === '[REDACTED]') refuse(`body value at ${path} is a redaction placeholder`);
}

function onlyKeys(obj, allowed, what) {
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) refuse(`${what}: key "${k}" is not allowed (allowed: ${allowed.join(', ')})`);
  }
}

/**
 * Structural equality for JSON values. Object key order is ignored; a key
 * whose value is undefined counts as absent (as in JSON.stringify).
 */
function deepEqual(a, b, depth = 0) {
  if (depth > 64) return false;
  if (a === b) return true;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, i) => deepEqual(v, b[i], depth + 1));
  }
  if (isPlainObject(a) && isPlainObject(b)) {
    const ka = Object.keys(a).filter((k) => a[k] !== undefined);
    const kb = Object.keys(b).filter((k) => b[k] !== undefined);
    if (ka.length !== kb.length) return false;
    return ka.every((k) => hasOwn(b, k) && deepEqual(a[k], b[k], depth + 1));
  }
  return false;
}

const without = (o, keys) => Object.fromEntries(Object.entries(o).filter(([k]) => !keys.includes(k)));

/** Top-level keys (of either object) whose values differ, ignoring `ignore`. */
function changedKeys(body, existing, ignore = []) {
  const keys = new Set([...Object.keys(body), ...Object.keys(existing)]);
  return [...keys].filter((k) => !ignore.includes(k) && !deepEqual(body[k], existing[k])).sort();
}

/**
 * The object being updated, as fetched by the tool right before the write
 * (context.existing). Updates without it are refused. It must carry its own
 * string id (`id` integration, `_id` classic) equal to the id in the path;
 * a missing id is refused as well (we can't tell which object it is).
 * Integration UUIDs compare case-insensitively, classic 24-hex ids exactly.
 */
function requireExisting(context, what, req, idKey = 'id') {
  const ex = context.existing;
  if (!isPlainObject(ex)) refuse(`current ${what} could not be determined (context.existing missing); ${what} updates fail closed`);
  const id = hasOwn(ex, idKey) ? ex[idKey] : undefined;
  if (typeof id !== 'string' || id.length === 0) refuse(`context.existing has no ${idKey}; cannot confirm it is the ${what} named in the path`);
  const same = idKey === 'id' ? id.toLowerCase() === String(req.id).toLowerCase() : id === req.id;
  if (!same) refuse(`context.existing is not the ${what} named in the path`);
  return ex;
}

function refuseReadOnly(body, keys, what) {
  for (const k of keys) {
    if (hasOwn(body, k) && body[k] !== undefined) refuse(`${what}: read-only field "${k}" must not be sent`);
  }
}

// --- zone-based firewall ------------------------------------------------------

// Names are user-editable and therefore never used to PERMIT anything; a
// WAN-looking name is only an additional refusal signal.
const WAN_ZONE_NAME_RE = /^(external|wan|internet)$/i;

function isWanZone(zone) {
  if (!zone) return true;
  if (typeof zone.name === 'string' && WAN_ZONE_NAME_RE.test(zone.name.trim())) return true;
  const md = zone.metadata;
  if (isPlainObject(md)) {
    for (const v of Object.values(md)) {
      if (typeof v === 'string' && WAN_ZONE_NAME_RE.test(v.trim())) return true;
    }
  }
  return false;
}

/**
 * Zone classification from configuration. The udm-client always sets
 * context.internalZoneIds / context.wanZoneIds from config.json
 * (firewall_internal_zone_ids / firewall_wan_zone_ids), overriding anything a
 * tool put there. Invalid values fail closed.
 */
function zoneConfig(context) {
  const norm = (v, key) => {
    if (v === undefined || v === null) return [];
    if (!Array.isArray(v) || v.length > 256 || !v.every((x) => typeof x === 'string' && UUID_RE.test(x))) {
      refuse(`${key} is invalid (must be an array of zone UUIDs); zone-based policy writes fail closed`);
    }
    return v.map((x) => x.toLowerCase());
  };
  const internal = norm(context.internalZoneIds, 'firewall_internal_zone_ids');
  const wan = norm(context.wanZoneIds, 'firewall_wan_zone_ids');
  if (internal.some((id) => wan.includes(id))) refuse('a zone is configured both in firewall_internal_zone_ids and firewall_wan_zone_ids; zone-based policy writes fail closed');
  return { internal, wan };
}

const zoneIdOf = (side) => (isPlainObject(side) && typeof side.zoneId === 'string' ? side.zoneId.toLowerCase() : undefined);
const findZone = (zones, id) => zones.find((z) => z && typeof z.id === 'string' && typeof id === 'string' && z.id.toLowerCase() === id);
const DENY_ACTIONS = ['BLOCK', 'REJECT'];
const isDenyAction = (action) => isPlainObject(action) && typeof action.type === 'string' && DENY_ACTIONS.includes(action.type.toUpperCase());

/**
 * A deny policy whose source is (or might be) the WAN side: source zone listed
 * in firewall_wan_zone_ids, OR not listed in firewall_internal_zone_ids, OR
 * unknown / WAN-named. Such a policy protects the network from the outside and
 * may only be changed cosmetically.
 */
function isWanSideDeny(policy, zones, cfg) {
  if (!isDenyAction(policy.action)) return false;
  const src = zoneIdOf(policy.source);
  if (!src || cfg.wan.includes(src) || !cfg.internal.includes(src)) return true;
  return isWanZone(findZone(zones, src));
}

const RO_POLICY = ['id', 'index', 'metadata'];
// Fields of a WAN-side deny policy that may change. Everything else (enabled,
// action, source, destination, schedule, ipProtocolScope,
// connectionStateFilter, ipsecFilter, unknown fields) must stay deep-equal.
const POLICY_COSMETIC_KEYS = ['name', 'description', 'loggingEnabled'];

function checkCosmeticPolicyFields(body) {
  if (body.name !== undefined && (typeof body.name !== 'string' || body.name.length === 0 || body.name.length > 256)) refuse('firewall policy: name must be a non-empty string');
  if (body.description !== undefined && body.description !== null && (typeof body.description !== 'string' || body.description.length > 1024)) refuse('firewall policy: description must be a string');
  if (body.loggingEnabled !== undefined && typeof body.loggingEnabled !== 'boolean') refuse('firewall policy: loggingEnabled must be a boolean');
}

function checkZoneFirewallPolicy(body, context, req) {
  const zones = context.zones;
  if (!Array.isArray(zones) || zones.length === 0) {
    refuse('firewall zones could not be determined; firewall policy writes fail closed');
  }
  const cfg = zoneConfig(context);
  refuseReadOnly(body, RO_POLICY, 'firewall policy');
  if (!isPlainObject(body.action) || typeof body.action.type !== 'string') refuse('firewall policy must have action.type');
  checkCosmeticPolicyFields(body);

  if (req.method === 'PUT') {
    const existing = requireExisting(context, 'firewall policy', req);
    if (isWanSideDeny(existing, zones, cfg)) {
      const changed = changedKeys(body, without(existing, RO_POLICY), POLICY_COSMETIC_KEYS);
      if (changed.length) {
        refuse(`policy is a WAN-side deny (BLOCK/REJECT from a zone that is not a configured internal zone); only ${POLICY_COSMETIC_KEYS.join(', ')} may change, not: ${changed.join(', ')}`);
      }
    }
  }

  if (isDenyAction(body.action)) return;
  // ALLOW, or anything unknown, is treated as ALLOW: both ends must be
  // configured internal zones that also exist on the controller.
  if (cfg.internal.length === 0) {
    refuse('ALLOW policies require firewall_internal_zone_ids in config.json; none configured, so zone-based ALLOW writes are refused');
  }
  for (const [side, label] of [['source', 'source'], ['destination', 'destination']]) {
    const id = zoneIdOf(body[side]);
    const zone = findZone(zones, id);
    if (!zone) refuse(`${label} zone ${JSON.stringify(id ?? null)} is unknown; ALLOW policies require a resolvable ${label} zone`);
    const wan = cfg.wan.includes(id) || isWanZone(zone);
    if (wan && side === 'source') refuse(`policy would allow WAN-in (ALLOW from WAN/External zone ${JSON.stringify(zone.name ?? id)})`);
    if (wan) refuse(`ALLOW to WAN/External zone ${JSON.stringify(zone.name ?? id)} is not allowed (destination must be a configured internal zone)`);
    if (!cfg.internal.includes(id)) refuse(`${label} zone ${JSON.stringify(zone.name ?? id)} is not in firewall_internal_zone_ids; ALLOW policies need internal source and destination zones`);
  }
}

function checkPatchFirewallPolicy(body, context, req) {
  requireExisting(context, 'firewall policy', req);
  onlyKeys(body, ['loggingEnabled'], 'firewall policy patch');
  if (typeof body.loggingEnabled !== 'boolean') refuse('firewall policy patch: loggingEnabled must be a boolean');
}

// --- legacy (pre-zone) firewall rules -----------------------------------------

// Exact (case-sensitive) rulesets of the classic firewall. Anything else is refused.
const LEGACY_RULESETS = Object.freeze(
  ['WAN', 'LAN', 'GUEST'].flatMap((zone) => ['', 'v6'].flatMap((v) => ['IN', 'OUT', 'LOCAL'].map((dir) => `${zone}${v}_${dir}`)))
);
const LEGACY_ACTIONS = Object.freeze(['accept', 'drop', 'reject']);
const RO_CLASSIC = ['_id', 'site_id'];
// Controller-managed markers on system/predefined rules: never sent on create,
// must stay equal on update.
const LEGACY_RO_ATTR_KEYS = ['attr_no_delete', 'attr_no_edit', 'attr_hidden', 'attr_hidden_id'];
// Fields of an existing WAN* drop/reject rule that may change. Both are
// cosmetic: the label, and whether matches are logged.
const LEGACY_COSMETIC_KEYS = ['name', 'logging'];
const isWanRuleset = (rs) => typeof rs === 'string' && rs.startsWith('WAN');
const isDropOrReject = (a) => a === 'drop' || a === 'reject';
// src/dst_networkconf_type of the classic rule model. It qualifies
// src/dst_networkconf_id: the network's subnet (NETv4/NETv6) or the gateway's
// address on that network (ADDRv4/ADDRv6). The controller also stores it, as
// NETv4 by default, on rules that reference no network; with an empty id it
// selects nothing. "" = none.
const LEGACY_NETCONF_TYPES = Object.freeze(['', 'NETv4', 'ADDRv4', 'NETv6', 'ADDRv6']);
const LEGACY_MAC_RE = /^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$/;

const optStr = (re, max = 128) => (v) => typeof v === 'string' && v.length <= max && re.test(v);
const isBool = (v) => typeof v === 'boolean';
const hexIdOrEmpty = (v) => v === '' || (typeof v === 'string' && HEX24_RE.test(v));
const groupIds = (v) => Array.isArray(v) && v.length <= 32 && v.every((x) => typeof x === 'string' && HEX24_RE.test(x));
const addressLike = optStr(/^[0-9A-Fa-f:.\/!,-]*$/, 256);
const portLike = optStr(/^[0-9,:!-]*$/, 256);
const tokenLike = optStr(/^[A-Za-z0-9_-]*$/, 64);
const scheduleLike = optStr(/^[A-Za-z0-9,:. -]*$/, 64);

/**
 * Writable fields of a classic rest/firewallrule object (UniFi Network
 * classic rule model) with a type/format check each. Any other key in a
 * create body or a merged update body is refused.
 */
const LEGACY_RULE_FIELDS = Object.freeze({
  name: (v) => typeof v === 'string' && v.length <= 256,
  enabled: isBool,
  ruleset: (v) => LEGACY_RULESETS.includes(v),
  rule_index: (v) => intLike(v, 0, 99999),
  action: (v) => LEGACY_ACTIONS.includes(v),
  protocol: tokenLike,
  protocol_match_excepted: isBool,
  protocol_v6: tokenLike,
  icmp_typename: tokenLike,
  icmpv6_typename: tokenLike,
  logging: isBool,
  state_new: isBool,
  state_established: isBool,
  state_invalid: isBool,
  state_related: isBool,
  ipsec: (v) => v === '' || v === 'match-ipsec' || v === 'match-none',
  src_firewallgroup_ids: groupIds,
  src_mac_address: (v) => v === '' || (typeof v === 'string' && LEGACY_MAC_RE.test(v)),
  src_address: addressLike,
  src_address_ipv6: addressLike,
  src_networkconf_id: hexIdOrEmpty,
  src_networkconf_type: (v) => LEGACY_NETCONF_TYPES.includes(v),
  src_port: portLike,
  dst_firewallgroup_ids: groupIds,
  dst_address: addressLike,
  dst_address_ipv6: addressLike,
  dst_networkconf_id: hexIdOrEmpty,
  dst_networkconf_type: (v) => LEGACY_NETCONF_TYPES.includes(v),
  dst_port: portLike,
  setting_preference: (v) => v === 'auto' || v === 'manual',
  // schedule (only narrows when a rule applies)
  contiguous: isBool,
  utc: isBool,
  weekdays: scheduleLike,
  weekdays_negate: isBool,
  monthdays: scheduleLike,
  monthdays_negate: isBool,
  startdate: scheduleLike,
  starttime: scheduleLike,
  stopdate: scheduleLike,
  stoptime: scheduleLike,
});
const LEGACY_FIELD_NAMES = Object.freeze(Object.keys(LEGACY_RULE_FIELDS));

// --- private address space (accept rules) --------------------------------------

// Address space an accept rule may name. 100.64.0.0/10 (RFC 6598 shared /
// CGNAT space) is included because Tailscale assigns tailnet addresses from
// it; it is never routed on the public internet. 169.254/16 and fe80::/10
// are link-local, fc00::/7 is IPv6 unique-local.
const PRIVATE_V4 = Object.freeze([
  ['10.0.0.0', 8],
  ['172.16.0.0', 12],
  ['192.168.0.0', 16],
  ['100.64.0.0', 10],
  ['169.254.0.0', 16],
]);
const PRIVATE_V6 = Object.freeze([
  ['fc00::', 7],
  ['fe80::', 10],
]);

function parseV4(s) {
  if (typeof s !== 'string' || !IPV4_RE.test(s)) return null;
  return s.split('.').reduce((n, o) => (n << 8n) | BigInt(o), 0n);
}

function parseV6(s) {
  if (typeof s !== 'string' || s.length > 39 || !/^[0-9A-Fa-f:]+$/.test(s)) return null;
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] === '' ? [] : halves[0].split(':');
  const tail = halves.length === 2 && halves[1] !== '' ? halves[1].split(':') : [];
  if (![...head, ...tail].every((h) => /^[0-9A-Fa-f]{1,4}$/.test(h))) return null;
  if (halves.length === 1 && head.length !== 8) return null;
  if (halves.length === 2 && head.length + tail.length > 7) return null;
  const groups = [...head, ...Array(8 - head.length - tail.length).fill('0'), ...tail];
  return groups.reduce((n, h) => (n << 16n) | BigInt(parseInt(h, 16)), 0n);
}

const FAMILIES = Object.freeze({
  v4: { bits: 32n, parse: parseV4 },
  v6: { bits: 128n, parse: parseV6 },
});

const blockRange = (fam, base, len) => {
  const f = FAMILIES[fam];
  const start = f.parse(base);
  const size = 1n << (f.bits - BigInt(len));
  return [start, start + size - 1n];
};
const PRIVATE_RANGES = Object.freeze({
  v4: PRIVATE_V4.map(([b, l]) => blockRange('v4', b, l)),
  v6: PRIVATE_V6.map(([b, l]) => blockRange('v6', b, l)),
});

/**
 * [start, end] covered by one address term: a single address, a CIDR
 * ("a/len"; host bits ignored, as the controller does) or a range ("a-b").
 * null if malformed or not of the given family.
 */
function termRange(term, fam) {
  const f = FAMILIES[fam];
  let m = /^([^/-]+)\/(0|[1-9]\d{0,2})$/.exec(term);
  if (m) {
    const addr = f.parse(m[1]);
    const len = BigInt(m[2]);
    if (addr === null || len > f.bits) return null;
    const host = (1n << (f.bits - len)) - 1n;
    const start = addr & ~host;
    return [start, start | host];
  }
  m = /^([^/-]+)-([^/-]+)$/.exec(term);
  if (m) {
    const a = f.parse(m[1]);
    const b = f.parse(m[2]);
    if (a === null || b === null || a > b) return null;
    return [a, b];
  }
  const a = f.parse(term);
  return a === null ? null : [a, a];
}

/**
 * Throws unless every comma-separated term of `value` is an address, CIDR or
 * range of family `fam` that lies entirely inside ONE private block.
 * Negation ("!") is refused: "everything except X" is not private.
 */
function requirePrivateAddresses(value, fam, what) {
  if (typeof value !== 'string' || value === '') refuse(`${what}: missing address`);
  for (const term of value.split(',')) {
    if (term.includes('!')) refuse(`${what}: negated address "${term}" is not allowed on accept rules (it matches everything else, including the internet)`);
    const r = termRange(term, fam);
    if (!r) refuse(`${what}: "${term}" is not a valid ${fam === 'v4' ? 'IPv4' : 'IPv6'} address, CIDR or range`);
    if (!PRIVATE_RANGES[fam].some(([s, e]) => s <= r[0] && r[1] <= e)) {
      const blocks = (fam === 'v4' ? PRIVATE_V4 : PRIVATE_V6).map(([b, l]) => `${b}/${l}`).join(', ');
      refuse(`${what}: "${term}" is not entirely inside private address space (${blocks}); accept rules may only name private addresses`);
    }
  }
}

/** Comma-separated ports or port ranges ("a-b" / "a:b"), 1-65535, no negation. */
function requireValidPorts(value, what) {
  if (typeof value !== 'string' || value === '') refuse(`${what}: missing port`);
  for (const term of value.split(',')) {
    if (term.includes('!')) refuse(`${what}: negated port "${term}" is not allowed on accept rules`);
    const m = /^(\d{1,5})(?:[-:](\d{1,5}))?$/.exec(term);
    const a = m ? Number(m[1]) : NaN;
    const b = m && m[2] !== undefined ? Number(m[2]) : a;
    if (!m || a < 1 || b > 65535 || a > b) refuse(`${what}: "${term}" is not a valid port or port range (1-65535)`);
  }
}

// --- legacy accept rules: source/destination resolution --------------------------

// Classic networkconf purposes an accept rule may reference. "wan" (and
// "vpn-client", a tunnel to an outside provider) are external; anything
// missing or unknown is refused (fail closed).
const INTERNAL_NETWORK_PURPOSES = Object.freeze(['corporate', 'guest', 'vlan-only', 'remote-user-vpn', 'site-vpn']);
const ADDRESS_GROUP_TYPES = Object.freeze({ 'address-group': 'v4', 'ipv6-address-group': 'v6' });
const ruleFamily = (ruleset) => (ruleset.includes('v6_') ? 'v6' : 'v4');
const nonEmpty = (v) => typeof v === 'string' && v !== '';
const famName = (fam) => (fam === 'v4' ? 'IPv4' : 'IPv6');
const ADDRESS_FIELDS = Object.freeze({ src_address: 'v4', dst_address: 'v4', src_address_ipv6: 'v6', dst_address_ipv6: 'v6' });
const addressKey = (side, fam) => (fam === 'v4' ? `${side}_address` : `${side}_address_ipv6`);
// Per family: the networkconf types and the address group type an accept rule may use.
const FAMILY_SELECTORS = Object.freeze({
  v4: { netconfTypes: ['NETv4', 'ADDRv4'], groupType: 'address-group' },
  v6: { netconfTypes: ['NETv6', 'ADDRv6'], groupType: 'ipv6-address-group' },
});
// Classic networkconf fields that can hold a network's static IPv6 subnet.
// Every one present must be private; at least one must be present.
const NETWORK_V6_SUBNET_KEYS = Object.freeze(['ipv6_subnet', 'ipv6_static_subnet']);

/** A network's subnet: one CIDR ("gateway address/prefix length"), entirely private. */
function requirePrivateSubnet(value, fam, what) {
  if (typeof value !== 'string' || !/^[^,!/-]+\/\d{1,3}$/.test(value)) {
    refuse(`${what} ${JSON.stringify(typeof value === 'string' ? value.slice(0, 64) : value ?? null)} is not an ${famName(fam)} CIDR; accept rules may not reference the network`);
  }
  requirePrivateAddresses(value, fam, what);
}

/**
 * context.networks: classic GET rest/networkconf data, fetched by the tool.
 * The referenced network must exist, have an internal purpose, and have a
 * private subnet in the family the networkconf type selects: ip_subnet for
 * NETv4/ADDRv4; for NETv6/ADDRv6 a static IPv6 subnet (ipv6_interface_type
 * "static"). A prefix delegated from the WAN is not in the record (and is
 * normally public), so it is refused, as is a network without IPv6.
 */
function requireInternalNetwork(id, type, side, context, ctxNote) {
  const nets = context.networks;
  if (!Array.isArray(nets)) refuse(`${side}_networkconf_id is set but the networks (classic rest/networkconf) could not be determined; accept rules fail closed${ctxNote('networks')}`);
  const n = nets.find((x) => isPlainObject(x) && x._id === id);
  if (!n) refuse(`${side}_networkconf_id ${id} is not a known network`);
  const label = typeof n.name === 'string' ? JSON.stringify(n.name.slice(0, 64)) : id;
  if (n.purpose === 'wan') refuse(`${side}_networkconf_id refers to WAN network ${label}; accept rules may only reference internal networks`);
  if (!INTERNAL_NETWORK_PURPOSES.includes(n.purpose)) {
    refuse(`${side}_networkconf_id refers to network ${label} with purpose ${JSON.stringify(n.purpose ?? null)}; only ${INTERNAL_NETWORK_PURPOSES.join(', ')} are allowed`);
  }
  const what = `${side}_networkconf_id network ${label}`;
  if (type === 'NETv4' || type === 'ADDRv4') {
    if (!nonEmpty(n.ip_subnet)) refuse(`${what} has no IPv4 subnet (ip_subnet), so it cannot be shown to be private; accept rules may not reference it with ${type}`);
    requirePrivateSubnet(n.ip_subnet, 'v4', `${what} subnet`);
    return;
  }
  const v6type = n.ipv6_interface_type;
  if (v6type === 'pd') {
    const from = nonEmpty(n.ipv6_pd_interface) ? JSON.stringify(n.ipv6_pd_interface.slice(0, 32)) : 'the WAN';
    refuse(`${what} gets its IPv6 prefix by prefix delegation from ${from}; the prefix is not in the network record and is normally public, so accept rules may not reference it with ${type}. Use ULA addresses in ${side}_address_ipv6 or an ipv6-address-group instead`);
  }
  if (v6type !== 'static') {
    refuse(`${what} has ipv6_interface_type ${JSON.stringify(v6type ?? null)}; only a network with a static IPv6 subnet can be referenced with ${type} on an accept rule`);
  }
  const keys = NETWORK_V6_SUBNET_KEYS.filter((k) => n[k] !== undefined && n[k] !== null && n[k] !== '');
  if (keys.length === 0) refuse(`${what} has no static IPv6 subnet (${NETWORK_V6_SUBNET_KEYS.join(', ')}), so it cannot be shown to be private; accept rules may not reference it with ${type}`);
  for (const k of keys) requirePrivateSubnet(n[k], 'v6', `${what} ${k}`);
}

/**
 * context.firewallGroups: classic GET rest/firewallgroup data, fetched by the
 * tool. Every referenced group must exist; address groups must be of the
 * rule's family and contain only private addresses, port groups only valid
 * ports. Returns true if an address group was referenced (for the
 * source-constraint check).
 */
function requireSafeGroups(ids, side, fam, ruleset, context, ctxNote) {
  let hasAddressGroup = false;
  if (!Array.isArray(ids) || ids.length === 0) return hasAddressGroup;
  const groups = context.firewallGroups;
  if (!Array.isArray(groups)) refuse(`${side}_firewallgroup_ids is set but the firewall groups (classic rest/firewallgroup) could not be determined; accept rules fail closed${ctxNote('firewallGroups')}`);
  for (const id of ids) {
    const g = groups.find((x) => isPlainObject(x) && x._id === id);
    if (!g) refuse(`${side}_firewallgroup_ids: firewall group ${id} does not exist`);
    const label = `firewall group ${typeof g.name === 'string' ? JSON.stringify(g.name.slice(0, 64)) : id}`;
    const members = g.group_members;
    if (!Array.isArray(members) || members.length === 0 || !members.every((m) => typeof m === 'string')) {
      refuse(`${side}_firewallgroup_ids: ${label} has no usable group_members`);
    }
    const gfam = ADDRESS_GROUP_TYPES[g.group_type];
    if (gfam) {
      if (gfam !== fam) refuse(`${side}_firewallgroup_ids: ${label} is an ${g.group_type}, but ${ruleset} is an ${famName(fam)} ruleset (only ${FAMILY_SELECTORS[fam].groupType} and port-group)`);
      for (const m of members) requirePrivateAddresses(m, gfam, `${side}_firewallgroup_ids: ${label}`);
      hasAddressGroup = true;
    } else if (g.group_type === 'port-group') {
      for (const m of members) requireValidPorts(m, `${side}_firewallgroup_ids: ${label}`);
    } else {
      refuse(`${side}_firewallgroup_ids: ${label} has unknown group_type ${JSON.stringify(g.group_type ?? null)}`);
    }
  }
  return hasAddressGroup;
}

/**
 * Accept rules on LAN_* / GUEST_* (v4 and v6; WAN_* accept is refused
 * earlier). The rule must name its source, and everything it names must be
 * internal: private addresses, internal networks with private subnets,
 * groups of private addresses. Every address selector must be of the
 * ruleset's family. No negation and no "match the opposite" flags. An absent
 * destination is allowed ("any internal destination" on *_IN, e.g. return
 * rules; "any" on *_OUT); a present one must be private as well.
 */
function checkLegacyAccept(body, context) {
  const ctxNote = (k) => (typeof context.lookupErrors?.[k] === 'string' ? ` (lookup failed: ${context.lookupErrors[k]})` : '');
  const { ruleset } = body;
  const fam = ruleFamily(ruleset);
  const sel = FAMILY_SELECTORS[fam];
  if (body.protocol_match_excepted === true) refuse('protocol_match_excepted (match every protocol except the one given) is not allowed on accept rules');
  for (const [k, f] of Object.entries(ADDRESS_FIELDS)) {
    if (!nonEmpty(body[k])) continue;
    if (f !== fam) refuse(`${k} is an ${famName(f)} field, but ${ruleset} is an ${famName(fam)} ruleset (use ${addressKey(k.slice(0, 3), fam)})`);
    requirePrivateAddresses(body[k], f, k);
  }
  for (const k of ['src_port', 'dst_port']) {
    if (nonEmpty(body[k])) requireValidPorts(body[k], k);
  }
  // Also checked by the field allowlist; repeated here so a MAC can never be
  // the reason an accept rule passes. It is only an extra restriction.
  if (nonEmpty(body.src_mac_address) && !LEGACY_MAC_RE.test(body.src_mac_address)) refuse('src_mac_address must be a colon-separated MAC address');
  const hasGroup = {
    src: requireSafeGroups(body.src_firewallgroup_ids, 'src', fam, ruleset, context, ctxNote),
    dst: requireSafeGroups(body.dst_firewallgroup_ids, 'dst', fam, ruleset, context, ctxNote),
  };
  for (const side of ['src', 'dst']) {
    const id = body[`${side}_networkconf_id`];
    const type = body[`${side}_networkconf_type`];
    if (nonEmpty(type) && !sel.netconfTypes.includes(type)) {
      refuse(`${side}_networkconf_type ${type} does not match ${ruleset}, an ${famName(fam)} ruleset (allowed: ${sel.netconfTypes.join(', ')} or "")`);
    }
    if (!nonEmpty(id)) continue;
    if (!nonEmpty(type)) refuse(`${side}_networkconf_id is set without ${side}_networkconf_type (${sel.netconfTypes.join(' or ')} on ${ruleset})`);
    // The classic UI picks one kind of source (and destination): a network, or
    // addresses/groups. A rule carrying both is ambiguous about what matches.
    if (nonEmpty(body[addressKey(side, fam)]) || hasGroup[side]) {
      refuse(`${side}_networkconf_id cannot be combined with ${addressKey(side, fam)} or an address group on the same side; use one of them`);
    }
    requireInternalNetwork(id, type, side, context, ctxNote);
  }

  // Source constraint, in the rule's own family (other families were refused
  // above). A port group or a MAC address alone does not narrow the source.
  const srcAddrKey = addressKey('src', fam);
  if (!(nonEmpty(body.src_networkconf_id) || nonEmpty(body[srcAddrKey]) || hasGroup.src)) {
    refuse(
      `legacy accept rule on ${ruleset} must constrain the source (src_networkconf_id, an ${sel.groupType} in src_firewallgroup_ids, or ${srcAddrKey}; src_mac_address only narrows one of these); accept-from-any is not allowed`
    );
  }
}

function checkLegacyRuleFields(body, isCreate) {
  for (const [k, v] of Object.entries(body)) {
    if (v === undefined) continue;
    if (RO_CLASSIC.includes(k) || LEGACY_RO_ATTR_KEYS.includes(k)) {
      if (isCreate) refuse(`legacy rule: read-only field "${k}" must not be sent`);
      continue; // update: compared with the existing rule
    }
    const ok = hasOwn(LEGACY_RULE_FIELDS, k) && LEGACY_RULE_FIELDS[k];
    if (!ok) refuse(`legacy rule: field "${k}" is not allowed (unknown fields are refused)`);
    if (!ok(v)) refuse(`legacy rule: invalid value for "${k}"`);
  }
}

function checkLegacyFirewallRule(body, context, req) {
  const isCreate = req.method === 'POST';
  const { ruleset, action } = body;
  if (!LEGACY_RULESETS.includes(ruleset)) refuse(`legacy rule ruleset ${JSON.stringify(ruleset ?? null)} is missing or unknown (allowed: ${LEGACY_RULESETS.join(', ')})`);
  if (!LEGACY_ACTIONS.includes(action)) refuse(`legacy rule action ${JSON.stringify(action ?? null)} is missing or unknown (allowed: ${LEGACY_ACTIONS.join(', ')})`);
  // Covers WAN_IN/WAN_LOCAL and also WAN_OUT (deliberately: no WAN accept rules at all).
  if (isWanRuleset(ruleset) && !isDropOrReject(action)) {
    refuse(`legacy rule on ${ruleset} with action "${action}" would allow WAN traffic; only drop/reject are allowed on WAN rulesets`);
  }
  checkLegacyRuleFields(body, isCreate);
  if (isCreate) {
    // Placement among WAN rules is the controller's choice, never the caller's.
    if (isWanRuleset(ruleset) && body.rule_index !== undefined) refuse(`legacy rule on ${ruleset}: rule_index must not be set on WAN* rulesets`);
  } else {
    checkLegacyRuleUpdate(body, context, req);
  }
  // Non-WAN accept (WAN accept was refused above): named, internal source;
  // private destination if one is given. Checked on the full merged body.
  if (action === 'accept') checkLegacyAccept(body, context);
}

/** Update-only rules: identity, read-only markers, the WAN* freeze. */
function checkLegacyRuleUpdate(body, context, req) {
  const { ruleset } = body;
  const existing = requireExisting(context, 'legacy firewall rule', req, '_id');
  if (existing.attr_no_edit === true) refuse('legacy rule is marked attr_no_edit by the controller (system rule); not editable');
  for (const k of [...RO_CLASSIC, ...LEGACY_RO_ATTR_KEYS]) {
    if (hasOwn(body, k) && body[k] !== undefined && !deepEqual(body[k], existing[k])) refuse(`legacy rule: read-only field "${k}" must equal the existing rule`);
  }
  const ignoreRo = [...RO_CLASSIC, ...LEGACY_RO_ATTR_KEYS];
  if (isWanRuleset(existing.ruleset) && isDropOrReject(existing.action)) {
    const changed = changedKeys(body, without(existing, ignoreRo), [...LEGACY_COSMETIC_KEYS, ...ignoreRo]);
    if (changed.length) {
      refuse(`rule is a ${existing.ruleset} ${existing.action} rule; only ${LEGACY_COSMETIC_KEYS.join(', ')} may change, not: ${changed.join(', ')}`);
    }
  }
  // Also for WAN accept rules created elsewhere: they may become drop/reject, never leave WAN.
  if (isWanRuleset(existing.ruleset) && ruleset !== existing.ruleset) {
    refuse(`legacy rule: moving a rule out of ${existing.ruleset} is not allowed (ruleset must stay ${existing.ruleset})`);
  }
  if ((isWanRuleset(ruleset) || isWanRuleset(existing.ruleset)) && !deepEqual(body.rule_index, existing.rule_index)) {
    refuse('changing rule_index on a WAN* ruleset is not allowed');
  }
}

// --- client actions -------------------------------------------------------------

// AUTHORIZE_GUEST_ACCESS limits: min/max from the 10.6.106 spec (also the tool's input schema).
const GUEST_LIMITS = Object.freeze({
  timeLimitMinutes: Object.freeze({ min: 1, max: 1000000 }),
  dataUsageLimitMBytes: Object.freeze({ min: 1, max: 1048576 }),
  rxRateLimitKbps: Object.freeze({ min: 2, max: 100000 }),
  txRateLimitKbps: Object.freeze({ min: 2, max: 100000 }),
});

function checkClientAction(body) {
  const action = body.action;
  if (action === 'AUTHORIZE_GUEST_ACCESS') {
    onlyKeys(body, ['action', ...Object.keys(GUEST_LIMITS)], 'client action');
    for (const [k, { min, max }] of Object.entries(GUEST_LIMITS)) {
      const v = body[k];
      if (v !== undefined && !(Number.isSafeInteger(v) && v >= min && v <= max)) refuse(`client action: ${k} must be an integer ${min}-${max}`);
    }
    return;
  }
  if (action === 'UNAUTHORIZE_GUEST_ACCESS') {
    onlyKeys(body, ['action'], 'client action');
    return;
  }
  refuse(`client action ${JSON.stringify(action ?? null)} is not allowed (only AUTHORIZE_GUEST_ACCESS / UNAUTHORIZE_GUEST_ACCESS)`);
}

// --- networks -------------------------------------------------------------------

const RO_NETWORK = ['id', 'metadata', 'default'];
// The only network field that may change (10.6.106 spec, gateway-managed
// network DTO): whether the network takes part in mDNS forwarding (boolean;
// null = site default). Everything else in the DTO (name, enabled, vlanId,
// management, zoneId, isolationEnabled, internetAccessEnabled,
// cellularBackupEnabled, ipv4/ipv6Configuration incl. DHCP, dhcpGuarding,
// deviceId) changes reachability, addressing or exposure and must stay equal.
const NETWORK_CHANGEABLE_KEYS = ['mdnsForwardingEnabled'];

function checkNetworkUpdate(body, context, req) {
  const existing = requireExisting(context, 'network', req);
  refuseReadOnly(body, RO_NETWORK, 'network update');
  const changed = changedKeys(body, without(existing, RO_NETWORK), NETWORK_CHANGEABLE_KEYS);
  if (changed.length) refuse(`network update: only ${NETWORK_CHANGEABLE_KEYS.join(', ')} may change, not: ${changed.join(', ')}`);
  const m = body.mdnsForwardingEnabled;
  if (m !== undefined && m !== null && typeof m !== 'boolean') refuse('network update: mdnsForwardingEnabled must be a boolean or null');
}

// --- WiFi broadcasts ------------------------------------------------------------

// securityConfiguration.type values of the 10.6.106 spec that use WPA2/WPA3.
// OPEN (incl. OWE "ENHANCED_OPEN") and anything unknown are refused.
const WIFI_SECURITY_TYPES = Object.freeze(['WPA2_PERSONAL', 'WPA2_WPA3_PERSONAL', 'WPA3_PERSONAL', 'WPA2_ENTERPRISE', 'WPA2_WPA3_ENTERPRISE', 'WPA3_ENTERPRISE']);
const WIFI_TYPES = Object.freeze(['STANDARD', 'IOT_OPTIMIZED']);
// Guest/captive-portal/hotspot/Passpoint settings (spec: hotspotConfiguration).
const WIFI_PORTAL_KEY_RE = /hotspot|captive|portal|passpoint|guest/i;
const RO_WIFI = ['id', 'metadata'];

function checkWifiBroadcast(body, context, req) {
  refuseReadOnly(body, RO_WIFI, 'wifi broadcast');
  if (!WIFI_TYPES.includes(body.type)) refuse('wifi broadcast: type must be STANDARD or IOT_OPTIMIZED');
  const sec = body.securityConfiguration;
  if (!isPlainObject(sec) || !WIFI_SECURITY_TYPES.includes(sec.type)) {
    refuse(`wifi broadcast: securityConfiguration.type must be one of ${WIFI_SECURITY_TYPES.join(', ')} (open/OWE/unknown security is refused)`);
  }

  if (req.method === 'POST') {
    const net = body.network;
    if (!isPlainObject(net) || net.type !== 'SPECIFIC' || typeof net.networkId !== 'string' || !UUID_RE.test(net.networkId)) {
      refuse('wifi broadcast create: network must be {type: "SPECIFIC", networkId: <UUID>} (NATIVE/default-network binding is not allowed)');
    }
    onlyKeys(net, ['type', 'networkId'], 'wifi broadcast network');
    for (const k of Object.keys(body)) {
      if (WIFI_PORTAL_KEY_RE.test(k)) refuse(`wifi broadcast create: "${k}" is not allowed (no hotspot/captive-portal SSIDs)`);
    }
    return;
  }

  const existing = requireExisting(context, 'WiFi broadcast', req);
  if (body.type !== existing.type) refuse('wifi broadcast update: type must not change');
  if (!deepEqual(body.network, existing.network)) refuse('wifi broadcast update: network binding must not change');
  if (!deepEqual(body.clientIsolationEnabled, existing.clientIsolationEnabled)) refuse('wifi broadcast update: clientIsolationEnabled must not change');
  for (const k of new Set([...Object.keys(body), ...Object.keys(existing)])) {
    if (WIFI_PORTAL_KEY_RE.test(k) && !deepEqual(body[k], existing[k])) refuse(`wifi broadcast update: "${k}" (hotspot/captive portal) must not change`);
  }
}

// --- AP radios (classic rest/device) --------------------------------------------

// Per-entry keys: `radio` and `name` identify the radio (name must equal the
// device's own value), the rest are the settings the tool may change.
const RADIO_ENTRY_KEYS = Object.freeze(['radio', 'name', 'channel', 'ht', 'tx_power_mode', 'tx_power', 'min_rssi_enabled', 'min_rssi']);
// ng = 2.4 GHz, na = 5 GHz, 6e = 6 GHz.
const RADIO_BANDS = Object.freeze(['ng', 'na', '6e']);
const HT_WIDTHS = [20, 40, 80, 160, 240, 320];
const TX_POWER_MODES = ['auto', 'low', 'medium', 'high', 'custom'];

/** Integer given as a JSON number or a decimal string (the controller stores some as strings). */
function intLike(v, min, max) {
  let n;
  if (typeof v === 'number') n = v;
  else if (typeof v === 'string' && /^-?\d{1,4}$/.test(v)) n = Number(v);
  else return false;
  return Number.isInteger(n) && n >= min && n <= max;
}

function checkRadioEntry(e, existingTable) {
  if (!isPlainObject(e)) refuse('radio_table entries must be objects');
  onlyKeys(e, RADIO_ENTRY_KEYS, 'radio_table entry');
  if (!RADIO_BANDS.includes(e.radio)) refuse(`radio_table entry: radio must be one of ${RADIO_BANDS.join(', ')}`);
  const current = existingTable.find((x) => isPlainObject(x) && x.radio === e.radio);
  if (!current) refuse(`radio_table entry: device has no ${e.radio} radio`);
  if (e.name !== undefined && (typeof e.name !== 'string' || e.name !== current.name)) refuse(`radio_table entry ${e.radio}: name must equal the device's radio name`);
  if (e.channel !== undefined && e.channel !== 'auto' && !intLike(e.channel, 1, 233)) refuse(`radio_table entry ${e.radio}: channel must be "auto" or 1-233`);
  if (e.ht !== undefined && !HT_WIDTHS.some((w) => e.ht === w || e.ht === String(w))) refuse(`radio_table entry ${e.radio}: ht must be one of ${HT_WIDTHS.join(', ')}`);
  if (e.tx_power_mode !== undefined && !TX_POWER_MODES.includes(e.tx_power_mode)) refuse(`radio_table entry ${e.radio}: tx_power_mode must be one of ${TX_POWER_MODES.join(', ')}`);
  if (e.tx_power !== undefined && !intLike(e.tx_power, 1, 30)) refuse(`radio_table entry ${e.radio}: tx_power must be an integer 1-30`);
  if (e.min_rssi_enabled !== undefined && typeof e.min_rssi_enabled !== 'boolean') refuse(`radio_table entry ${e.radio}: min_rssi_enabled must be a boolean`);
  if (e.min_rssi !== undefined && !intLike(e.min_rssi, -95, -40)) refuse(`radio_table entry ${e.radio}: min_rssi must be an integer -95..-40`);
}

function checkDeviceRadios(body, context, req) {
  const keys = Object.keys(body);
  if (keys.length !== 1 || keys[0] !== 'radio_table') refuse('device update body must contain exactly one key: radio_table');
  const table = body.radio_table;
  if (!Array.isArray(table) || table.length === 0 || table.length > 8) refuse('radio_table must be a non-empty array (max 8 entries)');
  const existing = requireExisting(context, 'device', req, '_id');
  if (existing.type !== 'uap') refuse('device update: device is not an access point (uap)');
  if (!Array.isArray(existing.radio_table)) refuse('device update: device has no radio_table');
  const seen = new Set();
  for (const e of table) {
    checkRadioEntry(e, existing.radio_table);
    if (seen.has(e.radio)) refuse(`radio_table lists radio ${e.radio} twice`);
    seen.add(e.radio);
  }
}

// --- classic clients (fixed IP) -------------------------------------------------

const REST_USER_KEYS = ['mac', 'use_fixedip', 'fixed_ip', 'network_id', 'name', 'note'];

function checkRestUser(body, { isCreate }) {
  onlyKeys(body, REST_USER_KEYS, 'client (rest/user) write');
  if (isCreate && (typeof body.mac !== 'string' || !MAC_RE.test(body.mac))) refuse('rest/user create requires a lowercase colon MAC');
  if (!isCreate && 'mac' in body) refuse('rest/user update must not change mac');
  if (body.mac !== undefined && !MAC_RE.test(body.mac)) refuse('rest/user: invalid mac');
  if (body.use_fixedip !== undefined && typeof body.use_fixedip !== 'boolean') refuse('rest/user: use_fixedip must be boolean');
  if (body.fixed_ip !== undefined && (typeof body.fixed_ip !== 'string' || !IPV4_RE.test(body.fixed_ip))) refuse('rest/user: fixed_ip must be IPv4');
  if (body.network_id !== undefined && (typeof body.network_id !== 'string' || !HEX24_RE.test(body.network_id))) refuse('rest/user: network_id must be a 24-hex id');
  for (const k of ['name', 'note']) {
    if (body[k] !== undefined && (typeof body[k] !== 'string' || body[k].length > 128)) refuse(`rest/user: ${k} must be a string (max 128)`);
  }
  if (body.use_fixedip === true && (!body.fixed_ip || !body.network_id)) refuse('rest/user: use_fixedip=true requires fixed_ip and network_id');
}

// ---------------------------------------------------------------------------
// Allowlist (default deny). Anchored regexes over the path without query.
// ---------------------------------------------------------------------------
const r = (s) => new RegExp(`^${s}$`);

const ALLOW = [
  // Reads (integration)
  { method: 'GET', re: r(`${I}/info`), name: 'get_info' },
  { method: 'GET', re: r(`${I}/sites`), name: 'list_sites' },
  { method: 'GET', re: r(`${IS}/wifi/broadcasts`), name: 'list_wifi_broadcasts' },
  { method: 'GET', re: r(`${IS}/wifi/broadcasts/${UUID}`), name: 'get_wifi_broadcast' },
  { method: 'GET', re: r(`${IS}/networks`), name: 'list_networks' },
  { method: 'GET', re: r(`${IS}/networks/${UUID}`), name: 'get_network' },
  { method: 'GET', re: r(`${IS}/firewall/zones`), name: 'list_firewall_zones' },
  { method: 'GET', re: r(`${IS}/firewall/policies`), name: 'list_firewall_policies' },
  { method: 'GET', re: r(`${IS}/firewall/policies/${UUID}`), name: 'get_firewall_policy' },
  { method: 'GET', re: r(`${IS}/clients`), name: 'list_clients' },
  { method: 'GET', re: r(`${IS}/clients/${UUID}`), name: 'get_client' },
  // Read-only, used only by scripts/probe-classic.cjs (no tool reads them)
  { method: 'GET', re: r(`${IS}/acl-rules`), name: 'list_acl_rules' },
  { method: 'GET', re: r(`${IS}/devices`), name: 'list_devices' },
  // Reads (classic)
  { method: 'GET', re: r(`${C}/rest/firewallrule`), name: 'classic_list_firewallrule' },
  { method: 'GET', re: r(`${C}/rest/firewallrule/${HEX24}`), name: 'classic_get_firewallrule' },
  { method: 'GET', re: r(`${C}/stat/device`), name: 'classic_list_devices' },
  { method: 'GET', re: r(`${C}/stat/device/${MAC}`), name: 'classic_get_device_by_mac' },
  { method: 'GET', re: r(`${C}/rest/user`), name: 'classic_list_users' },
  { method: 'GET', re: r(`${C}/rest/firewallgroup`), name: 'classic_list_firewallgroup' },
  // GET only: networkconf writes are denied above, for every method but GET.
  { method: 'GET', re: r(`${C}/rest/networkconf`), name: 'classic_list_networkconf' },

  // Writes (integration)
  { method: 'POST', re: r(`${IS}/wifi/broadcasts`), name: 'create_wifi_broadcast', bodyCheck: checkWifiBroadcast },
  { method: 'PUT', re: r(`${IS}/wifi/broadcasts/${UUID}`), name: 'update_wifi_broadcast', bodyCheck: checkWifiBroadcast },
  { method: 'POST', re: r(`${IS}/firewall/policies`), name: 'create_firewall_policy', bodyCheck: checkZoneFirewallPolicy },
  { method: 'PUT', re: r(`${IS}/firewall/policies/${UUID}`), name: 'update_firewall_policy', bodyCheck: checkZoneFirewallPolicy },
  { method: 'PATCH', re: r(`${IS}/firewall/policies/${UUID}`), name: 'patch_firewall_policy', bodyCheck: checkPatchFirewallPolicy },
  { method: 'POST', re: r(`${IS}/clients/${UUID}/actions`), name: 'client_action', bodyCheck: checkClientAction },
  { method: 'PUT', re: r(`${IS}/networks/${UUID}`), name: 'update_network', bodyCheck: checkNetworkUpdate },

  // Writes (classic)
  { method: 'PUT', re: r(`${C}/rest/device/${HEX24}`), name: 'update_device_radios', bodyCheck: checkDeviceRadios },
  { method: 'POST', re: r(`${C}/rest/firewallrule`), name: 'create_legacy_firewall_rule', bodyCheck: checkLegacyFirewallRule },
  { method: 'PUT', re: r(`${C}/rest/firewallrule/${HEX24}`), name: 'update_legacy_firewall_rule', bodyCheck: checkLegacyFirewallRule },
  { method: 'POST', re: r(`${C}/rest/user`), name: 'create_client_fixed_ip', bodyCheck: (b) => checkRestUser(b, { isCreate: true }) },
  { method: 'PUT', re: r(`${C}/rest/user/${HEX24}`), name: 'update_client_fixed_ip', bodyCheck: (b) => checkRestUser(b, { isCreate: false }) },
];

// ---------------------------------------------------------------------------
// Classic capabilities (cloud_allow_classic). Every classic path maps to one
// capability; the cloud client sends a classic path only if its capability is
// enabled, and refuses unmapped classic paths (fail closed).
// ---------------------------------------------------------------------------
const CLASSIC_CAPABILITIES = Object.freeze(['firewallrule', 'fixed_ip', 'radio']);
const CLASSIC_CAPABILITY_PATHS = Object.freeze([
  { re: new RegExp(`^${C}/rest/(firewallrule|firewallgroup|networkconf)(/|$)`), capability: 'firewallrule' },
  { re: new RegExp(`^${C}/rest/user(/|$)`), capability: 'fixed_ip' },
  { re: new RegExp(`^${C}/(stat|rest)/device(/|$)`), capability: 'radio' },
]);

/** Capability of a classic path (query ignored), or null if unmapped / not classic. */
function classicCapabilityOf(path) {
  if (typeof path !== 'string') return null;
  const pathOnly = path.split('?')[0];
  const hit = CLASSIC_CAPABILITY_PATHS.find((m) => m.re.test(pathOnly));
  return hit ? hit.capability : null;
}

/**
 * cloud_allow_classic: false/absent = none, true = all, or an array subset of
 * CLASSIC_CAPABILITIES (no duplicates). Returns a frozen, sorted array.
 * Throws TypeError (callers wrap it) on anything else.
 */
function normalizeClassicCapabilities(v) {
  if (v === undefined || v === null || v === false) return Object.freeze([]);
  if (v === true) return Object.freeze([...CLASSIC_CAPABILITIES]);
  if (!Array.isArray(v)) throw new TypeError(`must be false, true or an array of ${CLASSIC_CAPABILITIES.join(', ')}`);
  for (const c of v) {
    if (typeof c !== 'string' || !CLASSIC_CAPABILITIES.includes(c)) throw new TypeError(`has unknown capability ${JSON.stringify(c)} (allowed: ${CLASSIC_CAPABILITIES.join(', ')})`);
  }
  if (new Set(v).size !== v.length) throw new TypeError('lists a capability twice');
  return Object.freeze([...v].sort());
}

// ---------------------------------------------------------------------------

/**
 * Normalization checks shared by the canonical and the final full path.
 * Returns { pathOnly, query } (query is null when there is no "?").
 */
function splitAndCheckSyntax(path) {
  if (/[\u0000-\u001f\u007f]/.test(path)) refuse('control characters in path');
  if (path.includes('\\')) refuse('backslash in path');
  if (path.includes('#')) refuse('fragment in path');
  const qIdx = path.indexOf('?');
  const pathOnly = qIdx === -1 ? path : path.slice(0, qIdx);
  const query = qIdx === -1 ? null : path.slice(qIdx + 1);
  if (!pathOnly.startsWith('/')) refuse('path must be absolute');
  if (pathOnly.includes('..')) refuse('path traversal ("..") is not allowed');
  if (pathOnly.includes('//')) refuse('empty path segment ("//") is not allowed');
  if (/%2e|%2f|%5c/i.test(pathOnly)) refuse('encoded dot/slash/backslash in path is not allowed');
  if (pathOnly.includes('%')) refuse('percent-encoding in path is not allowed');
  if (pathOnly.includes(';')) refuse('";" (path parameters) in path is not allowed');
  if (/\/\.(\/|$)/.test(pathOnly)) refuse('"." path segment is not allowed');
  return { pathOnly, query };
}

// A canonical path never names the proxy, the cloud connector or another
// console app; the backend adapter alone adds "/proxy/network" or
// "/v1/connector/consoles/{id}/proxy/network".
// Covers "/proxy/...", "/proxy/protect", "/v1/connector/...", "/consoles/...".
const SMUGGLED_PREFIX_RE = /(^|\/)(proxy|consoles)(\/|$)|connector/i;

function checkQuery(query) {
  if (query === '') return;
  if (query.length > 2048) refuse('query string too long');
  for (const part of query.split('&')) {
    const eq = part.indexOf('=');
    if (eq <= 0) refuse('malformed query string');
    const k = part.slice(0, eq);
    let v;
    try {
      v = decodeURIComponent(part.slice(eq + 1).replace(/\+/g, ' '));
    } catch {
      refuse('malformed query encoding');
    }
    if (k === 'offset' || k === 'limit') {
      if (!/^\d{1,6}$/.test(v)) refuse(`query parameter ${k} must be a non-negative integer`);
    } else if (k === 'filter') {
      if (v.length > 1024 || /[\u0000-\u001f\u007f]/.test(v)) refuse('invalid filter value');
    } else {
      refuse(`query parameter "${k}" is not allowed`);
    }
  }
}

function checkRequest({ method, path, body, context } = {}) {
  if (typeof method !== 'string') refuse('method missing');
  if (method.toUpperCase() === 'DELETE') refuse('DELETE is never allowed');
  if (!ALLOWED_METHODS.has(method)) refuse(`method ${JSON.stringify(method)} is not allowed (must be uppercase GET/POST/PUT/PATCH)`);
  if (typeof path !== 'string' || path.length === 0 || path.length > 1024) refuse('path missing or too long');

  const { pathOnly, query } = splitAndCheckSyntax(path);
  if (query !== null && method !== 'GET') refuse('query strings are not allowed on writes');

  if (SMUGGLED_PREFIX_RE.test(pathOnly)) {
    refuse('canonical path must not contain a proxy/connector prefix or another app (the backend adds its own prefix)');
  }
  if (!pathOnly.startsWith('/integration/v1/') && !pathOnly.startsWith('/api/s/')) {
    refuse('canonical path must start with /integration/v1/ or /api/s/');
  }

  const isWrite = WRITE_METHODS.has(method);
  for (const d of DENY) {
    if (d.writes && !isWrite) continue;
    if (d.re.test(pathOnly)) refuse(d.reason);
  }

  const rule = ALLOW.find((a) => a.method === method && a.re.test(pathOnly));
  if (!rule) refuse(`${method} ${pathOnly} is not in the allowlist (default deny)`);

  if (!isWrite) {
    if (body !== undefined && body !== null) refuse('GET requests must not have a body');
    checkQuery(query ?? '');
    return { ok: true, rule: rule.name };
  }

  if (!isPlainObject(body)) refuse('write body must be a JSON object');
  if (context !== undefined && context !== null && !isPlainObject(context)) refuse('context must be an object');
  deepScan(body);
  // req.id: last path segment (the object id for PUT/PATCH).
  if (rule.bodyCheck) rule.bodyCheck(body, context || {}, { method, path: pathOnly, id: pathOnly.slice(pathOnly.lastIndexOf('/') + 1) });
  return { ok: true, rule: rule.name };
}

/**
 * Second check on the request line actually sent: `full` must be exactly
 * `prefix + canonical`, `prefix` must be one of the two constant backend
 * forms (cloud: validated console id), and the full path must pass the same
 * normalization checks as the canonical path.
 */
function checkFinalPath({ prefix, canonical, full }) {
  if (!isKnownPrefix(prefix)) refuse('unknown backend prefix');
  if (typeof canonical !== 'string' || typeof full !== 'string' || full !== prefix + canonical) {
    refuse('final path is not backend prefix + canonical path');
  }
  if (full.length > 1400) refuse('final path too long');
  const { pathOnly } = splitAndCheckSyntax(full);
  const rest = pathOnly.slice(prefix.length);
  if (!rest.startsWith('/integration/v1/') && !rest.startsWith('/api/s/')) refuse('final path does not continue with a canonical path');
  if (SMUGGLED_PREFIX_RE.test(rest)) refuse('final path contains a second proxy/connector prefix');
  return { ok: true };
}

module.exports = {
  checkRequest,
  checkFinalPath,
  cloudPrefix,
  isKnownPrefix,
  LOCAL_PREFIX,
  CONSOLE_ID_RE,
  GuardError,
  isWanZone,
  deepEqual,
  WIFI_SECURITY_TYPES,
  WIFI_TYPES,
  WIFI_PORTAL_KEY_RE,
  LEGACY_RULESETS,
  LEGACY_ACTIONS,
  LEGACY_FIELD_NAMES,
  LEGACY_NETCONF_TYPES,
  PRIVATE_V4,
  PRIVATE_V6,
  INTERNAL_NETWORK_PURPOSES,
  GUEST_LIMITS,
  CLASSIC_CAPABILITIES,
  classicCapabilityOf,
  normalizeClassicCapabilities,
  RADIO_ENTRY_KEYS,
  RADIO_BANDS,
  HT_WIDTHS,
  TX_POWER_MODES,
  NETWORK_CHANGEABLE_KEYS,
  RO_POLICY,
  RO_NETWORK,
  RO_WIFI,
  RO_CLASSIC,
  UUID_RE,
  HEX24_RE,
  MAC_RE,
  IPV4_RE,
  _ALLOW: ALLOW,
  _DENY: DENY,
};
