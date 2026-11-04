'use strict';

const { z } = require('zod');
const guard = require('./guard.cjs');
const { GuardError } = guard;
const { redact, makeScrubber } = require('./redact.cjs');
const { UdmHttpError } = require('./udm-client.cjs');
const { READ_TOOLS, WRITE_TOOLS } = require('./tool-names.cjs');
const { createWanExposure, WanExposureError } = require('./wan-exposure.cjs');

const TOOL_NAMES = Object.freeze([...READ_TOOLS, ...WRITE_TOOLS]);
// Tools that need classic /api/s/ endpoints, by classic capability. Registered
// only if the client enables that capability (local: all; cloud: per
// cloud_allow_classic). The client enforces the same per path.
const CLASSIC_TOOL_CAPABILITY = Object.freeze({
  unifi_rw_list_legacy_firewall_rules: 'firewallrule',
  unifi_rw_list_firewall_groups: 'firewallrule',
  unifi_rw_list_classic_networks: 'firewallrule',
  unifi_rw_create_legacy_firewall_rule: 'firewallrule',
  unifi_rw_update_legacy_firewall_rule: 'firewallrule',
  unifi_rw_list_fixed_ips: 'fixed_ip',
  unifi_rw_set_fixed_ip: 'fixed_ip',
  unifi_rw_clear_fixed_ip: 'fixed_ip',
  unifi_rw_list_access_points: 'radio',
  unifi_rw_update_ap_radios: 'radio',
});
const CLASSIC_TOOLS = Object.freeze(Object.keys(CLASSIC_TOOL_CAPABILITY));

/**
 * Tool names registered for a client with the given classic capabilities and
 * write mode. writeTools (UNIFI_WRITE_TOOLS) narrows the write tools; null or
 * undefined keeps them all. Read tools never depend on it.
 */
const toolNamesFor = ({ classicCapabilities = [], writesEnabled = false, writeTools = null } = {}) =>
  TOOL_NAMES.filter(
    (n) =>
      (READ_TOOLS.includes(n) || (writesEnabled === true && (writeTools === null || writeTools === undefined || writeTools.includes(n)))) &&
      (!CLASSIC_TOOL_CAPABILITY[n] || classicCapabilities.includes(CLASSIC_TOOL_CAPABILITY[n]))
  );

// --- schema helpers ---------------------------------------------------------
const uuid = () => z.string().regex(/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/, 'must be a UUID');
const hex24 = () => z.string().regex(/^[0-9a-f]{24}$/, 'must be a 24-hex id');
const macStr = () => z.string().regex(/^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$/, 'must be a MAC address');
const ipv4 = () => z.string().regex(/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/, 'must be an IPv4 address');
const obj = () => z.record(z.string(), z.unknown());
const dryRun = () => z.boolean().optional().default(false).describe('If true, run the guard and return the request that would be sent, without sending the write.');
const mergeMode = () => z.enum(['deep', 'shallow']).optional().default('deep').describe('deep: recursively merge objects (arrays replaced); shallow: replace top-level keys');
const strict = (shape) => z.object(shape).strict();

const normMac = (m) => m.toLowerCase().replace(/-/g, ':');
const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function deepMerge(base, changes) {
  const out = { ...base };
  for (const [k, v] of Object.entries(changes)) {
    out[k] = isPlainObject(v) && isPlainObject(base[k]) ? deepMerge(base[k], v) : v;
  }
  return out;
}

function mergeWith(mode, base, changes) {
  return mode === 'shallow' ? { ...base, ...changes } : deepMerge(base, changes);
}

function omit(o, keys) {
  const out = { ...o };
  for (const k of keys) delete out[k];
  return out;
}

const classicData = (resp) => (resp && Array.isArray(resp.data) ? resp.data : []);
const pageQuery = ({ offset, limit, filter }) => {
  const q = new URLSearchParams();
  if (offset !== undefined) q.set('offset', String(offset));
  if (limit !== undefined) q.set('limit', String(limit));
  if (filter !== undefined) q.set('filter', filter);
  const s = q.toString();
  return s ? `?${s}` : '';
};

// Upstream HTTP errors become the fixed structured {status, code?, message}
// (a code that contains any secret is dropped, not partly redacted);
// everything else is a locally generated message.
function errorText(e, scrub) {
  if (!(e instanceof UdmHttpError)) return (e && e.message) || String(e);
  const out = e.toJSON();
  if (out.code !== undefined && scrub(out.code) !== out.code) delete out.code;
  return JSON.stringify(out);
}

// Read-only fields (present in GET details, absent from the create/update DTOs in the 10.6.106 spec).
const { RO_WIFI, RO_POLICY, RO_NETWORK, RO_CLASSIC } = guard;

const RADIO_CHANGE_KEYS = ['channel', 'ht', 'tx_power_mode', 'tx_power', 'min_rssi_enabled', 'min_rssi'];
// The only per-radio keys ever sent back (identity + changeable settings).
const RADIO_SEND_KEYS = guard.RADIO_ENTRY_KEYS;

// --- tighter input schemas (the guard enforces the same rules again) ----------
const noKeys = (keys, what) => (o) => !Object.keys(o).some((k) => keys.includes(k)) || `${what}: ${keys.join(', ')} cannot be set`;
const refineWith = (schema, ...checks) =>
  checks.reduce(
    (sch, check) =>
      sch.superRefine((o, ctx) => {
        const r = check(o);
        if (r !== true) ctx.addIssue({ code: z.ZodIssueCode.custom, message: r });
      }),
    schema
  );
const noPortalKeys = (o) => !Object.keys(o).some((k) => guard.WIFI_PORTAL_KEY_RE.test(k)) || 'hotspot/captive-portal settings cannot be set or changed by this tool';

const wifiSecurity = () => z.object({ type: z.enum(guard.WIFI_SECURITY_TYPES) }).passthrough();
const wifiCreate = () =>
  refineWith(
    z
      .object({
        type: z.enum(guard.WIFI_TYPES),
        name: z.string().min(1).max(32),
        securityConfiguration: wifiSecurity(),
        network: strict({ type: z.literal('SPECIFIC'), networkId: uuid() }),
      })
      .passthrough(),
    noKeys(RO_WIFI, 'read-only fields'),
    noPortalKeys
  );
const wifiChanges = () =>
  refineWith(
    z.object({ securityConfiguration: z.object({ type: z.enum(guard.WIFI_SECURITY_TYPES).optional() }).passthrough().optional() }).passthrough(),
    noKeys([...RO_WIFI, 'type', 'network', 'clientIsolationEnabled'], 'immutable via this tool'),
    noPortalKeys
  );

const policyAction = () => z.object({ type: z.enum(['ALLOW', 'BLOCK', 'REJECT']) }).passthrough();
const policyCreate = () =>
  refineWith(
    z
      .object({
        name: z.string().min(1).max(256),
        enabled: z.boolean(),
        action: policyAction(),
        source: z.object({ zoneId: uuid() }).passthrough(),
        destination: z.object({ zoneId: uuid() }).passthrough(),
      })
      .passthrough(),
    noKeys(RO_POLICY, 'read-only fields')
  );
const policyChanges = () =>
  refineWith(
    z
      .object({
        action: z.object({ type: z.enum(['ALLOW', 'BLOCK', 'REJECT']).optional() }).passthrough().optional(),
        source: z.object({ zoneId: uuid().optional() }).passthrough().optional(),
        destination: z.object({ zoneId: uuid().optional() }).passthrough().optional(),
      })
      .passthrough(),
    noKeys(RO_POLICY, 'read-only fields')
  );

const isWanRuleset = (rs) => typeof rs === 'string' && rs.startsWith('WAN');
// WAN* accept is not refused here but in the handler (WAN-exposure check, then
// the guard), so the refusal reaches the write log.
const legacyRuleCreate = () =>
  refineWith(
    z.object({ ruleset: z.enum(guard.LEGACY_RULESETS), action: z.enum(guard.LEGACY_ACTIONS) }).passthrough(),
    (o) => !isWanRuleset(o.ruleset) || o.rule_index === undefined || 'rule_index cannot be set on WAN* rulesets',
    noKeys(RO_CLASSIC, 'read-only fields')
  );
const legacyRuleChanges = () => refineWith(obj(), noKeys(RO_CLASSIC, 'read-only fields'));

/**
 * @param {object} server  McpServer
 * @param {object} o
 * @param {object} o.client
 * @param {object} [o.auditLog]
 * @param {object} [o.writeLog]     UNIFI_WRITE_LOG (lib/write-log.cjs); every write tool call appends a line
 * @param {string[]|null} [o.writeTools]  UNIFI_WRITE_TOOLS; null/undefined registers every write tool
 * @param {object} [o.wanExposure]  lib/wan-exposure.cjs instance; default: refusals on, no configured WAN zone ids
 * @param {string[]} [o.secrets]
 */
function registerTools(server, { client, auditLog, writeLog = null, writeTools = null, wanExposure = createWanExposure(), secrets = [] }) {
  const c = client;
  if (c.probeReadOnly) throw new Error('registerTools: a probe client must not back MCP tools');
  if (writeTools !== null && writeTools !== undefined && (!Array.isArray(writeTools) || !writeTools.every((n) => WRITE_TOOLS.includes(n)))) {
    throw new Error(`registerTools: writeTools must list write tools only (${WRITE_TOOLS.join(', ')})`);
  }
  if (!wanExposure || typeof wanExposure.check !== 'function') throw new Error('registerTools: wanExposure must be a lib/wan-exposure.cjs instance');
  // A client without classicCapabilities gets no classic tools, one that is
  // not write-enabled gets no write tools, and a write tool UNIFI_WRITE_TOOLS
  // does not list is not registered at all (fail closed). The client refuses
  // writes on its own as well.
  const enabled = new Set(
    toolNamesFor({ classicCapabilities: Array.isArray(c.classicCapabilities) ? c.classicCapabilities : [], writesEnabled: c.writesEnabled === true, writeTools })
  );
  // Final scrubber for every string sent to the caller: bearer token here, API key in the client.
  const scrubToken = makeScrubber(secrets);
  const scrub = (str) => scrubToken(typeof c.scrub === 'function' ? c.scrub(str) : str);
  const textResult = (data) => ({ content: [{ type: 'text', text: scrub(JSON.stringify(data, null, 2)) }] });
  const errorResult = (e) => ({ isError: true, content: [{ type: 'text', text: scrub(errorText(e, scrub)) }] });

  function readTool(name, description, shape, fn) {
    if (!READ_TOOLS.includes(name)) throw new Error(`${name} is a read tool missing from READ_TOOLS (lib/tool-names.cjs)`);
    if (!enabled.has(name)) return;
    server.registerTool(
      name,
      { description, inputSchema: strict(shape), annotations: { readOnlyHint: true, destructiveHint: false } },
      async (args) => {
        try {
          return textResult(redact(await fn(args)));
        } catch (e) {
          return errorResult(e);
        }
      }
    );
  }

  function writeTool(name, description, shape, fn) {
    if (!WRITE_TOOLS.includes(name)) throw new Error(`${name} is a write tool missing from WRITE_TOOLS (lib/tool-names.cjs)`);
    if (!enabled.has(name)) return;
    server.registerTool(
      name,
      { description, inputSchema: strict({ ...shape, dry_run: dryRun() }), annotations: { readOnlyHint: false, destructiveHint: true } },
      async (args) => {
        const startedAt = new Date();
        const audit = { tool: name, args, logged: false };
        // The write the tool was about to send, for the write log when it is refused before the client sees it.
        let attempted = null;
        const send = async (req) => {
          attempted = { method: req.method, endpoint: req.path };
          // WAN exposure first: before the guard, before a dry run is answered, before anything is sent.
          await wanExposure.check(req, { loadZones: loadZonesStrict });
          return c.request({ ...req, dryRun: args.dry_run, audit });
        };
        let failure = null;
        try {
          return textResult(redact(await fn(args, send)));
        } catch (e) {
          failure = e;
          // Failures before a write request was attempted (lookup errors, tool-level validation, WAN refusals) are logged here.
          if (!audit.logged && auditLog) {
            try {
              const refused = e instanceof GuardError || e instanceof WanExposureError;
              auditLog.write({ tool: name, args, backend: c.backend, method: attempted ? attempted.method : null, endpoint: attempted ? attempted.endpoint : null, dry_run: args.dry_run, status: refused ? 'refused' : 'error', error: scrub(errorText(e, scrub)) });
            } catch {
              process.stderr.write('unifi-mcp-rw: audit log write failed\n');
            }
          }
          return errorResult(e);
        } finally {
          if (writeLog) writeLog.record(writeLogEntry(name, args, audit.request || attempted, failure, startedAt));
        }
      }
    );
  }

  function writeLogEntry(tool, args, req, failure, startedAt) {
    const entry = { tool, args, method: req ? req.method : null, endpoint: req ? req.endpoint : null, dryRun: args.dry_run === true, startedAt, durationMs: Date.now() - startedAt.getTime() };
    // An HTTP status, when the write reached the controller.
    if (req && Number.isInteger(req.status)) entry.status = req.status;
    if (failure === null) return { ...entry, outcome: entry.dryRun ? 'dry_run' : 'ok' };
    const reason = failure instanceof WanExposureError ? 'wan_exposure' : failure instanceof GuardError ? 'guard' : undefined;
    return { ...entry, outcome: reason ? 'refused' : 'error', ...(reason ? { reason } : {}), error: errorText(failure, scrub) };
  }

  const get = (path) => c.request({ method: 'GET', path });

  async function fetchZones() {
    try {
      const page = await get(await c.sitePath('/firewall/zones?limit=200'));
      return { zones: page && Array.isArray(page.data) ? page.data : undefined };
    } catch (e) {
      return { zones: undefined, error: e.message };
    }
  }

  // For the WAN-exposure check: the zone list, or a throw saying why it could not be read.
  async function loadZonesStrict() {
    const { zones, error } = await fetchZones();
    if (!zones) throw new Error(error || 'unexpected response shape');
    return zones;
  }

  async function sendPolicy(send, req, existing) {
    const { zones, error } = await fetchZones();
    try {
      return await send({ ...req, context: existing === undefined ? { zones } : { zones, existing } });
    } catch (e) {
      if (error && e instanceof GuardError) e.message += ` (zone lookup failed: ${error})`;
      throw e;
    }
  }

  // Classic lookups for legacy accept rules: the guard resolves firewall group
  // members and networkconf ids against them. A failed lookup leaves the field
  // undefined (the guard then refuses if it needs it). drop/reject rules need
  // neither, so nothing is fetched for them; nor are accept rules on WAN*
  // rulesets, which are refused before the lookups would be used.
  async function fetchLegacyRuleContext(rule) {
    const ctx = { lookupErrors: {} };
    if (!isPlainObject(rule) || rule.action !== 'accept' || isWanRuleset(rule.ruleset)) return ctx;
    for (const [key, p] of [['firewallGroups', '/rest/firewallgroup'], ['networks', '/rest/networkconf']]) {
      try {
        const resp = await get(c.classicPath(p));
        if (resp && Array.isArray(resp.data)) ctx[key] = resp.data;
        else ctx.lookupErrors[key] = 'unexpected response shape';
      } catch (e) {
        ctx.lookupErrors[key] = e.message;
      }
    }
    return ctx;
  }

  async function findClassicUser(mac) {
    const resp = await get(c.classicPath('/rest/user'));
    if (!resp || !Array.isArray(resp.data) || !resp.data.every((u) => isPlainObject(u) && typeof u.mac === 'string')) {
      throw new GuardError('client list could not be determined (classic rest/user); fixed-IP writes fail closed');
    }
    const users = resp.data;
    return users.find((u) => typeof u.mac === 'string' && u.mac.toLowerCase() === mac) || null;
  }

  // ---------------- read tools ----------------
  readTool('unifi_rw_get_info', 'Get UniFi Network application info (GET /v1/info).', {}, () => get(c.integration('/info')));

  readTool('unifi_rw_list_sites', 'List local sites (integration API).', {}, () => get(c.integration('/sites?limit=200')));

  const paging = {
    offset: z.number().int().min(0).optional(),
    limit: z.number().int().min(0).max(200).optional(),
    filter: z.string().max(1024).optional().describe('Integration API filter expression'),
  };

  readTool('unifi_rw_list_wifi_broadcasts', 'List WiFi broadcasts (SSIDs). Secrets are redacted.', paging, async (a) =>
    get((await c.sitePath('/wifi/broadcasts')) + pageQuery(a))
  );
  readTool('unifi_rw_get_wifi_broadcast', 'Get one WiFi broadcast by id. Secrets are redacted.', { broadcast_id: uuid() }, async (a) =>
    get(await c.sitePath(`/wifi/broadcasts/${a.broadcast_id.toLowerCase()}`))
  );
  readTool('unifi_rw_list_networks', 'List networks (integration API).', paging, async (a) => get((await c.sitePath('/networks')) + pageQuery(a)));
  readTool('unifi_rw_get_network', 'Get one network by id.', { network_id: uuid() }, async (a) =>
    get(await c.sitePath(`/networks/${a.network_id.toLowerCase()}`))
  );
  readTool('unifi_rw_list_firewall_zones', 'List firewall zones (zone-based firewall only; returns 400 if not configured).', paging, async (a) =>
    get((await c.sitePath('/firewall/zones')) + pageQuery(a))
  );
  readTool('unifi_rw_list_firewall_policies', 'List zone-based firewall policies (returns 400 if zone-based firewall is not configured).', paging, async (a) =>
    get((await c.sitePath('/firewall/policies')) + pageQuery(a))
  );
  readTool('unifi_rw_get_firewall_policy', 'Get one zone-based firewall policy.', { policy_id: uuid() }, async (a) =>
    get(await c.sitePath(`/firewall/policies/${a.policy_id.toLowerCase()}`))
  );
  readTool('unifi_rw_list_legacy_firewall_rules', 'List legacy (pre-zone) firewall rules via classic API rest/firewallrule.', {}, async () =>
    classicData(await get(c.classicPath('/rest/firewallrule')))
  );
  readTool(
    'unifi_rw_list_firewall_groups',
    'List legacy firewall groups (classic GET rest/firewallgroup): _id, name, group_type, group_members. Use the _id in src_firewallgroup_ids / dst_firewallgroup_ids of legacy rules. Groups cannot be created or changed by this server.',
    {},
    async () =>
      classicData(await get(c.classicPath('/rest/firewallgroup')))
        .filter(isPlainObject)
        .map((g) => ({ _id: g._id, name: g.name, group_type: g.group_type, group_members: g.group_members }))
  );
  // Only these fields are returned: networkconf records can also hold WAN/VPN credentials.
  readTool(
    'unifi_rw_list_classic_networks',
    'List networks as the classic API sees them (GET rest/networkconf), reduced to _id, name, purpose, enabled, vlan_enabled, vlan, ip_subnet, ipv6_interface_type, ipv6_subnet, ipv6_pd_interface, network_isolation_enabled. The _id is what legacy rules use in src_networkconf_id / dst_networkconf_id (it differs from the integration network id).',
    {},
    async () =>
      classicData(await get(c.classicPath('/rest/networkconf')))
        .filter(isPlainObject)
        .map((n) => ({
          _id: n._id,
          name: n.name,
          purpose: n.purpose,
          enabled: n.enabled,
          vlan_enabled: n.vlan_enabled,
          vlan: n.vlan,
          ip_subnet: n.ip_subnet,
          ipv6_interface_type: n.ipv6_interface_type,
          ipv6_subnet: n.ipv6_subnet,
          ipv6_pd_interface: n.ipv6_pd_interface,
          network_isolation_enabled: n.network_isolation_enabled,
        }))
  );
  readTool('unifi_rw_list_clients', 'List connected clients (integration API; supports offset/limit/filter).', paging, async (a) =>
    get((await c.sitePath('/clients')) + pageQuery(a))
  );
  readTool('unifi_rw_get_client', 'Get one connected client by integration id.', { client_id: uuid() }, async (a) =>
    get(await c.sitePath(`/clients/${a.client_id.toLowerCase()}`))
  );

  readTool('unifi_rw_list_access_points', 'List access points (classic stat/device, AP fields only).', {}, async () => {
    const devices = classicData(await get(c.classicPath('/stat/device')));
    return devices
      .filter((d) => d && d.type === 'uap')
      .map((d) => ({
        _id: d._id,
        mac: d.mac,
        name: d.name,
        model: d.model,
        type: d.type,
        radio_table: d.radio_table,
        radio_table_stats: Array.isArray(d.radio_table_stats)
          ? d.radio_table_stats.map((s) => ({
              name: s.name,
              radio: s.radio,
              channel: s.channel,
              tx_power: s.tx_power,
              num_sta: s.num_sta,
              cu_total: s.cu_total,
              satisfaction: s.satisfaction,
            }))
          : undefined,
      }));
  });

  readTool(
    'unifi_rw_list_fixed_ips',
    'List client records (classic rest/user) that have a fixed IP, or the record for a given MAC.',
    { mac: macStr().optional() },
    async (a) => {
      const mac = a.mac ? normMac(a.mac) : null;
      const users = classicData(await get(c.classicPath('/rest/user')));
      return users
        .filter((u) => u && (u.use_fixedip === true || (mac && typeof u.mac === 'string' && u.mac.toLowerCase() === mac)))
        .map((u) => ({ _id: u._id, mac: u.mac, name: u.name, hostname: u.hostname, use_fixedip: u.use_fixedip, fixed_ip: u.fixed_ip, network_id: u.network_id, note: u.note }));
    }
  );

  // ---------------- write tools ----------------
  writeTool(
    'unifi_rw_create_wifi_broadcast',
    'Create a WiFi broadcast (POST /v1/sites/{siteId}/wifi/broadcasts). `broadcast` is the request body per the 10.6.106 spec ("Wifi broadcast create or update"). Requires WPA2/WPA3 security, network {type:"SPECIFIC", networkId}, and no hotspot/captive-portal configuration.',
    { broadcast: wifiCreate() },
    async (a, send) => send({ method: 'POST', path: await c.sitePath('/wifi/broadcasts'), body: a.broadcast })
  );

  writeTool(
    'unifi_rw_update_wifi_broadcast',
    'Update a WiFi broadcast. GETs the current object, merges `changes`, strips read-only fields (id, metadata) and PUTs the full body (existing passphrase is preserved unless changed). type, network binding, clientIsolationEnabled and hotspot/captive-portal settings cannot change; security must stay WPA2/WPA3.',
    { broadcast_id: uuid(), changes: wifiChanges(), merge_mode: mergeMode() },
    async (a, send) => {
      const path = await c.sitePath(`/wifi/broadcasts/${a.broadcast_id.toLowerCase()}`);
      const current = await get(path);
      if (!isPlainObject(current)) throw new Error('unexpected response for current WiFi broadcast');
      const body = mergeWith(a.merge_mode, omit(current, RO_WIFI), omit(a.changes, RO_WIFI));
      return send({ method: 'PUT', path, body, context: { existing: current } });
    }
  );

  const radioChange = strict({
    radio: z.enum(guard.RADIO_BANDS).describe('ng = 2.4 GHz, na = 5 GHz, 6e = 6 GHz'),
    channel: z.union([z.literal('auto'), z.number().int().min(1).max(233)]).optional(),
    ht: z.union([z.literal(20), z.literal(40), z.literal(80), z.literal(160), z.literal(240), z.literal(320)]).optional().describe('channel width MHz'),
    tx_power_mode: z.enum(guard.TX_POWER_MODES).optional(),
    tx_power: z.number().int().min(1).max(30).optional(),
    min_rssi_enabled: z.boolean().optional(),
    min_rssi: z.number().int().min(-95).max(-40).optional(),
  });

  writeTool(
    'unifi_rw_update_ap_radios',
    'Change per-radio settings of one access point (classic PUT rest/device/{_id} with body {radio_table}). Reads the device first, verifies type=="uap", and sends one entry per existing radio containing only radio, name, channel, ht, tx_power_mode, tx_power, min_rssi_enabled, min_rssi (current values, with `radios` changes applied). Provide `mac` or `device_id`.',
    { mac: macStr().optional(), device_id: hex24().optional(), radios: z.array(radioChange).min(1).max(4) },
    async (a, send) => {
      if (!a.mac === !a.device_id) throw new Error('provide exactly one of mac or device_id');
      let device;
      if (a.mac) {
        device = classicData(await get(c.classicPath(`/stat/device/${normMac(a.mac)}`)))[0];
      } else {
        device = classicData(await get(c.classicPath('/stat/device'))).find((d) => d && d._id === a.device_id);
      }
      if (!device) throw new Error('device not found');
      if (device.type !== 'uap') throw new Error(`device ${device._id} is type ${JSON.stringify(device.type)}, not an access point (uap)`);
      if (!Array.isArray(device.radio_table) || device.radio_table.length === 0) throw new Error('device has no radio_table');
      const seen = new Set();
      // Only identity + changeable keys are sent; other per-radio keys are never written.
      const merged = device.radio_table.map((e) =>
        Object.fromEntries(RADIO_SEND_KEYS.filter((k) => isPlainObject(e) && e[k] !== undefined).map((k) => [k, e[k]]))
      );
      for (const ch of a.radios) {
        if (seen.has(ch.radio)) throw new Error(`radio ${ch.radio} listed twice`);
        seen.add(ch.radio);
        const entry = merged.find((e) => e.radio === ch.radio);
        if (!entry) throw new Error(`device has no ${ch.radio} radio (has: ${merged.map((e) => e.radio).join(', ')})`);
        for (const k of RADIO_CHANGE_KEYS) {
          if (ch[k] === undefined) continue;
          // Keep the controller's representation (some fields are stored as strings).
          entry[k] = typeof entry[k] === 'string' && typeof ch[k] === 'number' ? String(ch[k]) : ch[k];
        }
      }
      return send({ method: 'PUT', path: c.classicPath(`/rest/device/${device._id}`), body: { radio_table: merged }, context: { existing: device } });
    }
  );

  writeTool(
    'unifi_rw_create_firewall_policy',
    'Create a zone-based firewall policy (POST /v1/.../firewall/policies). `policy` per spec ("Create or update firewall policy"). ALLOW policies are allowed only between zones listed in the server config firewall_internal_zone_ids; BLOCK/REJECT anywhere.',
    { policy: policyCreate() },
    async (a, send) => sendPolicy(send, { method: 'POST', path: await c.sitePath('/firewall/policies'), body: a.policy })
  );

  writeTool(
    'unifi_rw_update_firewall_policy',
    'Update a zone-based firewall policy: GET, merge `changes`, strip read-only fields (id, index, metadata), PUT full body. ALLOW only between configured internal zones; a BLOCK/REJECT policy whose source is not a configured internal zone may only change name, description, loggingEnabled.',
    { policy_id: uuid(), changes: policyChanges(), merge_mode: mergeMode() },
    async (a, send) => {
      const path = await c.sitePath(`/firewall/policies/${a.policy_id.toLowerCase()}`);
      const current = await get(path);
      if (!isPlainObject(current)) throw new Error('unexpected response for current firewall policy');
      const body = mergeWith(a.merge_mode, omit(current, RO_POLICY), omit(a.changes, RO_POLICY));
      return sendPolicy(send, { method: 'PUT', path, body }, current);
    }
  );

  writeTool(
    'unifi_rw_patch_firewall_policy',
    'Patch a zone-based firewall policy (GET current, then PATCH; per spec only loggingEnabled).',
    { policy_id: uuid(), loggingEnabled: z.boolean() },
    async (a, send) => {
      const path = await c.sitePath(`/firewall/policies/${a.policy_id.toLowerCase()}`);
      const current = await get(path);
      if (!isPlainObject(current)) throw new Error('unexpected response for current firewall policy');
      return send({ method: 'PATCH', path, body: { loggingEnabled: a.loggingEnabled }, context: { existing: current } });
    }
  );

  writeTool(
    'unifi_rw_create_legacy_firewall_rule',
    'Create a legacy firewall rule (classic POST rest/firewallrule). ruleset: (WAN|LAN|GUEST)[v6]_(IN|OUT|LOCAL); action: accept|drop|reject; only known classic rule fields. Rules on WAN* rulesets must use drop or reject and must not set rule_index. Accept rules must name their source (src_networkconf_id, an address group or src_address; src_mac_address only narrows one of these), every address field, networkconf type and address group must match the ruleset family (IPv4 or v6), and every address, group member and referenced network subnet must be private; no negation. Firewall groups and networks are looked up (classic GET rest/firewallgroup, rest/networkconf) before the write.',
    { rule: legacyRuleCreate() },
    async (a, send) => {
      const context = await fetchLegacyRuleContext(a.rule);
      return send({ method: 'POST', path: c.classicPath('/rest/firewallrule'), body: omit(a.rule, RO_CLASSIC), context });
    }
  );

  writeTool(
    'unifi_rw_update_legacy_firewall_rule',
    'Update a legacy firewall rule: GET rest/firewallrule/{_id}, merge `changes`, PUT the full rule (only known classic rule fields). Existing WAN* drop/reject rules may only change name and logging; a rule never leaves a WAN* ruleset; rule_index never changes on WAN* rulesets; the merged rule, if it is an accept rule, must satisfy the same source/private-address rules as on create.',
    { rule_id: hex24(), changes: legacyRuleChanges(), merge_mode: mergeMode() },
    async (a, send) => {
      const path = c.classicPath(`/rest/firewallrule/${a.rule_id}`);
      const current = classicData(await get(path))[0];
      if (!isPlainObject(current)) throw new Error('legacy firewall rule not found');
      const body = mergeWith(a.merge_mode, omit(current, RO_CLASSIC), omit(a.changes, RO_CLASSIC));
      const context = await fetchLegacyRuleContext(body);
      return send({ method: 'PUT', path, body, context: { ...context, existing: current } });
    }
  );

  writeTool(
    'unifi_rw_set_fixed_ip',
    'Set a DHCP fixed IP for a client MAC (classic rest/user). Updates the existing client record or creates one. network_id is the CLASSIC networkconf _id (24 hex), e.g. taken from an existing record in unifi_rw_list_fixed_ips.',
    { mac: macStr(), fixed_ip: ipv4(), network_id: hex24(), name: z.string().min(1).max(128).optional() },
    async (a, send) => {
      const mac = normMac(a.mac);
      const existing = await findClassicUser(mac);
      const body = { use_fixedip: true, fixed_ip: a.fixed_ip, network_id: a.network_id };
      if (a.name !== undefined) body.name = a.name;
      if (existing) {
        if (!/^[0-9a-f]{24}$/.test(String(existing._id))) throw new Error('existing client record has an unexpected _id');
        return send({ method: 'PUT', path: c.classicPath(`/rest/user/${existing._id}`), body });
      }
      return send({ method: 'POST', path: c.classicPath('/rest/user'), body: { mac, ...body } });
    }
  );

  writeTool(
    'unifi_rw_clear_fixed_ip',
    'Remove the fixed IP from a client record (classic PUT rest/user/{_id} with {use_fixedip:false}).',
    { mac: macStr() },
    async (a, send) => {
      const existing = await findClassicUser(normMac(a.mac));
      if (!existing) throw new Error('no client record for that MAC');
      if (!/^[0-9a-f]{24}$/.test(String(existing._id))) throw new Error('existing client record has an unexpected _id');
      return send({ method: 'PUT', path: c.classicPath(`/rest/user/${existing._id}`), body: { use_fixedip: false } });
    }
  );

  writeTool(
    'unifi_rw_authorize_guest',
    'Authorize a guest client (POST /v1/.../clients/{clientId}/actions, AUTHORIZE_GUEST_ACCESS).',
    {
      client_id: uuid(),
      ...Object.fromEntries(Object.entries(guard.GUEST_LIMITS).map(([k, { min, max }]) => [k, z.number().int().min(min).max(max).optional()])),
    },
    async (a, send) => {
      const body = { action: 'AUTHORIZE_GUEST_ACCESS' };
      for (const k of Object.keys(guard.GUEST_LIMITS)) {
        if (a[k] !== undefined) body[k] = a[k];
      }
      return send({ method: 'POST', path: await c.sitePath(`/clients/${a.client_id.toLowerCase()}/actions`), body });
    }
  );

  writeTool(
    'unifi_rw_unauthorize_guest',
    'Unauthorize (and disconnect) a guest client (UNAUTHORIZE_GUEST_ACCESS).',
    { client_id: uuid() },
    async (a, send) =>
      send({ method: 'POST', path: await c.sitePath(`/clients/${a.client_id.toLowerCase()}/actions`), body: { action: 'UNAUTHORIZE_GUEST_ACCESS' } })
  );

  writeTool(
    'unifi_rw_update_network',
    'Update a network (PUT /v1/.../networks/{id}): GET current, apply `changes`, strip read-only fields (id, metadata, default), PUT. Only mdnsForwardingEnabled (boolean, or null for the site default) can change.',
    { network_id: uuid(), changes: strict({ mdnsForwardingEnabled: z.boolean().nullable() }) },
    async (a, send) => {
      const path = await c.sitePath(`/networks/${a.network_id.toLowerCase()}`);
      const current = await get(path);
      if (!isPlainObject(current)) throw new Error('unexpected response for current network');
      const body = { ...omit(current, RO_NETWORK), ...a.changes };
      return send({ method: 'PUT', path, body, context: { existing: current } });
    }
  );
}

module.exports = { registerTools, TOOL_NAMES, READ_TOOLS, WRITE_TOOLS, CLASSIC_TOOLS, CLASSIC_TOOL_CAPABILITY, toolNamesFor, deepMerge };
