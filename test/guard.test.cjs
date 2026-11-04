'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { checkRequest, checkFinalPath, cloudPrefix, GuardError, classicCapabilityOf } = require('../lib/guard.cjs');
const { createUdmClient } = require('../lib/udm-client.cjs');

const SITE = '88f7af54-98f8-306a-a1c7-c9349722b1f6';
const ID = '7a2e4c90-1d3b-4f6a-8e25-c4b9d0f13a77';
const HEX = '5f1e2d3c4b5a69788796a5b4';
const MAC = 'aa:bb:cc:dd:ee:ff';
// Canonical paths (relative to the Network app prefix; the backend adds the prefix).
const I = `/integration/v1/sites/${SITE}`;
const C = '/api/s/default';
const CONSOLE = '942A6FF664C0000000000964970E0000000009E710560000000068A9873F:9999999999';

const ZONE_INTERNAL = 'aaaaaaaa-0000-4000-8000-000000000001';
const ZONE_EXTERNAL = 'aaaaaaaa-0000-4000-8000-000000000002';
const ZONE_GATEWAY = 'aaaaaaaa-0000-4000-8000-000000000003';
const ZONE_IOT = 'aaaaaaaa-0000-4000-8000-000000000004';
// The External zone renamed by an admin: names prove nothing.
const ZONE_UPLINK = 'aaaaaaaa-0000-4000-8000-000000000005';
const ZONE_GHOST = 'aaaaaaaa-0000-4000-8000-000000000006'; // configured internal, but not on the controller
const zones = [
  { id: ZONE_INTERNAL, name: 'Internal', metadata: { origin: 'SYSTEM_DEFINED' }, networkIds: [] },
  { id: ZONE_EXTERNAL, name: 'External', metadata: { origin: 'SYSTEM_DEFINED' }, networkIds: [] },
  { id: ZONE_GATEWAY, name: 'Gateway', metadata: { origin: 'SYSTEM_DEFINED' }, networkIds: [] },
  { id: ZONE_IOT, name: 'IoT', metadata: { origin: 'USER_DEFINED' }, networkIds: [] },
  { id: ZONE_UPLINK, name: 'Uplink', metadata: { origin: 'SYSTEM_DEFINED' }, networkIds: [] },
];
const NET = '3f6c2a10-5b7e-4d2a-9c41-7e8d0a6b1c25';
// What config.json's firewall_internal_zone_ids / firewall_wan_zone_ids become.
const ZCFG = { internalZoneIds: [ZONE_INTERNAL, ZONE_IOT, ZONE_GHOST], wanZoneIds: [ZONE_EXTERNAL] };
const pctx = (extra = {}) => ({ zones, ...ZCFG, ...extra });
const strip = (o, keys) => Object.fromEntries(Object.entries(o).filter(([k]) => !keys.includes(k)));
const policy = (type, src, dst) => ({
  name: 'p',
  enabled: true,
  loggingEnabled: false,
  action: type === 'ALLOW' ? { type, allowReturnTraffic: false } : { type },
  source: { zoneId: src },
  destination: { zoneId: dst },
  ipProtocolScope: { ipVersion: 'IPV4' },
});

const RO_POLICY = ['id', 'index', 'metadata'];
const policyExisting = (type, src, dst, extra = {}) => ({
  id: ID,
  index: 10000,
  metadata: { origin: 'USER_DEFINED' },
  ...policy(type, src, dst),
  description: 'drop inbound',
  schedule: { mode: 'ALWAYS' },
  connectionStateFilter: ['NEW', 'INVALID'],
  ...extra,
});
const WAN_BLOCK = policyExisting('BLOCK', ZONE_EXTERNAL, ZONE_INTERNAL);
/** PUT of the merged policy, as unifi_rw_update_firewall_policy builds it. */
const policyPut = (existing, changes = {}, ctx = {}) => ({
  method: 'PUT',
  path: `${I}/firewall/policies/${ID}`,
  body: { ...strip(existing, RO_POLICY), ...changes },
  context: pctx({ existing, ...ctx }),
});

const WAN_RULE = {
  _id: HEX,
  site_id: 'site',
  name: 'block in',
  ruleset: 'WAN_IN',
  action: 'drop',
  rule_index: 2000,
  enabled: true,
  protocol: 'all',
  protocol_match_excepted: false,
  logging: false,
  state_established: false,
  state_new: true,
  src_firewallgroup_ids: [],
  src_address: '',
  dst_address: '',
  dst_port: '',
  ipsec: '',
  setting_preference: 'auto',
};
// Classic rest/networkconf and rest/firewallgroup data, as the legacy rule tools fetch it.
const WAN_NET = '6a1e2d3c4b5a69788796a5b4';
const NETWORKS = [
  { _id: HEX, name: 'Default', purpose: 'corporate', ip_subnet: '192.168.1.1/24', vlan_enabled: false, ipv6_interface_type: 'static', ipv6_subnet: 'fd00:1::1/64' },
  { _id: WAN_NET, name: 'Internet 1', purpose: 'wan', wan_type: 'dhcp' },
];
const ADDR_GROUP = '7a1e2d3c4b5a69788796a5b4';
const GROUPS = [{ _id: ADDR_GROUP, name: 'Trusted', group_type: 'address-group', group_members: ['192.168.1.10', '192.168.1.20-192.168.1.29'] }];
const LCTX = { networks: NETWORKS, firewallGroups: GROUPS };
const legacyPut = (existing, changes = {}) => ({
  method: 'PUT',
  path: `${C}/rest/firewallrule/${HEX}`,
  body: { ...strip(existing, ['_id', 'site_id']), ...changes },
  context: { existing, ...LCTX },
});

const WIFI_EX = {
  id: ID,
  metadata: { origin: 'USER_DEFINED' },
  type: 'STANDARD',
  name: 'Home',
  enabled: true,
  network: { type: 'SPECIFIC', networkId: NET },
  securityConfiguration: { type: 'WPA2_PERSONAL', passphrase: 'real-wifi-pass' },
  clientIsolationEnabled: false,
  hideName: false,
};
const wifiCreate = (extra = {}) => ({
  method: 'POST',
  path: `${I}/wifi/broadcasts`,
  body: {
    type: 'STANDARD',
    name: 'IoT',
    enabled: true,
    network: { type: 'SPECIFIC', networkId: NET },
    securityConfiguration: { type: 'WPA2_PERSONAL', passphrase: 'abcdefgh123' },
    clientIsolationEnabled: true,
    ...extra,
  },
});
const wifiPut = (existing, changes = {}) => ({
  method: 'PUT',
  path: `${I}/wifi/broadcasts/${ID}`,
  body: { ...strip(existing, ['id', 'metadata']), ...changes },
  context: { existing },
});

const NET_EX = {
  id: ID,
  management: 'GATEWAY',
  name: 'LAN',
  enabled: true,
  vlanId: 10,
  default: false,
  metadata: { origin: 'USER_DEFINED' },
  zoneId: ZONE_INTERNAL,
  isolationEnabled: false,
  internetAccessEnabled: true,
  cellularBackupEnabled: false,
  mdnsForwardingEnabled: false,
  ipv4Configuration: { hostIpAddress: '192.168.10.1', prefixLength: 24, dhcpConfiguration: { mode: 'SERVER', ipAddressRange: { start: '192.168.10.6', stop: '192.168.10.254' } } },
};
const netPut = (changes = {}, existing = NET_EX) => ({
  method: 'PUT',
  path: `${I}/networks/${ID}`,
  body: { ...strip(existing, ['id', 'metadata', 'default']), ...changes },
  context: { existing },
});

const DEVICE = {
  _id: HEX,
  type: 'uap',
  mac: MAC,
  radio_table: [
    { radio: 'ng', name: 'wifi0', channel: '6', ht: '20', tx_power_mode: 'auto', antenna_gain: 3, sens_level: -90 },
    { radio: 'na', name: 'wifi1', channel: 'auto', ht: 80, tx_power_mode: 'auto' },
  ],
};
const devPut = (radio_table, existing = DEVICE) => ({ method: 'PUT', path: `${C}/rest/device/${HEX}`, body: { radio_table }, context: { existing } });

// Every case is recorded and replayed through a local and a cloud client at
// the end of this file to prove that decisions do not depend on the backend.
const CASES = [];
const allowed = (req) => {
  assert.equal(checkRequest(req).ok, true);
  CASES.push({ req, refused: null });
};
function denied(req, re) {
  assert.throws(
    () => checkRequest(req),
    (e) => {
      assert.ok(e instanceof GuardError, `expected GuardError, got ${e}`);
      if (re) assert.match(e.message, re);
      CASES.push({ req, refused: e.message });
      return true;
    }
  );
}

test('allowed: every write tool path', () => {
  allowed(wifiCreate());
  allowed(wifiPut(WIFI_EX, { name: 'Home 2' }));
  allowed({ method: 'POST', path: `${I}/firewall/policies`, body: policy('BLOCK', ZONE_EXTERNAL, ZONE_INTERNAL), context: pctx() });
  allowed(policyPut(policyExisting('ALLOW', ZONE_INTERNAL, ZONE_IOT), { name: 'renamed' }));
  allowed({ method: 'PATCH', path: `${I}/firewall/policies/${ID}`, body: { loggingEnabled: true }, context: { existing: WAN_BLOCK } });
  allowed({ method: 'POST', path: `${I}/clients/${ID}/actions`, body: { action: 'AUTHORIZE_GUEST_ACCESS', timeLimitMinutes: 60 } });
  allowed({ method: 'POST', path: `${I}/clients/${ID}/actions`, body: { action: 'UNAUTHORIZE_GUEST_ACCESS' } });
  allowed(netPut({ mdnsForwardingEnabled: true }));
  allowed(devPut([{ radio: 'na', channel: '36', ht: 80, name: 'wifi1' }]));
  allowed({ method: 'POST', path: `${C}/rest/firewallrule`, body: { name: 'r', ruleset: 'LAN_IN', action: 'accept', rule_index: 2000, src_address: '192.168.1.0/24' } });
  allowed(legacyPut(WAN_RULE, { name: 'r' }));
  allowed({ method: 'POST', path: `${C}/rest/user`, body: { mac: MAC, use_fixedip: true, fixed_ip: '192.168.1.50', network_id: HEX, name: 'tv' } });
  allowed({ method: 'PUT', path: `${C}/rest/user/${HEX}`, body: { use_fixedip: true, fixed_ip: '192.168.1.50', network_id: HEX } });
  allowed({ method: 'PUT', path: `${C}/rest/user/${HEX}`, body: { use_fixedip: false } });
});

test('allowed: read paths, including paging query', () => {
  allowed({ method: 'GET', path: '/integration/v1/info' });
  allowed({ method: 'GET', path: '/integration/v1/sites?limit=200' });
  allowed({ method: 'GET', path: `${I}/clients?offset=0&limit=25&filter=${encodeURIComponent("ipAddress.eq('192.168.1.2')")}` });
  allowed({ method: 'GET', path: `${I}/firewall/zones?limit=200` });
  allowed({ method: 'GET', path: `${C}/stat/device` });
  allowed({ method: 'GET', path: `${C}/stat/device/${MAC}` });
  allowed({ method: 'GET', path: `${C}/rest/user` });
  allowed({ method: 'GET', path: `${C}/rest/firewallrule/${HEX}` });
  denied({ method: 'GET', path: `${I}/clients?evil=1` }, /not allowed/);
  denied({ method: 'GET', path: `${I}/clients`, body: {} }, /body/);
});

test('denied: DELETE on every resource', () => {
  const paths = [
    `${I}/wifi/broadcasts/${ID}`,
    `${I}/firewall/policies/${ID}`,
    `${I}/firewall/zones/${ID}`,
    `${I}/networks/${ID}`,
    `${I}/devices/${ID}`,
    `${I}/hotspot/vouchers`,
    `${I}/acl-rules/${ID}`,
    `${I}/dns/policies/${ID}`,
    `${I}/traffic-matching-lists/${ID}`,
    `${C}/rest/firewallrule/${HEX}`,
    `${C}/rest/user/${HEX}`,
    `${C}/rest/device/${HEX}`,
    `${C}/rest/portforward/${HEX}`,
  ];
  for (const p of paths) {
    for (const m of ['DELETE', 'delete', 'Delete']) denied({ method: m, path: p }, /DELETE is never allowed/);
  }
});

test('denied: firmware, device commands, integration device actions', () => {
  denied({ method: 'POST', path: `${C}/cmd/devmgr`, body: { cmd: 'upgrade', mac: MAC } }, /device manager/);
  denied({ method: 'POST', path: `${C}/cmd/devmgr/upgrade-external`, body: { url: 'x' } }, /device manager/);
  for (const cmd of ['restart', 'adopt', 'forget', 'provision', 'power-cycle']) {
    denied({ method: 'POST', path: `${C}/cmd/devmgr`, body: { cmd, mac: MAC } }, /device manager/);
  }
  denied({ method: 'POST', path: `${I}/devices`, body: { macAddress: MAC } }, /device/);
  denied({ method: 'POST', path: `${I}/devices/${ID}/actions`, body: { action: 'RESTART' } }, /device/);
  denied({ method: 'POST', path: `${I}/devices/${ID}/interfaces/ports/1/actions`, body: { action: 'POWER_CYCLE' } });
  denied({ method: 'POST', path: '/integration/v1/pending-devices', body: {} });
  denied({ method: 'POST', path: '/api/s/default/firmware/upgrade', body: {} }, /firmware|upgrade/);
});

test('denied: port forward, networkconf, settings/ssh, remote access, backup, admin, zones', () => {
  denied({ method: 'POST', path: `${C}/rest/portforward`, body: { fwd: '192.168.1.2', dst_port: '22' } }, /port forward/);
  denied({ method: 'PUT', path: `${C}/rest/portforward/${HEX}`, body: { enabled: true } }, /port forward/);
  denied({ method: 'POST', path: `${C}/rest/networkconf`, body: { purpose: 'wan' } }, /network configuration/);
  denied({ method: 'PUT', path: `${C}/rest/networkconf/${HEX}`, body: { purpose: 'corporate' } }, /network configuration/);
  denied({ method: 'PUT', path: `${C}/rest/setting/mgmt/${HEX}`, body: { x_ssh_enabled: true } }, /settings/);
  denied({ method: 'POST', path: `${C}/set/setting/mgmt`, body: { x_ssh_enabled: true } }, /settings/);
  denied({ method: 'PUT', path: '/api/s/default/remote-access', body: { enabled: true } }, /remote access/);
  denied({ method: 'POST', path: `${C}/cmd/backup`, body: { cmd: 'backup' } }, /backup/);
  denied({ method: 'POST', path: `${C}/cmd/sitemgr`, body: { cmd: 'grant-admin' } }, /site\/admin/);
  denied({ method: 'GET', path: '/api/self' }, /must start with/);
  denied({ method: 'GET', path: `${C}/self` }, /allowlist/);
  denied({ method: 'GET', path: `${C}/stat/admin` }, /admin/);
  denied({ method: 'POST', path: `${I}/firewall/zones`, body: { name: 'z', networkIds: [] } }, /zone/);
  denied({ method: 'PUT', path: `${I}/firewall/zones/${ID}`, body: { name: 'External', networkIds: [ID] } }, /zone/);
  denied({ method: 'PUT', path: `${I}/firewall/policies/ordering`, body: {} }, /ordering/);
  denied({ method: 'POST', path: `${I}/hotspot/vouchers`, body: {} }, /voucher/);
  denied({ method: 'POST', path: `${I}/acl-rules`, body: {} }, /ACL/);
  denied({ method: 'POST', path: `${I}/dns/policies`, body: {} }, /DNS/);
  denied({ method: 'POST', path: `${I}/networks`, body: { name: 'x' } }, /allowlist/);
  denied({ method: 'POST', path: `${C}/cmd/stamgr`, body: { cmd: 'kick-sta' } }, /cmd/);
});

test('denied: traversal / encoding / case / query tricks and default deny', () => {
  denied({ method: 'GET', path: `${I}/../../api/self` }, /traversal/);
  denied({ method: 'GET', path: `${I}/%2e%2e/%2e%2e/api/self` }, /encoded/);
  denied({ method: 'GET', path: `${I}/clients%2F${ID}` }, /encoded/);
  denied({ method: 'GET', path: `//integration/v1/info` }, /\/\//);
  denied({ method: 'GET', path: `/integration//v1/info` }, /\/\//);
  denied({ method: 'GET', path: `${I}/./clients` }, /"\."/);
  denied({ method: 'GET', path: `${I}\\clients` }, /backslash/);
  denied({ method: 'GET', path: `${I}/clients\u0000` }, /control/);
  denied({ method: 'GET', path: `${I}/clients#x` }, /fragment/);
  denied({ method: 'GET', path: `${I}/clients;jsessionid=1` }, /path parameters/);
  denied({ method: 'GET', path: '/INTEGRATION/v1/info' }, /must start with/);
  denied({ method: 'GET', path: '/integration/V1/info' }, /must start with/);
  denied({ method: 'GET', path: `${I.replace('/sites/', '/SITES/')}/clients` }, /allowlist/);
  denied({ method: 'get', path: '/integration/v1/info' }, /uppercase/);
  denied({ method: 'post', path: `${I}/wifi/broadcasts`, body: {} }, /uppercase/);
  denied({ method: 'HEAD', path: '/integration/v1/info' });
  denied({ method: 'POST', path: `${I}/wifi/broadcasts?force=true`, body: { name: 'x' } }, /query strings/);
  denied({ method: 'GET', path: '/api/self' }, /must start with/);
  denied({ method: 'GET', path: `${I}/vpn/servers` }, /allowlist/);
  denied({ method: 'GET', path: `${I}/wifi/broadcasts/not-a-uuid` }, /allowlist/);
  denied({ method: 'PUT', path: `${C}/rest/user/${HEX.toUpperCase()}`, body: { use_fixedip: false } }, /allowlist/);
  denied({ method: 'PUT', path: '/api/s/bad site/rest/user/' + HEX, body: { use_fixedip: false } });
  denied({ method: 'GET', path: '/integration/v1/infox' }, /allowlist/);
  denied({ method: 'GET', path: 'integration/v1/info' }, /absolute/);
});

test('denied: body restrictions', () => {
  denied({ method: 'PUT', path: `${C}/rest/user/${HEX}`, body: { use_fixedip: false, blocked: true } }, /"blocked"/);
  denied({ method: 'POST', path: `${C}/rest/user`, body: { mac: MAC, use_fixedip: true, fixed_ip: '10.0.0.1', network_id: HEX, is_admin: true } }, /is_admin/);
  denied({ method: 'POST', path: `${C}/rest/user`, body: { mac: 'AA:BB', use_fixedip: false } }, /MAC/);
  denied({ method: 'PUT', path: `${C}/rest/user/${HEX}`, body: { use_fixedip: true, fixed_ip: '999.1.1.1', network_id: HEX } }, /IPv4/);
  denied({ method: 'PUT', path: `${C}/rest/device/${HEX}`, body: { radio_table: [{ radio: 'na' }], name: 'x' } }, /exactly one key/);
  denied({ method: 'PUT', path: `${C}/rest/device/${HEX}`, body: { config_network: { type: 'static' } } }, /exactly one key/);
  denied({ method: 'PUT', path: `${C}/rest/device/${HEX}`, body: { radio_table: [] } }, /non-empty/);
  denied({ method: 'PUT', path: `${C}/rest/device/${HEX}`, body: { radio_table: [{ radio: 'na', x_ssh_password: 'x' }] } }, /x_ssh/);
  denied({ method: 'POST', path: `${I}/clients/${ID}/actions`, body: { action: 'RESTART' } }, /not allowed/);
  denied({ method: 'POST', path: `${I}/clients/${ID}/actions`, body: { action: 'BLOCK' } }, /not allowed/);
  denied({ method: 'POST', path: `${I}/clients/${ID}/actions`, body: { action: 'UNAUTHORIZE_GUEST_ACCESS', extra: 1 } }, /extra/);
  denied({ method: 'PATCH', path: `${I}/firewall/policies/${ID}`, body: { loggingEnabled: true, enabled: false }, context: { existing: WAN_BLOCK } }, /enabled/);
  denied({ method: 'POST', path: `${I}/wifi/broadcasts`, body: { name: 'x', securityConfiguration: { passphrase: '[REDACTED]' } } }, /redaction placeholder/);
  denied({ method: 'POST', path: `${I}/wifi/broadcasts`, body: { id: ID, name: 'x' } }, /read-only/);
  denied({ method: 'POST', path: `${I}/wifi/broadcasts`, body: [] }, /JSON object/);
  denied({ method: 'POST', path: `${C}/rest/firewallrule`, body: { ruleset: 'LAN_IN', action: 'accept', mgmt_x: 1 } }, /mgmt_x/);
  denied({ method: 'POST', path: `${C}/rest/firewallrule`, body: JSON.parse('{"ruleset":"LAN_IN","action":"accept","__proto__":{"x":1}}') }, /__proto__/);
});

test('network update: only mdnsForwardingEnabled may change (fix 4)', () => {
  allowed(netPut({ mdnsForwardingEnabled: true }));
  allowed(netPut({ mdnsForwardingEnabled: null }));
  allowed(netPut()); // no-op
  const changes = {
    isolationEnabled: true,
    internetAccessEnabled: false,
    vlanId: 11,
    zoneId: ZONE_EXTERNAL,
    management: 'SWITCH',
    enabled: false,
    name: 'Trusted',
    cellularBackupEnabled: true,
    purpose: 'wan',
    dhcpGuarding: { trustedDhcpServerIpAddresses: ['192.168.10.2'] },
    ipv6Configuration: { interfaceType: 'PREFIX_DELEGATION' },
    ipv4Configuration: { ...NET_EX.ipv4Configuration, dhcpConfiguration: { mode: 'RELAY', dhcpServerIpAddresses: ['10.0.0.1'] } },
  };
  for (const [k, v] of Object.entries(changes)) {
    denied(netPut({ [k]: v }), new RegExp(`only mdnsForwardingEnabled may change, not: ${k}`));
  }
  // dropping a field is a change as well
  denied({ ...netPut(), body: strip(netPut().body, ['ipv4Configuration']) }, /not: ipv4Configuration/);
  denied(netPut({ mdnsForwardingEnabled: 'yes' }), /boolean or null/);
  denied({ ...netPut({ mdnsForwardingEnabled: true }), context: undefined }, /context\.existing missing.*fail closed/);
  denied({ ...netPut({ mdnsForwardingEnabled: true }), context: { existingNetwork: NET_EX } }, /context\.existing missing/);
  denied(netPut({ metadata: {} }), /read-only/);
  denied(netPut({}, { ...NET_EX, id: ZONE_INTERNAL }), /not the network named in the path/);
});

test('WAN-in: zone-based firewall policies', () => {
  const P = `${I}/firewall/policies`;
  denied({ method: 'POST', path: P, body: policy('ALLOW', ZONE_EXTERNAL, ZONE_INTERNAL), context: pctx() }, /WAN-in/);
  denied({ method: 'POST', path: P, body: policy('ALLOW', ZONE_EXTERNAL, ZONE_GATEWAY), context: pctx() }, /WAN-in/);
  denied({ method: 'PUT', path: `${P}/${ID}`, body: policy('ALLOW', ZONE_EXTERNAL.toUpperCase(), ZONE_INTERNAL), context: pctx({ existing: policyExisting('ALLOW', ZONE_INTERNAL, ZONE_IOT) }) }, /WAN-in/);
  denied({ method: 'POST', path: P, body: policy('SOMETHING', ZONE_EXTERNAL, ZONE_INTERNAL), context: pctx() }, /WAN-in/);
  allowed({ method: 'POST', path: P, body: policy('BLOCK', ZONE_EXTERNAL, ZONE_INTERNAL), context: pctx() });
  allowed({ method: 'POST', path: P, body: policy('REJECT', ZONE_EXTERNAL, ZONE_GATEWAY), context: pctx() });
  allowed({ method: 'POST', path: P, body: policy('BLOCK', ZONE_UPLINK, ZONE_INTERNAL), context: pctx({ internalZoneIds: [], wanZoneIds: [] }) });
  denied({ method: 'POST', path: P, body: policy('ALLOW', 'bbbbbbbb-0000-4000-8000-000000000009', ZONE_INTERNAL), context: pctx() }, /unknown/);
  denied({ method: 'POST', path: P, body: { ...policy('ALLOW', ZONE_INTERNAL, ZONE_INTERNAL), source: {} }, context: pctx() }, /unknown/);
  denied({ method: 'POST', path: P, body: policy('BLOCK', ZONE_EXTERNAL, ZONE_INTERNAL) }, /zones could not be determined/);
  denied({ method: 'POST', path: P, body: policy('ALLOW', ZONE_INTERNAL, ZONE_IOT), context: pctx({ zones: [] }) }, /zones could not be determined/);
  denied({ method: 'POST', path: P, body: { ...policy('ALLOW', ZONE_INTERNAL, ZONE_INTERNAL), action: undefined }, context: pctx() }, /action/);
  denied({ method: 'POST', path: P, body: { ...policy('BLOCK', ZONE_EXTERNAL, ZONE_INTERNAL), index: 1 }, context: pctx() }, /read-only field "index"/);
});

test('zone-based ALLOW needs configured internal zones on both ends (fix 5)', () => {
  const P = `${I}/firewall/policies`;
  // internal -> internal, both configured and present: allowed
  allowed({ method: 'POST', path: P, body: policy('ALLOW', ZONE_INTERNAL, ZONE_IOT), context: pctx() });
  allowed({ method: 'POST', path: P, body: policy('ALLOW', ZONE_IOT.toUpperCase(), ZONE_INTERNAL), context: pctx() });
  // renamed External zone ("Uplink", SYSTEM_DEFINED, not configured): refused although the name looks harmless
  denied({ method: 'POST', path: P, body: policy('ALLOW', ZONE_UPLINK, ZONE_INTERNAL), context: pctx() }, /source zone "Uplink" is not in firewall_internal_zone_ids/);
  denied({ method: 'POST', path: P, body: policy('ALLOW', ZONE_UPLINK, ZONE_INTERNAL), context: pctx({ wanZoneIds: [] }) }, /not in firewall_internal_zone_ids/);
  // destination not internal
  denied({ method: 'POST', path: P, body: policy('ALLOW', ZONE_INTERNAL, ZONE_EXTERNAL), context: pctx() }, /ALLOW to WAN\/External zone/);
  denied({ method: 'POST', path: P, body: policy('ALLOW', ZONE_INTERNAL, ZONE_EXTERNAL), context: pctx({ wanZoneIds: [] }) }, /ALLOW to WAN\/External zone/);
  denied({ method: 'POST', path: P, body: policy('ALLOW', ZONE_INTERNAL, ZONE_GATEWAY), context: pctx() }, /destination zone "Gateway" is not in firewall_internal_zone_ids/);
  denied({ method: 'POST', path: P, body: policy('ALLOW', ZONE_INTERNAL, ZONE_UPLINK), context: pctx() }, /destination zone "Uplink" is not in/);
  // config missing / empty: every ALLOW refused
  for (const cfg of [{ internalZoneIds: undefined }, { internalZoneIds: [] }, { internalZoneIds: null }]) {
    denied({ method: 'POST', path: P, body: policy('ALLOW', ZONE_INTERNAL, ZONE_IOT), context: pctx(cfg) }, /require firewall_internal_zone_ids/);
  }
  denied(policyPut(policyExisting('ALLOW', ZONE_INTERNAL, ZONE_IOT), { name: 'x' }, { internalZoneIds: [] }), /require firewall_internal_zone_ids/);
  // configured internal but not present on the controller
  denied({ method: 'POST', path: P, body: policy('ALLOW', ZONE_GHOST, ZONE_INTERNAL), context: pctx() }, /unknown/);
  // a WAN-looking name refuses even if (mis)configured as internal; a name never permits
  const renamed = zones.map((z) => (z.id === ZONE_IOT ? { ...z, name: 'WAN' } : z));
  denied({ method: 'POST', path: P, body: policy('ALLOW', ZONE_IOT, ZONE_INTERNAL), context: pctx({ zones: renamed }) }, /WAN-in/);
  // invalid zone configuration fails closed (even for BLOCK)
  denied({ method: 'POST', path: P, body: policy('BLOCK', ZONE_EXTERNAL, ZONE_INTERNAL), context: pctx({ internalZoneIds: ['not-a-uuid'] }) }, /firewall_internal_zone_ids is invalid/);
  denied({ method: 'POST', path: P, body: policy('BLOCK', ZONE_EXTERNAL, ZONE_INTERNAL), context: pctx({ internalZoneIds: ZONE_INTERNAL }) }, /firewall_internal_zone_ids is invalid/);
  denied({ method: 'POST', path: P, body: policy('BLOCK', ZONE_EXTERNAL, ZONE_INTERNAL), context: pctx({ wanZoneIds: [ZONE_INTERNAL] }) }, /both in firewall_internal_zone_ids and firewall_wan_zone_ids/);
});

test('WAN-side deny policies: only name/description/loggingEnabled may change (fix 1)', () => {
  // cosmetic changes allowed
  allowed(policyPut(WAN_BLOCK, { description: 'still blocking' }));
  allowed(policyPut(WAN_BLOCK, { loggingEnabled: true }));
  allowed(policyPut(WAN_BLOCK, { name: 'Block WAN in' }));
  allowed(policyPut(WAN_BLOCK));
  allowed({ method: 'PATCH', path: `${I}/firewall/policies/${ID}`, body: { loggingEnabled: true }, context: { existing: WAN_BLOCK } });
  // everything else refused
  const bad = {
    enabled: false,
    action: { type: 'ALLOW', allowReturnTraffic: false },
    source: { zoneId: ZONE_INTERNAL },
    destination: { zoneId: ZONE_GATEWAY },
    schedule: { mode: 'ONE_TIME_ONLY', start: '2026-01-01T00:00:00Z' },
    ipProtocolScope: { ipVersion: 'IPV6' },
    connectionStateFilter: ['ESTABLISHED'],
    ipsecFilter: 'MATCH_ENCRYPTED',
    somethingNew: true,
  };
  for (const [k, v] of Object.entries(bad)) denied(policyPut(WAN_BLOCK, { [k]: v }), new RegExp(`WAN-side deny.*not: ${k}`));
  denied(policyPut(WAN_BLOCK, { action: { type: 'REJECT' } }), /WAN-side deny.*not: action/);
  denied(policyPut(WAN_BLOCK, { destination: { zoneId: ZONE_INTERNAL, trafficFilter: { type: 'PORT', portFilter: { type: 'PORTS', matchOpposite: true, items: [] } } } }), /not: destination/);
  denied({ ...policyPut(WAN_BLOCK), body: strip(policyPut(WAN_BLOCK).body, ['schedule']) }, /not: schedule/);
  denied(policyPut(WAN_BLOCK, { enabled: false, loggingEnabled: true }), /not: enabled/);
  denied(policyPut(WAN_BLOCK, { loggingEnabled: 'yes' }), /loggingEnabled must be a boolean/);
  // "WAN-side" = source not a configured internal zone, whatever its name
  for (const src of [ZONE_UPLINK, ZONE_GATEWAY, 'bbbbbbbb-0000-4000-8000-000000000009']) {
    denied(policyPut(policyExisting('REJECT', src, ZONE_INTERNAL), { enabled: false }), /WAN-side deny/);
  }
  denied(policyPut(policyExisting('BLOCK', undefined, ZONE_INTERNAL), { enabled: false }), /WAN-side deny/);
  // with no internal zones configured every deny policy is treated as WAN-side
  denied(policyPut(policyExisting('BLOCK', ZONE_INTERNAL, ZONE_IOT), { enabled: false }, { internalZoneIds: [] }), /WAN-side deny/);
  // an internal -> internal deny policy may be changed normally
  allowed(policyPut(policyExisting('BLOCK', ZONE_INTERNAL, ZONE_IOT), { enabled: false }));
  allowed(policyPut(policyExisting('BLOCK', ZONE_INTERNAL, ZONE_IOT), { action: { type: 'ALLOW', allowReturnTraffic: true } }));
  denied(policyPut(policyExisting('BLOCK', ZONE_INTERNAL, ZONE_IOT), { action: { type: 'ALLOW' }, destination: { zoneId: ZONE_EXTERNAL } }), /ALLOW to WAN/);
  // updates without the existing object, or with the wrong one, are refused
  denied({ ...policyPut(WAN_BLOCK, { loggingEnabled: true }), context: pctx() }, /context\.existing missing.*fail closed/);
  denied({ method: 'PATCH', path: `${I}/firewall/policies/${ID}`, body: { loggingEnabled: true } }, /context\.existing missing/);
  denied({ method: 'PATCH', path: `${I}/firewall/policies/${ID}`, body: { loggingEnabled: true }, context: { existing: 'x' } }, /context\.existing missing/);
  denied(policyPut({ ...WAN_BLOCK, id: NET }, { loggingEnabled: true }), /not the firewall policy named in the path/);
  denied({ method: 'PUT', path: `${I}/firewall/policies/${ID}`, body: policy('BLOCK', ZONE_EXTERNAL, ZONE_INTERNAL), context: 'x' }, /context must be an object/);
});

test('WAN-in: legacy firewall rules', () => {
  const P = `${C}/rest/firewallrule`;
  const rule = (ruleset, action, extra = {}) => ({ name: 'r', enabled: true, ruleset, action, ...extra });
  denied({ method: 'POST', path: P, body: rule('WAN_IN', 'accept') }, /WAN/);
  denied({ method: 'POST', path: P, body: rule('WAN_LOCAL', 'accept') }, /WAN/);
  denied({ method: 'POST', path: P, body: rule('WANv6_IN', 'accept') }, /WAN/);
  denied({ method: 'POST', path: P, body: rule('WANv6_LOCAL', 'ACCEPT') }, /action "ACCEPT" is missing or unknown/);
  denied(legacyPut({ ...WAN_RULE, action: 'accept' }, { dst_port: '22' }), /WAN/);
  denied({ method: 'POST', path: P, body: rule('wan_in', 'accept') }, /ruleset "wan_in" is missing or unknown/);
  allowed({ method: 'POST', path: P, body: rule('WAN_IN', 'drop') });
  allowed({ method: 'POST', path: P, body: rule('WAN_LOCAL', 'reject') });
  allowed({ method: 'POST', path: P, body: rule('LAN_IN', 'accept', { rule_index: 2000, src_address: '192.168.1.0/24' }) });
  allowed({ method: 'POST', path: P, body: rule('GUESTv6_IN', 'accept', { src_address_ipv6: 'fd00:7::/64' }) });
  denied({ method: 'POST', path: P, body: rule('CUSTOM', 'accept') }, /ruleset/);
  denied({ method: 'POST', path: P, body: { name: 'r', action: 'accept' } }, /ruleset/);
  denied({ method: 'POST', path: P, body: rule('LAN_IN', '') }, /action/);
  // rule_index is never set on WAN* rulesets
  denied({ method: 'POST', path: P, body: rule('WAN_IN', 'drop', { rule_index: 2000 }) }, /rule_index must not be set on WAN/);
  denied({ method: 'POST', path: P, body: rule('WANv6_LOCAL', 'reject', { rule_index: 4000 }) }, /rule_index must not be set on WAN/);
  denied({ method: 'POST', path: P, body: rule('LAN_IN', 'accept', { _id: HEX }) }, /read-only/);
});

test('existing WAN* drop/reject legacy rules: only name/logging may change (fix 1)', () => {
  allowed(legacyPut(WAN_RULE, { name: 'renamed' }));
  allowed(legacyPut(WAN_RULE, { logging: true }));
  allowed(legacyPut(WAN_RULE));
  allowed(legacyPut({ ...WAN_RULE, ruleset: 'WANv6_LOCAL', action: 'reject' }, { name: 'x', logging: true }));
  const bad = {
    enabled: false,
    ruleset: 'LAN_IN',
    rule_index: 2001,
    action: 'reject',
    protocol: 'tcp',
    protocol_match_excepted: true,
    src_address: '203.0.113.7',
    src_firewallgroup_ids: [HEX],
    dst_address: '192.168.1.10',
    dst_port: '22',
    state_established: true,
    state_new: false,
    ipsec: 'match-ipsec',
    setting_preference: 'manual',
    icmp_typename: 'echo-request',
  };
  for (const [k, v] of Object.entries(bad)) denied(legacyPut(WAN_RULE, { [k]: v }), new RegExp(`WAN_IN drop rule; only name, logging may change, not: ${k}`));
  denied({ ...legacyPut(WAN_RULE), body: strip(legacyPut(WAN_RULE).body, ['state_new']) }, /not: state_new/);
  denied(legacyPut(WAN_RULE, { logging: 'yes' }), /invalid value for "logging"/);
  // updates without (or with the wrong) existing rule are refused
  denied({ ...legacyPut(WAN_RULE, { name: 'x' }), context: undefined }, /context\.existing missing.*fail closed/);
  denied({ ...legacyPut(WAN_RULE, { name: 'x' }), context: { existing: [] } }, /context\.existing missing/);
  denied(legacyPut({ ...WAN_RULE, _id: '0'.repeat(24) }, { name: 'x' }), /not the legacy firewall rule named in the path/);
  // rule_index never changes on a WAN* ruleset, also when moving a rule into one
  const lan = { ...WAN_RULE, ruleset: 'LAN_IN', action: 'accept', src_address: '192.168.1.0/24' };
  allowed(legacyPut(lan, { rule_index: 2005, dst_port: '80' }));
  allowed(legacyPut(lan, { ruleset: 'WAN_IN', action: 'drop' }));
  denied(legacyPut(lan, { ruleset: 'WAN_IN', action: 'drop', rule_index: 2001 }), /rule_index on a WAN\* ruleset/);
  // an existing WAN accept rule (created elsewhere) can only be turned into drop/reject
  const wanAccept = { ...WAN_RULE, action: 'accept' };
  denied(legacyPut(wanAccept, { name: 'x' }), /only drop\/reject/);
  allowed(legacyPut(wanAccept, { action: 'drop' }));
  denied(legacyPut(wanAccept, { action: 'drop', rule_index: 1 }), /rule_index on a WAN\* ruleset/);
});

const RULESETS = ['WAN', 'LAN', 'GUEST'].flatMap((z) => ['', 'v6'].flatMap((v) => ['IN', 'OUT', 'LOCAL'].map((d) => `${z}${v}_${d}`)));
const LP = `${C}/rest/firewallrule`;
const lrule = (ruleset, action, extra = {}) => ({ name: 'r', enabled: true, ruleset, action, ...extra });
const LAN_RULE = { ...WAN_RULE, name: 'lan', ruleset: 'LAN_IN', action: 'accept', src_networkconf_id: HEX, src_networkconf_type: 'NETv4' };

test('legacy rules: ruleset is an exact enum of 18 rulesets', () => {
  assert.equal(RULESETS.length, 18);
  for (const rs of RULESETS) allowed({ method: 'POST', path: LP, body: lrule(rs, 'drop') });
  for (const rs of ['wan_in', 'WAN_in', 'Lan_IN', 'WANV6_IN', 'WAN6_IN', 'LAN', 'LAN_FORWARD', 'WAN_IN ', ' LAN_IN', '', 'INTERNET_IN', 'LANv4_IN', null, 1, ['LAN_IN']]) {
    denied({ method: 'POST', path: LP, body: lrule(rs, 'drop') }, /ruleset .* is missing or unknown/);
  }
  denied({ method: 'POST', path: LP, body: { name: 'r', action: 'drop' } }, /ruleset null is missing or unknown/);
  denied(legacyPut(LAN_RULE, { ruleset: 'LAN_FORWARD' }), /ruleset "LAN_FORWARD" is missing or unknown/);
});

test('legacy rules: action enum accept/drop/reject; every WAN* ruleset (incl. WAN_OUT) refuses accept', () => {
  for (const a of ['accept', 'drop', 'reject']) allowed({ method: 'POST', path: LP, body: lrule('LAN_IN', a, { src_address: '192.168.1.0/24' }) });
  for (const a of ['ACCEPT', 'Drop', 'allow', 'deny', 'return', '', 'accept ', null, true]) {
    denied({ method: 'POST', path: LP, body: lrule('LAN_IN', a) }, /action .* is missing or unknown/);
  }
  denied({ method: 'POST', path: LP, body: { name: 'r', ruleset: 'LAN_IN' } }, /action null is missing/);
  for (const rs of RULESETS.filter((r) => r.startsWith('WAN'))) {
    denied({ method: 'POST', path: LP, body: lrule(rs, 'accept') }, new RegExp(`on ${rs} with action "accept" would allow WAN traffic`));
    allowed({ method: 'POST', path: LP, body: lrule(rs, 'reject') });
  }
  // moving a LAN rule TO a WAN ruleset with accept
  denied(legacyPut(LAN_RULE, { ruleset: 'WAN_IN' }), /WAN_IN with action "accept"/);
  denied(legacyPut(LAN_RULE, { ruleset: 'WAN_OUT' }), /WAN_OUT with action "accept"/);
  denied(legacyPut(LAN_RULE, { ruleset: 'WANv6_LOCAL' }), /WANv6_LOCAL with action "accept"/);
});

test('legacy rules: field allowlist on create and on the merged update body', () => {
  const full = {
    name: 'all fields', enabled: true, ruleset: 'LAN_IN', rule_index: 2001, action: 'drop', protocol: 'tcp_udp', protocol_match_excepted: false,
    protocol_v6: '', icmp_typename: '', icmpv6_typename: '', logging: true, state_new: true, state_established: false, state_invalid: false,
    state_related: false, ipsec: '', src_firewallgroup_ids: [HEX], src_mac_address: 'AA:bb:cc:dd:ee:ff', src_address: '192.168.10.0/24',
    src_address_ipv6: '', src_networkconf_id: HEX, src_networkconf_type: 'NETv4', src_port: '1024-65535', dst_firewallgroup_ids: [],
    dst_address: '!192.168.1.1', dst_address_ipv6: 'fd00::/8', dst_networkconf_id: '', dst_networkconf_type: 'ADDRv4', dst_port: '80,443',
    setting_preference: 'manual', contiguous: false, utc: false, weekdays: 'mon,tue', weekdays_negate: false, monthdays: '1,15',
    monthdays_negate: false, startdate: '2026-10-18', starttime: '08:00', stopdate: '2026-12-31', stoptime: '17:30',
  };
  allowed({ method: 'POST', path: LP, body: full });
  allowed(legacyPut({ ...full, _id: HEX, site_id: 'site' }, { name: 'renamed' }));
  // unknown fields: create and update
  for (const k of ['foo', 'nat', 'redirect', 'dst_networkconf_ids', 'enable', 'Ruleset', 'src_zone', 'schedule', 'dst_mac_address']) {
    denied({ method: 'POST', path: LP, body: lrule('LAN_IN', 'drop', { [k]: 'x' }) }, new RegExp(`field "${k}" is not allowed`));
    denied(legacyPut(LAN_RULE, { [k]: 'x' }), new RegExp(`field "${k}" is not allowed`));
  }
  // an existing rule carrying an unknown field cannot be updated (merged body fails closed)
  denied(legacyPut({ ...LAN_RULE, new_controller_field: 1 }, { name: 'x' }), /field "new_controller_field" is not allowed/);
  // read-only: absent on create, equal to the existing rule on update
  for (const k of ['_id', 'site_id', 'attr_no_delete', 'attr_no_edit', 'attr_hidden', 'attr_hidden_id']) {
    denied({ method: 'POST', path: LP, body: lrule('LAN_IN', 'drop', { [k]: k === '_id' ? HEX : 'x' }) }, new RegExp(`read-only field "${k}" must not be sent`));
  }
  allowed({ ...legacyPut(LAN_RULE), body: { ...legacyPut(LAN_RULE).body, _id: HEX, site_id: 'site' } });
  denied({ ...legacyPut(LAN_RULE), body: { ...legacyPut(LAN_RULE).body, site_id: 'other-site' } }, /read-only field "site_id" must equal/);
  denied({ ...legacyPut(LAN_RULE), body: { ...legacyPut(LAN_RULE).body, _id: '1'.repeat(24) } }, /read-only field "_id" must equal/);
  const sys = { ...LAN_RULE, attr_no_delete: true, attr_hidden_id: 'x' };
  allowed(legacyPut(sys, { name: 'kept attrs' }));
  denied(legacyPut(sys, { attr_no_delete: false }), /read-only field "attr_no_delete" must equal/);
  denied(legacyPut({ ...LAN_RULE, attr_no_edit: true }, { name: 'x' }), /attr_no_edit/);
  // value formats
  const badValues = {
    enabled: 'true', logging: 1, rule_index: -1, protocol: 'tcp udp', ipsec: 'x', src_firewallgroup_ids: ['x'], dst_firewallgroup_ids: HEX,
    src_mac_address: 'zz:zz:zz:zz:zz:zz', src_address: 'evil.example', dst_port: 'abc', src_port: '22;', setting_preference: 'x',
    src_networkconf_type: 'WAN', dst_networkconf_type: 'NETv4 ', src_networkconf_id: 'abc', dst_networkconf_id: HEX.toUpperCase(),
    name: 'n'.repeat(257), weekdays: 'mon\nx', state_new: null,
  };
  for (const [k, v] of Object.entries(badValues)) {
    denied({ method: 'POST', path: LP, body: lrule('LAN_IN', 'drop', { [k]: v }) }, new RegExp(`invalid value for "${k}"`));
  }
  denied({ method: 'POST', path: LP, body: lrule('LAN_IN', 'drop', { rule_index: 1.5 }) }, /invalid value for "rule_index"/);
  denied({ method: 'POST', path: LP, body: lrule('LAN_IN', 'drop', { src_firewallgroup_ids: Array(33).fill(HEX) }) }, /src_firewallgroup_ids/);
});

test('existing WAN* drop/reject rules: every non-cosmetic field is frozen; rules never leave WAN*', () => {
  const frozen = {
    enabled: false, rule_index: 2001, ruleset: 'WAN_LOCAL', action: 'reject', protocol: 'tcp', protocol_match_excepted: true, protocol_v6: 'tcp',
    icmp_typename: 'echo-request', icmpv6_typename: 'echo-request', state_new: false, state_established: true, state_invalid: true, state_related: true,
    ipsec: 'match-none', src_firewallgroup_ids: [HEX], dst_firewallgroup_ids: [HEX], src_mac_address: MAC, src_address: '203.0.113.0/24',
    src_address_ipv6: '2001:db8::/32', src_networkconf_id: HEX, src_networkconf_type: 'ADDRv4', src_port: '53', dst_address: '192.168.1.10',
    dst_address_ipv6: 'fd00::1', dst_networkconf_id: HEX, dst_networkconf_type: 'NETv4', dst_port: '22', setting_preference: 'manual', weekdays: 'mon',
  };
  for (const [k, v] of Object.entries(frozen)) {
    denied(legacyPut(WAN_RULE, { [k]: v }), new RegExp(`WAN_IN drop rule; only name, logging may change, not: ${k}$`));
  }
  const v6 = { ...WAN_RULE, ruleset: 'WANv6_LOCAL', action: 'reject' };
  for (const k of ['enabled', 'src_address_ipv6', 'dst_port', 'ipsec']) {
    denied(legacyPut(v6, { [k]: frozen[k] }), new RegExp(`WANv6_LOCAL reject rule; only name, logging may change, not: ${k}`));
  }
  denied(legacyPut(WAN_RULE, { ruleset: 'WAN_OUT' }), /only name, logging may change, not: ruleset/);
  allowed(legacyPut(WAN_RULE, { name: 'renamed', logging: true }));
  // a WAN accept rule (created elsewhere) can become drop/reject but never leave WAN*
  const wanAccept = { ...WAN_RULE, action: 'accept' };
  denied(legacyPut(wanAccept, { ruleset: 'LAN_IN' }), /moving a rule out of WAN_IN is not allowed/);
  denied(legacyPut(wanAccept, { ruleset: 'LAN_IN', action: 'drop' }), /moving a rule out of WAN_IN/);
  denied(legacyPut(wanAccept, { ruleset: 'WAN_LOCAL', action: 'drop' }), /moving a rule out of WAN_IN/);
  allowed(legacyPut(wanAccept, { action: 'reject' }));
});

test('legacy accept rules on every non-WAN ruleset must constrain the source', () => {
  const NON_WAN = RULESETS.filter((r) => !r.startsWith('WAN'));
  assert.equal(NON_WAN.length, 12);
  for (const rs of NON_WAN) {
    denied({ method: 'POST', path: LP, body: lrule(rs, 'accept') }, new RegExp(`accept rule on ${rs} must constrain the source`));
    const netType = rs.includes('v6_') ? 'NETv6' : 'NETv4';
    denied({ method: 'POST', path: LP, body: lrule(rs, 'accept', { src_address: '', src_address_ipv6: '', src_firewallgroup_ids: [], src_mac_address: '', src_networkconf_id: '', src_networkconf_type: netType }) }, /must constrain the source/);
    // a MAC address alone is not a source constraint (0.2.1)
    denied({ method: 'POST', path: LP, body: lrule(rs, 'accept', { src_mac_address: MAC }) }, /must constrain the source/);
    allowed({ method: 'POST', path: LP, body: lrule(rs, 'drop') });
    allowed({ method: 'POST', path: LP, body: lrule(rs, 'reject') });
  }
  const v4Sources = [{ src_networkconf_id: HEX, src_networkconf_type: 'NETv4' }, { src_firewallgroup_ids: [ADDR_GROUP] }, { src_mac_address: MAC, src_address: '192.168.1.0/24' }, { src_address: '192.168.1.0/24' }];
  for (const rs of ['LAN_IN', 'LAN_OUT', 'LAN_LOCAL', 'GUEST_IN', 'GUEST_OUT', 'GUEST_LOCAL']) {
    for (const src of v4Sources) allowed({ method: 'POST', path: LP, body: lrule(rs, 'accept', { dst_port: '53', ...src }), context: LCTX });
  }
  allowed({ method: 'POST', path: LP, body: lrule('LANv6_LOCAL', 'accept', { src_address_ipv6: 'fd00::/64' }) });
  allowed({ method: 'POST', path: LP, body: lrule('GUESTv6_IN', 'accept', { src_networkconf_id: HEX, src_networkconf_type: 'NETv6' }), context: LCTX });
  // the source must be of the rule's own family: an IPv6 selector on an IPv4 rule (and vice versa) is refused (0.2.1)
  denied({ method: 'POST', path: LP, body: lrule('LAN_LOCAL', 'accept', { src_address_ipv6: 'fd00::/64' }) }, /src_address_ipv6 is an IPv6 field, but LAN_LOCAL is an IPv4 ruleset/);
  denied({ method: 'POST', path: LP, body: lrule('LANv6_IN', 'accept', { src_address: '192.168.1.0/24' }) }, /src_address is an IPv4 field, but LANv6_IN is an IPv6 ruleset/);
  // update: removing the source constraint of an accept rule is refused
  const local = { ...LAN_RULE, ruleset: 'LAN_LOCAL' };
  allowed(legacyPut(local, { dst_port: '53' }));
  denied(legacyPut(local, { src_networkconf_id: '' }), /must constrain the source/);
  denied(legacyPut({ ...LAN_RULE, src_networkconf_id: '' }, { ruleset: 'LAN_LOCAL' }), /must constrain the source/);
  denied(legacyPut({ ...LAN_RULE, src_networkconf_id: '', action: 'drop' }, { action: 'accept' }), /must constrain the source/);
});

test('guest authorization limits: spec min/max, safe integers only', () => {
  const GP = `${I}/clients/${ID}/actions`;
  const limits = { timeLimitMinutes: [1, 1000000], dataUsageLimitMBytes: [1, 1048576], rxRateLimitKbps: [2, 100000], txRateLimitKbps: [2, 100000] };
  for (const [k, [min, max]] of Object.entries(limits)) {
    allowed({ method: 'POST', path: GP, body: { action: 'AUTHORIZE_GUEST_ACCESS', [k]: min } });
    allowed({ method: 'POST', path: GP, body: { action: 'AUTHORIZE_GUEST_ACCESS', [k]: max } });
    for (const v of [min - 1, max + 1, 0, -5, 1.5, '10', null, true, 2 ** 53, Number.MAX_SAFE_INTEGER + 2]) {
      denied({ method: 'POST', path: GP, body: { action: 'AUTHORIZE_GUEST_ACCESS', [k]: v } }, new RegExp(`${k} must be an integer ${min}-${max}`));
    }
  }
  allowed({ method: 'POST', path: GP, body: { action: 'AUTHORIZE_GUEST_ACCESS', timeLimitMinutes: 60, dataUsageLimitMBytes: 1024, rxRateLimitKbps: 2000, txRateLimitKbps: 1000 } });
  denied({ method: 'POST', path: GP, body: { action: 'AUTHORIZE_GUEST_ACCESS', durationMinutes: 5 } }, /key "durationMinutes" is not allowed/);
  denied({ method: 'POST', path: GP, body: { action: 'UNAUTHORIZE_GUEST_ACCESS', timeLimitMinutes: 5 } }, /timeLimitMinutes/);
});

test('existing-object identity: own string id equal to the path id is required for every update', () => {
  const noId = (o, k) => strip(o, [k]);
  denied(netPut({ mdnsForwardingEnabled: true }, noId(NET_EX, 'id')), /context\.existing has no id/);
  denied(wifiPut(noId(WIFI_EX, 'id'), { hideName: true }), /context\.existing has no id/);
  denied(policyPut(noId(WAN_BLOCK, 'id'), { loggingEnabled: true }), /context\.existing has no id/);
  denied({ method: 'PATCH', path: `${I}/firewall/policies/${ID}`, body: { loggingEnabled: true }, context: { existing: noId(WAN_BLOCK, 'id') } }, /context\.existing has no id/);
  denied({ method: 'PATCH', path: `${I}/firewall/policies/${ID}`, body: { loggingEnabled: true }, context: { existing: { ...WAN_BLOCK, id: NET } } }, /not the firewall policy named in the path/);
  denied(legacyPut(noId(LAN_RULE, '_id'), { name: 'x' }), /context\.existing has no _id/);
  denied(devPut([{ radio: 'ng', channel: 1 }], noId(DEVICE, '_id')), /context\.existing has no _id/);
  // non-string / empty / inherited ids
  for (const bad of [123, '', null, [ID], { id: ID }]) {
    denied(netPut({ mdnsForwardingEnabled: true }, { ...NET_EX, id: bad }), /context\.existing has no id/);
  }
  denied(netPut({ mdnsForwardingEnabled: true }, Object.assign(Object.create({ id: ID }), noId(NET_EX, 'id'))), /has no id/);
  denied(legacyPut({ ...LAN_RULE, _id: 7 }, { name: 'x' }), /has no _id/);
  // a classic `id` does not stand in for `_id`, and vice versa
  denied({ ...legacyPut(LAN_RULE, { name: 'x' }), context: { existing: { ...noId(LAN_RULE, '_id'), id: HEX } } }, /has no _id/);
  denied(netPut({ mdnsForwardingEnabled: true }, { ...noId(NET_EX, 'id'), _id: ID }), /has no id/);
  // integration UUIDs compare case-insensitively, classic hex ids exactly
  allowed(netPut({ mdnsForwardingEnabled: true }, { ...NET_EX, id: ID.toUpperCase() }));
  denied(legacyPut({ ...LAN_RULE, _id: HEX.toUpperCase() }, { name: 'x' }), /not the legacy firewall rule named in the path/);
});

test('WiFi broadcasts: WPA2/WPA3 only, fixed network binding, no portals (fix 2)', () => {
  // create: every WPA2/WPA3 type
  for (const type of ['WPA2_PERSONAL', 'WPA2_WPA3_PERSONAL', 'WPA3_PERSONAL', 'WPA2_ENTERPRISE', 'WPA2_WPA3_ENTERPRISE', 'WPA3_ENTERPRISE']) {
    allowed(wifiCreate({ securityConfiguration: { type } }));
  }
  allowed(wifiCreate({ type: 'IOT_OPTIMIZED', clientIsolationEnabled: false }));
  // create: open / OWE / WEP / unknown / missing security refused
  for (const sc of [{ type: 'OPEN' }, { type: 'OPEN', encryption: 'ENHANCED_OPEN' }, { type: 'OPEN', encryption: 'ENHANCED_OPEN_WITH_TRANSITION' }, { type: 'WEP' }, { type: 'wpa2_personal' }, { type: 'WPA_PERSONAL' }, {}, null, 'WPA2_PERSONAL']) {
    denied(wifiCreate({ securityConfiguration: sc }), /securityConfiguration\.type must be one of/);
  }
  denied({ ...wifiCreate(), body: strip(wifiCreate().body, ['securityConfiguration']) }, /securityConfiguration\.type/);
  // create: network must be SPECIFIC + UUID
  denied(wifiCreate({ network: { type: 'NATIVE' } }), /network must be \{type: "SPECIFIC"/);
  denied(wifiCreate({ network: { type: 'SPECIFIC' } }), /network must be/);
  denied(wifiCreate({ network: { type: 'SPECIFIC', networkId: 'default' } }), /network must be/);
  denied(wifiCreate({ network: { type: 'SPECIFIC', networkId: NET, vlan: 1 } }), /key "vlan" is not allowed/);
  denied({ ...wifiCreate(), body: strip(wifiCreate().body, ['network']) }, /network must be/);
  // create: no hotspot / captive portal
  denied(wifiCreate({ hotspotConfiguration: { type: 'CAPTIVE_PORTAL' } }), /"hotspotConfiguration" is not allowed/);
  denied(wifiCreate({ hotspotConfiguration: null }), /"hotspotConfiguration" is not allowed/);
  denied(wifiCreate({ guestPortalEnabled: true }), /"guestPortalEnabled" is not allowed/);
  // type
  denied(wifiCreate({ type: 'GUEST' }), /type must be STANDARD or IOT_OPTIMIZED/);
  denied({ ...wifiCreate(), body: strip(wifiCreate().body, ['type']) }, /type must be/);

  // update
  allowed(wifiPut(WIFI_EX, { hideName: true }));
  allowed(wifiPut(WIFI_EX, { securityConfiguration: { type: 'WPA3_PERSONAL', passphrase: 'new-passphrase' } }));
  const hs = { ...WIFI_EX, hotspotConfiguration: { type: 'CAPTIVE_PORTAL' } };
  allowed(wifiPut(hs, { hideName: true }));
  denied(wifiPut(WIFI_EX, { securityConfiguration: { type: 'OPEN' } }), /securityConfiguration\.type/);
  denied(wifiPut({ ...WIFI_EX, securityConfiguration: { type: 'OPEN' } }, { hideName: true }), /securityConfiguration\.type/);
  denied(wifiPut(WIFI_EX, { network: { type: 'SPECIFIC', networkId: ZONE_INTERNAL } }), /network binding must not change/);
  denied(wifiPut(WIFI_EX, { network: { type: 'NATIVE' } }), /network binding must not change/);
  denied({ ...wifiPut(WIFI_EX), body: strip(wifiPut(WIFI_EX).body, ['network']) }, /network binding must not change/);
  denied(wifiPut(WIFI_EX, { clientIsolationEnabled: true }), /clientIsolationEnabled must not change/);
  denied(wifiPut({ ...WIFI_EX, clientIsolationEnabled: true }, { clientIsolationEnabled: false }), /clientIsolationEnabled must not change/);
  denied(wifiPut(WIFI_EX, { hotspotConfiguration: { type: 'CAPTIVE_PORTAL' } }), /"hotspotConfiguration" \(hotspot\/captive portal\) must not change/);
  denied(wifiPut(hs, { hotspotConfiguration: { type: 'PASSPOINT' } }), /hotspotConfiguration/);
  denied({ ...wifiPut(hs), body: strip(wifiPut(hs).body, ['hotspotConfiguration']) }, /hotspotConfiguration/);
  denied(wifiPut(WIFI_EX, { type: 'IOT_OPTIMIZED' }), /type must not change/);
  denied({ ...wifiPut(WIFI_EX, { hideName: true }), context: undefined }, /context\.existing missing.*fail closed/);
  denied(wifiPut({ ...WIFI_EX, id: NET }, { hideName: true }), /not the WiFi broadcast named in the path/);
});

test('AP radios: per-entry key allowlist, ranges, radios of this device (fix 6)', () => {
  allowed(devPut([{ radio: 'ng', name: 'wifi0', channel: 11, ht: '20', tx_power_mode: 'custom', tx_power: '12', min_rssi_enabled: true, min_rssi: -80 }]));
  allowed(devPut([{ radio: 'ng', channel: '1', ht: 40, tx_power: 30, min_rssi: '-95' }, { radio: 'na', channel: 'auto', ht: '160', tx_power_mode: 'high', min_rssi: -40 }]));
  // keys outside the allowlist
  for (const k of ['wlangroup_id', 'antenna_gain', 'sens_level', 'sens_level_enabled', 'vwire_enabled', 'hard_noise_floor_enabled', 'dfs', 'mode']) {
    denied(devPut([{ radio: 'ng', [k]: 1 }]), new RegExp(`radio_table entry: key "${k}" is not allowed`));
  }
  // unknown radio / radio not on this device
  for (const radio of ['ad', 'wifi6e', 'NG', '', 5, undefined]) denied(devPut([{ radio, channel: 1 }]), /radio must be one of ng, na, 6e/);
  denied(devPut([{ radio: '6e', channel: 37 }]), /device has no 6e radio/);
  denied(devPut([{ radio: 'ng', channel: 1 }, { radio: 'ng', channel: 6 }]), /twice/);
  denied(devPut([{ radio: 'ng', name: 'wifi1' }]), /name must equal/);
  // ranges
  for (const channel of [0, 234, -1, 6.5, 'abc', '', true]) denied(devPut([{ radio: 'ng', channel }]), /channel must be/);
  for (const ht of [10, 30, '45', 'HT20', 0, null]) denied(devPut([{ radio: 'na', ht }]), /ht must be one of/);
  for (const tx_power_mode of ['turbo', 'AUTO', '', 1]) denied(devPut([{ radio: 'na', tx_power_mode }]), /tx_power_mode must be one of/);
  for (const tx_power of [0, 31, 'auto', '1.5', -3, 12.5]) denied(devPut([{ radio: 'na', tx_power }]), /tx_power must be an integer 1-30/);
  for (const min_rssi of [-96, -39, -100, 0, '-120', 'low']) denied(devPut([{ radio: 'na', min_rssi }]), /min_rssi must be an integer -95..-40/);
  denied(devPut([{ radio: 'na', min_rssi_enabled: 'yes' }]), /min_rssi_enabled must be a boolean/);
  // the existing device is required and must be this AP
  denied({ ...devPut([{ radio: 'ng', channel: 1 }]), context: undefined }, /context\.existing missing.*fail closed/);
  denied(devPut([{ radio: 'ng', channel: 1 }], { ...DEVICE, type: 'usw' }), /not an access point/);
  denied(devPut([{ radio: 'ng', channel: 1 }], { ...DEVICE, _id: '0'.repeat(24) }), /not the device named in the path/);
  denied(devPut([{ radio: 'ng', channel: 1 }], { _id: HEX, type: 'uap' }), /no radio_table/);
});

test('denied: smuggled proxy / connector prefixes and other apps in the canonical path', () => {
  const smuggled = [
    '/proxy/network/integration/v1/info',
    `/proxy/network${I}/clients`,
    '/proxy/network/api/s/default/rest/user',
    '/proxy/protect/api/cameras',
    '/proxy/access/api/v1/doors',
    '/proxy/users/api/v2/users',
    `/v1/connector/consoles/${CONSOLE}/proxy/network/integration/v1/info`,
    '/v1/connector/consoles/x/proxy/protect/api/cameras',
    '/connector/consoles/x',
    `/integration/v1/proxy/protect/api/cameras`,
    `${I}/proxy/protect`,
    `/integration/v1/connector/x`,
    `/api/s/default/proxy/access/api`,
    `/api/s/default/consoles/x`,
    `${I}/clients/PROXY/x`,
  ];
  for (const p of smuggled) {
    denied({ method: 'GET', path: p }, /proxy\/connector prefix|must start with/);
    denied({ method: 'POST', path: p, body: { action: 'UNAUTHORIZE_GUEST_ACCESS' } }, /proxy\/connector prefix|must start with/);
  }
  // traversal out of the canonical root is refused before anything else
  denied({ method: 'GET', path: '/integration/v1/../../v1/connector/consoles/x/proxy/protect/api/cameras' }, /traversal/);
  denied({ method: 'GET', path: '/integration/v1/%2e%2e/%2e%2e/v1/connector/consoles/x/proxy/protect/api' }, /encoded/);
  denied({ method: 'GET', path: '/api/s/default/..%2f..%2fproxy/protect' }, /traversal|encoded/);
  denied({ method: 'GET', path: '/integration/v1/info?x=/../proxy/protect' }, /not allowed/);
  denied({ method: 'GET', path: '/v1/sites' }, /must start with/);
  denied({ method: 'GET', path: '/network/integration/v1/info' }, /must start with/);
});

test('checkFinalPath: only prefix + canonical with one of the two constant prefixes', () => {
  const canonical = '/integration/v1/info';
  const cloud = cloudPrefix(CONSOLE);
  assert.equal(cloud, `/v1/connector/consoles/${CONSOLE}/proxy/network`); // ":" kept literal, nothing else to encode
  assert.ok(checkFinalPath({ prefix: '/proxy/network', canonical, full: `/proxy/network${canonical}` }).ok);
  assert.ok(checkFinalPath({ prefix: cloud, canonical, full: cloud + canonical }).ok);
  assert.ok(checkFinalPath({ prefix: cloud, canonical: `${I}/clients?limit=5`, full: `${cloud}${I}/clients?limit=5` }).ok);
  const bad = (o, re) => assert.throws(() => checkFinalPath(o), (e) => e instanceof GuardError && re.test(e.message));
  bad({ prefix: '/proxy/protect', canonical, full: `/proxy/protect${canonical}` }, /unknown backend prefix/);
  bad({ prefix: '', canonical, full: canonical }, /unknown backend prefix/);
  bad({ prefix: '/v1/connector/consoles/a/b/proxy/network', canonical, full: `/v1/connector/consoles/a/b/proxy/network${canonical}` }, /unknown backend prefix/);
  bad({ prefix: `/v1/connector/consoles/${CONSOLE}%3A1/proxy/network`, canonical, full: `x` }, /unknown backend prefix/);
  bad({ prefix: '/proxy/network', canonical, full: `/proxy/network/x${canonical}` }, /prefix \+ canonical/);
  bad({ prefix: '/proxy/network', canonical: '/../proxy/protect', full: '/proxy/network/../proxy/protect' }, /traversal/);
  bad({ prefix: '/proxy/network', canonical: '/proxy/protect/api', full: '/proxy/network/proxy/protect/api' }, /canonical|second/);
  for (const id of ['abc/def12345', '../../../x', 'abcdefgh?x=1', 'abcdefgh#x', 'abcdefgh%2f', 'short', 'abcdefgh:', 'abcdefgh:12:34', 'abcdefgh.x']) {
    assert.throws(() => cloudPrefix(id), GuardError, id);
  }
});

test('zone classification comes from client config only; caller context cannot widen it', async () => {
  const okTransport = async () => ({ status: 200, headers: {}, text: '{}' });
  const mk = (backend, extra = {}) =>
    backend === 'local'
      ? createUdmClient({ backend, target: { host: 'udm.test', port: 443, isIp: false, hostHeader: 'udm.test' }, apiKey: 'k'.repeat(32), siteId: SITE, allowWrites: true, transport: okTransport, ...extra })
      : createUdmClient({ backend, consoleId: CONSOLE, apiKey: 'k'.repeat(32), siteId: SITE, allowWrites: true, transport: okTransport, ...extra });
  const req = { method: 'POST', path: `${I}/firewall/policies`, body: policy('ALLOW', ZONE_INTERNAL, ZONE_IOT), dryRun: true };
  for (const backend of ['local', 'cloud']) {
    // unconfigured client: a caller claiming internal zones is ignored
    await assert.rejects(mk(backend).request({ ...req, context: { zones, internalZoneIds: [ZONE_INTERNAL, ZONE_IOT] } }), /require firewall_internal_zone_ids/);
    // configured client: allowed; a caller trying to narrow/replace it is ignored as well
    const c = mk(backend, { firewallInternalZoneIds: [ZONE_INTERNAL, ZONE_IOT], firewallWanZoneIds: [ZONE_EXTERNAL] });
    assert.equal((await c.request({ ...req, context: { zones, internalZoneIds: [ZONE_EXTERNAL], wanZoneIds: [ZONE_INTERNAL] } })).dry_run, true);
    await assert.rejects(c.request({ ...req, body: policy('ALLOW', ZONE_EXTERNAL, ZONE_IOT), context: { zones, internalZoneIds: [ZONE_EXTERNAL], wanZoneIds: [] } }), /WAN-in/);
  }
});

test('parity: every case above gets the identical decision through the local and the cloud client', async () => {
  assert.ok(CASES.length > 150, `matrix has ${CASES.length} cases`);
  const okTransport = async () => ({ status: 200, headers: {}, text: '{"data":[]}' });
  // The zone classification is client configuration (config.json), never caller context:
  // build the clients with the case's zone ids.
  const clientsFor = (ctx) => {
    const zcfg = ctx && typeof ctx === 'object' ? { firewallInternalZoneIds: ctx.internalZoneIds, firewallWanZoneIds: ctx.wanZoneIds } : {};
    const common = { apiKey: 'k'.repeat(32), siteId: SITE, allowWrites: true, transport: okTransport, ...zcfg };
    return {
      local: createUdmClient({ backend: 'local', target: { host: 'udm.test', port: 443, isIp: false, hostHeader: 'udm.test' }, ...common }),
      cloudAll: createUdmClient({ backend: 'cloud', consoleId: CONSOLE, allowClassic: true, ...common }),
      cloud: createUdmClient({ backend: 'cloud', consoleId: CONSOLE, ...common }),
      cloudRadio: createUdmClient({ backend: 'cloud', consoleId: CONSOLE, allowClassic: ['radio'], ...common }),
      cloudFwFixed: createUdmClient({ backend: 'cloud', consoleId: CONSOLE, allowClassic: ['firewallrule', 'fixed_ip'], ...common }),
    };
  };
  const decide = async (client, req) => {
    try {
      await client.request({ ...req, dryRun: true });
      return null;
    } catch (e) {
      assert.ok(e instanceof GuardError, `${req.method} ${req.path}: ${e}`);
      return e.message;
    }
  };
  for (const { req, refused } of CASES) {
    const where = `${req.method} ${req.path}`;
    const { local, cloudAll, cloud, cloudRadio, cloudFwFixed } = clientsFor(req.context);
    assert.equal(await decide(local, req), refused, `local: ${where}`);
    assert.equal(await decide(cloudAll, req), refused, `cloud (classic allowed): ${where}`);
    // Default cloud client: same decision, except that guard-allowed classic paths are refused by the client's second check.
    const got = await decide(cloud, req);
    if (refused === null && req.path.startsWith('/api/s/')) assert.match(got, /classic \/api\/s\/ endpoints are disabled/, where);
    else assert.equal(got, refused, `cloud: ${where}`);
    // Partial capabilities: identical to the guard for enabled capabilities, client refusal otherwise.
    for (const [client, caps] of [[cloudRadio, ['radio']], [cloudFwFixed, ['firewallrule', 'fixed_ip']]]) {
      const d = await decide(client, req);
      const cap = classicCapabilityOf(req.path);
      if (refused === null && req.path.startsWith('/api/s/') && !caps.includes(cap)) assert.match(d, new RegExp(`capability "${cap}" is not enabled`), where);
      else assert.equal(d, refused, `cloud ${caps}: ${where}`);
    }
  }
});
