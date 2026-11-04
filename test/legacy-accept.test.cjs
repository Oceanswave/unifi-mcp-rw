'use strict';

// Legacy (classic rest/firewallrule) accept rules: the Sonos rule pair from
// the README, and the refusals around it.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { InMemoryTransport } = require('@modelcontextprotocol/sdk/inMemory.js');
const { checkRequest, GuardError } = require('../lib/guard.cjs');
const { buildMcpServer } = require('../http-server-rw.cjs');
const { createUdmClient } = require('../lib/udm-client.cjs');
const { createAuditLog } = require('../lib/audit-log.cjs');
const { tmpDir } = require('./helpers.cjs');

const C = '/api/s/default';
const LP = `${C}/rest/firewallrule`;
const CONSOLE = '942A6FF664C0000000000964970E0000000009E710560000000068A9873F:9999999999';
const SITE = '88f7af54-98f8-306a-a1c7-c9349722b1f6';
const API_KEY = 'cloud-site-manager-key-0123456789abcdef';
const PREFIX = `/v1/connector/consoles/${CONSOLE}/proxy/network`;

// Classic networkconf ids (placeholders) and the networks as rest/networkconf returns them.
const OWNER = '64f0a1b2c3d4e5f601234042';
const OCEAN_BREEZE = '64f0a1b2c3d4e5f601234007';
const WAN1 = '64f0a1b2c3d4e5f60123ffff';
const VPN_CLIENT = '64f0a1b2c3d4e5f60123fffe';
const PUBLIC_LAN = '64f0a1b2c3d4e5f60123fffd';
const ULA_LAN = '64f0a1b2c3d4e5f601230601';
const GUA_LAN = '64f0a1b2c3d4e5f601230602';
const PD_LAN = '64f0a1b2c3d4e5f601230603';
const NO_V6_LAN = '64f0a1b2c3d4e5f601230604';
const VLAN_ONLY = '64f0a1b2c3d4e5f601230605';
const ODD_V6_LAN = '64f0a1b2c3d4e5f601230606';
const NETWORKS = [
  { _id: OWNER, name: 'Owner', purpose: 'corporate', vlan_enabled: true, vlan: 42, ip_subnet: '192.168.50.1/24' },
  { _id: OCEAN_BREEZE, name: 'Guest', purpose: 'corporate', vlan_enabled: true, vlan: 7, network_isolation_enabled: true, ip_subnet: '192.168.7.1/24' },
  { _id: WAN1, name: 'Internet 1', purpose: 'wan', wan_type: 'dhcp' },
  { _id: VPN_CLIENT, name: 'Provider VPN', purpose: 'vpn-client' },
  { _id: PUBLIC_LAN, name: 'Routed block', purpose: 'corporate', ip_subnet: '203.0.113.1/28' },
  { _id: ULA_LAN, name: 'Lab ULA', purpose: 'corporate', ip_subnet: '192.168.60.1/24', ipv6_interface_type: 'static', ipv6_subnet: 'fd12:3456:789a:60::1/64' },
  { _id: GUA_LAN, name: 'Lab GUA', purpose: 'corporate', ip_subnet: '192.168.61.1/24', ipv6_interface_type: 'static', ipv6_subnet: '2001:db8:61::1/64' },
  { _id: PD_LAN, name: 'Lab PD', purpose: 'corporate', ip_subnet: '192.168.62.1/24', ipv6_interface_type: 'pd', ipv6_pd_interface: 'wan', ipv6_pd_prefixid: '2' },
  { _id: NO_V6_LAN, name: 'Lab v4 only', purpose: 'corporate', ip_subnet: '192.168.63.1/24', ipv6_interface_type: 'none' },
  { _id: VLAN_ONLY, name: 'Cameras L2', purpose: 'vlan-only', vlan_enabled: true, vlan: 30 },
  { _id: ODD_V6_LAN, name: 'Lab odd', purpose: 'corporate', ip_subnet: 'garbage', ipv6_interface_type: 'static', ipv6_subnet: 'fd00::1/64', ipv6_static_subnet: '2001:db8::1/64' },
];
const SONOS_IPS = '192.168.7.20,192.168.7.21';
const SONOS_GROUP = '64f0a1b2c3d4e5f60123a001';
const SONOS_PORTS = '64f0a1b2c3d4e5f60123a002';
const LEAKY_GROUP = '64f0a1b2c3d4e5f60123a003';
const BAD_PORTS = '64f0a1b2c3d4e5f60123a004';
const EMPTY_GROUP = '64f0a1b2c3d4e5f60123a005';
const UNKNOWN_ID = '64f0a1b2c3d4e5f60123dead';
const ULA_GROUP = '64f0a1b2c3d4e5f60123a006';
const GROUPS = [
  { _id: SONOS_GROUP, name: 'Sonos speakers', group_type: 'address-group', group_members: ['192.168.7.20', '192.168.7.21'] },
  { _id: SONOS_PORTS, name: 'Sonos ports', group_type: 'port-group', group_members: ['1400', '3400-3401'] },
  { _id: LEAKY_GROUP, name: 'Sonos and a public DNS', group_type: 'address-group', group_members: ['192.168.7.20', '8.8.8.8'] },
  { _id: BAD_PORTS, name: 'bad ports', group_type: 'port-group', group_members: ['70000'] },
  { _id: EMPTY_GROUP, name: 'empty', group_type: 'address-group', group_members: [] },
  { _id: ULA_GROUP, name: 'Lab ULA hosts', group_type: 'ipv6-address-group', group_members: ['fd12:3456:789a:60::10', 'fd12:3456:789a:60::/64'] },
];
const CTX = { networks: NETWORKS, firewallGroups: GROUPS };

const base = { enabled: true, ruleset: 'LAN_IN', action: 'accept', protocol: 'all', logging: false };
// Owner -> Sonos (new connections from the Owner network to the speakers).
const TO_SONOS_BY_NET = { ...base, name: 'Owner to Sonos', src_networkconf_id: OWNER, src_networkconf_type: 'NETv4', dst_address: SONOS_IPS };
const TO_SONOS_BY_CIDR = { ...base, name: 'Owner to Sonos', src_address: '192.168.50.0/24', dst_firewallgroup_ids: [SONOS_GROUP] };
// Sonos -> Owner, replies only.
const states = { state_established: true, state_related: true, state_new: false, state_invalid: false };
const RETURN_BY_IPS = { ...base, name: 'Sonos replies to Owner', ...states, src_address: SONOS_IPS, dst_networkconf_id: OWNER, dst_networkconf_type: 'NETv4' };
const RETURN_BY_GROUP = { ...base, name: 'Sonos replies to Owner', ...states, src_firewallgroup_ids: [SONOS_GROUP], dst_address: '192.168.50.0/24' };

const post = (body, context = CTX) => ({ method: 'POST', path: LP, body, context });
const ok = (req) => assert.equal(checkRequest(req).ok, true);
const no = (req, re) =>
  assert.throws(
    () => checkRequest(req),
    (e) => e instanceof GuardError && re.test(e.message)
  );

test('Sonos pair: both variants of both rules are allowed', () => {
  for (const r of [TO_SONOS_BY_NET, TO_SONOS_BY_CIDR, RETURN_BY_IPS, RETURN_BY_GROUP]) ok(post(r));
  // with a port group as destination port constraint, and on update
  ok(post({ ...TO_SONOS_BY_CIDR, dst_firewallgroup_ids: [SONOS_GROUP, SONOS_PORTS] }));
  ok(post({ ...TO_SONOS_BY_NET, protocol: 'tcp', dst_port: '1400,3400-3401' }));
  const existing = { ...RETURN_BY_IPS, _id: SONOS_GROUP, site_id: 's', rule_index: 2001 };
  const { _id, site_id, ...body } = existing;
  ok({ method: 'PUT', path: `${LP}/${SONOS_GROUP}`, body: { ...body, logging: true }, context: { ...CTX, existing } });
});

test('accept: source must be constrained on LAN_IN, LAN_OUT, GUEST_IN (and every other non-WAN ruleset)', () => {
  for (const ruleset of ['LAN_IN', 'LAN_OUT', 'GUEST_IN', 'GUEST_OUT', 'LAN_LOCAL', 'GUEST_LOCAL']) {
    no(post({ ...base, ruleset, dst_address: SONOS_IPS }), new RegExp(`accept rule on ${ruleset} must constrain the source`));
  }
  // a port group alone does not narrow the source
  no(post({ ...base, src_firewallgroup_ids: [SONOS_PORTS], dst_address: SONOS_IPS }), /must constrain the source/);
  // destination "any" is allowed on *_IN and *_OUT once the source is named
  ok(post({ ...base, src_networkconf_id: OWNER, src_networkconf_type: 'NETv4' }));
  ok(post({ ...base, ruleset: 'LAN_OUT', src_address: '192.168.50.0/24' }));
});

test('accept: public, unbounded, negated and malformed addresses are refused', () => {
  no(post({ ...TO_SONOS_BY_CIDR, src_address: '8.8.8.0/24' }), /src_address: "8\.8\.8\.0\/24" is not entirely inside private address space/);
  no(post({ ...TO_SONOS_BY_NET, dst_address: '1.1.1.1' }), /dst_address: "1\.1\.1\.1" is not entirely inside private/);
  no(post({ ...TO_SONOS_BY_NET, dst_address: '192.168.7.20,1.1.1.1' }), /"1\.1\.1\.1"/);
  for (const k of ['src_address', 'dst_address']) {
    no(post({ ...TO_SONOS_BY_CIDR, [k]: '0.0.0.0/0' }), /0\.0\.0\.0\/0" is not entirely inside private/);
  }
  no(post({ ...base, ruleset: 'LANv6_IN', src_address_ipv6: '::/0' }), /"::\/0" is not entirely inside private/);
  no(post({ ...base, ruleset: 'LANv6_IN', src_address_ipv6: '2001:db8::1' }), /not entirely inside private/);
  no(post({ ...TO_SONOS_BY_CIDR, src_address: '!192.168.50.0/24' }), /negated address/);
  no(post({ ...TO_SONOS_BY_NET, dst_address: '!192.168.7.20' }), /negated address/);
  no(post({ ...TO_SONOS_BY_NET, dst_port: '!1400' }), /negated port/);
  no(post({ ...TO_SONOS_BY_NET, protocol: 'tcp', protocol_match_excepted: true }), /protocol_match_excepted/);
  // outside the private blocks by a little; a range crossing a block boundary
  for (const a of ['172.32.0.1', '172.15.255.255', '100.128.0.0/16', '192.169.0.1', '11.0.0.0/8', '192.168.255.250-192.169.0.5', '10.0.0.0/7']) {
    no(post({ ...TO_SONOS_BY_CIDR, src_address: a }), /not entirely inside private/);
  }
  for (const a of ['192.168.1.0/33', '192.168.1', '300.1.1.1', '192.168.1.5-192.168.1.1', '192.168.1.1,', 'fd00::1', '010.0.0.1']) {
    no(post({ ...TO_SONOS_BY_CIDR, src_address: a }), /is not a valid IPv4 address, CIDR or range/);
  }
  no(post({ ...base, ruleset: 'LANv6_IN', src_address_ipv6: '192.168.1.1' }), /not a valid IPv6/);
  no(post({ ...base, ruleset: 'LANv6_IN', src_address_ipv6: 'fd00::1::2' }), /not a valid IPv6/);
  // every private block is usable, including 100.64/10 (tailnet) and link-local
  for (const a of ['10.1.2.3', '172.16.0.0/12', '172.31.255.255', '192.168.0.0/16', '100.64.0.0/10', '100.101.102.103', '169.254.1.1', '192.168.7.20-192.168.7.29']) {
    ok(post({ ...TO_SONOS_BY_CIDR, src_address: a }));
  }
  for (const a of ['fd12:3456::/48', 'fc00::/7', 'fe80::1', 'fe80::/10', 'fd00::1-fd00::ff']) {
    ok(post({ ...base, ruleset: 'GUESTv6_IN', src_address_ipv6: a }));
  }
  // drop/reject rules may still name public or negated addresses (blocking them is fine)
  ok(post({ ...base, action: 'drop', src_address: '8.8.8.0/24' }));
  ok(post({ ...base, action: 'reject', dst_address: '!192.168.1.1' }));
});

test('accept: firewall groups are resolved; unknown or leaky groups are refused', () => {
  no(post({ ...TO_SONOS_BY_NET, dst_address: '', dst_firewallgroup_ids: [LEAKY_GROUP] }), /dst_firewallgroup_ids: firewall group "Sonos and a public DNS": "8\.8\.8\.8" is not entirely inside private/);
  no(post({ ...RETURN_BY_GROUP, src_firewallgroup_ids: [LEAKY_GROUP] }), /src_firewallgroup_ids: .*"8\.8\.8\.8"/);
  no(post({ ...RETURN_BY_GROUP, src_firewallgroup_ids: [UNKNOWN_ID] }), new RegExp(`firewall group ${UNKNOWN_ID} does not exist`));
  no(post({ ...TO_SONOS_BY_CIDR, dst_firewallgroup_ids: [SONOS_GROUP, BAD_PORTS] }), /"70000" is not a valid port/);
  no(post({ ...RETURN_BY_GROUP, src_firewallgroup_ids: [EMPTY_GROUP] }), /has no usable group_members/);
  no(post(RETURN_BY_GROUP, { networks: NETWORKS }), /firewall groups .* could not be determined; accept rules fail closed/);
  no(post(RETURN_BY_GROUP, { networks: NETWORKS, lookupErrors: { firewallGroups: 'UDM: forbidden (403)' } }), /fail closed \(lookup failed: UDM: forbidden \(403\)\)/);
  no(post(RETURN_BY_GROUP, { networks: NETWORKS, firewallGroups: [{ ...GROUPS[0], group_type: 'mac-group' }] }), /unknown group_type "mac-group"/);
});

test('accept: networkconf ids must resolve to internal networks', () => {
  no(post({ ...TO_SONOS_BY_NET, src_networkconf_id: WAN1 }), /src_networkconf_id refers to WAN network "Internet 1"/);
  no(post({ ...RETURN_BY_IPS, dst_networkconf_id: WAN1 }), /dst_networkconf_id refers to WAN network/);
  no(post({ ...TO_SONOS_BY_NET, src_networkconf_id: UNKNOWN_ID }), new RegExp(`src_networkconf_id ${UNKNOWN_ID} is not a known network`));
  no(post({ ...TO_SONOS_BY_NET, src_networkconf_id: VPN_CLIENT }), /purpose "vpn-client"; only corporate/);
  no(post({ ...TO_SONOS_BY_NET, src_networkconf_id: PUBLIC_LAN }), /network "Routed block" subnet: "203\.0\.113\.1\/28" is not entirely inside private/);
  no(post({ ...TO_SONOS_BY_NET, src_networkconf_type: '' }), /src_networkconf_id is set without src_networkconf_type/);
  no(post(TO_SONOS_BY_NET, { firewallGroups: GROUPS }), /networks .* could not be determined; accept rules fail closed/);
  no(post(TO_SONOS_BY_NET, {}), /could not be determined/);
});

test('accept: a referenced network must have a private subnet in the family the networkconf type selects', () => {
  const v6 = { ...base, ruleset: 'LANv6_IN' };
  for (const side of ['src', 'dst']) {
    const other = side === 'src' ? { dst_address_ipv6: 'fd12:3456:789a:60::10' } : { src_address_ipv6: 'fd12:3456:789a:60::10' };
    const ref = (id, type = 'NETv6') => ({ ...v6, ...other, [`${side}_networkconf_id`]: id, [`${side}_networkconf_type`]: type });
    // static ULA prefix: allowed, as subnet and as gateway address
    ok(post(ref(ULA_LAN)));
    ok(post(ref(ULA_LAN, 'ADDRv6')));
    // static GUA prefix: refused
    no(post(ref(GUA_LAN)), new RegExp(`${side}_networkconf_id network "Lab GUA" ipv6_subnet: "2001:db8:61::1/64" is not entirely inside private`));
    no(post(ref(GUA_LAN, 'ADDRv6')), /"Lab GUA" ipv6_subnet: .* not entirely inside private/);
    // prefix delegation: the prefix is not in the record
    no(post(ref(PD_LAN)), new RegExp(`${side}_networkconf_id network "Lab PD" gets its IPv6 prefix by prefix delegation from "wan".*Use ULA addresses in ${side}_address_ipv6 or an ipv6-address-group`));
    // no IPv6 at all, unknown interface type, missing or unparseable subnet
    no(post(ref(NO_V6_LAN)), /"Lab v4 only" has ipv6_interface_type "none"/);
    no(post(ref(OWNER)), /"Owner" has ipv6_interface_type null/);
    no(post(ref(ULA_LAN), { ...CTX, networks: [{ ...NETWORKS[5], ipv6_interface_type: 'single_network' }] }), /ipv6_interface_type "single_network"/);
    no(post(ref(ULA_LAN), { ...CTX, networks: [{ ...NETWORKS[5], ipv6_subnet: '' }] }), /"Lab ULA" has no static IPv6 subnet/);
    no(post(ref(ULA_LAN), { ...CTX, networks: [{ ...NETWORKS[5], ipv6_subnet: 'fd12::1' }] }), /"fd12::1" is not an IPv6 CIDR/);
    no(post(ref(ULA_LAN), { ...CTX, networks: [{ ...NETWORKS[5], ipv6_subnet: 'fd12::1/64,2001:db8::/32' }] }), /is not an IPv6 CIDR/);
    no(post(ref(ULA_LAN), { ...CTX, networks: [{ ...NETWORKS[5], ipv6_subnet: ['fd12::1/64'] }] }), /\["fd12::1\/64"\] is not an IPv6 CIDR/);
    no(post(ref(ULA_LAN), { ...CTX, networks: [{ ...NETWORKS[5], ipv6_subnet: 'fd12::zz/64' }] }), /"fd12::zz\/64" is not a valid IPv6/);
    // every subnet field present must be private, not just one of them
    no(post(ref(ODD_V6_LAN)), /"Lab odd" ipv6_static_subnet: "2001:db8::1\/64" is not entirely inside private/);
  }
  // IPv4: the network needs a private ip_subnet; none, or a malformed one, is refused
  no(post({ ...TO_SONOS_BY_NET, src_networkconf_id: VLAN_ONLY }), /src_networkconf_id network "Cameras L2" has no IPv4 subnet \(ip_subnet\)/);
  no(post({ ...TO_SONOS_BY_NET, src_networkconf_type: 'ADDRv4', src_networkconf_id: VLAN_ONLY }), /"Cameras L2" has no IPv4 subnet/);
  no(post({ ...TO_SONOS_BY_NET, src_networkconf_id: ODD_V6_LAN }), /"Lab odd" subnet "garbage" is not an IPv4 CIDR/);
  no(post({ ...TO_SONOS_BY_NET, src_networkconf_id: OWNER }, { ...CTX, networks: [{ ...NETWORKS[0], ip_subnet: 42 }] }), /"Owner" has no IPv4 subnet/);
  // the destination network is checked the same way
  no(post({ ...RETURN_BY_IPS, dst_networkconf_id: PUBLIC_LAN }), /dst_networkconf_id network "Routed block" subnet: "203\.0\.113\.1\/28" is not entirely inside private/);
  no(post({ ...RETURN_BY_IPS, dst_networkconf_id: VLAN_ONLY }), /dst_networkconf_id network "Cameras L2" has no IPv4 subnet/);
  // a network with a GUA IPv6 prefix is still fine on IPv4 rules (only its IPv4 subnet is matched)
  ok(post({ ...TO_SONOS_BY_NET, src_networkconf_id: GUA_LAN }));
  ok(post({ ...TO_SONOS_BY_NET, src_networkconf_id: PD_LAN, src_networkconf_type: 'ADDRv4' }));
});

test('accept: every address selector must match the ruleset family', () => {
  const v6 = { ...base, ruleset: 'LANv6_IN', src_address_ipv6: 'fd12:3456:789a:60::/64' };
  // networkconf types
  no(post({ ...TO_SONOS_BY_NET, src_networkconf_type: 'NETv6' }), /src_networkconf_type NETv6 does not match LAN_IN, an IPv4 ruleset \(allowed: NETv4, ADDRv4 or ""\)/);
  no(post({ ...TO_SONOS_BY_NET, src_networkconf_type: 'ADDRv6' }), /src_networkconf_type ADDRv6 does not match LAN_IN/);
  no(post({ ...RETURN_BY_IPS, dst_networkconf_type: 'NETv6' }), /dst_networkconf_type NETv6 does not match LAN_IN/);
  no(post({ ...v6, dst_networkconf_id: ULA_LAN, dst_networkconf_type: 'NETv4' }), /dst_networkconf_type NETv4 does not match LANv6_IN, an IPv6 ruleset/);
  no(post({ ...base, ruleset: 'GUESTv6_IN', src_networkconf_id: ULA_LAN, src_networkconf_type: 'ADDRv4' }), /src_networkconf_type ADDRv4 does not match GUESTv6_IN/);
  // also when no network is referenced: the type must still fit the ruleset
  no(post({ ...TO_SONOS_BY_CIDR, src_networkconf_id: '', src_networkconf_type: 'NETv6' }), /src_networkconf_type NETv6 does not match LAN_IN/);
  no(post({ ...v6, src_networkconf_id: '', src_networkconf_type: 'NETv4' }), /src_networkconf_type NETv4 does not match LANv6_IN/);
  // the controller's default (same-family type, empty id) is inert and allowed, but is not a source
  ok(post({ ...TO_SONOS_BY_CIDR, src_networkconf_id: '', src_networkconf_type: 'NETv4', dst_networkconf_id: '', dst_networkconf_type: 'NETv4' }));
  ok(post({ ...v6, src_networkconf_id: '', src_networkconf_type: 'NETv6' }));
  no(post({ ...base, src_networkconf_id: '', src_networkconf_type: 'ADDRv4', dst_address: SONOS_IPS }), /must constrain the source/);
  // address fields
  no(post({ ...v6, src_address_ipv6: '', src_address: '192.168.50.0/24' }), /src_address is an IPv4 field, but LANv6_IN is an IPv6 ruleset \(use src_address_ipv6\)/);
  no(post({ ...v6, dst_address: '192.168.7.20' }), /dst_address is an IPv4 field, but LANv6_IN/);
  no(post({ ...TO_SONOS_BY_CIDR, src_address_ipv6: 'fd00::1' }), /src_address_ipv6 is an IPv6 field, but LAN_IN is an IPv4 ruleset \(use src_address\)/);
  no(post({ ...TO_SONOS_BY_NET, dst_address_ipv6: 'fd00::1' }), /dst_address_ipv6 is an IPv6 field, but LAN_IN/);
  // address groups (port groups fit either family)
  no(post({ ...TO_SONOS_BY_NET, dst_address: '', dst_firewallgroup_ids: [ULA_GROUP] }), /dst_firewallgroup_ids: firewall group "Lab ULA hosts" is an ipv6-address-group, but LAN_IN is an IPv4 ruleset/);
  no(post({ ...base, src_firewallgroup_ids: [ULA_GROUP] }), /src_firewallgroup_ids: .* is an ipv6-address-group, but LAN_IN/);
  no(post({ ...v6, src_address_ipv6: '', src_firewallgroup_ids: [SONOS_GROUP] }), /"Sonos speakers" is an address-group, but LANv6_IN is an IPv6 ruleset \(only ipv6-address-group and port-group\)/);
  no(post({ ...v6, dst_firewallgroup_ids: [SONOS_GROUP, SONOS_PORTS] }), /is an address-group, but LANv6_IN/);
  // a network reference is not combined with addresses or address groups on the same side
  no(post({ ...TO_SONOS_BY_NET, src_address: '192.168.50.0/24' }), /src_networkconf_id cannot be combined with src_address or an address group/);
  no(post({ ...TO_SONOS_BY_NET, src_firewallgroup_ids: [SONOS_GROUP] }), /src_networkconf_id cannot be combined/);
  no(post({ ...RETURN_BY_IPS, dst_address: '192.168.50.10' }), /dst_networkconf_id cannot be combined with dst_address/);
  no(post({ ...v6, src_address_ipv6: '', src_networkconf_id: ULA_LAN, src_networkconf_type: 'NETv6', src_firewallgroup_ids: [ULA_GROUP] }), /src_networkconf_id cannot be combined with src_address_ipv6/);
  // matched families are allowed
  ok(post(v6));
  ok(post({ ...v6, src_address_ipv6: '', src_firewallgroup_ids: [ULA_GROUP], dst_networkconf_id: ULA_LAN, dst_networkconf_type: 'NETv6' }));
  ok(post({ ...v6, ruleset: 'GUESTv6_OUT', src_address_ipv6: '', src_networkconf_id: ULA_LAN, src_networkconf_type: 'ADDRv6', dst_firewallgroup_ids: [SONOS_PORTS] }));
  ok(post({ ...TO_SONOS_BY_NET, src_firewallgroup_ids: [SONOS_PORTS] }));
  // drop/reject rules are not family-checked (blocking is harmless)
  ok(post({ ...base, action: 'drop', src_address_ipv6: '2001:db8::/32', src_networkconf_type: 'NETv6' }));
});

test('accept: a MAC address alone does not constrain the source', () => {
  const MAC = 'aa:bb:cc:dd:ee:01';
  for (const ruleset of ['GUEST_IN', 'LAN_IN', 'LAN_OUT', 'GUEST_LOCAL']) {
    no(post({ ...base, ruleset, src_mac_address: MAC }), new RegExp(`accept rule on ${ruleset} must constrain the source .*src_mac_address only narrows one of these`));
    no(post({ ...base, ruleset, src_mac_address: MAC, dst_address: SONOS_IPS }), /must constrain the source/);
    // with a private CIDR, an address group or a network it is an extra restriction
    ok(post({ ...base, ruleset, src_mac_address: MAC, src_address: '192.168.50.0/24' }));
    ok(post({ ...base, ruleset, src_mac_address: MAC.toUpperCase(), src_firewallgroup_ids: [SONOS_GROUP] }));
    ok(post({ ...base, ruleset, src_mac_address: MAC, src_networkconf_id: OWNER, src_networkconf_type: 'NETv4' }));
  }
  no(post({ ...base, ruleset: 'LANv6_IN', src_mac_address: MAC }), /must constrain the source/);
  ok(post({ ...base, ruleset: 'LANv6_IN', src_mac_address: MAC, src_address_ipv6: 'fd00::/64' }));
  // a port group plus a MAC is still no source
  no(post({ ...base, src_mac_address: MAC, src_firewallgroup_ids: [SONOS_PORTS] }), /must constrain the source/);
  // malformed or negated MACs are refused
  for (const m of ['aa:bb:cc:dd:ee', 'aa-bb-cc-dd-ee-01', 'aabb.ccdd.ee01', '!aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02', 'gg:bb:cc:dd:ee:01', ' aa:bb:cc:dd:ee:01', 42]) {
    no(post({ ...TO_SONOS_BY_CIDR, src_mac_address: m }), /invalid value for "src_mac_address"/);
  }
});

test('accept: WAN_* accept is still refused, whatever the addresses', () => {
  for (const ruleset of ['WAN_IN', 'WAN_OUT', 'WAN_LOCAL', 'WANv6_IN']) {
    no(post({ ...TO_SONOS_BY_CIDR, ruleset }), new RegExp(`on ${ruleset} with action "accept" would allow WAN traffic`));
  }
});

// ---------------------------------------------------------------------------
// Tool level: unifi_rw_create_legacy_firewall_rule through a fake connector
// ---------------------------------------------------------------------------
async function sonosStack(routes) {
  const dir = tmpDir();
  const auditLog = createAuditLog({ stateDir: path.join(dir, 'state') });
  const sent = [];
  const udm = createUdmClient({
    backend: 'cloud',
    consoleId: CONSOLE,
    allowClassic: ['firewallrule'],
    allowWrites: true,
    apiKey: API_KEY,
    siteId: SITE,
    auditLog,
    transport: async (req) => {
      sent.push(req);
      assert.ok(req.path.startsWith(PREFIX), req.path);
      const r = routes[`${req.method} ${req.path.slice(PREFIX.length)}`];
      if (!r) return { status: 404, headers: {}, text: '{"code":"not_found"}' };
      return { status: r.status, headers: {}, text: JSON.stringify(r.body) };
    },
  });
  const server = buildMcpServer({ udmClient: udm, auditLog });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(a);
  const client = new Client({ name: 'test', version: '1' });
  await client.connect(b);
  const call = async (name, args) => {
    const r = await client.callTool({ name, arguments: args });
    return { isError: Boolean(r.isError), text: r.content[0].text, json: r.isError ? undefined : JSON.parse(r.content[0].text) };
  };
  return { call, sent, auditLog, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

const classic = (data) => ({ status: 200, body: { meta: { rc: 'ok' }, data } });

test('tool dry_run: the Sonos pair through unifi_rw_create_legacy_firewall_rule (cloud connector, fake transport)', async (t) => {
  const s = await sonosStack({ [`GET ${C}/rest/firewallgroup`]: classic(GROUPS), [`GET ${C}/rest/networkconf`]: classic(NETWORKS) });
  t.after(s.cleanup);
  for (const rule of [TO_SONOS_BY_NET, RETURN_BY_IPS, TO_SONOS_BY_CIDR, RETURN_BY_GROUP]) {
    s.sent.length = 0;
    const r = await s.call('unifi_rw_create_legacy_firewall_rule', { rule, dry_run: true });
    assert.equal(r.isError, false, r.text);
    // the tool looked up groups and networks (GET only), then stopped before the write
    assert.deepEqual(s.sent.map((q) => `${q.method} ${q.path.slice(PREFIX.length)}`), [`GET ${C}/rest/firewallgroup`, `GET ${C}/rest/networkconf`]);
    assert.equal(r.json.dry_run, true);
    assert.equal(r.json.backend, 'cloud');
    assert.equal(r.json.request.method, 'POST');
    assert.equal(r.json.request.url, `https://api.ui.com${PREFIX}${LP}`);
    assert.equal(r.json.request.headers['X-API-KEY'], '[REDACTED]');
    assert.deepEqual(r.json.request.body, rule);
    assert.ok(!r.text.includes(API_KEY));
    t.diagnostic(`${rule.name}: ${JSON.stringify(r.json.request)}`);
  }
  const log = fs.readFileSync(s.auditLog.file, 'utf8').trim().split('\n').map(JSON.parse);
  assert.deepEqual(log.map((l) => [l.status, l.method, l.endpoint, l.dry_run]), Array(4).fill(['dry_run', 'POST', LP, true]));

  // refusals come back as tool errors and nothing is written
  s.sent.length = 0;
  const bad = await s.call('unifi_rw_create_legacy_firewall_rule', { rule: { ...TO_SONOS_BY_CIDR, src_address: '8.8.8.0/24' }, dry_run: true });
  assert.equal(bad.isError, true);
  assert.match(bad.text, /Refused by guard: src_address: "8\.8\.8\.0\/24"/);
  const leaky = await s.call('unifi_rw_create_legacy_firewall_rule', { rule: { ...TO_SONOS_BY_NET, dst_address: '', dst_firewallgroup_ids: [LEAKY_GROUP] } });
  assert.equal(leaky.isError, true);
  assert.equal(s.sent.filter((q) => q.method !== 'GET').length, 0);
});

test('read tools for rule building: classic networks and firewall groups, reduced to safe fields', async (t) => {
  const withSecrets = [{ ...NETWORKS[0], x_wan_password: 'pppoe-hunter2', x_ipsec_pre_shared_key: 'psk-hunter2', dhcpd_dns_1: '192.168.50.1' }, NETWORKS[2]];
  const s = await sonosStack({ [`GET ${C}/rest/firewallgroup`]: classic(GROUPS.slice(0, 2)), [`GET ${C}/rest/networkconf`]: classic(withSecrets) });
  t.after(s.cleanup);
  const nets = await s.call('unifi_rw_list_classic_networks', {});
  assert.equal(nets.isError, false, nets.text);
  assert.deepEqual(nets.json[0], { _id: OWNER, name: 'Owner', purpose: 'corporate', vlan_enabled: true, vlan: 42, ip_subnet: '192.168.50.1/24' });
  assert.deepEqual(Object.keys(nets.json[1]).sort(), ['_id', 'name', 'purpose']);
  assert.doesNotMatch(nets.text, /hunter2|dhcpd/);
  const groups = await s.call('unifi_rw_list_firewall_groups', {});
  assert.deepEqual(groups.json, GROUPS.slice(0, 2));
  assert.ok(s.sent.every((q) => q.method === 'GET'));
});

test('tool: a failed networkconf lookup fails closed and names the reason; drop rules need no lookups', async (t) => {
  const s = await sonosStack({ [`GET ${C}/rest/firewallgroup`]: classic(GROUPS), [`GET ${C}/rest/networkconf`]: { status: 403, body: { code: 'forbidden' } } });
  t.after(s.cleanup);
  const r = await s.call('unifi_rw_create_legacy_firewall_rule', { rule: TO_SONOS_BY_NET, dry_run: true });
  assert.equal(r.isError, true);
  assert.match(r.text, /networks \(classic rest\/networkconf\) could not be determined; accept rules fail closed \(lookup failed: Cloud connector: .*\(403\)/);
  // a rule that references no network still works without the networks
  assert.equal((await s.call('unifi_rw_create_legacy_firewall_rule', { rule: RETURN_BY_GROUP, dry_run: true })).isError, false);
  s.sent.length = 0;
  const drop = await s.call('unifi_rw_create_legacy_firewall_rule', { rule: { ...base, action: 'drop', name: 'block', src_address: '8.8.8.8' }, dry_run: true });
  assert.equal(drop.isError, false, drop.text);
  assert.equal(s.sent.length, 0);
});
