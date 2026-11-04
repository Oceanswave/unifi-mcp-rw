'use strict';

/**
 * The one list of tool names. lib/tools.cjs refuses to register a tool that
 * is not listed here on the right side (a write tool missing from
 * WRITE_TOOLS, or a read tool listed in it), and UNIFI_WRITE_TOOLS is
 * validated against WRITE_TOOLS, so the lists cannot fall behind the code.
 */
const READ_TOOLS = Object.freeze([
  'unifi_rw_get_info',
  'unifi_rw_list_sites',
  'unifi_rw_list_wifi_broadcasts',
  'unifi_rw_get_wifi_broadcast',
  'unifi_rw_list_networks',
  'unifi_rw_get_network',
  'unifi_rw_list_firewall_zones',
  'unifi_rw_list_firewall_policies',
  'unifi_rw_get_firewall_policy',
  'unifi_rw_list_legacy_firewall_rules',
  'unifi_rw_list_firewall_groups',
  'unifi_rw_list_classic_networks',
  'unifi_rw_list_clients',
  'unifi_rw_get_client',
  'unifi_rw_list_access_points',
  'unifi_rw_list_fixed_ips',
]);

const WRITE_TOOLS = Object.freeze([
  'unifi_rw_create_wifi_broadcast',
  'unifi_rw_update_wifi_broadcast',
  'unifi_rw_update_ap_radios',
  'unifi_rw_create_firewall_policy',
  'unifi_rw_update_firewall_policy',
  'unifi_rw_patch_firewall_policy',
  'unifi_rw_create_legacy_firewall_rule',
  'unifi_rw_update_legacy_firewall_rule',
  'unifi_rw_set_fixed_ip',
  'unifi_rw_clear_fixed_ip',
  'unifi_rw_authorize_guest',
  'unifi_rw_unauthorize_guest',
  'unifi_rw_update_network',
]);

/**
 * Parse a UNIFI_WRITE_TOOLS value: comma-separated write tool names, with
 * whitespace around each ignored. "" or "none" enables no write tools.
 * Returns { tools, unknown, readTools }: tools in WRITE_TOOLS order without
 * duplicates; read tool names and anything else that is not a write tool
 * come back separately so the caller can say which is which.
 */
function parseWriteTools(value) {
  const names = [...new Set(String(value).split(',').map((n) => n.trim()).filter((n) => n !== ''))];
  if (names.length === 1 && names[0].toLowerCase() === 'none') return { tools: [], unknown: [], readTools: [] };
  return {
    tools: WRITE_TOOLS.filter((t) => names.includes(t)),
    readTools: names.filter((n) => READ_TOOLS.includes(n)),
    unknown: names.filter((n) => !WRITE_TOOLS.includes(n) && !READ_TOOLS.includes(n)),
  };
}

module.exports = { READ_TOOLS, WRITE_TOOLS, parseWriteTools };
