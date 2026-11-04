'use strict';

/**
 * Hard refusals for writes that would let traffic in from the WAN. They run
 * in the tool layer before the guard, before a dry run is answered and before
 * anything is sent, and no tool argument turns them off: dry_run does not, and
 * neither does anything the model passes. Only the operator can, with
 * UNIFI_ALLOW_WAN_EXPOSURE=true, and then the guard's own rules (which refuse
 * most of the same writes for other reasons) still apply.
 *
 * Which zone is the WAN: a zone is the WAN when its id is in
 * UNIFI_WAN_ZONE_IDS or config firewall_wan_zone_ids, when it is
 * system-defined and named "External" (what the controller creates), or when
 * its name is External, WAN or Internet. Names can be edited, so the id list
 * is the reliable signal and the names a fallback. When the zones cannot be
 * read, or a zone a change depends on is not among them, the write is
 * refused: a check that cannot run must not pass.
 *
 * Checked, by canonical request path:
 *   zone-based policies   POST/PUT/PATCH .../firewall/policies[/{id}]
 *                         refused if the policy as it would be after the
 *                         write ALLOWs (anything but BLOCK/REJECT) traffic
 *                         whose source zone is the WAN, or has no source zone
 *   firewall zones        POST/PUT/PATCH .../firewall/zones[/{id}]
 *                         refused if it edits the WAN zone or takes networks
 *                         from it (no tool sends these today; the guard
 *                         refuses them as well)
 *   networks              PUT/PATCH .../networks/{id}, classic rest/networkconf
 *                         refused if the network would move into or out of
 *                         the WAN zone, or become a WAN (purpose "wan")
 *   legacy firewall rules POST/PUT classic rest/firewallrule[/{_id}]
 *                         refused on WAN_IN, WAN_LOCAL, WANv6_IN, WANv6_LOCAL
 *                         unless the action is drop or reject; on update the
 *                         merged rule is what is checked
 */

const WAN_RULESETS = Object.freeze(['WAN_IN', 'WAN_LOCAL', 'WANv6_IN', 'WANv6_LOCAL']);
const WAN_ZONE_NAME_RE = /^(external|wan|internet)$/i;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// PATCH fields that cannot widen a policy: reporting only.
const HARMLESS_POLICY_PATCH_KEYS = Object.freeze(['loggingEnabled']);

const ID = '[A-Za-z0-9_-]{1,64}';
const POLICY_RE = new RegExp(`^/integration/v1/sites/${ID}/firewall/policies(?:/(${ID}))?$`);
const ZONE_RE = new RegExp(`^/integration/v1/sites/${ID}/firewall/zones(?:/(${ID}))?$`);
const NETWORK_RE = new RegExp(`^/integration/v1/sites/${ID}/networks(?:/(${ID}))?$`);
const CLASSIC_NETWORK_RE = new RegExp(`^/api/s/${ID}/rest/networkconf(?:/(${ID}))?$`);
const LEGACY_RULE_RE = new RegExp(`^/api/s/${ID}/rest/firewallrule(?:/(${ID}))?$`);

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const lower = (v) => (typeof v === 'string' ? v.toLowerCase() : undefined);

class WanExposureError extends Error {
  constructor(reason) {
    super(
      `Refused: ${reason}. This server does not make changes that could let traffic in from the WAN, and dry_run does not change that; if the change is intended, make it in the UniFi console.`
    );
    this.name = 'WanExposureError';
    this.reason = reason;
  }
}

const refuse = (reason) => {
  throw new WanExposureError(reason);
};

/** Any action but BLOCK or REJECT lets traffic through, including a missing one. */
function policyAllowsTraffic(policy) {
  const type = isPlainObject(policy.action) ? lower(policy.action.type) : undefined;
  return type !== 'block' && type !== 'reject';
}

/** Any legacy action but drop or reject lets traffic through, including a missing one. */
const legacyAllowsTraffic = (action) => !['drop', 'reject'].includes(lower(action));

const isWanRuleset = (ruleset) => typeof ruleset === 'string' && WAN_RULESETS.some((r) => r.toLowerCase() === ruleset.toLowerCase());

const zoneLabel = (zone) => JSON.stringify(typeof zone.name === 'string' ? zone.name : zone.id);

/**
 * @param {object} [o]
 * @param {boolean} [o.allowExposure]  UNIFI_ALLOW_WAN_EXPOSURE=true: skip every check
 * @param {string[]} [o.zoneIds]       zone ids that are the WAN (UNIFI_WAN_ZONE_IDS + config firewall_wan_zone_ids)
 */
function createWanExposure({ allowExposure = false, zoneIds = [] } = {}) {
  if (!Array.isArray(zoneIds) || !zoneIds.every((id) => typeof id === 'string' && UUID_RE.test(id))) {
    throw new Error('createWanExposure: zoneIds must be an array of zone UUIDs');
  }
  const wanIds = Object.freeze([...new Set(zoneIds.map((id) => id.toLowerCase()))]);

  function isWanZone(zone) {
    if (wanIds.includes(lower(zone.id))) return true;
    const name = typeof zone.name === 'string' ? zone.name.trim() : '';
    if (WAN_ZONE_NAME_RE.test(name)) return true;
    return isPlainObject(zone.metadata) && zone.metadata.origin === 'SYSTEM_DEFINED' && name.toLowerCase() === 'external';
  }

  /** Zones from the request context if a tool already fetched them, else loadZones(). Refuses if unavailable. */
  async function zonesFor(req, loadZones) {
    let zones = isPlainObject(req.context) ? req.context.zones : undefined;
    let why;
    if (!Array.isArray(zones) && typeof loadZones === 'function') {
      try {
        zones = await loadZones();
      } catch (e) {
        why = (e && e.message) || String(e);
      }
    }
    if (!Array.isArray(zones) || zones.length === 0) {
      refuse(`the firewall zones could not be read to find the WAN zone${why ? ` (${why})` : ''}`);
    }
    return zones.filter((z) => isPlainObject(z) && typeof z.id === 'string');
  }

  function findZone(zones, id, what) {
    const zone = zones.find((z) => lower(z.id) === lower(id));
    if (!zone) refuse(`${what} (${JSON.stringify(id)}) is not one of this site's firewall zones, so it cannot be checked against the WAN zone`);
    return zone;
  }

  async function checkPolicy(req, loadZones) {
    const existing = isPlainObject(req.context) && isPlainObject(req.context.existing) ? req.context.existing : undefined;
    let policy = req.body;
    if (req.method === 'PATCH') {
      if (Object.keys(req.body).every((k) => HARMLESS_POLICY_PATCH_KEYS.includes(k))) return;
      if (!existing) refuse('the policy being patched could not be read, so the result cannot be checked against the WAN zone');
      policy = { ...existing, ...req.body };
    }
    if (!policyAllowsTraffic(policy)) return;
    const src = isPlainObject(policy.source) && typeof policy.source.zoneId === 'string' ? policy.source.zoneId : undefined;
    if (src === undefined) refuse('the policy ALLOWs traffic but has no source.zoneId, so its source cannot be checked against the WAN zone');
    const zone = findZone(await zonesFor(req, loadZones), src, 'its source zone');
    if (isWanZone(zone)) refuse(`the policy would ALLOW traffic from the ${zoneLabel(zone)} zone, which is the WAN`);
  }

  async function checkZone(req, zoneId, loadZones) {
    const zones = await zonesFor(req, loadZones);
    if (zoneId !== undefined) {
      const zone = findZone(zones, zoneId, 'the zone');
      if (isWanZone(zone)) refuse(`the change would modify the ${zoneLabel(zone)} zone, which is the WAN`);
    }
    const networkIds = Array.isArray(req.body.networkIds) ? req.body.networkIds.filter((id) => typeof id === 'string') : [];
    const wanNetworks = new Set(zones.filter(isWanZone).flatMap((z) => (Array.isArray(z.networkIds) ? z.networkIds : [])).map(lower));
    const moved = networkIds.filter((id) => wanNetworks.has(lower(id)));
    if (moved.length) refuse(`the change would move networks out of the WAN zone: ${moved.join(', ')}`);
  }

  async function checkNetwork(req, loadZones) {
    const existing = isPlainObject(req.context) && isPlainObject(req.context.existing) ? req.context.existing : {};
    const body = req.method === 'PATCH' ? { ...existing, ...req.body } : req.body;
    if (lower(body.purpose) === 'wan' && lower(existing.purpose) !== 'wan') refuse('the change would turn the network into a WAN (purpose "wan")');
    const next = body.zoneId;
    const current = typeof existing.zoneId === 'string' ? existing.zoneId : undefined;
    if (next === undefined || lower(next) === lower(current)) return;
    if (typeof next !== 'string') refuse('the network zoneId is not a string, so it cannot be checked against the WAN zone');
    const zones = await zonesFor(req, loadZones);
    if (current !== undefined) {
      const from = findZone(zones, current, "the network's current zoneId");
      if (isWanZone(from)) refuse(`the change would move the network out of the ${zoneLabel(from)} zone, which is the WAN`);
    }
    const to = findZone(zones, next, "the network's zoneId");
    if (isWanZone(to)) refuse(`the change would put the network in the ${zoneLabel(to)} zone, which is the WAN`);
  }

  function checkLegacyRule(req) {
    const { ruleset, action } = req.body;
    if (isWanRuleset(ruleset) && legacyAllowsTraffic(action)) {
      refuse(`legacy rule on ${ruleset} with action ${JSON.stringify(action ?? null)} would let traffic in from the WAN; WAN* rulesets allow only drop/reject`);
    }
  }

  /**
   * Check one request before it goes to the client. Throws WanExposureError.
   * @param {{method: string, path: string, body?: object, context?: object}} req  canonical path; for updates the merged body
   * @param {object} [o]
   * @param {Function} [o.loadZones]  async () => zone list, used when req.context.zones is absent
   */
  async function check(req, { loadZones } = {}) {
    if (allowExposure) return;
    const method = String(req && req.method).toUpperCase();
    if (method === 'GET') return;
    const path = typeof req.path === 'string' ? req.path.split('?')[0] : '';
    // Every write this layer knows has a JSON object body; anything else cannot be checked.
    const body = req.body;
    if (POLICY_RE.test(path)) {
      if (!isPlainObject(body)) refuse('the firewall policy body is not an object, so it cannot be checked against the WAN zone');
      return checkPolicy({ ...req, method }, loadZones);
    }
    const zone = ZONE_RE.exec(path);
    if (zone) {
      if (!isPlainObject(body) && method !== 'DELETE') refuse('the firewall zone body is not an object, so it cannot be checked against the WAN zone');
      return checkZone({ ...req, method, body: isPlainObject(body) ? body : {} }, zone[1], loadZones);
    }
    if (NETWORK_RE.test(path) || CLASSIC_NETWORK_RE.test(path)) {
      if (!isPlainObject(body)) return method === 'DELETE' ? undefined : refuse('the network body is not an object, so it cannot be checked against the WAN zone');
      return checkNetwork({ ...req, method }, loadZones);
    }
    if (LEGACY_RULE_RE.test(path)) {
      if (!isPlainObject(body)) refuse('the legacy firewall rule body is not an object, so it cannot be checked');
      return checkLegacyRule({ ...req, method });
    }
  }

  return Object.freeze({ allowExposure: allowExposure === true, zoneIds: wanIds, check, isWanZone });
}

module.exports = { createWanExposure, WanExposureError, WAN_RULESETS };
