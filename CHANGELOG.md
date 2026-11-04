# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
semantic versioning. From 0.3.0, a `vX.Y.Z` tag and GitHub release mark each
released version.

## [0.4.0] - 2026-11-04

Prepared for a public release.

### Changed

- **Breaking:** the proxy hostname is no longer built in. Set `MCP_PUBLIC_HOST`
  (a bare DNS name, e.g. your `tailscale serve` name) to allow it as Host and
  `https://` Origin; without it only loopback is accepted. The startup line
  shows `public_host=`.
- CI and the merge workflows run on GitHub-hosted runners.
- MIT licensed.

### Removed

- The copies of Ubiquiti's Network API 10.6.106 spec under `docs/`; it is
  published at developer.ui.com.

## [0.3.0] - 2026-11-04

Three write-mode safeguards modeled on upstream `unifi-network-mcp`
(`UNIFI_NETWORK_WRITE_TOOLS`, `UNIFI_NETWORK_WRITE_LOG`,
`UNIFI_NETWORK_ALLOW_WAN_EXPOSURE`, `UNIFI_NETWORK_WAN_ZONE_IDS`), set by
environment variable. With none of them set, the tools and their behaviour
are the same as in 0.2.1 apart from the error text of some refusals.

### Added

- `UNIFI_WRITE_TOOLS`: comma-separated write tool names to register
  (whitespace ignored; `""` or `none` for none). Unset registers all of them,
  as upstream does. Unlisted write tools are not registered. Read tools are
  always registered. An unknown name or a read tool name stops the server
  with exit 2 and lists the valid write tool names. Validated but ignored in
  read-only mode. No group names, unlike upstream.
- `UNIFI_WRITE_LOG`: absolute path of a JSON Lines file with one line per
  write tool call: timestamps, tool, redacted args, canonical method and
  endpoint, `dry_run`, `outcome` (`ok` / `dry_run` / `refused` / `error`),
  HTTP status, refusal `reason` (`guard` / `wan_exposure`), short error
  summary, duration. Request and response bodies are never logged. The file
  is created 0600 (directories 0700). Startup fails (exit 2) for a relative
  path, a symlink (`lstat` plus `O_NOFOLLOW`), a symlinked directory anywhere
  on the path, a parent directory that is group- or world-writable without
  the sticky bit or isn't owned by the current user or root, a non-regular
  file (checked before the open, which also uses `O_NONBLOCK`, so a FIFO
  can't hang startup), a file with other hard links, or a group- or
  world-writable file. A wider read-only
  mode is left alone, as upstream does. Ignored in read-only mode. Separate
  from the always-on `writes.log` audit log, which is unchanged.
- WAN-exposure refusals (`lib/wan-exposure.cjs`), on by default, checked in
  the tool layer before the guard, before dry-run output and before any
  write. They refuse zone-based policies that ALLOW traffic from the WAN zone
  (or whose source can't be checked), edits to the WAN zone, network
  updates that move a network into or out of the WAN zone or make it a WAN,
  and legacy rules on `WAN_IN`, `WAN_LOCAL`, `WANv6_IN` and `WANv6_LOCAL`
  whose action isn't drop or reject (checked on the merged rule for
  updates). No tool argument bypasses them. `UNIFI_ALLOW_WAN_EXPOSURE=true`
  turns them off (with a startup warning), and the guard still applies.
  `UNIFI_WAN_ZONE_IDS` adds WAN zone ids to `firewall_wan_zone_ids`.
- A second startup line in write mode:
  `write safeguards: write_tools=... write_log=... wan_exposure=...`.
- `lib/tool-names.cjs`: the single list of read and write tool names.
  Registering a tool that isn't on the right list throws.
- Commented `Environment=` lines for the new variables in the systemd unit,
  and a "Minimum allowlist" section in the README.

### Changed

- A legacy accept rule on a `WAN*` ruleset is no longer refused by the
  create tool's input schema. It now reaches the handler, where the
  WAN-exposure check (or, for `WAN_OUT`, the guard) refuses it, so the
  refusal is logged. The firewall group and network lookups are skipped for
  such rules.
- The `writes.log` audit entry for a write refused before it reached the
  client now carries the method and endpoint it would have used.

### Fixed

- Refuse inherited object property names in the legacy firewall rule field
  allowlist, so unknown fields cannot pass validation.
- Refuse fixed-IP writes when the classic client list is malformed, instead
  of treating an unreadable list as empty and creating a record.
- Drain pending upstream writes and their audit entries on shutdown even
  after the MCP client has disconnected, within the existing 35-second limit.
- Scrub credentials from fatal startup errors and omit exception text from
  audit-log failure warnings.
- Correct README runtime requirements, zone-policy update limits and the
  missing/empty internal-zone warning; clarify the existing write-call API
  and audit logging limits.

## [0.2.1] - 2026-10-18

Closes three gaps in how legacy accept rules on LAN and guest rulesets check
their source, found in a review of 0.2.0. All three made the guard accept
rules it should have refused; none affected WAN rulesets, where accept was
and is refused outright.

### Upgrade note

Some accept rules that 0.2.0 let through are now refused, including updates
to existing rules of that shape (see "Changed"). Drop and reject rules are
not affected. If an existing rule can no longer be edited here, the error
names the field; fix it in the UniFi UI.

### Changed

- A network referenced by `src_networkconf_id` or `dst_networkconf_id` must
  have a private subnet in the family its `*_networkconf_type` selects.
  `NETv4`/`ADDRv4` need a private `ip_subnet`. `NETv6`/`ADDRv6` need
  `ipv6_interface_type: "static"` and a private (fc00::/7 or fe80::/10)
  `ipv6_subnet`, plus `ipv6_static_subnet` if that is present too. A network
  without the subnet, with one that does not parse, with a public IPv6
  prefix, or that gets its prefix by prefix delegation from the WAN is
  refused. Before, only the IPv4 subnet was checked, and only if the network
  had one, so an IPv6 rule could reference a network with a public prefix.
- Every address selector of an accept rule must match the ruleset's family.
  IPv4 rulesets take `src_address`/`dst_address`, `address-group` groups and
  networkconf types `NETv4`/`ADDRv4`; v6 rulesets take the `_ipv6` address
  fields, `ipv6-address-group` groups and `NETv6`/`ADDRv6`. Port groups fit
  both. Anything of the other family is refused instead of being ignored.
  A networkconf type with an empty id is how the controller stores rules
  that reference no network; it is allowed if it fits the family, and does
  not count as a source.
- A network reference can no longer be combined with an address or address
  group on the same side of the rule. The UniFi UI never produces that, and
  it is not clear which of the two the controller would use.
- `src_mac_address` no longer counts as the source of an accept rule. It is
  still allowed next to a source address, address group or network, as an
  extra restriction.

### Added

- `unifi_rw_list_classic_networks` also returns `ipv6_interface_type`,
  `ipv6_subnet` and `ipv6_pd_interface`, the fields the guard now checks.

## [0.2.0] - 2026-10-18

### Upgrade note

The server now starts in read-only mode unless `"allow_writes": true` is set
in `config.json` (or `UNIFI_ALLOW_WRITES=true` is in the environment). The
deployed config has no such key, so after upgrading it will only
offer read tools until the key is added. See "Upgrading from 0.1.0" in the
README.

### Added

- `allow_writes` config key (boolean, default `false`) and the
  `UNIFI_ALLOW_WRITES` environment override (`true`/`1` turns writes on,
  `false`/`0` turns them off, anything else defers to the config). In
  read-only mode no write tools are registered, and the UniFi client refuses
  every non-GET request itself, dry runs included.
- Accept rules on every non-WAN legacy ruleset (`LAN_*`, `GUEST_*`, IPv4 and
  IPv6) must name their source, and every address they mention must be
  private: 10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16, fc00::/7,
  fe80::/10. Negated addresses and ports, and `protocol_match_excepted`, are
  refused on accept rules.
- The legacy rule tools look up `rest/firewallgroup` and `rest/networkconf`
  (classic GET, under the `firewallrule` capability) before writing an accept
  rule. The guard checks that referenced firewall groups exist and contain
  only private addresses or valid ports, and that referenced networks exist
  and are not WAN or VPN-client networks. A failed lookup refuses the write.
- Read tools `unifi_rw_list_classic_networks` and
  `unifi_rw_list_firewall_groups` (`firewallrule` capability), which return
  the classic ids legacy rules refer to. The network list is reduced to a
  fixed set of fields, because networkconf records can hold WAN and VPN
  credentials.
- The classic probe also reads `rest/networkconf` and reports network
  purposes and firewall group types (counts only).
- Startup log line with version, backend, write mode and where that mode came
  from. No secrets.
- On SIGTERM the server refuses new writes and gives in-flight requests up to
  35 seconds to finish before exiting.
- Handlers for uncaught exceptions and unhandled rejections that log one
  scrubbed line and exit, so systemd restarts the service.
- `npm run check` (syntax check of every source file), `files` in
  `package.json`, this changelog.

### Changed

- The `*_LOCAL` source-constraint rule from 0.1.0 now applies to all non-WAN
  rulesets, and a source only counts if it matches the rule's address family
  (an IPv6 source does not narrow an IPv4 rule; a port group is not a
  source).
- Path-valued config keys (`rw_token_file`, `cloud_rw_key_file`,
  `local_rw_key_file`) must be strings; the error names the key.
- systemd unit: `TimeoutStopSec=45`, `RestartPreventExitStatus=2` (no restart
  loop on config errors), dropped the `network-online.target` dependency,
  which a user unit cannot use.

## [0.1.0] - 2026-10-18

First deployed version, built up over four commits on the same day.

### Added

- Write-enabled MCP server over Streamable HTTP on `127.0.0.1:18778`, meant
  to sit behind `tailscale serve`. Bearer token, Host and Origin allowlists,
  POST and JSON only, 256 KiB body cap.
- Two backends: the Site Manager cloud connector (`api.ui.com`, default) and
  the UDM on the LAN with TLS pinning or a CA file. Tools and the guard work
  on canonical paths, so decisions are identical for both.
- Request guard: explicit deny list, anchored allowlist, deep body scan, and
  per-endpoint checks for WiFi broadcasts, zone-based policies, legacy
  firewall rules, the network mDNS flag, AP radios, guest authorization and
  fixed IPs. WAN-side deny rules and policies can only be changed
  cosmetically. Zone classification comes from config only.
- Write log (`writes.log`) for every attempt, with secrets redacted and
  scrubbed. Upstream error bodies never reach the caller.
- Classic `/api/s/` tools grouped into the capabilities `firewallrule`,
  `fixed_ip` and `radio`, enabled per capability for the cloud backend with
  `cloud_allow_classic`.
- Read-only probe (`scripts/probe-classic.cjs`) that shows which classic
  endpoints answer through the configured backend, printing only shapes and
  counts.
