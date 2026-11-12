# unifi-mcp-rw

An MCP server that can make a small, fixed set of changes to the UniFi Network
application on a UniFi console such as a UDM (tested on Network 10.6.109,
written against the Network API 10.6.106 published at
[developer.ui.com](https://developer.ui.com/network/v10.6.106/gettingstarted)).
It is meant to run next to a read-only UniFi MCP server, listens on
`127.0.0.1:18778`, and is reached through a reverse proxy such as
`tailscale serve`. It talks to the console either through the Ubiquiti Site
Manager cloud connector (`api.ui.com`, the default) or directly to the UDM on
the LAN.

MIT licensed; see `LICENSE`. Use it at your own risk: it changes a live network.

## Why a separate server

A read-only UniFi MCP server stays exactly as it is. It answers questions
about the network and cannot change anything, which is the right default for
an assistant.

Some changes are worth delegating, though: toggling mDNS forwarding on a
network, adding an SSID, setting a fixed IP, allowing one network to reach a
couple of devices on another. This server lets an agent make that short list of
changes and nothing else. Keeping it separate means it has its own token, its
own API key, its own log, and can be stopped or switched to read-only without
touching the server everything else depends on.

What makes this safe enough is the guard (`lib/guard.cjs`). Every request,
reads included, passes through it before a socket is opened. It allows a
fixed list of endpoints and, for each write, inspects the full body that will
be sent: WAN rules and policies can't be weakened, accept rules may only name
private addresses and internal networks, WiFi must use WPA2/WPA3, a network
update may only change the mDNS flag, and so on. The tools enforce the same
rules in their input schemas, but the guard does not rely on them. Writes are
also off unless the config turns them on, and validated attempts, including
dry runs and guard refusals, are recorded in a log.

Three more safeguards sit in front of the guard (see Write safeguards): an
allowlist that decides which write tools exist at all, an optional per-call
write log at a path you choose, and a WAN-exposure check that refuses
anything that would let traffic in from the internet, whatever the caller
asks for.

## Upgrading from 0.2.1

0.3.0 adds the write safeguards. With no new environment variables set,
nothing changes for normal use: every write tool is still registered and
there is no extra log. Two things can differ:

- The WAN-exposure refusals are on by default. With the current tools, every
  write they refuse was already refused by the guard, so in practice only the
  error text changes
  (it now starts with `Refused:` instead of `Refused by guard:`).
- A legacy accept rule on a `WAN*` ruleset is no longer stopped by the tool's
  input schema but inside the tool, so the refusal now shows up in the logs.

For an agent that only needs the common changes, set `UNIFI_WRITE_TOOLS` to the
list in "Minimum allowlist" below, and point `UNIFI_WRITE_LOG` somewhere under the state directory. The
systemd unit has commented lines for both. Copy it again and run
`daemon-reload`.

## Upgrading from 0.2.0

0.2.1 only tightens the checks on legacy accept rules (see the guard rules
below and the changelog). A few accept rules that 0.2.0 allowed are now
refused, including updates to existing rules of that shape: a source given
only as a MAC address, an address field, group or networkconf type of the
other address family, a network reference with no private subnet in the
rule's family (IPv6 networks with a delegated or public prefix in
particular), and a network reference mixed with addresses on the same side.
Nothing else changes; copy the files and run `npm ci` as usual.

## Upgrading from 0.1.0

0.2.0 starts in read-only mode unless writes are enabled explicitly. The
a config written for 0.1.0 has no `allow_writes` key, so after the upgrade the
server will list only read tools and refuse every write. When upgrading, add

```json
"allow_writes": true
```

to `~/.config/unifi-connectivity/config.json`, then restart the service and
check the startup line in the journal for `mode=read-write`. The rest of the
upgrade is the usual copy and `npm ci` (see Install). Other changes that can
affect existing use:

- Legacy accept rules are checked much more strictly (see the guard rules
  below). A rule that names a public address, or no source at all, is now
  refused on every LAN and guest ruleset, not only on `*_LOCAL`.
- Creating or updating a legacy accept rule now also reads `rest/firewallgroup`
  and `rest/networkconf`. Both are classic reads under the `firewallrule`
  capability, so they count against the connector's rate limit (100 requests
  per minute per console).
- The systemd unit changed (`TimeoutStopSec`, `RestartPreventExitStatus`, no
  `network-online.target`). Copy it again and run `daemon-reload`.

## Tools

Read tools (always registered, subject to classic capabilities below):
`unifi_rw_get_info`, `unifi_rw_list_sites`, `unifi_rw_list_wifi_broadcasts`,
`unifi_rw_get_wifi_broadcast`, `unifi_rw_list_networks`,
`unifi_rw_get_network`, `unifi_rw_list_firewall_zones`,
`unifi_rw_list_firewall_policies`, `unifi_rw_get_firewall_policy`,
`unifi_rw_list_clients`, `unifi_rw_get_client`, and the classic-backed
`unifi_rw_list_legacy_firewall_rules`, `unifi_rw_list_firewall_groups`,
`unifi_rw_list_classic_networks`, `unifi_rw_list_access_points`,
`unifi_rw_list_fixed_ips`. Secrets in responses are redacted.

Write tools, registered only when writes are enabled, and then only those
`UNIFI_WRITE_TOOLS` names if it is set. All take `dry_run` (default `false`).
There is no per-call `confirm` argument: with write mode enabled, omitting
`dry_run` sends the write after the guard passes.

| Tool | What it sends |
|---|---|
| `unifi_rw_update_network` | GET, then PUT the network with only `mdnsForwardingEnabled` changed |
| `unifi_rw_create_wifi_broadcast` | POST a new SSID |
| `unifi_rw_update_wifi_broadcast` | GET, merge `changes`, PUT the full SSID (passphrase kept unless changed) |
| `unifi_rw_create_firewall_policy` / `update_` / `patch_` | Zone-based policy POST, GET+PUT, GET+PATCH (`loggingEnabled` only) |
| `unifi_rw_create_legacy_firewall_rule` / `update_` | Classic `rest/firewallrule` POST, or GET+merge+PUT |
| `unifi_rw_set_fixed_ip` / `clear_fixed_ip` | Classic `rest/user` PUT or POST |
| `unifi_rw_update_ap_radios` | Classic `rest/device/{_id}` PUT with `radio_table` only |
| `unifi_rw_authorize_guest` / `unauthorize_guest` | Client action POST |

Update tools read the current object first, merge the caller's changes, strip
read-only fields and send the whole object. The guard receives the object as it
was read and compares the result against it.

Classic `/api/s/` tools are grouped into three capabilities: `firewallrule`
(legacy rules, firewall groups, classic networks), `fixed_ip` (`rest/user`)
and `radio` (`stat/device`, `rest/device`). The local backend has all three.
The cloud backend has none unless `cloud_allow_classic` enables them, and the
client refuses classic paths of a disabled capability even if a tool tried.

Not offered at all: deletes, creating networks, device adopt/restart/upgrade
and port actions, port forwards and NAT, WAN, DDNS and UPnP settings, zone
changes, policy ordering, ACL rules, DNS policies, VPN, vouchers, controller
settings (SSH, remote access), admin accounts, backups, firewall group
changes.

## Install

Requires Node.js >=22.23.4. CI tests Node.js 22.23.5 and 24.22.3.

On the host that runs it:

```sh
mkdir -p ~/.local/share/unifi-mcp-rw ~/.local/state/unifi-mcp-rw
chmod 700 ~/.local/state/unifi-mcp-rw
cp -r http-server-rw.cjs lib scripts package.json package-lock.json ~/.local/share/unifi-mcp-rw/
(cd ~/.local/share/unifi-mcp-rw && npm ci --omit=dev)

umask 077
openssl rand -hex 32 > ~/.config/unifi-connectivity/mcp-rw-token
cat > ~/.config/unifi-connectivity/cloud-rw-key     # paste the Site Manager API key, Ctrl-D
chmod 600 ~/.config/unifi-connectivity/mcp-rw-token ~/.config/unifi-connectivity/cloud-rw-key
```

The Site Manager key comes from unifi.ui.com, Settings, API Keys. It carries
the rights of the account that created it, so that account needs admin rights
on the console. The `console_id` is the `id` of the console in
`curl -s -H "X-API-KEY: $(cat ~/.config/unifi-connectivity/cloud-rw-key)" https://api.ui.com/v1/hosts`.

Add this server's keys to the shared `~/.config/unifi-connectivity/config.json`
(keys it doesn't know are ignored); `config.example.json` shows the cloud form
and `config.local.example.json` the local one. Then install the unit:

```sh
cp unifi-mcp-rw.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now unifi-mcp-rw.service
journalctl --user -u unifi-mcp-rw -n 20
tailscale serve --bg --set-path /unifi-mcp-rw http://127.0.0.1:18778/unifi-mcp-rw
```

Set `MCP_PUBLIC_HOST` in the unit to the name the proxy serves (for
`tailscale serve`, the machine's `*.ts.net` name); requests for any other Host
are refused.

The last startup line looks like

```
unifi-mcp-rw: started version=0.3.0 node=v24.22.3 listen=http://127.0.0.1:18778 public_host=mcp-host.example.ts.net backend=cloud mode=read-only allow_writes_source=default classic=off config=/home/you/.config/unifi-connectivity/config.json console_id=0123…
```

In write mode it is preceded by a safeguards line, for example
`write safeguards: write_tools=all write_log=/home/you/.local/state/unifi-mcp-rw/write-calls.jsonl wan_exposure=refused`.

The server refuses to start (exit status 2, one line naming the problem) if
the config is invalid or a secret file is not a regular file owned by the
user with mode 0600. The unit does not restart on status 2. In user units the
sandboxing directives depend on unprivileged user namespaces; check what
applies with `systemd-analyze --user security unifi-mcp-rw.service`. If `node`
is not on the user manager's `PATH` (nvm, for example), put its absolute path
in `ExecStart`.

## Turning writes on safely

Writes need two things: write mode, and for classic tools on the cloud
backend, the capability.

1. **Write mode.** Set `"allow_writes": true` in config.json. The environment
   variable `UNIFI_ALLOW_WRITES` overrides the config in both directions:
   `true` or `1` turns writes on, `false` or `0` turns them off, and an empty
   or unset variable leaves the decision to the config. Any other value is
   ignored with a startup warning. The systemd unit has a commented
   `UNIFI_ALLOW_WRITES=false` line for forcing read-only mode without editing
   the config. In read-only mode no write tool is registered, and the client
   independently refuses every non-GET request, dry runs included.
2. **Classic capabilities (cloud only).** Whether classic endpoints work
   through the cloud connector with a Site Manager key has not been verified.
   Run the probe first; it only reads and prints shapes and counts, never
   values:
   ```sh
   cd ~/.local/share/unifi-mcp-rw && npm run probe -- --config ~/.config/unifi-connectivity/config.json
   ```
   If `rest/firewallrule`, `rest/firewallgroup` and `rest/networkconf` answer
   with 200, enable only what you need, e.g. `"cloud_allow_classic":
   ["firewallrule"]`.
3. **Dry run first.** Every write tool accepts `"dry_run": true`. The guard
   runs and the prerequisite reads happen, but the write is not sent; the
   response shows the exact method, URL and body (API key redacted).
4. **Watch the log.** `tail -f ~/.local/state/unifi-mcp-rw/writes.log` while
   making the first real change. Each line has the tool, its redacted
   arguments, the canonical endpoint, `dry_run`, and the outcome: an HTTP
   status, `refused`, `dry_run` or `error`.
5. **Register only what you need.** Set `UNIFI_WRITE_TOOLS` (next section) so
   that write tools you don't use don't exist.

## Write safeguards

These are set with environment variables rather than config.json, so they
can live in the systemd unit next to the service they protect and can't be
changed by whatever else edits the shared config. All of them are read once
at startup. A bad value stops the server with exit status 2 and one line
saying what is wrong. They only matter in write mode: in read-only mode
`UNIFI_WRITE_TOOLS` and `UNIFI_WRITE_LOG` are still checked, so a typo shows
up early, but are then ignored with a warning.

| Variable | Default | Meaning |
|---|---|---|
| `UNIFI_WRITE_TOOLS` | unset: every write tool | Comma-separated write tool names to register. `""` or `none` registers none. |
| `UNIFI_WRITE_LOG` | unset: off | Absolute path of a JSON Lines file that gets one line per write tool call. |
| `UNIFI_ALLOW_WAN_EXPOSURE` | unset: refusals on | `true` (any case) turns the WAN-exposure refusals off. Nothing else does. |
| `UNIFI_WAN_ZONE_IDS` | empty | Comma-separated zone UUIDs to treat as the WAN, on top of `firewall_wan_zone_ids`. |

When writes are on, a second startup line shows what is in effect, e.g.
`write safeguards: write_tools=all write_log=off wan_exposure=refused`.

### The write-tool allowlist (`UNIFI_WRITE_TOOLS`)

Leaving it unset registers every write tool, the same as upstream
`unifi-network-mcp` does with `UNIFI_NETWORK_WRITE_TOOLS` and the same as
0.2.x. Once it is set, only the write tools it names are registered. The
others are not hidden or disabled; they don't exist, and a call to one fails
as an unknown tool. Names are separated by commas, and spaces around them
don't matter. Read tools (`unifi_rw_list_*`, `unifi_rw_get_*`, including
`unifi_rw_list_fixed_ips`) are always registered and can't be listed. Naming
one, or a name that isn't a write tool at all, is a startup error that lists
the valid write tool names. Unlike upstream there are no group names; the
list is short enough to spell out.

Classic capabilities still apply on top. A listed classic tool on the cloud
backend only appears if `cloud_allow_classic` enables its capability.

The names live in one place, `lib/tool-names.cjs`. Registering a tool that
isn't listed there on the right side (read or write) throws, so the list
can't drift from the code.

### Minimum allowlist

What a typical home-network agent needs: SSIDs, the mDNS flag, the Sonos-style
legacy LAN rules and fixed IPs. Guest authorization, zone-based policies and
AP radio changes are left out.

```
unifi_rw_create_wifi_broadcast,unifi_rw_update_wifi_broadcast,unifi_rw_update_network,unifi_rw_create_legacy_firewall_rule,unifi_rw_update_legacy_firewall_rule,unifi_rw_set_fixed_ip,unifi_rw_clear_fixed_ip
```

That is:

- `unifi_rw_create_wifi_broadcast`
- `unifi_rw_update_wifi_broadcast`
- `unifi_rw_update_network`
- `unifi_rw_create_legacy_firewall_rule`
- `unifi_rw_update_legacy_firewall_rule`
- `unifi_rw_set_fixed_ip`
- `unifi_rw_clear_fixed_ip`

With it, `unifi_rw_authorize_guest`, `unifi_rw_unauthorize_guest`,
`unifi_rw_create_firewall_policy`, `unifi_rw_update_firewall_policy`,
`unifi_rw_patch_firewall_policy` and `unifi_rw_update_ap_radios` are not
registered. On the cloud backend the legacy rule and fixed IP tools also
need `"cloud_allow_classic": ["firewallrule", "fixed_ip"]`.

### The write log (`UNIFI_WRITE_LOG`)

One JSON line per write tool call: `ts` (UTC) and `ts_local`, `tool`, `args`
with secrets redacted, the canonical `method` and `endpoint` (no host,
console id or headers), `dry_run`, `outcome` (`ok`, `dry_run`, `refused` or
`error`), `status` when the controller answered, `reason` for refusals
(`guard` or `wan_exposure`), a short `error` summary, and `duration_ms`.

Two things are never logged. Bodies are never logged in either direction:
`args` is what the caller sent, not the merged object the server built from
the controller's copy, and controller responses don't appear at all. Secrets
are never logged either: any key that looks like a secret (`x_passphrase`,
`password`, anything with `key`, `token`, `secret`, and so on) is replaced by
`[REDACTED]`, and the API key and bearer token are scrubbed from the whole
line in case they turn up somewhere unexpected.

The path must be absolute; systemd and MCP hosts don't expand `~`. The file
is opened once at startup, created with mode 0600 (missing directories
0700), and appended to. Like upstream, the server refuses to start if the
path is a symlink (it is checked with `lstat` and opened with
`O_NOFOLLOW`), isn't a regular file, has other hard links, or is writable
by group or others. A FIFO or other special file is turned away before the
open, and the open is non-blocking, so nothing at that path can hang
startup. A file that others can read but not write is left as it is.

The directory gets checked too, since whoever controls it can swap the file
out. Every directory on the path must be a real directory, not a symlink,
so use the resolved path (on macOS that means `/private/var/...`, not
`/var/...`). The directory holding the file must belong to you or root, and
can't be writable by group or others unless it has the sticky bit, like
`/tmp`.

If a write to the log fails later (disk full, say), that is reported once
on stderr and tool calls carry on.

This is separate from `writes.log` in the state directory, which is always
on and records each controller write request. The write log is opt-in, goes
where you point it, and has one line per tool call, including calls refused
before any request was built. Under the systemd unit
(`ProtectHome=read-only`), the file has to be inside a `ReadWritePaths=`
directory; the state directory is the easy choice:

```ini
Environment=UNIFI_WRITE_LOG=%h/.local/state/unifi-mcp-rw/write-calls.jsonl
```

### WAN-exposure refusals (`UNIFI_ALLOW_WAN_EXPOSURE`, `UNIFI_WAN_ZONE_IDS`)

These are on by default and refuse:

- a zone-based firewall policy that would ALLOW traffic (any action other
  than BLOCK or REJECT, a missing one included) from the WAN zone, on create,
  update, or a patch that touches more than logging;
- an edit to the WAN zone, or a zone change that takes networks out of it;
- a network update that would move the network into or out of the WAN zone,
  or turn it into a WAN (`purpose: "wan"`);
- a legacy firewall rule on `WAN_IN`, `WAN_LOCAL`, `WANv6_IN` or
  `WANv6_LOCAL` whose action isn't `drop` or `reject`. On update, the merged
  rule is checked, so flipping an existing drop rule to accept is caught too.

Drop and reject rules on those rulesets are still allowed. Some of these
writes have no tool here (zone edits, network zone moves); they are checked
anyway in case one is added later.

The check runs inside the tool before the guard, before a dry run is
answered, and before anything is sent. A refusal starts with `Refused:`,
says why, and is logged with `reason: "wan_exposure"`. `dry_run` doesn't get
around it, and since every tool schema is strict there is no argument that
could. Upstream lets its `confirm` flag through only after the operator
turns the refusals off; this server has no confirm flag. The only switch is
`UNIFI_ALLOW_WAN_EXPOSURE=true` in the environment, which logs a warning at
startup. Even then the guard still refuses WAN accept rules and ALLOW
policies from the WAN on its own, so the variable mostly exists to match
upstream and to rule this layer out when debugging.

A zone counts as the WAN when its id is in `UNIFI_WAN_ZONE_IDS` or
`firewall_wan_zone_ids`, when it is system-defined and named External (what
the controller creates), or when it is named External, WAN or Internet. Names
can be edited, so the ids are the reliable signal. If the zones can't be
read, or a zone the change depends on isn't among them, the write is
refused. A zone id in both `UNIFI_WAN_ZONE_IDS` and
`firewall_internal_zone_ids` is a startup error.

Input-schema rejections happen before tool handlers and are not audited.
Audit logging is best effort: a storage failure emits `audit log write failed`
in the journal and does not prevent an otherwise allowed write.

## Examples

All examples use the MCP endpoint directly with curl. `$TOKEN` is the bearer
token; ids are placeholders.

```sh
TOKEN=$(cat ~/.config/unifi-connectivity/mcp-rw-token)
mcp() {
  curl -s https://mcp-host.example.ts.net/unifi-mcp-rw \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' -d "$1"
}
```

### mDNS forwarding toggle (dry run)

```sh
mcp '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
  "name":"unifi_rw_update_network",
  "arguments":{"network_id":"3f6c2a10-5b7e-4d2a-9c41-7e8d0a6b1c25",
               "changes":{"mdnsForwardingEnabled":true},"dry_run":true}}}'
```

The result text is a JSON object like

```json
{"dry_run": true, "backend": "cloud",
 "request": {"method": "PUT",
             "url": "https://api.ui.com/v1/connector/consoles/<console_id>/proxy/network/integration/v1/sites/<site>/networks/3f6c2a10-…",
             "headers": {"X-API-KEY": "[REDACTED]", "…": "…"},
             "body": {"name": "…", "mdnsForwardingEnabled": true, "…": "…"}}}
```

Drop `"dry_run":true` to send it. The body is the full network as read a
moment earlier, with only `mdnsForwardingEnabled` changed; the guard refuses
it if anything else differs.

### Worked example: Owner devices to the Sonos speakers

The goal: devices on the Owner network (192.168.50.0/24, VLAN 42) control the
Sonos speakers on Guest (VLAN 7, Isolate Network on). The site
runs the legacy firewall (the zone-based firewall is not configured), so this
takes two `LAN_IN` accept rules: one for new connections from Owner to the
speakers, and one that lets the speakers' replies back to Owner, limited to
established and related traffic. (`LAN_IN` assumes Guest is a
corporate network with isolation, which is what "Isolate Network" implies. A
network with purpose `guest` uses the `GUEST_*` rulesets instead;
`unifi_rw_list_classic_networks` shows the purpose.) This needs the `firewallrule` capability,
and classic writes through the connector are unverified, so start with dry
runs.

First find the classic `_id` of the Owner network. It is not the integration
network id.

```sh
mcp '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unifi_rw_list_classic_networks","arguments":{}}}'
```

Rule 1, Owner to the speakers. The speaker addresses below are placeholders
for their fixed IPs:

```sh
mcp '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
  "name":"unifi_rw_create_legacy_firewall_rule",
  "arguments":{"dry_run":true,"rule":{
    "name":"Owner to Sonos","enabled":true,"ruleset":"LAN_IN","action":"accept",
    "protocol":"all","logging":false,
    "src_networkconf_id":"<Owner _id>","src_networkconf_type":"NETv4",
    "dst_address":"192.168.7.20,192.168.7.21"}}}}'
```

Rule 2, replies from the speakers to Owner:

```sh
mcp '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
  "name":"unifi_rw_create_legacy_firewall_rule",
  "arguments":{"dry_run":true,"rule":{
    "name":"Sonos replies to Owner","enabled":true,"ruleset":"LAN_IN","action":"accept",
    "protocol":"all","logging":false,
    "state_established":true,"state_related":true,"state_new":false,"state_invalid":false,
    "src_address":"192.168.7.20,192.168.7.21",
    "dst_networkconf_id":"<Owner _id>","dst_networkconf_type":"NETv4"}}}}'
```

Two variations pass the guard as well. The Owner network can be given as
`"src_address":"192.168.50.0/24"` (and `"dst_address"` in rule 2) instead of
by id. The speakers can be an address group created in the UniFi UI (this
server cannot create groups); look up its `_id` with
`unifi_rw_list_firewall_groups` and use `"dst_firewallgroup_ids":["<id>"]` in
rule 1 and `"src_firewallgroup_ids":["<id>"]` in rule 2. Whether the
controller accepts a comma-separated list in `dst_address` has not been
verified; if it rejects it, use the group.

Before each write the tool reads the firewall groups and classic networks.
The guard then checks that the Owner id refers to an existing, non-WAN
network with a private IPv4 subnet, that every address is private, and that any
group exists and contains only private addresses. The dry-run response shows
the exact request. Without `rule_index` the controller places the rule; check
in the UniFi UI that both rules come before any `LAN_IN` drop rule matching
the same traffic. Sonos also relies on multicast discovery and may open
connections from a speaker to the phone running the app; if control still
fails with both rules in place, look at mDNS forwarding and at traffic in that
direction.

## Configuration

`config.json` may be shared with other UniFi tools on the same host; this server
reads only the keys below. Path: `~/.config/unifi-connectivity/config.json`,
or `$UNIFI_MCP_RW_CONFIG`.

| Key | Default | Meaning |
|---|---|---|
| `allow_writes` | `false` | Register write tools and allow non-GET requests. Overridden by `UNIFI_ALLOW_WRITES`. |
| `backend` | `"cloud"` | `"cloud"` (Site Manager connector) or `"local"` (UDM on the LAN) |
| `console_id` | required (cloud) | Console id from `GET https://api.ui.com/v1/hosts` |
| `cloud_rw_key_file` | `~/.config/unifi-connectivity/cloud-rw-key` | Site Manager API key, mode 0600 |
| `cloud_allow_classic` | `false` | `false`, `true` (all) or a subset of `["firewallrule", "fixed_ip", "radio"]` |
| `local_host` | required (local) | UDM hostname or IPv4, optional `:port` |
| `local_tls_cert_sha256` / `local_tls_ca_file` | system CA | Certificate pin, or CA file, for the UDM (one of them) |
| `local_rw_key_file` | `~/.config/unifi-connectivity/local-rw-key` | UDM integration API key, mode 0600 |
| `site_id` (`local_site_id`) | the only site | Integration site UUID |
| `site_name` (`local_site_name`) | `"default"` | Classic site name |
| `rw_token_file` | `~/.config/unifi-connectivity/mcp-rw-token` | MCP bearer token, mode 0600, at least 32 characters |
| `rw_listen_host` / `rw_listen_port` | `127.0.0.1` / `18778` | Loopback only |
| `firewall_internal_zone_ids` / `firewall_wan_zone_ids` | empty | Zone UUIDs for zone-based policies (see guard rules) |

Environment: `UNIFI_ALLOW_WRITES` (see above), `UNIFI_MCP_RW_CONFIG` (config
path), `UNIFI_MCP_RW_STATE_DIR` (directory of `writes.log`, default
`~/.local/state/unifi-mcp-rw`), and the write safeguards `UNIFI_WRITE_TOOLS`,
`UNIFI_WRITE_LOG`, `UNIFI_ALLOW_WAN_EXPOSURE` and `UNIFI_WAN_ZONE_IDS` (see
Write safeguards). In cloud mode the host is always
`api.ui.com:443` with normal certificate verification; keys such as
`cloud_host` or `cloud_tls_*` are refused, and `local_*` keys are ignored with
a warning. Every value is validated at startup and errors name the key.

## Guard rules

The guard sees canonical paths (`/integration/v1/…` or `/api/s/{site}/…`).
The backend prefix (`/proxy/network`, or
`/v1/connector/consoles/{id}/proxy/network`) is added afterwards and the full
path is checked again, so both backends get the same decisions. In order:

1. **Path and method.** Only `GET`, `POST`, `PUT`, `PATCH`; `DELETE` never.
   No `..`, `//`, `.` segments, percent-encoding, backslashes, `;`, control
   characters or fragments. Query strings only on GET and only `offset`,
   `limit`, `filter`. A canonical path that already contains a proxy or
   connector prefix, or names another console app, is refused.
2. **Deny list**, for clear refusal messages: device commands, firmware,
   deletes, port forwards, `rest/networkconf` writes, WAN, DDNS, UPnP, admin
   and settings endpoints, remote access, zone writes, policy ordering, ACL
   rules, DNS policies, VPN, vouchers, RADIUS.
3. **Allowlist.** Anchored patterns for exactly the paths the tools use, plus
   GET-only reads used by the probe. Everything else is refused.
4. **Body scan.** Write bodies must be JSON objects. Keys like `ssh*`,
   `mgmt*`, `remote_access*`, `firmware*`, `port_forward*`, `upnp*` and
   `__proto__` are refused at any depth, as is the literal `"[REDACTED]"`, so
   a redacted read can never be written back.
5. **Per-endpoint checks**, described below. Every update needs the object as
   read just before (`context.existing`), with its own id equal to the id in
   the path; otherwise it is refused.

**Legacy firewall rules** (classic `rest/firewallrule`; on this site the live
firewall). `ruleset` must be one of the 18 classic rulesets (`WAN`, `LAN`,
`GUEST`, each with `v6` variants, each `IN`, `OUT`, `LOCAL`) and `action` one
of `accept`, `drop`, `reject`. Only known rule fields are allowed, each with
a type check; unknown fields are refused, so a rule the controller returns
with an unfamiliar field cannot be edited here. Rules marked `attr_no_edit`
are never edited.

- No accept on any `WAN*` ruleset. New `WAN*` rules may not set
  `rule_index`. An existing `WAN*` drop or reject rule may only change `name`
  and `logging`. A rule never moves out of a `WAN*` ruleset, and `rule_index`
  never changes on one.
- An accept rule on any other ruleset must name its source in the rule's own
  address family: `src_networkconf_id`, an address group in
  `src_firewallgroup_ids` (`address-group` for IPv4 rulesets,
  `ipv6-address-group` for v6), or `src_address` (`src_address_ipv6` for v6).
  A port group alone does not count, and neither does `src_mac_address`: a
  MAC may be added to one of the above as an extra restriction, but it says
  nothing about where the traffic comes from.
- Everything an accept rule uses to select addresses must be of the
  ruleset's family. IPv4 rulesets (`LAN_IN`, `GUEST_OUT`, ...) take
  `src_address`/`dst_address`, `address-group` groups, and networkconf types
  `NETv4`/`ADDRv4`. v6 rulesets (`LANv6_IN`, ...) take
  `src_address_ipv6`/`dst_address_ipv6`, `ipv6-address-group` groups, and
  `NETv6`/`ADDRv6`. Port groups fit both. Anything of the other family is
  refused, not ignored.
- In the classic rule model `*_networkconf_type` qualifies
  `*_networkconf_id`: `NET` is the network's subnet, `ADDR` the gateway's
  address on it. A non-empty id needs a type. An empty id with a type of the
  right family is how the controller stores rules without a network
  reference; that is allowed and does not count as a source. A network
  reference cannot be combined with an address or address group on the same
  side, since the UniFi UI never produces that and it is unclear which one
  the controller would match.
- Every address in an accept rule (`src_address`, `dst_address`, and the
  `_ipv6` fields; single addresses, CIDRs, `a-b` ranges and comma-separated
  lists of them) must lie entirely inside one private block: 10.0.0.0/8,
  172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16, fc00::/7,
  fe80::/10. 100.64.0.0/10 is shared address space; it is included because
  Tailscale assigns tailnet addresses from it. Public addresses, `0.0.0.0/0`,
  `::/0` and anything malformed are refused.
- Accept rules may not negate: `!` in an address or port, and
  `protocol_match_excepted: true`, are refused. Ports must be 1-65535.
- Firewall groups and networks are resolved from data the tool reads right
  before the write. Every referenced group must exist; address groups may
  contain only private addresses, port groups only valid ports, other group
  types are refused. A referenced network must exist, have purpose
  `corporate`, `guest`, `vlan-only`, `remote-user-vpn` or `site-vpn` (so `wan`,
  `vpn-client` and unknown purposes are refused), and a private subnet in the
  family the networkconf type selects. For `NETv4`/`ADDRv4` that is
  `ip_subnet`. For `NETv6`/`ADDRv6` the network must have
  `ipv6_interface_type: "static"` and an `ipv6_subnet` (and
  `ipv6_static_subnet`, if present) inside fc00::/7 or fe80::/10. A missing
  or malformed subnet is refused, as is a network whose IPv6 prefix is
  delegated from the WAN (`ipv6_interface_type: "pd"`): the prefix is not in
  the network record and is normally public. For IPv6 accept rules on such
  networks, name ULA addresses in `src_address_ipv6`/`dst_address_ipv6` or
  use an `ipv6-address-group` instead. If the lookup failed, the rule is
  refused and the reason is included.
- The destination may be left out. On `*_IN` that means any destination the
  traffic from that internal source is routed to; on `*_OUT` it means any
  destination on that side. Both are common (a broad reply rule, for
  example) and are allowed deliberately. If a destination is given it is
  checked like the source.
- Drop and reject rules may name public or negated addresses; blocking them
  is harmless.

**Zone-based policies.** The zone object carries no reliable type and names
can be edited, so zones are classified by id in config
(`firewall_internal_zone_ids`, `firewall_wan_zone_ids`, from
`unifi_rw_list_firewall_zones`). ALLOW policies need both ends in the internal
list and present on the controller; without that list every ALLOW is refused.
When `firewall_internal_zone_ids` is missing, null or empty, startup warns:
`firewall_internal_zone_ids not set: zone-based ALLOW policies will be refused, and every BLOCK/REJECT policy is treated as WAN-side (cosmetic changes only)`.
New BLOCK/REJECT policies are still allowed when the zones can be fetched;
the cosmetic-only restriction applies to updates of existing deny policies.
A BLOCK or REJECT policy whose source is not a configured internal zone may
only change `name`, `description` and `loggingEnabled`. A zone named
External, WAN or Internet is always treated as WAN. PATCH may only set
`loggingEnabled`.

**WiFi broadcasts.** Security must be WPA2 or WPA3 (personal or enterprise);
open and OWE networks are refused. A new SSID must bind to a named network
(`{"type": "SPECIFIC", "networkId": …}`), not the default network, and may not
have hotspot or captive-portal settings. Updates may not change the type, the
network binding, client isolation or portal settings.

**Networks.** Only `mdnsForwardingEnabled` may differ from the current
object. Everything else in the network DTO affects addressing, reachability or
exposure.

**AP radios, fixed IPs, guests.** Radio updates send only `radio_table`, only
for radios the AP has, and only `channel`, `ht`, `tx_power_mode`, `tx_power`,
`min_rssi_enabled`, `min_rssi` within fixed ranges. Fixed-IP writes may only
touch `mac`, `use_fixedip`, `fixed_ip`, `network_id`, `name`, `note`. Guest
actions are limited to authorize and unauthorize, with the limits from the
10.6.106 spec.

Refusals come back as tool errors starting with `Refused by guard:` and are
logged with status `refused`. Upstream error responses are reduced to
`{"status", "code", "message"}` with a fixed message per status, and the API
key and bearer token are scrubbed from everything sent to the caller or
written to the log.

## HTTP layer

Checks run in this order: Host, Origin, path, method, bearer token,
Content-Type, size, JSON. Allowed hosts are `localhost:18778`,
`127.0.0.1:18778`, and the proxy's name from `MCP_PUBLIC_HOST` (with or without
`:443`), if set; an Origin header, if present, must be `https://` plus that name
or a loopback URL.
Paths are `/mcp` and `/unifi-mcp-rw`. Only POST with `application/json`, at
most 256 KiB. Clients must send `Accept: application/json, text/event-stream`
(an SDK requirement; otherwise 406). The MCP transport is created per request
(stateless, JSON responses). Internal errors return a fixed `Internal error`; details go only
to the journal.

On SIGTERM the server stops accepting connections, refuses new writes, and
gives in-flight requests up to 35 seconds (just above the 30-second cloud
timeout) before closing what is left. The unit allows 45 seconds.

## Verification status

Verified on 2026-10-18 on a UDM through the cloud
connector (backend `cloud`, `cloud_allow_classic: false`, no zone ids
configured):

- `GET /integration/v1/sites` returned 200 with one site, `Default`.
- `unifi_rw_update_network` toggled `mdnsForwardingEnabled` on one network in
  both directions, HTTP 200 each time. The readback showed only that field
  changed; the full-object PUT did not reset server-managed fields.
- `unifi_rw_create_wifi_broadcast` created an SSID through the connector at
  6:26 PM ET.
- So integration API writes work through the connector, and the Site Manager
  key has write rights on this console.

The site has the zone-based firewall not configured (`firewall/policies` and
`firewall/zones` return 400), so the legacy rules are the live firewall, and
the integration API has no endpoints for them.

Verified on 2026-11-04 with 0.3.0 deployed (backend `cloud`,
`cloud_allow_classic` for `firewallrule` and `fixed_ip`, write log on):

- Classic reads through the connector: `unifi_rw_list_legacy_firewall_rules`
  (10 rules), `unifi_rw_list_fixed_ips` (3) and
  `unifi_rw_list_firewall_groups` (none) returned without error.
- A dry-run `unifi_rw_create_legacy_firewall_rule` with `WAN_IN` / `accept`
  was refused by the WAN-exposure check before any request, and the write
  log recorded it as `outcome: refused`, `reason: wan_exposure`.

Not verified: any classic `/api/s/` write, through the connector or with a
UDM API key on the LAN, and any classic read with a LAN API key. That covers
writes to legacy rules, firewall groups, classic networks, fixed IPs and AP
radios. The other integration writes (WiFi update,
zone-based policies, guest actions) follow the 10.6.106 OpenAPI spec at
developer.ui.com but have not been exercised live.

## Limitations

- The guard trusts the reads it is given. The current object, the zone list,
  firewall groups and networks are read by the tool just before the write; a
  compromised controller, or another admin changing something between the
  read and the write, could make that data stale or false. Zone
  classification comes from config only.
- "Private" is not the same as "internal". If the ISP uses CGNAT, the WAN side
  of the gateway may itself be in 100.64.0.0/10; with double NAT it may be in
  192.168.0.0/16. A LAN or guest accept rule still cannot open inbound WAN
  traffic, because that is filtered by `WAN_IN`/`WAN_LOCAL`, where accept is
  refused and existing drop rules are frozen, and port forwards are denied.
- LAN and guest rules can still change reachability between internal networks.
  That is their purpose, and it is why each one should go through a dry run
  and a look at the UniFi UI.
- An existing accept rule that breaks the new rules (made in the UI with a
  public address, say) cannot be edited here, only turned into drop or reject.
  Use the UniFi UI for it.
- Firewall groups can only be created and edited in the UniFi UI.
- Networks without an `ip_subnet` (`vlan-only`, and `site-vpn` networks,
  which list their remote subnets elsewhere) cannot be referenced by id in
  an accept rule; name their addresses instead. The same goes for IPv6
  networks with a delegated or public prefix, which covers most IPv6 setups
  on a residential connection. The IPv6 checks are based on the classic
  networkconf fields as documented by the community, not on a live record
  from this site; a controller that stores the IPv6 subnet under another
  field name will see such references refused, not allowed.
- If the controller stores a networkconf type of the other family on rules
  that reference no network (`NETv4` on a v6 rule, say), accept rules of
  that kind made in the UI cannot be edited here.
- AP radio updates: if the controller replaces rather than merges
  `radio_table` entries, per-radio settings this tool does not send (antenna
  gain, sensitivity) may revert to defaults. Try it on one AP first.
- An existing zone-based ALLOW policy from a WAN or non-internal zone cannot
  remain ALLOW on a full update, even when disabling it. It can be changed
  to BLOCK/REJECT; PATCH may change only its logging flag.
- The WAN-exposure check relies on the same reads as the guard (zone list,
  current object), so the first point applies to it too. It knows the WAN
  zone by id only if you configure it; otherwise it goes by the zone's name
  and origin.
- `UNIFI_WRITE_TOOLS` decides what is registered. It is not a second check
  in the client: a tool that is registered can send whatever the guard
  allows.
- There is no client-side rate limiter. An update makes two or three requests;
  creating a legacy accept rule makes three, updating one four.

## Development

```sh
npm test         # node --test test/*.test.cjs
npm run check    # node --check on every source file
```

Tests use `node:test` only and contact nothing but localhost: the guard
matrix, replayed through local and cloud clients to show identical
decisions; the HTTP gate; a real server process on an ephemeral loopback
port (startup line, read-only and read-write modes, config errors, SIGTERM
drain, the write safeguards); config and secret-file validation; dry runs
through the full MCP stack; the write-tool allowlist, write log and
WAN-exposure refusals; the Sonos rule pair and its refusals; the probe; and TLS behaviour
against local TLS servers with throwaway certificates (skipped if `openssl`
is missing). The test glob is expanded by the shell. CI uses the Node.js
versions listed under Install.
