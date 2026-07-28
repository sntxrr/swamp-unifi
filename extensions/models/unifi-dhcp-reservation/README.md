# @sntxrr/unifi-dhcp-reservation

Declarative DHCP fixed-IP reservations on a local UniFi controller
(UDM / UDM Pro / UDM SE).

UniFi stores reservations on the legacy Network API as `user` objects carrying
`use_fixedip` and `fixed_ip`. This model treats a desired reservation set as
data: read what the controller has, compare, then reconcile.

## Why

A homelab typically ends up with static addressing spread across three places
that nothing reconciles — in-guest config (LXC `ip=`, VM netplan), controller
reservations, and device-local settings. Nothing detects when they disagree, so
a lease quietly moves and whatever hardcoded the old address breaks silently.

`drift` is the answer to that: it is read-only, safe to run on a schedule, and
reports the disagreements before they become outages.

## Methods

| Method | Writes? | Purpose |
| --- | --- | --- |
| `sync` | no | Store one resource per reservation the controller holds. |
| `inventory` | no | Every host the controller knows, clients and adopted hardware. |
| `drift` | no | Compare a desired set against the controller's reservations. |
| `verify` | no | Compare a desired set against live DHCP leases. |
| `apply` | **yes** | Reconcile the controller to the desired set. Supports `dryRun`. |
| `set_pool` | **yes** | Change the DHCP range. Supports `dryRun`. |
| `device_pin` | **yes** | Static address in device config for adopted hardware. Supports `dryRun`. |

`drift` and `verify` answer different questions. `drift` asks *what has the
controller been told?*; `verify` asks *where are these hosts actually sitting
right now?* A desired set can be perfectly consistent with the reservation
table and still be wrong about reality.

### What `drift` reports

- **missing** — desired, but the controller has no reservation at all
- **mismatched** — reserved, but pinned to a different address than desired
- **unmanaged** — reserved on the controller, absent from the desired set
  (informational; does not by itself count as drift)
- **poolConflicts** — desired addresses that fall **inside** the DHCP range
- **duplicates** — one address claimed by more than one MAC

`inSync` is true when `missing`, `mismatched` and `duplicates` are all empty.

### What `verify` reports

- **confirmed** — host is online at exactly the desired address
- **moved** — host is online at a *different* address than the set expects
- **offline** — MAC is not currently visible, so nothing can be confirmed
- **occupied** — the desired address is currently held by a **different**
  device, so reserving it would collide

`safeToApply` is true when `occupied` is empty.

This is the check to run before reserving hosts *in place* from an earlier
audit. Unreserved hosts are precisely the ones that drift, so an address
recorded days ago may since have been leased to something else — `moved` says
the set is stale, `occupied` says applying it would take an address away from a
live device.

Two hosts swapping addresses is not reported as `occupied`: both are managed, so
the set resolves itself. A MAC that is offline is reported as such rather than
assumed correct — the controller only reports addresses for hosts it can see,
and silence is not confirmation. Adopted UniFi hardware (APs, switches) is read
from `/stat/device` as well as `/stat/sta`, since it is not a "client".

### The failure mode this exists to catch

A reservation whose address is already owned by a **statically configured** host
is silently refused — the controller keeps leasing the client some other
address, and the reservation looks correct in the UI while never taking effect.
Because the controller has no idea static hosts exist, it will also happily
hand out an address a static host already owns.

`duplicates` catches the first case in the desired set before `apply` runs;
`poolConflicts` catches the second. `apply` refuses outright to run against a
desired set that assigns one address to multiple MACs, rather than letting the
last write win.

### Two mechanisms, not one

Reservations only work for **clients**. Adopted UniFi hardware — APs, switches
— is managed by the controller as a *device*, and a reservation for one is
rejected with `api.err.FixedIpAlreadyUsedByDevice`. Those get `device_pin`,
which writes `config_network` directly. `verify` reports them as
`adoptedDevices` so a mixed desired set fails the pre-flight rather than
producing a 400 per device mid-write.

Adopted hardware also never appears on `/stat/sta`, only `/stat/device`, so
anything reading just the client table reports every AP as offline.

### What `set_pool` reports

Narrowing a range moves nothing by itself — existing leases are kept until they
expire. What matters is who is left holding an address the new range no longer
covers:

- **displaced** — held a lease from the *old* pool that the new one excludes.
  Unreserved ones re-lease inside the new range at expiry; reserved ones keep
  their address, since out-of-pool reservations are honoured.
- **strandedReservations** — reservations still inside the shrunken range.

An address that was already outside the old pool is deliberately **not**
reported as displaced. It was never leased — it is static on the host, or an
out-of-pool reservation — so the change is a no-op for it. Saying "will
re-lease" there would be wrong: there is no lease to expire. The controller
cannot distinguish a static address from a leased one (both just appear on
`/stat/sta`), so old-pool membership is the only available proxy.

## Authentication

| Account type | Configuration |
| --- | --- |
| Local-only admin (no MFA) | `host`, `username`, `password` |
| UniFi SSO account with MFA | the above plus `totpSecret` |

UniFi SSO accounts with MFA enabled reject password-only logins with
`{"code":"MFA_AUTH_REQUIRED"}`. Supply the base32 `totpSecret` and the model
derives an RFC 6238 code per run, so it works unattended. Both `password` and
`totpSecret` are marked sensitive and are redacted from logs and error text.

A local-only admin is the lower-risk option where you can create one — it
scopes the credential to the controller and avoids storing a long-lived TOTP
seed.

## Usage

```bash
swamp model create @sntxrr/unifi/dhcp_reservation home-udm

# read-only
swamp model @sntxrr/unifi/dhcp_reservation method run sync home-udm
swamp model @sntxrr/unifi/dhcp_reservation method run drift home-udm \
  --input-file desired.json
swamp model @sntxrr/unifi/dhcp_reservation method run verify home-udm \
  --input-file desired.json

# what is sitting at an address, and what vendor is it?
swamp model @sntxrr/unifi/dhcp_reservation method run inventory home-udm \
  --arguments '{"ips": ["192.0.2.234"]}'

# reconcile — always dry-run first
swamp model @sntxrr/unifi/dhcp_reservation method run apply home-udm \
  --input-file desired-dryrun.json

# narrow the DHCP range, rehearsing first
swamp model @sntxrr/unifi/dhcp_reservation method run set_pool home-udm \
  --arguments '{"start":"192.0.2.23","stop":"192.0.2.199","dryRun":true}'

# pin adopted hardware, which cannot hold a reservation
swamp model @sntxrr/unifi/dhcp_reservation method run device_pin home-udm \
  --input-file fabric-dryrun.json
```

`fabric-dryrun.json`:

```json
{
  "devices": [
    { "mac": "02:00:5e:00:53:07", "ip": "192.0.2.12", "name": "ap-back" }
  ],
  "netmask": "255.255.255.0",
  "gateway": "192.0.2.1",
  "dns1": "192.0.2.7",
  "dryRun": true
}
```

`desired.json`:

```json
{
  "desired": [
    { "mac": "02:00:5e:00:53:01", "ip": "192.0.2.201", "name": "app-server" },
    { "mac": "02:00:5e:00:53:02", "ip": "192.0.2.202", "name": "bridge-host" }
  ]
}
```

`dryRun` is passed in the same input file — copy `desired.json` to
`desired-dryrun.json` and add `"dryRun": true` at the top level alongside
`"desired"`.

MAC addresses are normalised, so `02:00:5E:00:53:01`, `02-00-5e-00-53-01` and
`02005e005301` all match the same client.

## Notes

- Uses `curl` rather than `fetch` because UDM controllers present self-signed
  certificates and Deno's `fetch` cannot skip TLS verification.
- Targets the legacy Network API via `/proxy/network/api/s/<site>/rest/user`.
  The cloud Site Manager API cannot manage reservations.
- `apply` fans out over every entry in a single execution, acquiring the model
  lock once, rather than one run per reservation.

## Credits

The UniFi API client is derived from
[`@mgreten/unifi`](https://github.com/meagerfindings/swamp-unifi)'s
`_lib/unifi.ts` (MIT, Copyright (c) 2026 Mat Greten), extended here with
TOTP/MFA support.

## License

MIT — see [LICENSE.md](LICENSE.md).
