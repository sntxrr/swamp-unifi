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
| `drift` | no | Compare a desired set against the controller. |
| `apply` | **yes** | Reconcile the controller to the desired set. Supports `dryRun`. |

### What `drift` reports

- **missing** — desired, but the controller has no reservation at all
- **mismatched** — reserved, but pinned to a different address than desired
- **unmanaged** — reserved on the controller, absent from the desired set
  (informational; does not by itself count as drift)
- **poolConflicts** — desired addresses that fall **inside** the DHCP range
- **duplicates** — one address claimed by more than one MAC

`inSync` is true when `missing`, `mismatched` and `duplicates` are all empty.

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
  --arguments-file desired.json

# reconcile — always dry-run first
swamp model @sntxrr/unifi/dhcp_reservation method run apply home-udm \
  --arguments-file desired.json --arguments '{"dryRun": true}'
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
