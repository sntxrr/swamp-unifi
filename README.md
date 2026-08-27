# swamp-unifi

A [swamp](https://swamp-club.com) extension repo for a local **UniFi** network
controller (UDM / UDM Pro / UDM SE), using only Deno's built-in APIs plus
`curl` for the controller's self-signed TLS — no vendor SDK.

## Extensions

### [`@sntxrr/unifi-dhcp-reservation`](./extensions/models/unifi-dhcp-reservation/README.md)

Declarative DHCP fixed-IP reservations. Treats a desired reservation set as
data: read what the controller has, compare, then reconcile — so static
addressing stops drifting silently across in-guest config, controller
reservations, and device-local settings.

| Method       | Writes? | What it does                                                     |
| ------------ | ------- | ---------------------------------------------------------------- |
| `sync`       | no      | One resource per reservation the controller holds                |
| `inventory`  | no      | Every host the controller knows, clients and adopted hardware    |
| `drift`      | no      | Compare a desired set: missing, mismatched, unmanaged, conflicts |
| `verify`     | no      | Compare a desired set against live leases before writing         |
| `apply`      | **yes** | Reconcile to the desired set; supports `dryRun`                  |
| `set_pool`   | **yes** | Change the DHCP range; supports `dryRun`                         |
| `device_pin` | **yes** | Static device config for adopted APs/switches; supports `dryRun` |

Handles MFA-enabled accounts (derives an RFC 6238 TOTP code per run) and catches
the failure mode where a reservation silently never takes effect because its
address is already claimed by a statically-configured host. Reservations apply
to clients; adopted UniFi hardware is pinned through `device_pin` instead,
since the controller rejects reservations for anything it manages as a device. Full usage,
arguments, and setup are in the
[extension README](./extensions/models/unifi-dhcp-reservation/README.md).

## Quick start

An API key is the preferred credential: it performs no login exchange, so it
neither negotiates MFA nor spends a single-use TOTP code, and two methods can
run back to back without colliding. Password auth is still supported -- see
[Authentication](./extensions/models/unifi-dhcp-reservation/README.md#authentication)
if you cannot issue a key.

```bash
# Store an API key, issued under Settings -> Control Plane -> Integrations
swamp vault create local_encryption udm
swamp vault put udm UNIFI_API_KEY           # paste the API key

# Register the controller (wire the secret from the vault)
swamp model create @sntxrr/unifi/dhcp_reservation home-udm \
  --global-arg 'host=192.0.2.1' \
  --global-arg 'apiKey=${{ vault.get(udm, UNIFI_API_KEY) }}'

# Read what the controller has (read-only)
swamp model @sntxrr/unifi/dhcp_reservation method run sync home-udm

# Compare a desired set without writing (read-only)
swamp model @sntxrr/unifi/dhcp_reservation method run drift home-udm \
  --input-file desired.json

# Check the desired set against where hosts actually are (read-only)
swamp model @sntxrr/unifi/dhcp_reservation method run verify home-udm \
  --input-file desired.json

# Reconcile — always dry-run first
swamp model @sntxrr/unifi/dhcp_reservation method run apply home-udm \
  --input-file desired-dryrun.json    # desired.json plus "dryRun": true
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

## Scheduled watchers

Two read-only workflows ship with the extension, so drift gets noticed without
being asked:

```bash
swamp workflow run @sntxrr/unifi-drift-watch --input-file desired.json
swamp workflow run @sntxrr/unifi-device-drift-watch --input-file devices.json
```

| Workflow | Watches |
| --- | --- |
| `@sntxrr/unifi-drift-watch` | DHCP reservations, plus a dated host inventory |
| `@sntxrr/unifi-device-drift-watch` | Static pins on adopted APs and switches |

Both expect a `home-udm` controller instance and an `apprise` notifier instance,
and both stay silent unless something has actually drifted — notification is
gated on the finding via a step `guard`, not on run status. Neither carries a
trigger: the desired set lives in your file, not in the workflow. Details in the
[extension README](./extensions/models/unifi-dhcp-reservation/README.md#bundled-workflows).

> Upgrading from an earlier version: `drift` now writes to the data instance
> `drift` rather than `current`, which `inventory` also wrote. See the
> [breaking-change note](./extensions/models/unifi-dhcp-reservation/README.md#what-drift-reports).

## Development

```bash
~/.swamp/deno/deno check extensions/models/unifi-dhcp-reservation/unifi_dhcp_reservation.ts
~/.swamp/deno/deno test  --allow-run extensions/models/unifi-dhcp-reservation/unifi_dhcp_reservation_test.ts
swamp extension quality  extensions/models/unifi-dhcp-reservation/manifest.yaml --json
```

## License

MIT — see [LICENSE.md](./extensions/models/unifi-dhcp-reservation/LICENSE.md).
