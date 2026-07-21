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

| Method  | Writes? | What it does                                                     |
| ------- | ------- | --------------------------------------------------------------- |
| `sync`  | no      | One resource per reservation the controller holds               |
| `drift` | no      | Compare a desired set: missing, mismatched, unmanaged, conflicts |
| `apply` | **yes** | Reconcile to the desired set; supports `dryRun`                  |

Handles MFA-enabled accounts (derives an RFC 6238 TOTP code per run) and catches
the failure mode where a reservation silently never takes effect because its
address is already claimed by a statically-configured host. Full usage,
arguments, and setup are in the
[extension README](./extensions/models/unifi-dhcp-reservation/README.md).

## Quick start

```bash
# Store the controller password (and TOTP seed, if the account uses MFA)
swamp vault create local_encryption udm
swamp vault put udm UNIFI_PASSWORD          # paste the admin password
swamp vault put udm UNIFI_TOTP_SECRET       # base32 seed; omit for a local-only admin

# Register the controller (wire secrets from the vault)
swamp model create @sntxrr/unifi/dhcp_reservation home-udm \
  --global-arg 'host=192.0.2.1' \
  --global-arg 'username=admin' \
  --global-arg 'password=${{ vault.get(udm, UNIFI_PASSWORD) }}' \
  --global-arg 'totpSecret=${{ vault.get(udm, UNIFI_TOTP_SECRET) }}'

# Read what the controller has (read-only)
swamp model @sntxrr/unifi/dhcp_reservation method run sync home-udm

# Compare a desired set without writing (read-only)
swamp model @sntxrr/unifi/dhcp_reservation method run drift home-udm \
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

## Development

```bash
~/.swamp/deno/deno check extensions/models/unifi-dhcp-reservation/unifi_dhcp_reservation.ts
~/.swamp/deno/deno test  --allow-run extensions/models/unifi-dhcp-reservation/unifi_dhcp_reservation_test.ts
swamp extension quality  extensions/models/unifi-dhcp-reservation/manifest.yaml --json
```

## License

MIT — see [LICENSE.md](./extensions/models/unifi-dhcp-reservation/LICENSE.md).
