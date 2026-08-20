# @sntxrr/unifi-fabric

Structural health monitoring for a UniFi fabric.

## Why this exists

A UniFi fabric degrades badly while every outcome-based check still reports
green. When an access point loses its wired uplink it does not fail — it
silently brings up a **wireless mesh uplink** and keeps serving clients. The
internet still works. The controller still shows every device "connected".
Uptime monitors stay green, because nothing is down.

What changed is a *structural* fact: `uplink.type` flipped from `wire` to
`wireless`. That is a boolean, not a threshold, so it can be asserted exactly —
no statistics, no tuning, no false positives.

The incident this was written for cascaded, which is why per-device checks miss
it:

1. A riser between two distribution switches drops.
2. The downstream switch loses its only path to the core.
3. The access point wired to that switch can no longer reach the controller over
   the wire, so it **meshes**.
4. The switch now reaches the network *backwards through the access point it
   powers*.

Three devices reported a changed parent. None reported a fault. The mesh
delivered usable throughput for days. The only outcome-level tell was latency —
sub-millisecond on the wire, 5–40 ms and jittery over the mesh — which is why
this model asserts on structure and leaves latency to a continuous prober that
can actually see jitter.

## What it checks

| Check | Catches |
| --- | --- |
| `wirelessUplinks` | A device expected on the wire that is meshing. The primary signal. |
| `parentMismatches` | Attached to the wrong upstream device — the cascade above, even where the type is still `wire`. |
| `slowUplinks` / `slowPorts` | Negotiated below the expected speed. A gigabit run that comes up at 100 is the classic two-pair cable-damage signature. |
| `erroringPorts` | Non-zero rx/tx counters — the physical layer complaining. |
| `darkPortsWithHistory` | Down, but has carried real traffic before. |

`darkPortsWithHistory` is the one with no equivalent in outcome-based
monitoring. Every never-patched port reads zero bytes forever, so a dark port
with a large byte count is a run that **used** to work. In the incident above it
was what located the dead riser: one port, down, with 973 GB behind it, among a
dozen dark ports that had never carried anything.

## Counters are totals, not rates

Error counters are cumulative since the device booted. A large total on a
long-uptime switch may be old scars from a fault already fixed — during the
incident above a port showed 1,277 receive errors that turned out to be frozen,
and the wrong theory that produced cost real time.

So `erroringPorts` is **informational and does not affect `inSync`**. Treat a
*rising* count as the signal: `rate()` over the pushed
`unifi_port_rx_errors_total` gauge separates an active fault from a healed one.

Likewise `darkPortsWithHistory` goes quiet after a device reboots, because the
byte counters reset. It finds a fresh break, not an old one.

## Usage

```bash
swamp model create @sntxrr/unifi-fabric/topology home-fabric
swamp model @sntxrr/unifi-fabric/topology method run check home-fabric \
  --input-file fabric-topology.json
```

Global arguments:

```yaml
globalArguments:
  host: 192.0.2.1
  apiKey: ${{ vault.get('unifi', 'API_KEY') }}
  site: default
```

Authentication is by **API key** (`X-API-KEY`), issued under
Settings → Control Plane → Integrations. UniFi OS rejects password logins on
MFA-enabled SSO accounts with HTTP 499; an API key sidesteps that entirely while
still reaching the classic Network API.

A topology declaration looks like this:

```json
{
  "links": [
    { "name": "sw-core", "expectUplink": "wire", "expectParent": "gw",
      "minUplinkSpeed": 1000 },
    { "name": "sw-edge", "expectUplink": "wire", "expectParent": "sw-core",
      "minUplinkSpeed": 1000 },
    { "name": "ap-low",  "expectUplink": "wire", "expectParent": "sw-edge",
      "minUplinkSpeed": 1000 },
    { "name": "ap-shed", "expectUplink": "wireless", "expectParent": "ap-low" }
  ],
  "ports": [
    { "device": "sw-core", "port": 11, "minSpeed": 1000,
      "label": "riser to sw-edge" }
  ]
}
```

Devices are matched on the leading label, so `sw-core` matches
`sw-core.example.internal`. Supply `mac` as well when a device may be renamed —
a MAC match wins over a name match.

Set `expectUplink: "wireless"` for a node that is *meant* to mesh, so deliberate
mesh does not alarm. Its `expectParent` is still checked, so a mesh node that
homes on the wrong peer is not silently accepted.

## Metrics

`check` emits a flat, Prometheus-ready series in `metrics` alongside the
verdict, so a push step can forward it without reshaping the document:

| Series | Labels |
| --- | --- |
| `unifi_uplink_is_wired` | `device`, `expected` |
| `unifi_uplink_speed_mbps` | `device` |
| `unifi_device_present` | `device` |
| `unifi_port_up` | `device`, `port`, `label` |
| `unifi_port_speed_mbps` | `device`, `port`, `label` |
| `unifi_port_rx_errors_total` / `..._tx_errors_total` | `device`, `port` |
| `unifi_fabric_in_sync` | — |

`unifi_uplink_is_wired` is emitted for **every** declared device, healthy ones
included. A metric that only appears when something breaks cannot be alerted on
with `== 0`, and the alert you want is exactly that:

```yaml
- alert: UnifiDeviceMeshing
  expr: unifi_uplink_is_wired{expected="wire"} == 0
  for: 10m
```

## Read-only

`check` never writes to the controller. It is safe to schedule against a
production fabric and safe to wire to an alerting path — there is no flag one
keystroke away from mutating anything.
