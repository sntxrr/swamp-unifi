/**
 * Structural health monitoring for a UniFi fabric.
 *
 * A UniFi fabric degrades badly while every outcome-based check still reports
 * green. When an access point loses its wired uplink it does not fail — it
 * silently brings up a wireless mesh uplink and keeps serving clients. The
 * internet still works, the controller still shows every device "connected",
 * and uptime monitors stay green, because nothing is down. What changed is a
 * *structural* fact: `uplink.type` flipped from `wire` to `wireless`. That is a
 * boolean, not a threshold, so it can be asserted exactly — no statistics, no
 * tuning, no false positives.
 *
 * The failure this was written for cascaded, which is why per-device checks
 * miss it. A riser between two distribution switches dropped; the downstream
 * switch lost its only path to the core; the access point wired to that switch
 * could no longer reach the controller over the wire, so it meshed; and the
 * switch then reached the network *backwards through the access point it
 * powers*. Three devices reported a changed parent, none reported a fault, and
 * the mesh delivered usable throughput for days. The only outcome-level tell was
 * latency — sub-millisecond on the wire, 5-40ms and jittery over the mesh —
 * which is why this model asserts on structure and leaves latency to a
 * continuous prober that can actually see jitter.
 *
 * Six independent checks, roughly in order of how specific they are:
 *
 *   - `wirelessUplinks`      a device expected on the wire that is meshing.
 *                            Zero-noise, and the highest-value signal here.
 *   - `parentMismatches`     attached to the wrong upstream device. Catches the
 *                            cascade above even where the type is still `wire`.
 *   - `slowUplinks`,
 *     `slowPorts`            negotiated below the expected speed. A gigabit run
 *                            that comes up at 100 is the classic two-pair
 *                            cable-damage signature.
 *   - `erroringPorts`        non-zero rx/tx counters — the physical layer
 *                            complaining.
 *   - `darkPortsWithHistory` down, but has carried real traffic before. Every
 *                            never-patched port reads zero bytes forever, so a
 *                            dark port with a large byte count is a run that
 *                            *used* to work. This is what located the riser in
 *                            the incident above, and it has no equivalent in any
 *                            outcome-based check.
 *
 * Error counters are cumulative since the device booted, so `erroringPorts`
 * reports a total, not a rate. A large total on a long-uptime switch may be old
 * scars from a fault already fixed — during the incident above a port showed
 * 1,277 receive errors that turned out to be frozen, and the wrong theory it
 * produced cost real time. Treat a *rising* count as the signal, which is what
 * the Prometheus series in `metrics` is for: `rate()` over the pushed gauge
 * separates an active fault from a healed one. `inSync` deliberately does not
 * gate on error totals for this reason.
 *
 * Authentication is by API key (`X-API-KEY`), not username/password. UniFi OS
 * rejects password logins on MFA-enabled SSO accounts with HTTP 499, and an API
 * key sidesteps that entirely while still reaching the classic Network API.
 * Issue one under Settings → Control Plane → Integrations.
 *
 * @module
 */

import { z } from "npm:zod@4";

const GlobalArgsSchema = z.object({
  host: z.string().describe(
    "UniFi OS console IP or hostname, e.g. 192.0.2.1",
  ),
  apiKey: z.string().meta({ sensitive: true }).describe(
    "API key issued under Settings → Control Plane → Integrations (use a " +
      "vault reference). Preferred over password auth, which MFA-enabled SSO " +
      "accounts reject with HTTP 499.",
  ),
  site: z.string().default("default").describe("UniFi site name"),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

/** How one device is expected to be attached to the fabric. */
const DesiredLinkSchema = z.object({
  name: z.string().describe(
    "Device name as the controller reports it. Matched on the leading label, " +
      "so `sw-core` matches `sw-core.example.internal`.",
  ),
  mac: z.string().optional().describe(
    "Device MAC (any separator style). Preferred over name when present, " +
      "since a device can be renamed but not re-MACed.",
  ),
  expectUplink: z.enum(["wire", "wireless"]).default("wire").describe(
    "How this device should reach the fabric. Set `wireless` only for a " +
      "deliberate mesh node, so intentional mesh does not alarm.",
  ),
  expectParent: z.string().optional().describe(
    "Leading label of the device this one should uplink through. Omit to " +
      "accept any parent.",
  ),
  minUplinkSpeed: z.number().optional().describe(
    "Minimum acceptable negotiated uplink speed in Mbit/s, e.g. 1000.",
  ),
});

/** A switch port whose negotiated speed is worth asserting. */
const DesiredPortSchema = z.object({
  device: z.string().describe("Leading label of the switch."),
  port: z.number().describe("Port index as the controller numbers it."),
  minSpeed: z.number().optional().describe(
    "Minimum acceptable negotiated speed in Mbit/s.",
  ),
  label: z.string().optional().describe(
    "What is on the port, for readable alerts, e.g. 'riser to sw-edge'.",
  ),
});

const FabricSchema = z.object({
  checkedAt: z.string(),
  inSync: z.boolean(),
  deviceCount: z.number(),
  declaredCount: z.number(),
  wirelessUplinks: z.array(z.object({
    name: z.string(),
    parent: z.string().optional(),
    rssi: z.number().optional(),
  })).describe("Expected on the wire, currently meshing. The primary signal."),
  parentMismatches: z.array(z.object({
    name: z.string(),
    expected: z.string(),
    actual: z.string().optional(),
  })).describe("Attached to an unexpected upstream device."),
  slowUplinks: z.array(z.object({
    name: z.string(),
    speed: z.number().optional(),
    expected: z.number(),
  })).describe("Uplink negotiated below the declared minimum."),
  slowPorts: z.array(z.object({
    device: z.string(),
    port: z.number(),
    speed: z.number().optional(),
    expected: z.number(),
    label: z.string().optional(),
  })).describe("Declared port negotiated below its minimum."),
  erroringPorts: z.array(z.object({
    device: z.string(),
    port: z.number(),
    rxErrors: z.number(),
    txErrors: z.number(),
    label: z.string().optional(),
  })).describe(
    "Non-zero error counters. Cumulative totals, not rates — informational, " +
      "does NOT affect inSync. Alert on the rate via the pushed metric.",
  ),
  darkPortsWithHistory: z.array(z.object({
    device: z.string(),
    port: z.number(),
    rxBytes: z.number(),
    label: z.string().optional(),
  })).describe(
    "Down, but has carried traffic before — a run that used to work.",
  ),
  offline: z.array(z.object({ name: z.string() })).describe(
    "Declared devices absent from /stat/device entirely.",
  ),
  metrics: z.array(z.object({
    name: z.string(),
    value: z.number(),
    labels: z.record(z.string(), z.string()),
  })).describe(
    "Flat Prometheus-ready series, so a push step can forward them without " +
      "reshaping this document.",
  ),
});

type DesiredLink = z.infer<typeof DesiredLinkSchema>;
type DesiredPort = z.infer<typeof DesiredPortSchema>;
type Fabric = z.infer<typeof FabricSchema>;

/** Controller device names are FQDNs; declarations use the short label. */
export function shortName(name: unknown): string {
  return typeof name === "string" ? name.split(".")[0] : "";
}

/** Lowercase, strip every separator, so `9C:05:D6` and `9c05d6` compare equal. */
export function normalizeMac(mac: string): string {
  return mac.toLowerCase().replace(/[^0-9a-f]/g, "");
}

function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

/**
 * Compare a desired fabric topology against live `/stat/device` rows.
 *
 * Split out from `execute` so the whole decision surface is testable without a
 * controller — every branch below is reachable from a plain object fixture.
 */
export function computeFabric(
  links: DesiredLink[],
  ports: DesiredPort[],
  live: Record<string, unknown>[],
  checkedAt: string,
  darkPortByteThreshold = 1_000_000,
): Fabric {
  const byKey = new Map<string, Record<string, unknown>>();
  for (const row of live) {
    const short = shortName(row.name);
    if (short) byKey.set(short, row);
    const mac = typeof row.mac === "string" ? normalizeMac(row.mac) : "";
    if (mac) byKey.set(mac, row);
  }

  const wirelessUplinks: Fabric["wirelessUplinks"] = [];
  const parentMismatches: Fabric["parentMismatches"] = [];
  const slowUplinks: Fabric["slowUplinks"] = [];
  const slowPorts: Fabric["slowPorts"] = [];
  const erroringPorts: Fabric["erroringPorts"] = [];
  const darkPortsWithHistory: Fabric["darkPortsWithHistory"] = [];
  const offline: Fabric["offline"] = [];
  const metrics: Fabric["metrics"] = [];

  for (const want of links) {
    const row = (want.mac && byKey.get(normalizeMac(want.mac))) ||
      byKey.get(want.name);
    if (!row) {
      offline.push({ name: want.name });
      metrics.push({
        name: "unifi_device_present",
        value: 0,
        labels: { device: want.name },
      });
      continue;
    }
    metrics.push({
      name: "unifi_device_present",
      value: 1,
      labels: { device: want.name },
    });

    const uplink = (row.uplink ?? {}) as Record<string, unknown>;
    const actualType = typeof uplink.type === "string"
      ? uplink.type
      : undefined;
    // A meshing device often reports `uplink_mac` with no `uplink_device_name`,
    // which would otherwise render as "via undefined" in the one alert where
    // knowing the peer matters most. The MAC is resolvable against the same
    // device list, so resolve it; fall back to the raw MAC when the peer is not
    // adopted, which is still more actionable than nothing.
    const parentMac = typeof uplink.uplink_mac === "string"
      ? normalizeMac(uplink.uplink_mac)
      : "";
    const parent = shortName(uplink.uplink_device_name) ||
      (parentMac ? shortName(byKey.get(parentMac)?.name) || parentMac : "") ||
      undefined;
    const speed = num(uplink.speed);

    // Emitted for every declared device, not only failing ones, so Prometheus
    // can alarm on the series dropping to 0 rather than on this document
    // changing shape. A metric that only appears when something is broken
    // cannot be alerted on with `== 0`.
    const wired = actualType === "wire";
    metrics.push({
      name: "unifi_uplink_is_wired",
      value: wired ? 1 : 0,
      labels: { device: want.name, expected: want.expectUplink },
    });
    const meshedUnexpectedly = want.expectUplink === "wire" && !wired;
    if (meshedUnexpectedly) {
      wirelessUplinks.push({ name: want.name, parent, rssi: num(uplink.rssi) });
    }

    // Suppressed when the device is already reported as meshing: a meshed
    // device's parent is whichever peer it found, so it would *always* mismatch
    // its declared wired parent, double-counting one fault as two findings and
    // firing two alerts for it. `wirelessUplinks` already carries the parent.
    // A device declared `wireless` is still checked, so a deliberate mesh node
    // homing on the wrong peer is not silently accepted.
    if (
      want.expectParent && parent !== want.expectParent && !meshedUnexpectedly
    ) {
      parentMismatches.push({
        name: want.name,
        expected: want.expectParent,
        actual: parent,
      });
    }

    if (speed !== undefined) {
      metrics.push({
        name: "unifi_uplink_speed_mbps",
        value: speed,
        labels: { device: want.name },
      });
    }
    if (want.minUplinkSpeed !== undefined) {
      // An absent speed counts as slow: a meshing device reports none, and
      // silently passing that would hide the very case this model exists for.
      if (speed === undefined || speed < want.minUplinkSpeed) {
        slowUplinks.push({
          name: want.name,
          speed,
          expected: want.minUplinkSpeed,
        });
      }
    }
  }

  // Index every switch port once, rather than re-scanning the device list per
  // declared port.
  const portIndex = new Map<string, Record<string, unknown>>();
  for (const row of live) {
    const dev = shortName(row.name);
    if (!dev) continue;
    const table = Array.isArray(row.port_table) ? row.port_table : [];
    for (const p of table as Record<string, unknown>[]) {
      const idx = num(p.port_idx);
      if (idx !== undefined) portIndex.set(`${dev}:${idx}`, p);
    }
  }

  for (const want of ports) {
    const p = portIndex.get(`${want.device}:${want.port}`);
    if (!p) continue;
    const up = p.up === true;
    const speed = num(p.speed);
    const labels: Record<string, string> = {
      device: want.device,
      port: String(want.port),
      ...(want.label ? { label: want.label } : {}),
    };
    metrics.push({ name: "unifi_port_up", value: up ? 1 : 0, labels });
    if (speed !== undefined) {
      metrics.push({ name: "unifi_port_speed_mbps", value: speed, labels });
    }
    if (up && want.minSpeed !== undefined && (speed ?? 0) < want.minSpeed) {
      slowPorts.push({
        device: want.device,
        port: want.port,
        speed,
        expected: want.minSpeed,
        label: want.label,
      });
    }
  }

  // Error counters and dark-with-history across every port, declared or not:
  // the port that matters is usually the one nobody thought to declare.
  for (const [key, p] of portIndex) {
    const sep = key.lastIndexOf(":");
    const dev = key.slice(0, sep);
    const idxRaw = key.slice(sep + 1);
    const idx = Number(idxRaw);
    const declared = ports.find((w) => w.device === dev && w.port === idx);
    const rxErrors = num(p.rx_errors) ?? 0;
    const txErrors = num(p.tx_errors) ?? 0;
    const rxBytes = num(p.rx_bytes) ?? 0;
    const up = p.up === true;

    if (up && (rxErrors > 0 || txErrors > 0)) {
      erroringPorts.push({
        device: dev,
        port: idx,
        rxErrors,
        txErrors,
        label: declared?.label,
      });
      metrics.push({
        name: "unifi_port_rx_errors_total",
        value: rxErrors,
        labels: { device: dev, port: idxRaw },
      });
      metrics.push({
        name: "unifi_port_tx_errors_total",
        value: txErrors,
        labels: { device: dev, port: idxRaw },
      });
    }

    // A never-patched port reads zero bytes forever, so any meaningful byte
    // count on a down port means the run once carried traffic. Counters reset
    // when the device reboots, so this finds a fresh break rather than an old
    // one — and goes quiet after a restart, which is a limitation worth knowing.
    if (!up && rxBytes >= darkPortByteThreshold) {
      darkPortsWithHistory.push({
        device: dev,
        port: idx,
        rxBytes,
        label: declared?.label,
      });
    }
  }

  // Error totals are excluded from the verdict on purpose — see the module
  // comment. Everything else is a structural assertion that is either true or
  // false right now.
  const inSync = wirelessUplinks.length === 0 &&
    parentMismatches.length === 0 &&
    slowUplinks.length === 0 &&
    slowPorts.length === 0 &&
    darkPortsWithHistory.length === 0 &&
    offline.length === 0;

  metrics.push({
    name: "unifi_fabric_in_sync",
    value: inSync ? 1 : 0,
    labels: {},
  });

  return {
    checkedAt,
    inSync,
    deviceCount: live.length,
    declaredCount: links.length,
    wirelessUplinks,
    parentMismatches,
    slowUplinks,
    slowPorts,
    erroringPorts,
    darkPortsWithHistory,
    offline,
    metrics,
  };
}

// curl rather than fetch: UniFi OS consoles serve a self-signed certificate and
// Deno's fetch cannot be told to skip verification. The key travels in a header
// passed via a file-backed config rather than argv, because process arguments
// are world-readable on most systems.
async function fetchDevices(g: GlobalArgs): Promise<Record<string, unknown>[]> {
  const headerFile = await Deno.makeTempFile({ prefix: "unifi-fabric-" });
  try {
    await Deno.writeTextFile(headerFile, `header = "X-API-KEY: ${g.apiKey}"\n`);
    const url = `https://${g.host}/proxy/network/api/s/${g.site}/stat/device`;
    const cmd = new Deno.Command("curl", {
      args: ["-sk", "--connect-timeout", "10", "--config", headerFile, url],
      stdout: "piped",
      stderr: "piped",
    });
    const { code, stdout, stderr } = await cmd.output();
    if (code !== 0) {
      throw new Error(
        `curl exited ${code}: ${
          new TextDecoder().decode(stderr).slice(0, 200)
        }`,
      );
    }
    const text = new TextDecoder().decode(stdout);
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      // A UniFi console answers HTML on auth failure, so surface that plainly
      // rather than letting a JSON parse error stand in for "bad API key".
      throw new Error(
        `controller did not return JSON — check the API key and host (got: ${
          text.slice(0, 120)
        })`,
      );
    }
    const data = (parsed as { data?: unknown }).data;
    if (!Array.isArray(data)) {
      throw new Error("controller response had no data array");
    }
    return data as Record<string, unknown>[];
  } finally {
    await Deno.remove(headerFile).catch(() => {});
  }
}

interface Context {
  globalArgs: GlobalArgs;
  writeResource: (
    spec: string,
    instance: string,
    data: unknown,
  ) => Promise<unknown>;
  logger: {
    info: (msg: string, props?: Record<string, unknown>) => void;
    warn: (msg: string, props?: Record<string, unknown>) => void;
  };
}

/**
 * The `@sntxrr/unifi-fabric/topology` model.
 *
 * Exposes a single read-only `check` method that compares a declared fabric
 * topology against the controller's live view and writes one `fabric` resource
 * carrying the verdict, the individual findings, and a flat Prometheus series.
 */
export const model = {
  type: "@sntxrr/unifi-fabric/topology",
  version: "2026.08.20.1",
  globalArguments: GlobalArgsSchema,

  resources: {
    fabric: {
      description:
        "Comparison between a desired UniFi fabric topology and how devices are actually attached, plus port speed and error health.",
      schema: FabricSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
  },

  // NOTE: `export const model` takes `methods` as a plain OBJECT. The sibling
  // `export const extension` form takes an ARRAY of single-key objects instead.
  // Getting it wrong fails at load time with "Invalid input: expected array,
  // received object" — and the model still resolves without the method, so it
  // looks like the file was ignored rather than rejected.
  methods: {
    check: {
      description:
        "Compare a desired fabric topology against live UniFi devices. Reports wireless uplinks where wire was expected, wrong uplink parents, under-negotiated links, erroring ports and down-but-previously-used ports. Read-only — never writes to the controller.",
      arguments: z.object({
        links: z.array(DesiredLinkSchema).describe(
          "How each device should be attached to the fabric.",
        ),
        ports: z.array(DesiredPortSchema).default([]).describe(
          "Switch ports whose speed is worth asserting.",
        ),
        darkPortByteThreshold: z.number().default(1_000_000).describe(
          "Bytes a down port must have carried before it is reported as a run " +
            "that used to work. Filters ports that only ever saw link " +
            "negotiation traffic.",
        ),
      }),
      execute: async (
        args: {
          links: DesiredLink[];
          ports: DesiredPort[];
          darkPortByteThreshold: number;
        },
        context: Context,
      ): Promise<{ dataHandles: unknown[] }> => {
        context.logger.info(
          "Checking fabric topology for {n} declared devices against {host}",
          { n: args.links.length, host: context.globalArgs.host },
        );

        const rows = await fetchDevices(context.globalArgs);
        const result = computeFabric(
          args.links,
          args.ports,
          rows,
          new Date().toISOString(),
          args.darkPortByteThreshold,
        );

        if (result.inSync) {
          context.logger.info(
            "Fabric in sync ({n} declared devices all attached as expected)",
            { n: result.declaredCount },
          );
        } else {
          context.logger.warn(
            "Fabric drift: {mesh} meshing, {parent} wrong parent, {slow} slow, {dark} dark-with-history, {off} offline",
            {
              mesh: result.wirelessUplinks.length,
              parent: result.parentMismatches.length,
              slow: result.slowUplinks.length + result.slowPorts.length,
              dark: result.darkPortsWithHistory.length,
              off: result.offline.length,
            },
          );
          for (const w of result.wirelessUplinks) {
            context.logger.warn(
              "{device} expected on the wire but is meshing via {parent} (rssi {rssi})",
              { device: w.name, parent: w.parent, rssi: w.rssi },
            );
          }
          for (const d of result.darkPortsWithHistory) {
            context.logger.warn(
              "{device} port {port} is down but has carried {bytes} bytes — a run that used to work",
              { device: d.device, port: d.port, bytes: d.rxBytes },
            );
          }
        }
        if (result.erroringPorts.length > 0) {
          context.logger.warn(
            "{n} ports carry non-zero error counters (cumulative — check the rate, not the total)",
            { n: result.erroringPorts.length },
          );
        }

        const handle = await context.writeResource("fabric", "fabric", result);
        return { dataHandles: [handle] };
      },
    },
  },
};
