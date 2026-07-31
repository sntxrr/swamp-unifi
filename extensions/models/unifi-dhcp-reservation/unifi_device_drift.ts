/**
 * Read-only drift detection for adopted UniFi hardware.
 *
 * Extends `@sntxrr/unifi/dhcp_reservation` with a `device_drift` method that
 * compares the `config_network` block of adopted devices (APs, switches) against
 * a desired set, without writing. It is the read-only counterpart to
 * `device_pin`, which is what actually pins them.
 *
 * This exists because adopted hardware is invisible to the `drift` method.
 * Devices cannot hold DHCP reservations at all — the controller rejects those
 * with `api.err.FixedIpAlreadyUsedByDevice` — so they are addressed through
 * device config instead, and nothing was comparing that. The gap is not
 * theoretical: a switch was found carrying a stale `config_network.ip` while
 * actually sitting at a different address, a latent collision with another
 * host's target that went unnoticed because no check covered this surface.
 *
 * `device_pin --dryRun` can report the same divergence, but it is a write method
 * one flag away from mutating the fabric, and it emits one resource per MAC with
 * no aggregate verdict. A scheduled watcher should not be wired to a writer, so
 * this is a separate read-only method producing a single summary.
 *
 * Writes its result under the resource spec AND instance name `device_drift`.
 * That is deliberate: `inventory` and `drift` in the sibling module both write
 * to the instance name `current`, and because instance names are not namespaced
 * by resource spec they clobber each other under one data name. Using the same
 * word for both keeps `data.latest(model, 'device_drift')` unambiguous no matter
 * what else runs in the same workflow.
 *
 * @module
 */

import { z } from "npm:zod@4";
import {
  list,
  login,
  normalizeMac,
  type UnifiGlobalArgs,
} from "./unifi_dhcp_reservation.ts";

/** One adopted device that should hold a given static address. */
const DesiredDeviceSchema = z.object({
  mac: z.string().describe("Device MAC (any separator style)."),
  target: z.string().describe("Static address the device should be pinned to."),
  name: z.string().optional(),
  kind: z.string().optional().describe(
    "Free-form role label, e.g. ap, switch.",
  ),
  // Present in fabric-devices.json as a record of the address at pin time.
  // Accepted so that file can be passed through verbatim, but never compared
  // against -- the controller is the authority on what is live, not a note in
  // a JSON file.
  current: z.string().optional(),
});

const DeviceDriftSchema = z.object({
  checkedAt: z.string(),
  inSync: z.boolean(),
  desiredCount: z.number(),
  adoptedCount: z.number(),
  matched: z.array(z.object({
    mac: z.string(),
    ip: z.string(),
    name: z.string().optional(),
  })).describe("Pinned static to exactly the desired address."),
  mismatched: z.array(z.object({
    mac: z.string(),
    desired_ip: z.string(),
    live_ip: z.string(),
    name: z.string().optional(),
  })).describe("Pinned static, but to a different address than desired."),
  dynamic: z.array(z.object({
    mac: z.string(),
    desired_ip: z.string(),
    live_type: z.string(),
    name: z.string().optional(),
  })).describe(
    "Adopted but not statically pinned at all — back on DHCP, so the address is not guaranteed.",
  ),
  unadopted: z.array(z.object({
    mac: z.string(),
    desired_ip: z.string(),
    name: z.string().optional(),
  })).describe(
    "Desired devices absent from /stat/device — unadopted, offline or replaced.",
  ),
  undeclared: z.array(z.object({
    mac: z.string(),
    live_ip: z.string(),
    name: z.string().optional(),
  })).describe(
    "Adopted devices statically pinned but absent from the desired set. Informational: does NOT affect inSync, matching how `drift` treats `unmanaged`.",
  ),
});

type DesiredDevice = z.infer<typeof DesiredDeviceSchema>;

/**
 * Compare desired device pins against live `/stat/device` rows.
 *
 * Split out from `execute` so it is testable without a controller.
 */
export function computeDeviceDrift(
  desired: DesiredDevice[],
  live: Record<string, unknown>[],
  checkedAt: string,
): z.infer<typeof DeviceDriftSchema> {
  const byMac = new Map<string, Record<string, unknown>>();
  for (const row of live) {
    const mac = typeof row.mac === "string" ? normalizeMac(row.mac) : "";
    if (mac) byMac.set(mac, row);
  }

  const matched: z.infer<typeof DeviceDriftSchema>["matched"] = [];
  const mismatched: z.infer<typeof DeviceDriftSchema>["mismatched"] = [];
  const dynamic: z.infer<typeof DeviceDriftSchema>["dynamic"] = [];
  const unadopted: z.infer<typeof DeviceDriftSchema>["unadopted"] = [];
  const undeclared: z.infer<typeof DeviceDriftSchema>["undeclared"] = [];

  const desiredMacs = new Set<string>();

  for (const d of desired) {
    const mac = normalizeMac(d.mac);
    desiredMacs.add(mac);
    const row = byMac.get(mac);

    if (!row) {
      unadopted.push({ mac, desired_ip: d.target, name: d.name });
      continue;
    }

    const cfg = (row.config_network ?? {}) as Record<string, unknown>;
    const type = typeof cfg.type === "string" ? cfg.type : "dhcp";
    const ip = typeof cfg.ip === "string" ? cfg.ip : undefined;

    if (type !== "static" || !ip) {
      dynamic.push({
        mac,
        desired_ip: d.target,
        live_type: type,
        name: d.name,
      });
    } else if (ip !== d.target) {
      mismatched.push({
        mac,
        desired_ip: d.target,
        live_ip: ip,
        name: d.name,
      });
    } else {
      matched.push({ mac, ip, name: d.name });
    }
  }

  // Anything the controller has pinned that nobody declared. Devices left on
  // DHCP are not flagged -- they are not pinned, so there is nothing to have
  // drifted; only a deliberate static pin nobody asked for is interesting.
  for (const [mac, row] of byMac) {
    if (desiredMacs.has(mac)) continue;
    const cfg = (row.config_network ?? {}) as Record<string, unknown>;
    if (cfg.type !== "static" || typeof cfg.ip !== "string") continue;
    const name = typeof row.name === "string" ? row.name : undefined;
    undeclared.push({ mac, live_ip: cfg.ip, name });
  }

  return {
    checkedAt,
    // `undeclared` is deliberately excluded, mirroring how the sibling `drift`
    // method treats `unmanaged`. Gate on it in the workflow if you want it.
    inSync: mismatched.length === 0 && dynamic.length === 0 &&
      unadopted.length === 0,
    desiredCount: desired.length,
    adoptedCount: byMac.size,
    matched,
    mismatched,
    dynamic,
    unadopted,
    undeclared,
  };
}

export const extension = {
  type: "@sntxrr/unifi/dhcp_reservation",

  resources: {
    device_drift: {
      description:
        "Comparison between desired static pins on adopted UniFi hardware and what the controller actually holds.",
      schema: DeviceDriftSchema,
      lifetime: "infinite",
      garbageCollection: 30,
    },
  },

  // NOTE: `export const extension` takes `methods` as an ARRAY of single-key
  // objects, unlike `export const model` in the sibling module which takes a
  // plain object. Getting this wrong fails with
  // "Invalid input: expected array, received object" at load time -- and the
  // model still resolves without the method, so it looks like the file was
  // ignored rather than rejected.
  methods: [
    {
      device_drift: {
        description:
          "Compare a desired set of static device pins against adopted UniFi hardware. Reports mismatched, dynamic (unpinned), unadopted and undeclared devices. Read-only — never writes to the controller.",
        arguments: z.object({
          devices: z.array(DesiredDeviceSchema).describe(
            "The adopted devices that should hold static addresses.",
          ),
        }),
        execute: async (
          args: { devices: DesiredDevice[] },
          context: {
            globalArgs: UnifiGlobalArgs;
            writeResource: (
              spec: string,
              instance: string,
              data: unknown,
            ) => Promise<unknown>;
            logger: {
              info: (msg: string, props?: Record<string, unknown>) => void;
              warn: (msg: string, props?: Record<string, unknown>) => void;
            };
          },
        ): Promise<{ dataHandles: unknown[] }> => {
          context.logger.info(
            "Comparing {n} desired device pins against {host}",
            { n: args.devices.length, host: context.globalArgs.host },
          );

          const client = await login(context.globalArgs);
          try {
            const rows = await list<Record<string, unknown>>(
              client,
              "/stat/device",
            );
            const result = computeDeviceDrift(
              args.devices,
              rows,
              new Date().toISOString(),
            );

            if (result.inSync) {
              context.logger.info("Device pins in sync ({n} devices)", {
                n: result.desiredCount,
              });
            } else {
              context.logger.warn(
                "Device pin drift: {mismatched} mismatched, {dynamic} unpinned, {unadopted} unadopted",
                {
                  mismatched: result.mismatched.length,
                  dynamic: result.dynamic.length,
                  unadopted: result.unadopted.length,
                },
              );
            }
            if (result.undeclared.length > 0) {
              context.logger.warn(
                "{n} adopted devices are statically pinned but not declared",
                { n: result.undeclared.length },
              );
            }

            // Spec and instance are the same word on purpose -- see the module
            // comment. Keeps data.latest(model, 'device_drift') unambiguous.
            const handle = await context.writeResource(
              "device_drift",
              "device_drift",
              result,
            );
            return { dataHandles: [handle] };
          } finally {
            await client.cleanup();
          }
        },
      },
    },
  ],
};
