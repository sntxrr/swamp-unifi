import { assertEquals } from "jsr:@std/assert@1";
import { computeFabric, normalizeMac, shortName } from "./unifi_fabric.ts";

/**
 * A healthy fabric is the only state a live run can reach without breaking
 * something on purpose, so these cover the branches that appear only when the
 * network has actually degraded — which is the entire point of the model.
 *
 * Fixtures use RFC 7042 documentation MACs (02:00:5e:00:53:xx) and generic
 * device labels, never real hardware from any operator's fabric.
 */

const AT = "2026-08-20T12:00:00.000Z";

/** A /stat/device row for a device attached over ethernet. */
function wired(
  name: string,
  parent: string,
  opts: { mac?: string; speed?: number; ports?: unknown[] } = {},
) {
  return {
    name: `${name}.example.internal`,
    ...(opts.mac ? { mac: opts.mac } : {}),
    uplink: {
      type: "wire",
      uplink_device_name: `${parent}.example.internal`,
      speed: opts.speed ?? 1000,
    },
    ...(opts.ports ? { port_table: opts.ports } : {}),
  };
}

/** A /stat/device row for a device that has fallen back to mesh. */
function meshed(name: string, parent: string, rssi = 28) {
  return {
    name: `${name}.example.internal`,
    uplink: {
      type: "wireless",
      uplink_device_name: `${parent}.example.internal`,
      rssi,
    },
  };
}

function port(
  idx: number,
  o: {
    up?: boolean;
    speed?: number;
    rx_errors?: number;
    tx_errors?: number;
    rx_bytes?: number;
  } = {},
) {
  return {
    port_idx: idx,
    up: o.up ?? true,
    speed: o.speed ?? 1000,
    rx_errors: o.rx_errors ?? 0,
    tx_errors: o.tx_errors ?? 0,
    rx_bytes: o.rx_bytes ?? 0,
  };
}

Deno.test("a fully wired fabric is in sync", () => {
  const r = computeFabric(
    [
      { name: "sw-core", expectUplink: "wire", minUplinkSpeed: 1000 },
      { name: "ap-one", expectUplink: "wire", expectParent: "sw-core" },
    ],
    [],
    [wired("sw-core", "gw"), wired("ap-one", "sw-core")],
    AT,
  );
  assertEquals(r.inSync, true);
  assertEquals(r.wirelessUplinks, []);
  assertEquals(r.declaredCount, 2);
});

Deno.test("an AP that fell back to mesh is caught", () => {
  const r = computeFabric(
    [{ name: "ap-one", expectUplink: "wire" }],
    [],
    [meshed("ap-one", "ap-two", 28)],
    AT,
  );
  assertEquals(r.inSync, false);
  assertEquals(r.wirelessUplinks.length, 1);
  assertEquals(r.wirelessUplinks[0].name, "ap-one");
  assertEquals(r.wirelessUplinks[0].parent, "ap-two");
  assertEquals(r.wirelessUplinks[0].rssi, 28);
});

Deno.test("a deliberate mesh node does not alarm", () => {
  const r = computeFabric(
    [{ name: "ap-shed", expectUplink: "wireless" }],
    [],
    [meshed("ap-shed", "ap-one")],
    AT,
  );
  assertEquals(r.inSync, true);
  assertEquals(r.wirelessUplinks, []);
});

Deno.test("attachment to the wrong parent is caught even when still wired", () => {
  const r = computeFabric(
    [{ name: "sw-edge", expectUplink: "wire", expectParent: "sw-core" }],
    [],
    [wired("sw-edge", "ap-one")],
    AT,
  );
  assertEquals(r.inSync, false);
  assertEquals(r.parentMismatches, [
    { name: "sw-edge", expected: "sw-core", actual: "ap-one" },
  ]);
});

Deno.test("an uplink negotiated below its minimum is caught", () => {
  const r = computeFabric(
    [{ name: "sw-edge", expectUplink: "wire", minUplinkSpeed: 1000 }],
    [],
    [wired("sw-edge", "sw-core", { speed: 100 })],
    AT,
  );
  assertEquals(r.inSync, false);
  assertEquals(r.slowUplinks, [
    { name: "sw-edge", speed: 100, expected: 1000 },
  ]);
});

Deno.test("a meshing device reports no speed, which counts as slow", () => {
  // Guards the case where an absent speed silently passes a minimum check —
  // exactly the device this model exists to catch.
  const r = computeFabric(
    [{ name: "ap-one", expectUplink: "wire", minUplinkSpeed: 1000 }],
    [],
    [meshed("ap-one", "ap-two")],
    AT,
  );
  assertEquals(r.slowUplinks.length, 1);
  assertEquals(r.slowUplinks[0].speed, undefined);
});

Deno.test("a gigabit port negotiated at 100 is caught", () => {
  const r = computeFabric(
    [],
    [{ device: "sw-core", port: 3, minSpeed: 1000, label: "riser to sw-edge" }],
    [wired("sw-core", "gw", { ports: [port(3, { speed: 100 })] })],
    AT,
  );
  assertEquals(r.inSync, false);
  assertEquals(r.slowPorts, [{
    device: "sw-core",
    port: 3,
    speed: 100,
    expected: 1000,
    label: "riser to sw-edge",
  }]);
});

Deno.test("error counters are reported but do NOT fail the verdict", () => {
  // Counters are cumulative since boot, so a total cannot distinguish an active
  // fault from old scars. The rate does, via the pushed metric.
  const r = computeFabric(
    [],
    [],
    [wired("sw-core", "gw", { ports: [port(1, { rx_errors: 1277 })] })],
    AT,
  );
  assertEquals(r.inSync, true);
  assertEquals(r.erroringPorts.length, 1);
  assertEquals(r.erroringPorts[0].rxErrors, 1277);
});

Deno.test("a down port that used to carry traffic is reported", () => {
  // The riser signature: every never-patched port reads zero bytes forever, so
  // a dark port with real history is a run that used to work.
  const r = computeFabric(
    [],
    [],
    [wired("sw-core", "gw", {
      ports: [port(11, { up: false, rx_bytes: 973_725_818_575 })],
    })],
    AT,
  );
  assertEquals(r.darkPortsWithHistory.length, 1);
  assertEquals(r.darkPortsWithHistory[0].port, 11);
});

Deno.test("a dark port does NOT fail the verdict on its own", () => {
  // The regression this guards: a laptop on a wired dock reads exactly like a
  // severed run in one snapshot — down, with gigabytes behind it. Gating
  // `inSync` on that turned every sleeping laptop into an hourly interrupt.
  // The frozen-counter test that tells them apart needs two observations and
  // therefore cannot live here; see unifi_port_rx_bytes_total.
  const r = computeFabric(
    [],
    [],
    [wired("sw-edge", "sw-core", {
      ports: [port(7, { up: false, rx_bytes: 237_166_661_688 })],
    })],
    AT,
  );
  assertEquals(r.darkPortsWithHistory.length, 1);
  assertEquals(r.inSync, true);
  assertEquals(
    r.metrics.find((x) => x.name === "unifi_fabric_in_sync")?.value,
    1,
  );
});

Deno.test("every port gets up and rx_bytes series, declared or not", () => {
  // A rule cannot compare a series that does not exist, and the port that
  // matters is usually the one nobody thought to declare.
  const r = computeFabric(
    [],
    [{ device: "sw-core", port: 5, label: "uplink to gw" }],
    [wired("sw-core", "gw", {
      ports: [
        port(5),
        port(14, { up: false, rx_bytes: 237_166_661_688 }),
      ],
    })],
    AT,
  );

  const up = r.metrics.filter((x) => x.name === "unifi_port_up");
  assertEquals(up.length, 2);
  assertEquals(up.find((x) => x.labels.port === "5")?.value, 1);
  assertEquals(up.find((x) => x.labels.port === "14")?.value, 0);

  // The declared port carries its label through; the undeclared one has none.
  assertEquals(
    up.find((x) => x.labels.port === "5")?.labels.label,
    "uplink to gw",
  );
  assertEquals(up.find((x) => x.labels.port === "14")?.labels.label, undefined);

  const bytes = r.metrics.filter((x) => x.name === "unifi_port_rx_bytes_total");
  assertEquals(bytes.length, 2);
  assertEquals(
    bytes.find((x) => x.labels.port === "14")?.value,
    237_166_661_688,
  );
});

Deno.test("a down port emits no speed series", () => {
  // A down port reports speed 0, and `unifi_port_speed_mbps < 1000` would read
  // that as a gigabit run negotiating zero rather than as an empty socket.
  const r = computeFabric(
    [],
    [{ device: "sw-core", port: 14, minSpeed: 1000 }],
    [wired("sw-core", "gw", {
      ports: [port(14, { up: false, speed: 0, rx_bytes: 237_166_661_688 })],
    })],
    AT,
  );
  assertEquals(
    r.metrics.filter((x) => x.name === "unifi_port_speed_mbps"),
    [],
  );
  // ...and it is not reported as slow either: a link that is not negotiated
  // has no speed to assert on.
  assertEquals(r.slowPorts, []);
});

Deno.test("a down port that was never used is ignored", () => {
  const r = computeFabric(
    [],
    [],
    [wired("sw-core", "gw", { ports: [port(6, { up: false, rx_bytes: 0 })] })],
    AT,
  );
  assertEquals(r.inSync, true);
  assertEquals(r.darkPortsWithHistory, []);
  // It still gets a series, so a rule can watch it start carrying traffic.
  assertEquals(
    r.metrics.find((x) => x.name === "unifi_port_rx_bytes_total")?.value,
    0,
  );
});

Deno.test("the dark-port threshold is honoured", () => {
  const rows = [
    wired("sw-core", "gw", { ports: [port(6, { up: false, rx_bytes: 5_000 })] }),
  ];
  assertEquals(computeFabric([], [], rows, AT, 1_000_000).darkPortsWithHistory, []);
  assertEquals(
    computeFabric([], [], rows, AT, 1_000).darkPortsWithHistory.length,
    1,
  );
});

Deno.test("a declared device missing from the controller is offline", () => {
  const r = computeFabric(
    [{ name: "ap-gone", expectUplink: "wire" }],
    [],
    [wired("sw-core", "gw")],
    AT,
  );
  assertEquals(r.inSync, false);
  assertEquals(r.offline, [{ name: "ap-gone" }]);
  const present = r.metrics.find((m) => m.name === "unifi_device_present");
  assertEquals(present?.value, 0);
});

Deno.test("uplink_is_wired is emitted for healthy devices too", () => {
  // A metric that only appears when something breaks cannot be alerted on with
  // `== 0`, so the healthy case must emit the series as well.
  const r = computeFabric(
    [{ name: "ap-one", expectUplink: "wire" }],
    [],
    [wired("ap-one", "sw-core")],
    AT,
  );
  const m = r.metrics.find((x) => x.name === "unifi_uplink_is_wired");
  assertEquals(m?.value, 1);
  assertEquals(m?.labels.device, "ap-one");
  assertEquals(
    r.metrics.find((x) => x.name === "unifi_fabric_in_sync")?.value,
    1,
  );
});

Deno.test("devices are matched by MAC in preference to name", () => {
  const r = computeFabric(
    [{
      name: "renamed-since",
      mac: "02:00:5e:00:53:01",
      expectUplink: "wire",
    }],
    [],
    [wired("whatever-it-is-called-now", "sw-core", {
      mac: "02-00-5E-00-53-01",
    })],
    AT,
  );
  assertEquals(r.offline, []);
  assertEquals(r.inSync, true);
});

Deno.test("the real cascade is reported as three distinct facts", () => {
  // Riser drops -> downstream switch loses its path to the core -> the AP wired
  // to it can no longer reach the controller and meshes -> the switch then
  // reaches the network backwards through the AP it powers. Nothing is "down",
  // which is why outcome-based checks stayed green for days.
  const r = computeFabric(
    [
      { name: "sw-edge", expectUplink: "wire", expectParent: "sw-core" },
      { name: "ap-low", expectUplink: "wire", expectParent: "sw-edge" },
    ],
    [{ device: "sw-core", port: 11, minSpeed: 1000, label: "riser to sw-edge" }],
    [
      wired("sw-core", "gw", {
        ports: [port(11, { up: false, rx_bytes: 973_725_818_575 })],
      }),
      wired("sw-edge", "ap-low"),
      meshed("ap-low", "ap-mid", 28),
    ],
    AT,
  );
  assertEquals(r.inSync, false);
  // 1. the AP is meshing
  assertEquals(r.wirelessUplinks.map((w) => w.name), ["ap-low"]);
  // 2. the switch reaches the fabric through the wrong device.
  //    `ap-low` is NOT listed here despite also having the wrong parent — a
  //    meshed device always mismatches its declared wired parent, and counting
  //    that separately would fire two alerts for one fault.
  assertEquals(r.parentMismatches.map((p) => p.name), ["sw-edge"]);
  // 3. the riser itself is dark but has history
  assertEquals(r.darkPortsWithHistory.map((d) => d.port), [11]);
});

Deno.test("a deliberate mesh node on the wrong peer still reports", () => {
  // The de-duplication above must not swallow this: the device is meant to
  // mesh, so there is no wirelessUplinks finding to carry the parent, and the
  // mismatch is the only signal that it homed on the wrong peer.
  const r = computeFabric(
    [{ name: "ap-shed", expectUplink: "wireless", expectParent: "ap-one" }],
    [],
    [meshed("ap-shed", "ap-two")],
    AT,
  );
  assertEquals(r.wirelessUplinks, []);
  assertEquals(r.parentMismatches, [
    { name: "ap-shed", expected: "ap-one", actual: "ap-two" },
  ]);
  assertEquals(r.inSync, false);
});

Deno.test("name and mac helpers normalise as documented", () => {
  assertEquals(shortName("sw-core.example.internal"), "sw-core");
  assertEquals(shortName(undefined), "");
  assertEquals(normalizeMac("02:00:5E:00:53:01"), "02005e005301");
  assertEquals(normalizeMac("02-00-5e-00-53-01"), "02005e005301");
});

Deno.test("a mesh peer given only as a MAC is resolved to its device name", () => {
  // Real controllers frequently report `uplink_mac` with no
  // `uplink_device_name` for a meshing device, which rendered as "via
  // undefined" in the one alert where the peer matters most.
  const r = computeFabric(
    [{ name: "ap-low", expectUplink: "wire" }],
    [],
    [
      {
        name: "ap-low.example.internal",
        uplink: { type: "wireless", uplink_mac: "02:00:5e:00:53:09" },
      },
      { name: "ap-mid.example.internal", mac: "02:00:5e:00:53:09" },
    ],
    AT,
  );
  assertEquals(r.wirelessUplinks[0].parent, "ap-mid");
});

Deno.test("an unresolvable mesh peer falls back to the raw MAC", () => {
  const r = computeFabric(
    [{ name: "ap-low", expectUplink: "wire" }],
    [],
    [{
      name: "ap-low.example.internal",
      uplink: { type: "wireless", uplink_mac: "02:00:5e:00:53:ff" },
    }],
    AT,
  );
  assertEquals(r.wirelessUplinks[0].parent, "02005e0053ff");
});
