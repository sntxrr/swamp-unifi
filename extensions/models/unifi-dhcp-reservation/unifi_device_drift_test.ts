import { assertEquals } from "jsr:@std/assert@1";
import { computeDeviceDrift } from "./unifi_device_drift.ts";

/**
 * Live runs only ever exercise the everything-in-sync path -- provoking real
 * drift would mean mutating the fabric. These cover the branches that only
 * appear when something has actually gone wrong, which is the whole point of
 * the method.
 *
 * Fixtures use RFC 7042 documentation MACs (02:00:5e:00:53:xx) and TEST-NET-1
 * addresses (192.0.2.0/24), never real hardware from any operator's fabric.
 */

const AT = "2026-07-31T21:00:00.000Z";

/** A /stat/device row with a static pin. */
function pinned(mac: string, ip: string, name?: string) {
  return {
    mac,
    ...(name ? { name } : {}),
    config_network: { type: "static", ip },
  };
}

/** A /stat/device row still on DHCP. */
function dhcp(mac: string, name?: string) {
  return {
    mac,
    ...(name ? { name } : {}),
    config_network: { type: "dhcp" },
  };
}

Deno.test("device_drift: all pins matching is inSync", () => {
  const r = computeDeviceDrift(
    [{ mac: "02:00:5e:00:53:01", target: "192.0.2.12", name: "ap-back" }],
    [pinned("02:00:5e:00:53:01", "192.0.2.12")],
    AT,
  );
  assertEquals(r.inSync, true);
  assertEquals(r.matched.length, 1);
  assertEquals(r.desiredCount, 1);
  assertEquals(r.adoptedCount, 1);
});

Deno.test("device_drift: pinned to the wrong address is mismatched", () => {
  // The failure this method exists to catch: a switch left statically pinned to
  // a stale address that now collides with another host's target.
  const r = computeDeviceDrift(
    [{ mac: "02:00:5e:00:53:02", target: "192.0.2.15", name: "sw-main" }],
    [pinned("02:00:5e:00:53:02", "192.0.2.209")],
    AT,
  );
  assertEquals(r.inSync, false);
  assertEquals(r.mismatched, [{
    mac: "02:00:5e:00:53:02",
    desired_ip: "192.0.2.15",
    live_ip: "192.0.2.209",
    name: "sw-main",
  }]);
  assertEquals(r.matched.length, 0);
});

Deno.test("device_drift: a device back on DHCP is dynamic, not mismatched", () => {
  const r = computeDeviceDrift(
    [{ mac: "02:00:5e:00:53:03", target: "192.0.2.16", name: "sw-front" }],
    [dhcp("02:00:5e:00:53:03")],
    AT,
  );
  assertEquals(r.inSync, false);
  assertEquals(r.dynamic.length, 1);
  assertEquals(r.dynamic[0].live_type, "dhcp");
  assertEquals(r.mismatched.length, 0);
});

Deno.test("device_drift: config_network absent is treated as dhcp", () => {
  const r = computeDeviceDrift(
    [{ mac: "02:00:5e:00:53:03", target: "192.0.2.16" }],
    [{ mac: "02:00:5e:00:53:03" }],
    AT,
  );
  assertEquals(r.dynamic.length, 1);
  assertEquals(r.dynamic[0].live_type, "dhcp");
});

Deno.test("device_drift: static type with no ip is dynamic, not a crash", () => {
  const r = computeDeviceDrift(
    [{ mac: "02:00:5e:00:53:03", target: "192.0.2.16" }],
    [{ mac: "02:00:5e:00:53:03", config_network: { type: "static" } }],
    AT,
  );
  assertEquals(r.dynamic.length, 1);
  assertEquals(r.mismatched.length, 0);
});

Deno.test("device_drift: a desired device absent from the controller is unadopted", () => {
  const r = computeDeviceDrift(
    [{ mac: "02:00:5e:00:53:04", target: "192.0.2.17", name: "ap-living" }],
    [],
    AT,
  );
  assertEquals(r.inSync, false);
  assertEquals(r.unadopted, [{
    mac: "02:00:5e:00:53:04",
    desired_ip: "192.0.2.17",
    name: "ap-living",
  }]);
});

Deno.test("device_drift: an undeclared static pin does NOT break inSync", () => {
  // Mirrors how the sibling `drift` method treats `unmanaged`. The workflow
  // gates on undeclared separately; the model stays consistent with its peer.
  const r = computeDeviceDrift(
    [],
    [pinned("02:00:5e:00:53:05", "192.0.2.99", "rogue-ap")],
    AT,
  );
  assertEquals(r.inSync, true);
  assertEquals(r.undeclared, [{
    mac: "02:00:5e:00:53:05",
    live_ip: "192.0.2.99",
    name: "rogue-ap",
  }]);
});

Deno.test("device_drift: an undeclared DHCP device is ignored entirely", () => {
  // The gateway itself shows up in /stat/device but is not statically pinned,
  // so it must not be reported as undeclared -- otherwise every run alerts.
  const r = computeDeviceDrift(
    [],
    [dhcp("02:00:5e:00:53:06", "gateway")],
    AT,
  );
  assertEquals(r.inSync, true);
  assertEquals(r.undeclared.length, 0);
  assertEquals(r.adoptedCount, 1);
});

Deno.test("device_drift: MAC separator style does not affect matching", () => {
  const r = computeDeviceDrift(
    [{ mac: "02-00-5E-00-53-01", target: "192.0.2.12" }],
    [pinned("02:00:5e:00:53:01", "192.0.2.12")],
    AT,
  );
  assertEquals(r.inSync, true);
  assertEquals(r.matched.length, 1);
  assertEquals(r.undeclared.length, 0);
});

Deno.test("device_drift: rows without a usable mac are skipped", () => {
  const r = computeDeviceDrift(
    [{ mac: "02:00:5e:00:53:01", target: "192.0.2.12" }],
    [{ notAMac: true }, pinned("02:00:5e:00:53:01", "192.0.2.12")],
    AT,
  );
  assertEquals(r.adoptedCount, 1);
  assertEquals(r.inSync, true);
});

Deno.test("device_drift: mixed failure modes are reported together", () => {
  const r = computeDeviceDrift(
    [
      { mac: "02:00:5e:00:53:01", target: "192.0.2.12", name: "ok" },
      { mac: "02:00:5e:00:53:02", target: "192.0.2.13", name: "wrong" },
      { mac: "02:00:5e:00:53:03", target: "192.0.2.14", name: "unpinned" },
      { mac: "02:00:5e:00:53:04", target: "192.0.2.15", name: "gone" },
    ],
    [
      pinned("02:00:5e:00:53:01", "192.0.2.12"),
      pinned("02:00:5e:00:53:02", "192.0.2.99"),
      dhcp("02:00:5e:00:53:03"),
      pinned("02:00:5e:00:53:05", "192.0.2.50", "extra"),
    ],
    AT,
  );
  assertEquals(r.inSync, false);
  assertEquals(r.matched.length, 1);
  assertEquals(r.mismatched.length, 1);
  assertEquals(r.dynamic.length, 1);
  assertEquals(r.unadopted.length, 1);
  assertEquals(r.undeclared.length, 1);
  assertEquals(r.desiredCount, 4);
  assertEquals(r.adoptedCount, 4);
  assertEquals(r.checkedAt, AT);
});
