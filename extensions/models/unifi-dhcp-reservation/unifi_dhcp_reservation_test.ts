import { assertEquals, assertThrows } from "jsr:@std/assert@1";
import {
  analysePoolChange,
  base32Decode,
  buildInventory,
  computeDrift,
  computeVerification,
  inPool,
  ipToInt,
  normalizeMac,
  totpCode,
} from "./unifi_dhcp_reservation.ts";

/* ---------------- TOTP ---------------- */

// RFC 6238 Appendix B reference vectors (SHA-1, secret "12345678901234567890").
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

Deno.test("totpCode matches RFC 6238 vector at T=59", async () => {
  assertEquals(await totpCode(RFC_SECRET, 59_000, 30, 8), "94287082");
});

Deno.test("totpCode matches RFC 6238 vector at T=1111111109", async () => {
  assertEquals(
    await totpCode(RFC_SECRET, 1_111_111_109_000, 30, 8),
    "07081804",
  );
});

Deno.test("totpCode matches RFC 6238 vector at T=1234567890", async () => {
  assertEquals(
    await totpCode(RFC_SECRET, 1_234_567_890_000, 30, 8),
    "89005924",
  );
});

Deno.test("totpCode defaults to 6 digits and zero-pads", async () => {
  const code = await totpCode(RFC_SECRET, 59_000);
  assertEquals(code, "287082");
  assertEquals(code.length, 6);
});

Deno.test("totpCode is stable within a 30s step and rolls at the boundary", async () => {
  const a = await totpCode(RFC_SECRET, 30_000);
  const b = await totpCode(RFC_SECRET, 59_999);
  const c = await totpCode(RFC_SECRET, 60_000);
  assertEquals(a, b);
  assertEquals(a === c, false);
});

Deno.test("base32Decode handles padding, lowercase and whitespace", () => {
  assertEquals(base32Decode("MZXW6==="), base32Decode("mzxw6"));
  assertEquals(base32Decode("MZXW 6"), base32Decode("MZXW6"));
});

Deno.test("base32Decode rejects invalid input", () => {
  assertThrows(() => base32Decode("MZXW1"), Error, "Invalid base32");
  assertThrows(() => base32Decode(""), Error, "Empty base32");
});

/* ---------------- IP helpers ---------------- */

Deno.test("ipToInt orders addresses correctly", () => {
  assertEquals(ipToInt("0.0.0.0"), 0);
  assertEquals(ipToInt("255.255.255.255"), 4294967295);
  assertEquals(ipToInt("192.0.2.10") < ipToInt("192.0.2.132"), true);
});

Deno.test("ipToInt rejects malformed addresses", () => {
  assertThrows(() => ipToInt("192.0.2"), Error);
  assertThrows(() => ipToInt("192.0.2.999"), Error);
  assertThrows(() => ipToInt("not-an-ip"), Error);
});

Deno.test("inPool is inclusive of both endpoints", () => {
  assertEquals(inPool("192.0.2.23", "192.0.2.23", "192.0.2.235"), true);
  assertEquals(
    inPool("192.0.2.235", "192.0.2.23", "192.0.2.235"),
    true,
  );
  assertEquals(inPool("192.0.2.22", "192.0.2.23", "192.0.2.235"), false);
  assertEquals(
    inPool("192.0.2.236", "192.0.2.23", "192.0.2.235"),
    false,
  );
});

Deno.test("inPool is false when the pool is unknown", () => {
  assertEquals(inPool("192.0.2.50", undefined, undefined), false);
});

Deno.test("normalizeMac canonicalises separators and case", () => {
  assertEquals(normalizeMac("02:00:5E:00:53:01"), "02:00:5e:00:53:01");
  assertEquals(normalizeMac("02-00-5e-00-53-01"), "02:00:5e:00:53:01");
  assertEquals(normalizeMac("02005e005301"), "02:00:5e:00:53:01");
});

/* ---------------- Drift ---------------- */

const POOL = {
  start: "192.0.2.23",
  stop: "192.0.2.235",
  label: "np 192.0.2.23-192.0.2.235",
};
const AT = "2026-07-21T00:00:00.000Z";

Deno.test("computeDrift reports an in-sync set", () => {
  const d = computeDrift(
    [{ mac: "02:00:5e:00:53:01", ip: "192.0.2.201" }],
    [{
      mac: "02:00:5E:00:53:01",
      fixed_ip: "192.0.2.201",
      use_fixedip: true,
    }],
    POOL,
    AT,
  );
  assertEquals(d.inSync, true);
  assertEquals(d.missing.length, 0);
  assertEquals(d.mismatched.length, 0);
});

Deno.test("computeDrift finds a reservation the controller lacks", () => {
  const d = computeDrift(
    [{ mac: "02:00:5e:00:53:01", ip: "192.0.2.201", name: "app-server" }],
    [],
    POOL,
    AT,
  );
  assertEquals(d.inSync, false);
  assertEquals(d.missing, [{
    mac: "02:00:5e:00:53:01",
    ip: "192.0.2.201",
    name: "app-server",
  }]);
});

Deno.test("computeDrift finds an address that moved", () => {
  const d = computeDrift(
    [{ mac: "02:00:5e:00:53:01", ip: "192.0.2.201" }],
    [{
      mac: "02:00:5e:00:53:01",
      fixed_ip: "192.0.2.132",
      use_fixedip: true,
    }],
    POOL,
    AT,
  );
  assertEquals(d.inSync, false);
  assertEquals(d.mismatched, [{
    mac: "02:00:5e:00:53:01",
    desired_ip: "192.0.2.201",
    live_ip: "192.0.2.132",
    name: undefined,
  }]);
});

Deno.test("computeDrift ignores clients that are not pinned", () => {
  const d = computeDrift(
    [],
    [
      { mac: "aa:bb:cc:dd:ee:ff", use_fixedip: false },
      { mac: "11:22:33:44:55:66" },
    ],
    POOL,
    AT,
  );
  assertEquals(d.liveCount, 0);
  assertEquals(d.unmanaged.length, 0);
});

Deno.test("computeDrift surfaces reservations absent from the desired set", () => {
  const d = computeDrift(
    [],
    [{
      mac: "02:00:5e:00:53:05",
      fixed_ip: "192.0.2.235",
      use_fixedip: true,
      name: "workstation",
    }],
    POOL,
    AT,
  );
  assertEquals(d.unmanaged, [{
    mac: "02:00:5e:00:53:05",
    fixed_ip: "192.0.2.235",
    name: "workstation",
  }]);
  // Unmanaged entries are informational — they do not by themselves mean drift.
  assertEquals(d.inSync, true);
});

Deno.test("computeDrift flags desired addresses inside the DHCP pool", () => {
  const d = computeDrift(
    [
      { mac: "02:00:5e:00:53:01", ip: "192.0.2.132" }, // in pool
      { mac: "02:00:5e:00:53:02", ip: "192.0.2.249" }, // above pool ceiling
    ],
    [],
    POOL,
    AT,
  );
  assertEquals(d.poolConflicts, [{
    mac: "02:00:5e:00:53:01",
    ip: "192.0.2.132",
    pool: POOL.label,
  }]);
});

Deno.test("computeDrift catches two MACs claiming one address", () => {
  // The real .10 collision: a reservation pointing at an address another host
  // already owns is silently refused by the controller.
  const d = computeDrift(
    [
      { mac: "02:00:5e:00:53:03", ip: "192.0.2.10" },
      { mac: "02:00:5e:00:53:04", ip: "192.0.2.10" },
    ],
    [],
    POOL,
    AT,
  );
  assertEquals(d.inSync, false);
  assertEquals(d.duplicates, [{
    ip: "192.0.2.10",
    macs: ["02:00:5e:00:53:03", "02:00:5e:00:53:04"],
  }]);
});

Deno.test("computeDrift catches one MAC claiming two addresses", () => {
  // The mirror of the duplicate-IP case: a hand-edited desired set that lists
  // the same host twice with different addresses. apply must refuse this rather
  // than PUT twice and let the last write win.
  const d = computeDrift(
    [
      { mac: "02:00:5e:00:53:01", ip: "192.0.2.201" },
      { mac: "02:00:5E:00:53:01", ip: "192.0.2.202" },
    ],
    [],
    POOL,
    AT,
  );
  assertEquals(d.inSync, false);
  assertEquals(d.conflictingMacs, [{
    mac: "02:00:5e:00:53:01",
    ips: ["192.0.2.201", "192.0.2.202"],
  }]);
});

Deno.test("computeDrift does not flag one MAC listed twice with the same IP", () => {
  const d = computeDrift(
    [
      { mac: "02:00:5e:00:53:01", ip: "192.0.2.201" },
      { mac: "02:00:5e:00:53:01", ip: "192.0.2.201" },
    ],
    [{
      mac: "02:00:5e:00:53:01",
      fixed_ip: "192.0.2.201",
      use_fixedip: true,
    }],
    POOL,
    AT,
  );
  assertEquals(d.conflictingMacs.length, 0);
});

Deno.test("computeDrift matches MACs across separator styles", () => {
  const d = computeDrift(
    [{ mac: "02-00-5E-00-53-01", ip: "192.0.2.201" }],
    [{
      mac: "02005e005301",
      fixed_ip: "192.0.2.201",
      use_fixedip: true,
    }],
    POOL,
    AT,
  );
  assertEquals(d.inSync, true);
});

/* ---------------- computeVerification ---------------- */

Deno.test("computeVerification confirms a host sitting at its desired address", () => {
  const v = computeVerification(
    [{ mac: "02:00:5e:00:53:01", ip: "192.0.2.201", name: "app" }],
    [{ mac: "02:00:5e:00:53:01", ip: "192.0.2.201" }],
    [],
    AT,
  );
  assertEquals(v.confirmed.length, 1);
  assertEquals(v.moved.length, 0);
  assertEquals(v.offline.length, 0);
  assertEquals(v.safeToApply, true);
});

Deno.test("computeVerification flags a host that has drifted since the audit", () => {
  const v = computeVerification(
    [{ mac: "02:00:5e:00:53:01", ip: "192.0.2.201", name: "app" }],
    [{ mac: "02:00:5e:00:53:01", ip: "192.0.2.55" }],
    [],
    AT,
  );
  assertEquals(v.moved, [{
    mac: "02:00:5e:00:53:01",
    desired_ip: "192.0.2.201",
    actual_ip: "192.0.2.55",
    name: "app",
  }]);
  assertEquals(v.confirmed.length, 0);
});

Deno.test("computeVerification reports an unseen host as offline, not confirmed", () => {
  const v = computeVerification(
    [{ mac: "02:00:5e:00:53:01", ip: "192.0.2.201", name: "app" }],
    [{ mac: "02:00:5e:00:53:99", ip: "192.0.2.10" }],
    [],
    AT,
  );
  assertEquals(v.offline.length, 1);
  assertEquals(v.confirmed.length, 0);
  assertEquals(v.moved.length, 0);
});

Deno.test("computeVerification catches a desired address held by another device", () => {
  const v = computeVerification(
    [{ mac: "02:00:5e:00:53:01", ip: "192.0.2.201", name: "app" }],
    [
      { mac: "02:00:5e:00:53:01", ip: "192.0.2.55" },
      { mac: "aa:bb:cc:dd:ee:ff", ip: "192.0.2.201", hostname: "someones-tv" },
    ],
    [],
    AT,
  );
  assertEquals(v.occupied, [{
    ip: "192.0.2.201",
    desired_mac: "02:00:5e:00:53:01",
    held_by_mac: "aa:bb:cc:dd:ee:ff",
    held_by_hostname: "someones-tv",
    name: "app",
  }]);
  assertEquals(v.safeToApply, false);
});

Deno.test("computeVerification does not flag a swap between two desired hosts", () => {
  // During a renumber each host transiently sits on the other's target. Both
  // are managed, so the set resolves itself and this is not a collision.
  const v = computeVerification(
    [
      { mac: "02:00:5e:00:53:01", ip: "192.0.2.201", name: "a" },
      { mac: "02:00:5e:00:53:02", ip: "192.0.2.202", name: "b" },
    ],
    [
      { mac: "02:00:5e:00:53:01", ip: "192.0.2.202" },
      { mac: "02:00:5e:00:53:02", ip: "192.0.2.201" },
    ],
    [],
    AT,
  );
  assertEquals(v.occupied.length, 0);
  assertEquals(v.moved.length, 2);
  assertEquals(v.safeToApply, true);
});

Deno.test("computeVerification ignores clients the controller reports without an address", () => {
  const v = computeVerification(
    [{ mac: "02:00:5e:00:53:01", ip: "192.0.2.201" }],
    [{ mac: "02:00:5e:00:53:01" }],
    [],
    AT,
  );
  assertEquals(v.offline.length, 1);
});

Deno.test("computeVerification matches MACs across separator styles", () => {
  const v = computeVerification(
    [{ mac: "02-00-5E-00-53-01", ip: "192.0.2.201" }],
    [{ mac: "02005e005301", ip: "192.0.2.201" }],
    [],
    AT,
  );
  assertEquals(v.confirmed.length, 1);
});

Deno.test("computeVerification flags adopted UniFi hardware as unreservable", () => {
  // The controller rejects a fixed-IP reservation for anything it manages as a
  // device with api.err.FixedIpAlreadyUsedByDevice, so this has to be caught
  // before apply rather than surfacing as a 400 per device.
  const v = computeVerification(
    [{ mac: "02:00:5e:00:53:07", ip: "192.0.2.30", name: "ap-back" }],
    [],
    [{ mac: "02:00:5e:00:53:07", ip: "192.0.2.30", name: "ap-back" }],
    AT,
  );
  assertEquals(v.adoptedDevices, [{
    mac: "02:00:5e:00:53:07",
    ip: "192.0.2.30",
    name: "ap-back",
  }]);
  assertEquals(v.safeToApply, false);
  // Still confirmed as present at the right address — it is reachable, just
  // not reservable.
  assertEquals(v.confirmed.length, 1);
});

Deno.test("computeVerification leaves a pure client set safe to apply", () => {
  const v = computeVerification(
    [{ mac: "02:00:5e:00:53:01", ip: "192.0.2.201", name: "app" }],
    [{ mac: "02:00:5e:00:53:01", ip: "192.0.2.201" }],
    [{ mac: "02:00:5e:00:53:07", ip: "192.0.2.30" }],
    AT,
  );
  assertEquals(v.adoptedDevices.length, 0);
  assertEquals(v.safeToApply, true);
});

Deno.test("computeVerification resolves a device address without calling it occupied", () => {
  // An AP holding the address it is supposed to hold is not a collision.
  const v = computeVerification(
    [{ mac: "02:00:5e:00:53:07", ip: "192.0.2.30", name: "ap-back" }],
    [],
    [{ mac: "02:00:5e:00:53:07", ip: "192.0.2.30" }],
    AT,
  );
  assertEquals(v.occupied.length, 0);
});

/* ---------------- analysePoolChange ---------------- */

const OLD_POOL = { start: "192.0.2.23", stop: "192.0.2.235" };

const entry = (
  ip: string,
  o: Partial<
    { mac: string; reserved: boolean; is_device: boolean; label: string }
  > = {},
) => ({
  mac: o.mac ?? `02:00:5e:00:00:${ip.split(".").pop()!.padStart(2, "0")}`,
  ip,
  label: o.label,
  is_device: o.is_device ?? false,
  reserved: o.reserved ?? false,
  in_dhcp_pool: false,
});

Deno.test("analysePoolChange reports an unreserved lease above the new ceiling", () => {
  const r = analysePoolChange(
    [entry("192.0.2.204", { label: "sonos" })],
    OLD_POOL,
    "192.0.2.23",
    "192.0.2.199",
  );
  assertEquals(r.displaced.length, 1);
  assertEquals(r.displaced[0].reserved, false);
});

Deno.test("analysePoolChange marks a displaced but reserved host as safe", () => {
  // Inside the old pool, outside the new one, but pinned — out-of-pool
  // reservations are honoured, so it keeps its address.
  const r = analysePoolChange(
    [entry("192.0.2.220", { reserved: true, label: "udsliving" })],
    OLD_POOL,
    "192.0.2.23",
    "192.0.2.199",
  );
  assertEquals(r.displaced.length, 1);
  assertEquals(r.displaced[0].reserved, true);
});

Deno.test("analysePoolChange ignores a host that was never in the old pool", () => {
  // .236 sits above the old ceiling of .235, so its address cannot have come
  // from a lease — it is static on the host. Narrowing the pool is a no-op for
  // it, and saying "will re-lease" would be wrong: there is no lease to expire.
  const r = analysePoolChange(
    [entry("192.0.2.236", { label: "kvm1" })],
    OLD_POOL,
    "192.0.2.23",
    "192.0.2.199",
  );
  assertEquals(r.displaced.length, 0);
});

Deno.test("analysePoolChange ignores adopted hardware, which takes no lease", () => {
  const r = analysePoolChange(
    [entry("192.0.2.220", { is_device: true, label: "switch" })],
    OLD_POOL,
    "192.0.2.23",
    "192.0.2.199",
  );
  assertEquals(r.displaced.length, 0);
});

Deno.test("analysePoolChange flags reservations left inside the new range", () => {
  const r = analysePoolChange(
    [entry("192.0.2.132", { reserved: true, label: "patchmon" })],
    OLD_POOL,
    "192.0.2.23",
    "192.0.2.199",
  );
  assertEquals(r.strandedReservations.length, 1);
  assertEquals(r.displaced.length, 0);
});

Deno.test("analysePoolChange leaves a host inside the new range alone", () => {
  const r = analysePoolChange(
    [entry("192.0.2.50")],
    OLD_POOL,
    "192.0.2.23",
    "192.0.2.199",
  );
  assertEquals(r.displaced.length, 0);
  assertEquals(r.strandedReservations.length, 0);
});

Deno.test("analysePoolChange skips hosts with no known address", () => {
  const r = analysePoolChange(
    [{
      mac: "02:00:5e:00:00:01",
      is_device: false,
      reserved: false,
      in_dhcp_pool: false,
    }],
    OLD_POOL,
    "192.0.2.23",
    "192.0.2.199",
  );
  assertEquals(r.displaced.length, 0);
});

/* ---------------- buildInventory ---------------- */

Deno.test("buildInventory joins reservation, live and device views by MAC", () => {
  const inv = buildInventory(
    [{
      mac: "02:00:5E:00:53:01",
      name: "app",
      use_fixedip: true,
      fixed_ip: "192.0.2.201",
    }],
    [{ mac: "02:00:5e:00:53:01", ip: "192.0.2.201", oui: "Acme" }],
    [],
    { start: "192.0.2.23", stop: "192.0.2.199" },
  );
  assertEquals(inv.length, 1);
  assertEquals(inv[0].reserved, true);
  assertEquals(inv[0].oui, "Acme");
  assertEquals(inv[0].is_device, false);
  assertEquals(inv[0].in_dhcp_pool, false);
});

Deno.test("buildInventory marks adopted hardware and sorts by address", () => {
  const inv = buildInventory(
    [],
    [{ mac: "02:00:5e:00:53:02", ip: "192.0.2.150" }],
    [{ mac: "02:00:5e:00:53:07", ip: "192.0.2.30", model: "U6-Pro" }],
    { start: "192.0.2.23", stop: "192.0.2.199" },
  );
  assertEquals(inv.map((e) => e.ip), ["192.0.2.30", "192.0.2.150"]);
  assertEquals(inv[0].is_device, true);
  assertEquals(inv[0].label, "U6-Pro");
  assertEquals(inv[1].in_dhcp_pool, true);
});

Deno.test("buildInventory sorts hosts with no address last", () => {
  const inv = buildInventory(
    [{ mac: "02:00:5e:00:53:09" }],
    [{ mac: "02:00:5e:00:53:02", ip: "192.0.2.150" }],
    [],
    {},
  );
  assertEquals(inv[0].ip, "192.0.2.150");
  assertEquals(inv[1].ip, undefined);
});
