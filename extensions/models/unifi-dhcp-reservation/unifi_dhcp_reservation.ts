// @sntxrr/unifi/dhcp_reservation
//
// Declarative DHCP reservations on a local UniFi controller (UDM / UDM Pro / UDM SE).
//
// Reservations live on the legacy Network API as "user" objects carrying
// `use_fixedip` + `fixed_ip`. This model reads them (`sync`), compares them
// against a desired set without writing (`drift`), and reconciles them
// (`apply`).
//
// The UniFi API client below is derived from @mgreten/unifi's `_lib/unifi.ts`
// (MIT, Copyright (c) 2026 Mat Greten) and extends it with TOTP/MFA support,
// which the upstream login flow does not implement.

import { z } from "npm:zod@4";

/* ------------------------------------------------------------------ *
 * TOTP (RFC 6238) — UniFi SSO accounts with MFA reject password-only
 * logins with {"code":"MFA_AUTH_REQUIRED"}. Deriving the code in-process
 * keeps the model runnable unattended.
 * ------------------------------------------------------------------ */

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/**
 * Decode a base32 (RFC 4648) secret into bytes.
 *
 * Tolerates lowercase, embedded whitespace and trailing `=` padding, which is
 * how TOTP seeds are usually presented by authenticator apps.
 *
 * @param input Base32-encoded secret.
 * @returns The decoded bytes.
 * @throws If the input is empty or contains a non-base32 character.
 */
export function base32Decode(input: string): Uint8Array<ArrayBuffer> {
  const clean = input.toUpperCase().replace(/=+$/, "").replace(/\s+/g, "");
  if (clean.length === 0) throw new Error("Empty base32 secret");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`Invalid base32 character: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  // Back the view with a concrete ArrayBuffer so it satisfies BufferSource.
  const view = new Uint8Array(new ArrayBuffer(out.length));
  view.set(out);
  return view;
}

/**
 * Derive an RFC 6238 TOTP code (HMAC-SHA1) from a base32 secret.
 *
 * `nowMs` is an explicit parameter rather than an internal `Date.now()` call so
 * the function is deterministic and testable against the RFC's reference
 * vectors.
 *
 * @param secret Base32-encoded shared secret.
 * @param nowMs Current time in milliseconds since the epoch.
 * @param stepSeconds Time step; the RFC default is 30 seconds.
 * @param digits Code length; the RFC default is 6.
 * @returns The zero-padded numeric code.
 */
export async function totpCode(
  secret: string,
  nowMs: number,
  stepSeconds = 30,
  digits = 6,
): Promise<string> {
  const counter = Math.floor(nowMs / 1000 / stepSeconds);
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(0, Math.floor(counter / 2 ** 32));
  view.setUint32(4, counter >>> 0);

  const key = await crypto.subtle.importKey(
    "raw",
    base32Decode(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, buf));
  const offset = sig[sig.length - 1] & 0x0f;
  const bin = ((sig[offset] & 0x7f) << 24) |
    (sig[offset + 1] << 16) |
    (sig[offset + 2] << 8) |
    sig[offset + 3];
  return (bin % 10 ** digits).toString().padStart(digits, "0");
}

/* ------------------------------------------------------------------ *
 * IPv4 helpers — used to catch reservations that fall inside the DHCP
 * pool (the controller may refuse them) or collide with each other.
 * ------------------------------------------------------------------ */

/**
 * Convert a dotted-quad IPv4 address to its integer value, for range compares.
 *
 * @param ip Dotted-quad address, e.g. `192.0.2.10`.
 * @returns The address as an unsigned 32-bit integer.
 * @throws If the input is not a well-formed IPv4 address.
 */
export function ipToInt(ip: string): number {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) throw new Error(`Not an IPv4 address: ${ip}`);
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) throw new Error(`Not an IPv4 address: ${ip}`);
    const octet = parseInt(p, 10);
    if (octet > 255) throw new Error(`Octet out of range in: ${ip}`);
    n = n * 256 + octet;
  }
  return n;
}

/**
 * Test whether an address falls inside a DHCP range, endpoints included.
 *
 * Returns `false` when the range is unknown or any address is malformed — an
 * unparseable value should not be reported as a pool conflict.
 *
 * @param ip Address to test.
 * @param start First address of the DHCP range.
 * @param stop Last address of the DHCP range.
 * @returns True when `ip` lies within `[start, stop]`.
 */
export function inPool(ip: string, start?: string, stop?: string): boolean {
  if (!start || !stop) return false;
  try {
    const v = ipToInt(ip);
    return v >= ipToInt(start) && v <= ipToInt(stop);
  } catch {
    return false;
  }
}

/**
 * Canonicalise a MAC address to lowercase colon-separated form.
 *
 * Lets `02:00:5E:00:53:01`, `bc-24-11-ce-ea-1f` and `02005e005301` all compare
 * equal, since the controller and hand-written desired sets rarely agree on
 * separator style.
 *
 * @param mac MAC address in any common separator style.
 * @returns The normalised address, e.g. `02:00:5e:00:53:01`.
 */
export function normalizeMac(mac: string): string {
  return mac.trim().toLowerCase().replace(/[^0-9a-f]/g, "").match(/.{1,2}/g)
    ?.join(":") ?? mac.trim().toLowerCase();
}

/* ------------------------------------------------------------------ *
 * UniFi API client
 * ------------------------------------------------------------------ */

/**
 * Connection and credential arguments shared by every method on this model.
 */
export const UnifiGlobalArgsSchema = z.object({
  host: z.string().describe("UDM IP address or hostname, e.g. 192.0.2.1"),
  username: z.string().describe("UniFi admin username"),
  password: z.string().meta({ sensitive: true }).describe(
    "UniFi admin password (use a vault reference)",
  ),
  totpSecret: z.string().meta({ sensitive: true }).optional().describe(
    "Base32 TOTP secret for MFA-enabled accounts (use a vault reference). " +
      "Omit for local-only admin accounts, which bypass SSO MFA.",
  ),
  site: z.string().default("default").describe("UniFi site name"),
});

/** Resolved form of {@link UnifiGlobalArgsSchema}. */
export type UnifiGlobalArgs = z.infer<typeof UnifiGlobalArgsSchema>;

/** An authenticated session against a UniFi controller. */
export interface UnifiClient {
  request<T = unknown>(
    path: string,
    method?: string,
    body?: unknown,
  ): Promise<T>;
  cleanup(): Promise<void>;
  baseUrl: string;
  site: string;
}

// curl rather than fetch: UDM controllers use self-signed certificates and
// Deno's fetch cannot skip TLS verification.
async function curl(
  url: string,
  init: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
  } = {},
): Promise<Response> {
  const args = ["-sk", "--connect-timeout", "10", "-X", init.method || "GET"];

  if (init.headers) {
    for (const [key, value] of Object.entries(init.headers)) {
      args.push("-H", `${key}: ${value}`);
    }
  }
  // Feed the body through stdin rather than argv. Process arguments are world
  // readable via `ps` on most hosts, and the login body carries the password
  // and TOTP code.
  const hasBody = init.body !== undefined;
  if (hasBody) args.push("--data-binary", "@-");

  args.push("-D", "/dev/stderr", url);

  const cmd = new Deno.Command("curl", {
    args,
    stdin: hasBody ? "piped" : "null",
    stdout: "piped",
    stderr: "piped",
  });

  let output;
  if (hasBody) {
    const child = cmd.spawn();
    const writer = child.stdin.getWriter();
    await writer.write(new TextEncoder().encode(init.body as string));
    await writer.close();
    output = await child.output();
  } else {
    output = await cmd.output();
  }
  const body = new TextDecoder().decode(output.stdout);
  const headerText = new TextDecoder().decode(output.stderr);

  const statusMatch = headerText.match(/HTTP\/[\d.]+ (\d+)/);
  const status = statusMatch
    ? parseInt(statusMatch[1])
    : (output.success ? 200 : 500);

  const responseHeaders = new Headers();
  for (const line of headerText.split(/\r?\n/)) {
    const colonIdx = line.indexOf(":");
    if (colonIdx > 0) {
      responseHeaders.append(
        line.slice(0, colonIdx).trim(),
        line.slice(colonIdx + 1).trim(),
      );
    }
  }
  return new Response(body, { status, headers: responseHeaders });
}

// Never let the password or TOTP secret reach a log line or thrown error.
function redact(text: string, secrets: (string | undefined)[]): string {
  let out = text;
  for (const s of secrets) {
    if (s && s.length > 0) out = out.replaceAll(s, "[REDACTED]");
  }
  return out;
}

/**
 * Authenticate against a UniFi controller and return a session.
 *
 * Posts to `/api/auth/login`, capturing the session cookie and CSRF token. When
 * `totpSecret` is set, a TOTP code is derived and sent as `token` — accounts
 * with MFA enabled reject password-only logins with `MFA_AUTH_REQUIRED`.
 * Credentials are redacted from any error raised here.
 *
 * @param args Connection and credential arguments.
 * @param nowMs Current time, injectable for deterministic TOTP in tests.
 * @returns An authenticated {@link UnifiClient}. Call `cleanup()` when done.
 * @throws If authentication fails, with a hint when MFA is the cause.
 */
export async function login(
  args: UnifiGlobalArgs,
  nowMs: number = Date.now(),
): Promise<UnifiClient> {
  const baseUrl = `https://${args.host}`;
  const secrets = [args.password, args.totpSecret];

  const payload: Record<string, unknown> = {
    username: args.username,
    password: args.password,
    rememberMe: true,
  };
  if (args.totpSecret) {
    payload.token = await totpCode(args.totpSecret, nowMs);
  }

  const loginResp = await curl(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(payload),
  });

  if (!loginResp.ok) {
    const text = redact(await loginResp.text(), secrets);
    const hint = text.includes("MFA_AUTH_REQUIRED")
      ? " — this account requires MFA; set `totpSecret`, or use a local-only admin account"
      : "";
    throw new Error(
      `UniFi login to ${args.host} failed (${loginResp.status})${hint}: ${text}`,
    );
  }

  const csrfToken = loginResp.headers.get("x-csrf-token") || "";
  const setCookie = loginResp.headers.get("set-cookie") || "";
  const cookie = setCookie
    .split(",")
    .map((c) => c.split(";")[0].trim())
    .filter((c) => c.length > 0)
    .join("; ");

  return {
    baseUrl,
    site: args.site,
    async request<T = unknown>(
      path: string,
      method = "GET",
      body?: unknown,
    ): Promise<T> {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
        Accept: "application/json",
        Cookie: cookie,
      };
      if (method !== "GET" && method !== "HEAD") {
        headers["X-CSRF-Token"] = csrfToken;
      }

      const resp = await curl(`${baseUrl}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      });

      if (!resp.ok) {
        const text = redact(await resp.text(), secrets);
        throw new Error(
          `UniFi API ${method} ${path} failed (${resp.status}): ${text}`,
        );
      }

      const text = await resp.text();
      if (!text) return undefined as unknown as T;
      try {
        return JSON.parse(text) as T;
      } catch {
        return text as unknown as T;
      }
    },
    async cleanup() {
      try {
        await curl(`${baseUrl}/api/auth/logout`, {
          method: "POST",
          headers: { Cookie: cookie, "X-CSRF-Token": csrfToken },
        });
      } catch {
        // best-effort
      }
    },
  };
}

/**
 * Build a path into the legacy Network API as proxied by the controller.
 *
 * @param site UniFi site name, usually `default`.
 * @param suffix Endpoint below the site root, e.g. `/rest/user`.
 * @returns The full request path.
 */
export function networkPath(site: string, suffix: string): string {
  return `/proxy/network/api/s/${site}${suffix}`;
}

const UnifiListResponseSchema = z.object({
  meta: z.object({
    rc: z.string().optional(),
    msg: z.string().optional(),
  }).optional(),
  data: z.array(z.unknown()).optional(),
});

/**
 * GET a Network API list endpoint and return its `data` array.
 *
 * @param client An authenticated session.
 * @param endpoint Endpoint below the site root, e.g. `/rest/user`.
 * @returns The rows the controller returned, or an empty array.
 * @throws If the controller reports a non-`ok` result code.
 */
export async function list<T = Record<string, unknown>>(
  client: UnifiClient,
  endpoint: string,
): Promise<T[]> {
  const raw = await client.request<unknown>(
    networkPath(client.site, endpoint),
    "GET",
  );
  const resp = UnifiListResponseSchema.parse(raw);
  if (resp.meta?.rc && resp.meta.rc !== "ok") {
    throw new Error(`UniFi API returned rc=${resp.meta.rc}: ${resp.meta.msg}`);
  }
  return (resp.data ?? []) as T[];
}

/* ------------------------------------------------------------------ *
 * Schemas
 * ------------------------------------------------------------------ */

const UnifiUserSchema = z.object({
  _id: z.string().optional(),
  mac: z.string(),
  name: z.string().optional(),
  hostname: z.string().optional(),
  fixed_ip: z.string().optional(),
  use_fixedip: z.boolean().optional(),
  network_id: z.string().optional(),
});
type UnifiUser = z.infer<typeof UnifiUserSchema>;

const NetworkConfSchema = z.object({
  _id: z.string().optional(),
  name: z.string().optional(),
  purpose: z.string().optional(),
  ip_subnet: z.string().optional(),
  dhcpd_enabled: z.boolean().optional(),
  dhcpd_start: z.string().optional(),
  dhcpd_stop: z.string().optional(),
});
type NetworkConf = z.infer<typeof NetworkConfSchema>;

// `/stat/sta` — clients the controller currently sees. Unlike `/rest/user`
// (every client ever known), this carries the address a host is *actually*
// using right now, which is what a reserve-in-place set has to be checked
// against.
const ActiveClientSchema = z.object({
  mac: z.string(),
  ip: z.string().optional(),
  hostname: z.string().optional(),
  name: z.string().optional(),
  is_wired: z.boolean().optional(),
});
type ActiveClient = z.infer<typeof ActiveClientSchema>;

const VerifySchema = z.object({
  checkedAt: z.string(),
  desiredCount: z.number(),
  safeToApply: z.boolean().describe(
    "True when no desired address is currently held by a different device.",
  ),
  confirmed: z.array(z.object({
    mac: z.string(),
    ip: z.string(),
    name: z.string().optional(),
  })).describe("Host is online at exactly the desired address."),
  moved: z.array(z.object({
    mac: z.string(),
    desired_ip: z.string(),
    actual_ip: z.string(),
    name: z.string().optional(),
  })).describe(
    "Host is online at a different address than the desired set expects. " +
      "For a reserve-in-place set this means the set is stale.",
  ),
  offline: z.array(z.object({
    mac: z.string(),
    ip: z.string(),
    name: z.string().optional(),
  })).describe(
    "Desired MAC is not currently visible, so its address cannot be " +
      "confirmed either way.",
  ),
  occupied: z.array(z.object({
    ip: z.string(),
    desired_mac: z.string(),
    held_by_mac: z.string(),
    held_by_hostname: z.string().optional(),
    name: z.string().optional(),
  })).describe(
    "Desired address is currently in use by a different device — reserving " +
      "it would collide.",
  ),
  adoptedDevices: z.array(z.object({
    mac: z.string(),
    ip: z.string(),
    name: z.string().optional(),
  })).describe(
    "Desired MAC is adopted UniFi hardware. The controller refuses DHCP " +
      "reservations for these with api.err.FixedIpAlreadyUsedByDevice — they " +
      "must be pinned in device config instead.",
  ),
});

const ReservationSchema = z.object({
  mac: z.string(),
  fixed_ip: z.string(),
  name: z.string().optional(),
  hostname: z.string().optional(),
  unifi_id: z.string().optional(),
  in_dhcp_pool: z.boolean().describe(
    "True when this address falls inside the controller's DHCP range.",
  ),
});

const DesiredEntrySchema = z.object({
  mac: z.string().describe("Client MAC address (any common separator)"),
  ip: z.string().describe("Desired fixed IPv4 address"),
  name: z.string().optional().describe("Optional alias to set on the client"),
});

const DriftSchema = z.object({
  checkedAt: z.string(),
  inSync: z.boolean(),
  desiredCount: z.number(),
  liveCount: z.number(),
  missing: z.array(z.object({
    mac: z.string(),
    ip: z.string(),
    name: z.string().optional(),
  })).describe("Desired reservations the controller does not have at all."),
  mismatched: z.array(z.object({
    mac: z.string(),
    desired_ip: z.string(),
    live_ip: z.string(),
    name: z.string().optional(),
  })).describe("Reserved, but pinned to a different address than desired."),
  unmanaged: z.array(z.object({
    mac: z.string(),
    fixed_ip: z.string(),
    name: z.string().optional(),
  })).describe("Reservations on the controller absent from the desired set."),
  poolConflicts: z.array(z.object({
    mac: z.string(),
    ip: z.string(),
    pool: z.string(),
  })).describe(
    "Desired addresses inside the DHCP range — reachable but liable to collide.",
  ),
  duplicates: z.array(z.object({
    ip: z.string(),
    macs: z.array(z.string()),
  })).describe("One address claimed by more than one desired entry."),
  conflictingMacs: z.array(z.object({
    mac: z.string(),
    ips: z.array(z.string()),
  })).describe("One MAC assigned more than one address by the desired set."),
});

const ApplyResultSchema = z.object({
  mac: z.string(),
  ip: z.string(),
  action: z.enum(["created", "updated", "unchanged", "failed"]),
  detail: z.string().optional(),
  dryRun: z.boolean().describe(
    "True when no write was actually issued. Without this, a rehearsal is " +
      "indistinguishable from a real run in stored data.",
  ),
});

/* ------------------------------------------------------------------ *
 * Pure comparison logic (exported for tests)
 * ------------------------------------------------------------------ */

/**
 * Compare a desired reservation set against what the controller holds.
 *
 * Pure and side-effect free — all I/O happens in the calling method, so the
 * comparison rules can be tested directly.
 *
 * `unmanaged` entries are reported but do **not** clear `inSync`: a reservation
 * outside the managed set is information, not drift. `duplicates` and
 * `poolConflicts` catch the two ways a reservation silently fails to take
 * effect — an address claimed twice, and an address inside the DHCP range.
 *
 * @param desired The reservation set that should exist.
 * @param live Client objects as returned by `/rest/user`.
 * @param pool The controller's DHCP range, with a label for reporting.
 * @param checkedAt Timestamp to stamp on the result.
 * @returns The drift report.
 */
export function computeDrift(
  desired: { mac: string; ip: string; name?: string }[],
  live: UnifiUser[],
  pool: { start?: string; stop?: string; label: string },
  checkedAt: string,
): z.infer<typeof DriftSchema> {
  const norm = desired.map((d) => ({ ...d, mac: normalizeMac(d.mac) }));
  const liveReserved = live
    .filter((u) => u.use_fixedip === true && u.fixed_ip)
    .map((u) => ({ ...u, mac: normalizeMac(u.mac) }));

  const liveByMac = new Map(liveReserved.map((u) => [u.mac, u]));
  const desiredByMac = new Map(norm.map((d) => [d.mac, d]));

  const missing: { mac: string; ip: string; name?: string }[] = [];
  const mismatched: {
    mac: string;
    desired_ip: string;
    live_ip: string;
    name?: string;
  }[] = [];

  for (const d of norm) {
    const l = liveByMac.get(d.mac);
    if (!l) {
      missing.push({ mac: d.mac, ip: d.ip, name: d.name });
    } else if (l.fixed_ip !== d.ip) {
      mismatched.push({
        mac: d.mac,
        desired_ip: d.ip,
        live_ip: l.fixed_ip!,
        name: d.name,
      });
    }
  }

  const unmanaged = liveReserved
    .filter((l) => !desiredByMac.has(l.mac))
    .map((l) => ({ mac: l.mac, fixed_ip: l.fixed_ip!, name: l.name }));

  const poolConflicts = norm
    .filter((d) => inPool(d.ip, pool.start, pool.stop))
    .map((d) => ({ mac: d.mac, ip: d.ip, pool: pool.label }));

  const byIp = new Map<string, string[]>();
  for (const d of norm) {
    byIp.set(d.ip, [...(byIp.get(d.ip) ?? []), d.mac]);
  }
  const duplicates = [...byIp.entries()]
    .filter(([, macs]) => macs.length > 1)
    .map(([ip, macs]) => ({ ip, macs }));

  // The mirror case: one MAC listed twice with different addresses. Without
  // this, `apply` would issue both writes and the last one would silently win,
  // and both results would collide on the same instance name.
  const byMac = new Map<string, string[]>();
  for (const d of norm) {
    byMac.set(d.mac, [...(byMac.get(d.mac) ?? []), d.ip]);
  }
  const conflictingMacs = [...byMac.entries()]
    .filter(([, ips]) => new Set(ips).size > 1)
    .map(([mac, ips]) => ({ mac, ips: [...new Set(ips)] }));

  return {
    checkedAt,
    inSync: missing.length === 0 && mismatched.length === 0 &&
      duplicates.length === 0 && conflictingMacs.length === 0,
    desiredCount: norm.length,
    liveCount: liveReserved.length,
    missing,
    mismatched,
    unmanaged,
    poolConflicts,
    duplicates,
    conflictingMacs,
  };
}

/**
 * Check a desired reservation set against where hosts actually are right now.
 *
 * `drift` compares desired against *reservations*; this compares desired
 * against *live leases*. The difference matters for a reserve-in-place set
 * built from an earlier audit: an unreserved host may have moved since, and
 * the address the set wants to pin may meanwhile have been leased to something
 * else. Pinning it then collides.
 *
 * A desired MAC that is offline lands in `offline` rather than being assumed
 * correct — the controller only reports addresses for clients it can see, and
 * silence is not confirmation.
 *
 * Pure and side-effect free, so the rules can be tested without a controller.
 *
 * Adopted UniFi hardware is a special case: the controller rejects a fixed-IP
 * reservation for anything it manages as a *device* rather than a client, with
 * `api.err.FixedIpAlreadyUsedByDevice`. Those entries are reported separately
 * so the set can be corrected before `apply` runs into a 400 per device.
 *
 * @param desired The reservation set that should exist.
 * @param active Client objects as returned by `/stat/sta`.
 * @param devices Adopted hardware as returned by `/stat/device`.
 * @param checkedAt Timestamp to stamp on the result.
 * @returns The verification report.
 */
export function computeVerification(
  desired: { mac: string; ip: string; name?: string }[],
  active: ActiveClient[],
  devices: ActiveClient[],
  checkedAt: string,
): z.infer<typeof VerifySchema> {
  const norm = desired.map((d) => ({ ...d, mac: normalizeMac(d.mac) }));
  const seen = [...active, ...devices]
    .filter((c) => c.ip && c.ip.length > 0)
    .map((c) => ({ ...c, mac: normalizeMac(c.mac) }));
  const deviceMacs = new Set(devices.map((d) => normalizeMac(d.mac)));

  const byMac = new Map(seen.map((c) => [c.mac, c]));
  const byIp = new Map(seen.map((c) => [c.ip!, c]));
  const desiredMacs = new Set(norm.map((d) => d.mac));

  const confirmed: { mac: string; ip: string; name?: string }[] = [];
  const moved: {
    mac: string;
    desired_ip: string;
    actual_ip: string;
    name?: string;
  }[] = [];
  const offline: { mac: string; ip: string; name?: string }[] = [];
  const occupied: {
    ip: string;
    desired_mac: string;
    held_by_mac: string;
    held_by_hostname?: string;
    name?: string;
  }[] = [];

  for (const d of norm) {
    const live = byMac.get(d.mac);
    if (!live) {
      offline.push({ mac: d.mac, ip: d.ip, name: d.name });
    } else if (live.ip === d.ip) {
      confirmed.push({ mac: d.mac, ip: d.ip, name: d.name });
    } else {
      moved.push({
        mac: d.mac,
        desired_ip: d.ip,
        actual_ip: live.ip!,
        name: d.name,
      });
    }

    // Is the address we want to pin already in use by something else? A host
    // sitting at its own desired address is not a conflict; another device
    // there is. Two desired entries colliding is `drift`'s `duplicates`.
    const holder = byIp.get(d.ip);
    if (holder && holder.mac !== d.mac && !desiredMacs.has(holder.mac)) {
      occupied.push({
        ip: d.ip,
        desired_mac: d.mac,
        held_by_mac: holder.mac,
        held_by_hostname: holder.hostname ?? holder.name,
        name: d.name,
      });
    }
  }

  const adoptedDevices = norm
    .filter((d) => deviceMacs.has(d.mac))
    .map((d) => ({ mac: d.mac, ip: d.ip, name: d.name }));

  return {
    checkedAt,
    desiredCount: norm.length,
    // Both of these make `apply` fail rather than merely be unwise, so
    // "safe" has to mean "every write will be accepted".
    safeToApply: occupied.length === 0 && adoptedDevices.length === 0,
    confirmed,
    moved,
    offline,
    occupied,
    adoptedDevices,
  };
}

/* ------------------------------------------------------------------ *
 * Model
 * ------------------------------------------------------------------ */

interface Context {
  globalArgs: UnifiGlobalArgs;
  writeResource: (
    spec: string,
    instance: string,
    data: unknown,
  ) => Promise<unknown>;
  logger: {
    info: (msg: string, props?: unknown) => void;
    warn: (msg: string, props?: unknown) => void;
  };
}

/**
 * Parse client rows, skipping any that do not match the expected shape.
 *
 * A single malformed record should not abort a whole run — the controller can
 * carry odd legacy entries, and dropping one row is far better than failing
 * the reconciliation of every other host.
 */
function parseUsers(
  rows: unknown[],
  logger: { warn: (msg: string, props?: unknown) => void },
): UnifiUser[] {
  const parsed: UnifiUser[] = [];
  let skipped = 0;
  for (const row of rows) {
    const result = UnifiUserSchema.safeParse(row);
    if (result.success) parsed.push(result.data);
    else skipped++;
  }
  if (skipped > 0) {
    logger.warn(
      "Skipped {count} client records that did not match the expected shape",
      { count: skipped },
    );
  }
  return parsed;
}

async function loadPool(
  client: UnifiClient,
): Promise<{ start?: string; stop?: string; label: string }> {
  const networks = await list<NetworkConf>(client, "/rest/networkconf");
  const lan = networks
    .map((n) => NetworkConfSchema.safeParse(n))
    .flatMap((r) => r.success ? [r.data] : [])
    .find((n) => n.purpose !== "wan" && n.dhcpd_enabled === true);
  if (!lan) return { start: undefined, stop: undefined, label: "none" };
  return {
    start: lan.dhcpd_start,
    stop: lan.dhcpd_stop,
    label: `${lan.name ?? "lan"} ${lan.dhcpd_start}-${lan.dhcpd_stop}`,
  };
}

/**
 * Swamp model for UniFi DHCP fixed-IP reservations.
 *
 * Three methods:
 * - `sync` — store one resource per reservation the controller holds. Read-only.
 * - `drift` — compare a desired set against the controller. Read-only.
 * - `apply` — reconcile the controller to the desired set. Writes; supports
 *   `dryRun`, and refuses a desired set that assigns one address to multiple
 *   MACs rather than letting the last write win.
 */
export const model = {
  type: "@sntxrr/unifi/dhcp_reservation",
  version: "2026.07.28.1",
  globalArguments: UnifiGlobalArgsSchema,
  resources: {
    reservation: {
      description: "A DHCP fixed-IP reservation known to the controller.",
      schema: ReservationSchema,
      lifetime: "infinite" as const,
      garbageCollection: 3,
    },
    drift: {
      description:
        "Comparison of a desired reservation set against the controller.",
      schema: DriftSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    verification: {
      description:
        "Pre-flight of a desired reservation set against live DHCP leases.",
      schema: VerifySchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    apply_result: {
      description: "Outcome of reconciling one reservation.",
      schema: ApplyResultSchema,
      lifetime: "infinite" as const,
      garbageCollection: 5,
    },
  },
  methods: {
    sync: {
      description:
        "Read every fixed-IP reservation from the controller and store one " +
        "resource per reservation. Read-only.",
      arguments: z.object({}),
      execute: async (_args: Record<never, never>, context: Context) => {
        context.logger.info("Reading reservations from {host}", {
          host: context.globalArgs.host,
        });
        const client = await login(context.globalArgs);
        try {
          const pool = await loadPool(client);
          const reserved = parseUsers(
            await list<UnifiUser>(client, "/rest/user"),
            context.logger,
          ).filter((u) => u.use_fixedip === true && u.fixed_ip);

          context.logger.info(
            "Found {count} fixed-IP reservations (DHCP pool: {pool})",
            { count: reserved.length, pool: pool.label },
          );

          const handles: unknown[] = [];
          for (const u of reserved) {
            const mac = normalizeMac(u.mac);
            handles.push(
              await context.writeResource("reservation", mac, {
                mac,
                fixed_ip: u.fixed_ip!,
                name: u.name,
                hostname: u.hostname,
                unifi_id: u._id,
                in_dhcp_pool: inPool(u.fixed_ip!, pool.start, pool.stop),
              }),
            );
          }
          return { dataHandles: handles };
        } finally {
          await client.cleanup();
        }
      },
    },

    drift: {
      description:
        "Compare a desired reservation set against the controller without " +
        "writing. Reports missing, mismatched, unmanaged, pool-conflicting " +
        "and duplicate entries. Read-only.",
      arguments: z.object({
        desired: z.array(DesiredEntrySchema).describe(
          "The reservation set that should exist.",
        ),
      }),
      execute: async (
        args: { desired: z.infer<typeof DesiredEntrySchema>[] },
        context: Context,
      ) => {
        context.logger.info(
          "Comparing {n} desired reservations against {host}",
          { n: args.desired.length, host: context.globalArgs.host },
        );
        const client = await login(context.globalArgs);
        try {
          const pool = await loadPool(client);
          const users = parseUsers(
            await list<UnifiUser>(client, "/rest/user"),
            context.logger,
          );

          const result = computeDrift(
            args.desired,
            users,
            pool,
            new Date().toISOString(),
          );

          if (!result.inSync) {
            context.logger.warn(
              "Drift: {missing} missing, {mismatched} mismatched, {dupes} duplicate",
              {
                missing: result.missing.length,
                mismatched: result.mismatched.length,
                dupes: result.duplicates.length,
              },
            );
          } else {
            context.logger.info("Reservations in sync ({n} entries)", {
              n: result.desiredCount,
            });
          }
          if (result.poolConflicts.length > 0) {
            context.logger.warn(
              "{n} desired addresses sit inside the DHCP pool ({pool})",
              { n: result.poolConflicts.length, pool: pool.label },
            );
          }

          // "latest" is reserved by swamp for internal use.
          const handle = await context.writeResource(
            "drift",
            "current",
            result,
          );
          return { dataHandles: [handle] };
        } finally {
          await client.cleanup();
        }
      },
    },

    verify: {
      description:
        "Pre-flight a desired reservation set against live DHCP leases: where " +
        "each host actually is now, and whether any desired address is already " +
        "held by a different device. Read-only.",
      arguments: z.object({
        desired: z.array(DesiredEntrySchema).describe(
          "The reservation set that should exist.",
        ),
      }),
      execute: async (
        args: { desired: z.infer<typeof DesiredEntrySchema>[] },
        context: Context,
      ) => {
        context.logger.info(
          "Checking {n} desired reservations against live leases on {host}",
          { n: args.desired.length, host: context.globalArgs.host },
        );
        const client = await login(context.globalArgs);
        try {
          // Adopted UniFi hardware (APs, switches) is not a "client" and never
          // appears on /stat/sta. It is read separately rather than merged,
          // because the controller also refuses to reserve it.
          let skipped = 0;
          const parseRows = (rows: unknown[]): ActiveClient[] => {
            const out: ActiveClient[] = [];
            for (const row of rows) {
              const parsed = ActiveClientSchema.safeParse(row);
              if (parsed.success) out.push(parsed.data);
              else skipped++;
            }
            return out;
          };

          const active = parseRows(await list(client, "/stat/sta"));
          const devices = parseRows(await list(client, "/stat/device"));
          if (skipped > 0) {
            context.logger.warn(
              "Skipped {count} client records that did not match the expected shape",
              { count: skipped },
            );
          }

          const result = computeVerification(
            args.desired,
            active,
            devices,
            new Date().toISOString(),
          );

          context.logger.info(
            "{online} of {total} desired hosts online: {ok} at the expected address, {moved} elsewhere",
            {
              online: result.confirmed.length + result.moved.length,
              total: result.desiredCount,
              ok: result.confirmed.length,
              moved: result.moved.length,
            },
          );
          for (const m of result.moved) {
            context.logger.warn(
              "{name} ({mac}) is at {actual}, desired set says {desired}",
              {
                name: m.name ?? "unnamed",
                mac: m.mac,
                actual: m.actual_ip,
                desired: m.desired_ip,
              },
            );
          }
          for (const o of result.occupied) {
            context.logger.warn(
              "{ip} is currently held by {holder} — reserving it for {name} would collide",
              {
                ip: o.ip,
                holder: o.held_by_hostname ?? o.held_by_mac,
                name: o.name ?? o.desired_mac,
              },
            );
          }
          for (const a of result.adoptedDevices) {
            context.logger.warn(
              "{name} ({mac}) is adopted UniFi hardware — it cannot hold a DHCP reservation; pin it in device config instead",
              { name: a.name ?? "unnamed", mac: a.mac },
            );
          }
          if (result.offline.length > 0) {
            context.logger.info(
              "{n} desired hosts are not currently visible; their addresses could not be confirmed",
              { n: result.offline.length },
            );
          }

          const handle = await context.writeResource(
            "verification",
            "current",
            result,
          );
          return { dataHandles: [handle] };
        } finally {
          await client.cleanup();
        }
      },
    },

    apply: {
      description:
        "Reconcile the controller to a desired reservation set. Creates " +
        "missing client objects, updates mismatched ones, leaves correct " +
        "ones untouched. Fans out over every entry in a single run. WRITES.",
      arguments: z.object({
        desired: z.array(DesiredEntrySchema).describe(
          "The reservation set that should exist.",
        ),
        dryRun: z.boolean().default(false).describe(
          "Report the actions that would be taken without writing.",
        ),
      }),
      execute: async (
        args: {
          desired: z.infer<typeof DesiredEntrySchema>[];
          dryRun: boolean;
        },
        context: Context,
      ) => {
        context.logger.info(
          "Reconciling {n} reservations on {host} (dryRun={dry})",
          {
            n: args.desired.length,
            host: context.globalArgs.host,
            dry: args.dryRun,
          },
        );
        const client = await login(context.globalArgs);
        try {
          const pool = await loadPool(client);
          const users = parseUsers(
            await list<UnifiUser>(client, "/rest/user"),
            context.logger,
          );
          const liveByMac = new Map(
            users.map((u) => [normalizeMac(u.mac), u]),
          );

          // Refuse a set that contradicts itself — applying it would leave the
          // controller in whichever state the last write happened to produce.
          const preflight = computeDrift(
            args.desired,
            users,
            pool,
            new Date().toISOString(),
          );
          if (preflight.duplicates.length > 0) {
            throw new Error(
              `Desired set assigns one address to multiple MACs: ` +
                preflight.duplicates
                  .map((d) => `${d.ip} -> ${d.macs.join(", ")}`)
                  .join("; "),
            );
          }
          if (preflight.conflictingMacs.length > 0) {
            throw new Error(
              `Desired set assigns multiple addresses to one MAC: ` +
                preflight.conflictingMacs
                  .map((c) => `${c.mac} -> ${c.ips.join(", ")}`)
                  .join("; "),
            );
          }

          const handles: unknown[] = [];
          for (const entry of args.desired) {
            const mac = normalizeMac(entry.mac);
            const existing = liveByMac.get(mac);
            let action: z.infer<typeof ApplyResultSchema>["action"];
            let detail: string | undefined;

            try {
              if (
                existing?.use_fixedip === true && existing.fixed_ip === entry.ip
              ) {
                action = "unchanged";
              } else if (existing?._id) {
                if (!args.dryRun) {
                  await client.request(
                    networkPath(client.site, `/rest/user/${existing._id}`),
                    "PUT",
                    {
                      use_fixedip: true,
                      fixed_ip: entry.ip,
                      ...(entry.name ? { name: entry.name } : {}),
                    },
                  );
                }
                action = "updated";
                detail = existing.fixed_ip
                  ? `${existing.fixed_ip} -> ${entry.ip}`
                  : `unpinned -> ${entry.ip}`;
              } else {
                if (!args.dryRun) {
                  await client.request(
                    networkPath(client.site, "/rest/user"),
                    "POST",
                    {
                      mac,
                      use_fixedip: true,
                      fixed_ip: entry.ip,
                      ...(entry.name ? { name: entry.name } : {}),
                    },
                  );
                }
                action = "created";
                detail = `new client object pinned to ${entry.ip}`;
              }

              if (inPool(entry.ip, pool.start, pool.stop)) {
                detail = `${detail ?? ""} (inside DHCP pool ${pool.label})`
                  .trim();
              }
            } catch (err) {
              action = "failed";
              detail = err instanceof Error ? err.message : String(err);
              context.logger.warn("Reservation for {mac} failed: {detail}", {
                mac,
                detail,
              });
            }

            handles.push(
              await context.writeResource("apply_result", mac, {
                mac,
                ip: entry.ip,
                action,
                detail,
                dryRun: args.dryRun,
              }),
            );
          }

          context.logger.info(
            "{mode}: {n} reservations processed",
            {
              mode: args.dryRun ? "Dry run" : "Applied",
              n: args.desired.length,
            },
          );
          return { dataHandles: handles };
        } finally {
          await client.cleanup();
        }
      },
    },
  },
};
