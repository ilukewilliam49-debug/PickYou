/**
 * Access-control integration tests.
 *
 * Verifies, against the live backend, that:
 *  1. Every protected table is unreachable for the anonymous (unauthenticated) role.
 *  2. Only the intentionally public reference tables are readable by anon.
 *  3. Protected RPCs reject anonymous callers.
 *  4. Admin-only RPCs reject a non-admin authenticated caller.
 *  5. A signed-in (driver) caller CAN reach the tables/RPCs it legitimately needs.
 *
 * These tests hit the real Data API, so they assert the full stack
 * (GRANTs + RLS + function guards), not just database metadata.
 */
import { describe, expect, it, beforeAll } from "vitest";

const URL = process.env.VITE_SUPABASE_URL ?? import.meta.env.VITE_SUPABASE_URL;
const ANON =
  process.env.VITE_SUPABASE_PUBLISHABLE_KEY ??
  import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;

const TEST_DRIVER_EMAIL = "testdriver@pickyou.test";
const TEST_DRIVER_PASSWORD = "Test1234!";

/** Tables intentionally readable without signing in (public reference data). */
const PUBLIC_TABLES = ["geo_zones", "private_hire_zones", "taxi_rates"];

/** Every other public-schema table must be closed to anon. */
const PROTECTED_TABLES = [
  "admin_audit_log",
  "delivery_bids",
  "driver_application_drafts",
  "driver_rides",
  "driver_shift_events",
  "email_send_log",
  "email_send_state",
  "email_unsubscribe_tokens",
  "fare_estimate_audit_log",
  "invoices",
  "notification_logs",
  "notification_rate_limits",
  "notifications",
  "org_members",
  "organization_applications",
  "organizations",
  "password_reset_attempts",
  "payout_requests",
  "phone_otps",
  "platform_config",
  "pricing_config",
  "profiles",
  "push_subscriptions",
  "recent_locations",
  "ride_events",
  "ride_message_reactions",
  "ride_messages",
  "ride_ratings",
  "rides",
  "saved_places",
  "service_pricing",
  "shift_sessions",
  "support_conversations",
  "suppressed_emails",
  "user_roles",
  "verifications",
];

/**
 * Tables that stay closed even to ordinary authenticated users
 * (secrets / rate-limit / email-infra tables touched only by edge functions).
 */
const SERVICE_ONLY_TABLES = [
  "email_send_state",
  "email_unsubscribe_tokens",
  "notification_rate_limits",
  "password_reset_attempts",
  "phone_otps",
  "suppressed_emails",
];

/** RPCs that must never be callable anonymously. */
const PROTECTED_RPCS: Array<{ name: string; args: Record<string, unknown> }> = [
  { name: "accept_ride", args: { _ride_id: ZERO_UUID(), _driver_profile_id: ZERO_UUID() } },
  { name: "auto_offline_overdue_shifts", args: {} },
  { name: "auto_offline_stale_drivers", args: {} },
  { name: "check_notification_rate_limit", args: { _key: "test" } },
  { name: "ensure_ride_track_token", args: { _ride_id: ZERO_UUID() } },
  { name: "get_ride_stats", args: {} },
  { name: "get_total_revenue", args: {} },
  { name: "is_driver_live", args: { _profile_id: ZERO_UUID() } },
  { name: "provision_capability", args: { _intent: "rider" } },
  { name: "touch_driver_seen", args: {} },
  { name: "_test_find_other_driver", args: {} },
];

/** RPCs that require the admin role, tested with a non-admin driver session. */
const ADMIN_ONLY_RPCS = ["get_total_revenue", "get_ride_stats"];

function ZERO_UUID() {
  return "00000000-0000-0000-0000-000000000000";
}

async function restSelect(table: string, token?: string) {
  const res = await fetch(`${URL}/rest/v1/${table}?select=*&limit=1`, {
    headers: {
      apikey: ANON,
      Authorization: `Bearer ${token ?? ANON}`,
    },
  });
  return { status: res.status, body: await res.text() };
}

async function callRpc(name: string, args: Record<string, unknown>, token?: string) {
  const res = await fetch(`${URL}/rest/v1/rpc/${name}`, {
    method: "POST",
    headers: {
      apikey: ANON,
      Authorization: `Bearer ${token ?? ANON}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(args),
  });
  return { status: res.status, body: await res.text() };
}

/**
 * A denied response is a 401/403, a 404 "not exposed" from PostgREST, or a
 * 400 raised by an in-function auth guard ("Not authorized" / "Not authenticated").
 */
function isDenied(r: { status: number; body: string }) {
  if (r.status === 401 || r.status === 403) return true;
  if (r.status === 400 && /not authori[sz]ed|not authenticated/i.test(r.body)) {
    return true;
  }
  // PostgREST hides objects the role has no privilege on.
  return (
    r.status === 404 &&
    /(does not exist|not find|permission denied)/i.test(r.body)
  );
}

describe("anonymous access is locked down", () => {
  it("has backend credentials configured", () => {
    expect(URL, "VITE_SUPABASE_URL must be set").toBeTruthy();
    expect(ANON, "VITE_SUPABASE_PUBLISHABLE_KEY must be set").toBeTruthy();
  });

  it.each(PROTECTED_TABLES)("anon cannot read %s", async (table) => {
    const r = await restSelect(table);
    expect(
      isDenied(r),
      `anon read of ${table} returned ${r.status}: ${r.body.slice(0, 200)}`,
    ).toBe(true);
  });

  it.each(PROTECTED_TABLES)("anon cannot write %s", async (table) => {
    const res = await fetch(`${URL}/rest/v1/${table}`, {
      method: "POST",
      headers: {
        apikey: ANON,
        Authorization: `Bearer ${ANON}`,
        "Content-Type": "application/json",
        Prefer: "return=representation",
      },
      body: JSON.stringify({}),
    });
    const body = await res.text();
    expect(
      res.status >= 400,
      `anon insert into ${table} returned ${res.status}: ${body.slice(0, 200)}`,
    ).toBe(true);
  });

  it.each(PUBLIC_TABLES)("anon CAN read public reference table %s", async (table) => {
    const r = await restSelect(table);
    expect(r.status, `${table} -> ${r.body.slice(0, 200)}`).toBe(200);
  });

  it.each(PROTECTED_RPCS.map((r) => [r.name, r.args] as const))(
    "anon cannot execute %s",
    async (name, args) => {
      const r = await callRpc(name, args as Record<string, unknown>);
      expect(
        isDenied(r),
        `anon rpc ${name} returned ${r.status}: ${r.body.slice(0, 200)}`,
      ).toBe(true);
    },
  );
});

describe("authenticated (non-admin driver) access", () => {
  let token = "";

  beforeAll(async () => {
    const res = await fetch(`${URL}/auth/v1/token?grant_type=password`, {
      method: "POST",
      headers: { apikey: ANON, "Content-Type": "application/json" },
      body: JSON.stringify({
        email: TEST_DRIVER_EMAIL,
        password: TEST_DRIVER_PASSWORD,
      }),
    });
    const json = (await res.json()) as { access_token?: string };
    token = json.access_token ?? "";
  });

  it("signs in the test driver", () => {
    expect(token, "test driver sign-in failed").toBeTruthy();
  });

  it.each(["profiles", "rides", "notifications", "saved_places", "recent_locations"])(
    "driver CAN read own-scoped table %s",
    async (table) => {
      const r = await restSelect(table, token);
      expect(r.status, `${table} -> ${r.body.slice(0, 200)}`).toBe(200);
    },
  );

  it.each(SERVICE_ONLY_TABLES)(
    "driver cannot read service-only table %s",
    async (table) => {
      const r = await restSelect(table, token);
      expect(
        isDenied(r),
        `driver read of ${table} returned ${r.status}: ${r.body.slice(0, 200)}`,
      ).toBe(true);
    },
  );

  it.each(ADMIN_ONLY_RPCS)("non-admin cannot execute admin RPC %s", async (name) => {
    const r = await callRpc(name, {}, token);
    const denied =
      isDenied(r) || /not authorized/i.test(r.body) || r.status >= 400;
    expect(denied, `${name} returned ${r.status}: ${r.body.slice(0, 200)}`).toBe(
      true,
    );
  });

  it("driver CAN call touch_driver_seen", async () => {
    const r = await callRpc("touch_driver_seen", {}, token);
    expect(r.status, r.body.slice(0, 200)).toBeLessThan(300);
  });
});
