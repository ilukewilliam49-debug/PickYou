/**
 * Admin-surface access-control tests.
 *
 * Asserts, against the live backend, that every admin-only capability is
 * denied to BOTH:
 *   - anon (no session), and
 *   - a signed-in NON-admin user (the test driver account).
 *
 * Covered surfaces:
 *   1. Admin-only RPCs (revenue + ride stats).
 *   2. Admin config tables (pricing, taxi rates, platform config, zones).
 *   3. The verification review endpoints (verifications table read/update)
 *      plus the driver's own-row scoping.
 *   4. Role escalation via user_roles.
 *   5. Admin-only edge function (test-ride-flow).
 */
import { describe, expect, it, beforeAll } from "vitest";

const URL = process.env.VITE_SUPABASE_URL ?? import.meta.env.VITE_SUPABASE_URL;
const ANON =
  process.env.VITE_SUPABASE_PUBLISHABLE_KEY ??
  import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;

const TEST_DRIVER_EMAIL = "testdriver@pickyou.test";
const TEST_DRIVER_PASSWORD = "Test1234!";
const ZERO_UUID = "00000000-0000-0000-0000-000000000000";

/** Admin-only RPCs: must be denied for anon AND for non-admin authenticated. */
const ADMIN_RPCS: Array<[string, Record<string, unknown>]> = [
  ["get_total_revenue", {}],
  ["get_ride_stats", {}],
];

/**
 * Admin-managed config tables. Reads may be public/authenticated by design,
 * but writes must be admin-only.
 */
const ADMIN_WRITE_TABLES = [
  "pricing_config",
  "service_pricing",
  "taxi_rates",
  "platform_config",
  "geo_zones",
  "private_hire_zones",
  "organizations",
];

function headers(token?: string, extra: Record<string, string> = {}) {
  return {
    apikey: ANON,
    Authorization: `Bearer ${token ?? ANON}`,
    "Content-Type": "application/json",
    ...extra,
  };
}

async function req(
  path: string,
  init: RequestInit & { token?: string } = {},
) {
  const { token, ...rest } = init;
  const res = await fetch(`${URL}${path}`, {
    ...rest,
    headers: headers(token, (rest.headers as Record<string, string>) ?? {}),
  });
  return { status: res.status, body: await res.text() };
}

/** Anon is denied when PostgREST refuses the role outright. */
function isAnonDenied(r: { status: number; body: string }) {
  if (r.status === 401 || r.status === 403) return true;
  if (r.status === 400 && /not authori[sz]ed|not authenticated/i.test(r.body)) {
    return true;
  }
  return (
    r.status === 404 && /(does not exist|not find|permission denied)/i.test(r.body)
  );
}

/**
 * A non-admin write is denied when RLS rejects it (401/403/42501), or when the
 * request matches zero rows (RLS filtered the target away) — which PostgREST
 * reports as an empty representation.
 */
function isWriteDenied(r: { status: number; body: string }) {
  if (r.status >= 400) return true;
  return r.body.trim() === "[]" || r.body.trim() === "";
}

describe("admin-only RPCs", () => {
  let driverToken = "";

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
    driverToken = json.access_token ?? "";
  });

  it("has credentials and a non-admin session", () => {
    expect(URL).toBeTruthy();
    expect(ANON).toBeTruthy();
    expect(driverToken, "test driver sign-in failed").toBeTruthy();
  });

  it("the test driver is genuinely NOT an admin", async () => {
    const r = await req("/rest/v1/rpc/has_role", {
      method: "POST",
      token: driverToken,
      body: JSON.stringify({ _user_id: ZERO_UUID, _role: "admin" }),
    });
    // Sanity check: role lookup works and the driver has no admin row.
    const own = await req("/rest/v1/user_roles?select=role", {
      token: driverToken,
    });
    expect(r.status).toBeLessThan(500);
    expect(own.status).toBe(200);
    expect(own.body).not.toMatch(/"admin"/);
  });

  it.each(ADMIN_RPCS)("anon cannot execute %s", async (name, args) => {
    const r = await req(`/rest/v1/rpc/${name}`, {
      method: "POST",
      body: JSON.stringify(args),
    });
    expect(isAnonDenied(r), `${name} -> ${r.status}: ${r.body.slice(0, 200)}`).toBe(
      true,
    );
  });

  it.each(ADMIN_RPCS)(
    "non-admin authenticated cannot execute %s",
    async (name, args) => {
      const r = await req(`/rest/v1/rpc/${name}`, {
        method: "POST",
        token: driverToken,
        body: JSON.stringify(args),
      });
      expect(
        r.status >= 400 && /not authori[sz]ed/i.test(r.body),
        `${name} -> ${r.status}: ${r.body.slice(0, 200)}`,
      ).toBe(true);
    },
  );
});

describe("admin config tables", () => {
  let driverToken = "";

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
    driverToken = json.access_token ?? "";
  });

  it.each(ADMIN_WRITE_TABLES)("anon cannot insert into %s", async (table) => {
    const r = await req(`/rest/v1/${table}`, {
      method: "POST",
      body: JSON.stringify({}),
    });
    expect(r.status >= 400, `${table} -> ${r.status}: ${r.body.slice(0, 160)}`).toBe(
      true,
    );
  });

  it.each(ADMIN_WRITE_TABLES)(
    "non-admin cannot insert into %s",
    async (table) => {
      const r = await req(`/rest/v1/${table}`, {
        method: "POST",
        token: driverToken,
        body: JSON.stringify({}),
      });
      expect(
        r.status >= 400,
        `${table} -> ${r.status}: ${r.body.slice(0, 160)}`,
      ).toBe(true);
    },
  );

  it.each(ADMIN_WRITE_TABLES)(
    "non-admin cannot update rows in %s",
    async (table) => {
      const r = await req(`/rest/v1/${table}?id=neq.${ZERO_UUID}`, {
        method: "PATCH",
        token: driverToken,
        headers: { Prefer: "return=representation" },
        body: JSON.stringify({ id: ZERO_UUID }),
      });
      expect(
        isWriteDenied(r),
        `${table} -> ${r.status}: ${r.body.slice(0, 200)}`,
      ).toBe(true);
    },
  );

  it.each(ADMIN_WRITE_TABLES)(
    "non-admin cannot delete rows from %s",
    async (table) => {
      const r = await req(`/rest/v1/${table}?id=neq.${ZERO_UUID}`, {
        method: "DELETE",
        token: driverToken,
        headers: { Prefer: "return=representation" },
      });
      expect(
        isWriteDenied(r),
        `${table} -> ${r.status}: ${r.body.slice(0, 200)}`,
      ).toBe(true);
    },
  );

  it("anon cannot read the admin audit log", async () => {
    const r = await req("/rest/v1/admin_audit_log?select=*&limit=1");
    expect(isAnonDenied(r), `${r.status}: ${r.body.slice(0, 200)}`).toBe(true);
  });

  it("non-admin sees no rows in the admin audit log", async () => {
    const r = await req("/rest/v1/admin_audit_log?select=*&limit=5", {
      token: driverToken,
    });
    expect(r.status).toBe(200);
    expect(r.body.trim()).toBe("[]");
  });

  it("non-admin cannot write to the admin audit log", async () => {
    const r = await req("/rest/v1/admin_audit_log", {
      method: "POST",
      token: driverToken,
      body: JSON.stringify({
        admin_profile_id: ZERO_UUID,
        action: "escalate",
        target_type: "profile",
        target_id: ZERO_UUID,
      }),
    });
    expect(r.status).toBeGreaterThanOrEqual(400);
  });
});

describe("verification review endpoints", () => {
  let driverToken = "";
  let driverProfileId = "";

  beforeAll(async () => {
    const res = await fetch(`${URL}/auth/v1/token?grant_type=password`, {
      method: "POST",
      headers: { apikey: ANON, "Content-Type": "application/json" },
      body: JSON.stringify({
        email: TEST_DRIVER_EMAIL,
        password: TEST_DRIVER_PASSWORD,
      }),
    });
    const json = (await res.json()) as {
      access_token?: string;
      user?: { id: string };
    };
    driverToken = json.access_token ?? "";
    const prof = await req(
      `/rest/v1/profiles?select=id&user_id=eq.${json.user?.id}`,
      { token: driverToken },
    );
    driverProfileId = (JSON.parse(prof.body)[0]?.id as string) ?? "";
  });

  it("anon cannot read verifications", async () => {
    const r = await req("/rest/v1/verifications?select=*&limit=1");
    expect(isAnonDenied(r), `${r.status}: ${r.body.slice(0, 200)}`).toBe(true);
  });

  it("anon cannot approve a verification", async () => {
    const r = await req(`/rest/v1/verifications?id=neq.${ZERO_UUID}`, {
      method: "PATCH",
      body: JSON.stringify({ status: "approved" }),
    });
    expect(r.status >= 400, `${r.status}: ${r.body.slice(0, 200)}`).toBe(true);
  });

  it("non-admin only ever sees its OWN verification rows", async () => {
    const r = await req("/rest/v1/verifications?select=id,driver_id,status", {
      token: driverToken,
    });
    expect(r.status).toBe(200);
    const rows = JSON.parse(r.body) as Array<{ driver_id: string }>;
    expect(driverProfileId).toBeTruthy();
    for (const row of rows) {
      expect(row.driver_id).toBe(driverProfileId);
    }
  });

  it("non-admin cannot read another driver's verifications", async () => {
    const r = await req(
      `/rest/v1/verifications?select=id&driver_id=neq.${driverProfileId}`,
      { token: driverToken },
    );
    expect(r.status).toBe(200);
    expect(r.body.trim()).toBe("[]");
  });

  it("non-admin cannot approve its OWN verification", async () => {
    const r = await req(
      `/rest/v1/verifications?driver_id=eq.${driverProfileId}`,
      {
        method: "PATCH",
        token: driverToken,
        headers: { Prefer: "return=representation" },
        body: JSON.stringify({ status: "approved" }),
      },
    );
    expect(
      isWriteDenied(r),
      `self-approve returned ${r.status}: ${r.body.slice(0, 200)}`,
    ).toBe(true);
  });

  it("non-admin cannot approve someone else's verification", async () => {
    const r = await req(
      `/rest/v1/verifications?driver_id=neq.${driverProfileId}`,
      {
        method: "PATCH",
        token: driverToken,
        headers: { Prefer: "return=representation" },
        body: JSON.stringify({ status: "approved" }),
      },
    );
    expect(
      isWriteDenied(r),
      `cross-approve returned ${r.status}: ${r.body.slice(0, 200)}`,
    ).toBe(true);
  });

  it("non-admin cannot write reviewer fields on a verification", async () => {
    const r = await req(
      `/rest/v1/verifications?driver_id=eq.${driverProfileId}`,
      {
        method: "PATCH",
        token: driverToken,
        headers: { Prefer: "return=representation" },
        body: JSON.stringify({
          reviewer_notes: "self-approved",
          reviewed_by: driverProfileId,
        }),
      },
    );
    expect(isWriteDenied(r), `${r.status}: ${r.body.slice(0, 200)}`).toBe(true);
  });
});

describe("role escalation is impossible", () => {
  let driverToken = "";
  let userId = "";

  beforeAll(async () => {
    const res = await fetch(`${URL}/auth/v1/token?grant_type=password`, {
      method: "POST",
      headers: { apikey: ANON, "Content-Type": "application/json" },
      body: JSON.stringify({
        email: TEST_DRIVER_EMAIL,
        password: TEST_DRIVER_PASSWORD,
      }),
    });
    const json = (await res.json()) as {
      access_token?: string;
      user?: { id: string };
    };
    driverToken = json.access_token ?? "";
    userId = json.user?.id ?? "";
  });

  it("anon cannot grant itself a role", async () => {
    const r = await req("/rest/v1/user_roles", {
      method: "POST",
      body: JSON.stringify({ user_id: ZERO_UUID, role: "admin" }),
    });
    expect(r.status).toBeGreaterThanOrEqual(400);
  });

  it("non-admin cannot grant itself the admin role", async () => {
    const r = await req("/rest/v1/user_roles", {
      method: "POST",
      token: driverToken,
      body: JSON.stringify({ user_id: userId, role: "admin" }),
    });
    expect(r.status, r.body.slice(0, 200)).toBeGreaterThanOrEqual(400);
  });

  it("non-admin cannot read other users' roles", async () => {
    const r = await req(`/rest/v1/user_roles?select=*&user_id=neq.${userId}`, {
      token: driverToken,
    });
    expect(r.status).toBe(200);
    expect(r.body.trim()).toBe("[]");
  });
});

describe("admin-only edge function: test-ride-flow", () => {
  let driverToken = "";

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
    driverToken = json.access_token ?? "";
  });

  it("anon cannot invoke test-ride-flow", async () => {
    const res = await fetch(`${URL}/functions/v1/test-ride-flow`, {
      method: "POST",
      headers: { apikey: ANON, "Content-Type": "application/json" },
      body: JSON.stringify({ scenarios: [] }),
    });
    const body = await res.text();
    expect([401, 403], `${res.status}: ${body.slice(0, 200)}`).toContain(
      res.status,
    );
  });

  it("non-admin authenticated cannot invoke test-ride-flow", async () => {
    const res = await fetch(`${URL}/functions/v1/test-ride-flow`, {
      method: "POST",
      headers: {
        apikey: ANON,
        Authorization: `Bearer ${driverToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ scenarios: [] }),
    });
    const body = await res.text();
    expect(res.status, body.slice(0, 300)).toBe(403);
    expect(body).toMatch(/admin/i);
  });
});
