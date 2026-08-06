import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

function jsonRes(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

interface StepResult {
  step: string;
  status: "ok" | "failed" | "skipped";
  duration_ms: number;
  details?: unknown;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  let skipCleanup = false;
  let scenarios: string[] = ["full", "cancel", "scheduled", "stops", "guest"];
  try {
    const body = await req.clone().json();
    skipCleanup = body?.skip_cleanup === true;
    if (Array.isArray(body?.scenarios) && body.scenarios.length) {
      scenarios = body.scenarios;
    }
  } catch { /* no body */ }

  const steps: StepResult[] = [];
  const totalStart = Date.now();
  const createdRideIds: string[] = [];

  const record = (
    step: string,
    status: "ok" | "failed" | "skipped",
    started: number,
    details?: unknown,
  ) => {
    steps.push({ step, status, duration_ms: Date.now() - started, details });
  };

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const admin = createClient(supabaseUrl, serviceKey);

    // ---- Admin-only guard ------------------------------------------------
    // This function drives service-role writes against real rides, so it must
    // never be reachable by anonymous or ordinary authenticated callers.
    const authHeader = req.headers.get("Authorization") ?? "";
    const jwt = authHeader.replace(/^Bearer\s+/i, "");
    if (!jwt) {
      return jsonRes({ error: "Unauthorized" }, 401);
    }
    const { data: userData, error: userErr } = await admin.auth.getUser(jwt);
    if (userErr || !userData?.user) {
      return jsonRes({ error: "Unauthorized" }, 401);
    }
    const { data: isAdmin, error: roleErr } = await admin.rpc("has_role", {
      _user_id: userData.user.id,
      _role: "admin",
    });
    if (roleErr || isAdmin !== true) {
      return jsonRes({ error: "Forbidden: admin role required" }, 403);
    }


    // ── Step 0: Find a rider and a taxi-capable driver ─────────────
    let t = Date.now();
    const { data: rider, error: riderErr } = await admin
      .from("profiles")
      .select("id, full_name")
      .eq("is_rider", true)
      .eq("is_driver", false)
      .order("created_at", { ascending: true })
      .limit(1)
      .maybeSingle();

    const { data: driver, error: driverErr } = await admin
      .from("profiles")
      .select("id, full_name, latitude, longitude, can_taxi, vehicle_type")
      .eq("is_driver", true)
      .eq("can_taxi", true)
      .order("created_at", { ascending: true })
      .limit(1)
      .maybeSingle();

    if (!rider || !driver) {
      return jsonRes({
        error: "Need at least 1 rider and 1 taxi-capable driver",
        has_rider: !!rider,
        has_driver: !!driver,
        rider_err: riderErr?.message,
        driver_err: driverErr?.message,
      }, 400);
    }
    record("0_find_profiles", "ok", t, {
      rider: { id: rider.id, name: rider.full_name },
      driver: { id: driver.id, name: driver.full_name, vehicle: driver.vehicle_type },
    });

    // Bring driver online (live = is_available + last_seen < 60s)
    t = Date.now();
    const { error: onlineErr } = await admin.from("profiles").update({
      is_available: true,
      last_seen_at: new Date().toISOString(),
      went_online_at: new Date().toISOString(),
      latitude: driver.latitude || 62.454,
      longitude: driver.longitude || -114.372,
    }).eq("id", driver.id);
    record("0b_set_driver_online", onlineErr ? "failed" : "ok", t, onlineErr?.message);

    // Clear any active rides for this rider so duplicate-active trigger doesn't bite
    t = Date.now();
    const { data: activeRides } = await admin
      .from("rides")
      .select("id")
      .eq("rider_id", rider.id)
      .in("status", ["requested", "accepted", "arrived", "in_progress"]);
    if (activeRides && activeRides.length) {
      const ids = activeRides.map((r: any) => r.id);
      await admin.from("rides").update({ status: "cancelled", cancellation_reason: "test-cleanup" }).in("id", ids);
    }
    record("0c_clear_stale_active", "ok", t, { cleared: activeRides?.length || 0 });

    const insertRide = async (overrides: Record<string, unknown>) => {
      const base = {
        rider_id: rider.id,
        pickup_address: "100 Pickup St, Yellowknife",
        dropoff_address: "200 Drop Ave, Yellowknife",
        pickup_lat: 62.454,
        pickup_lng: -114.372,
        dropoff_lat: 62.460,
        dropoff_lng: -114.380,
        service_type: "taxi",
        status: "requested",
        estimated_price: 15.00,
        payment_option: "in_app",
        pricing_model: "metered",
      };
      return await admin.from("rides").insert({ ...base, ...overrides }).select("id, status").single();
    };

    const cancelRide = async (id: string) => {
      await admin.from("rides").update({
        status: "cancelled",
        cancellation_reason: "scenario-cleanup",
      }).eq("id", id);
    };

    // ============================================================
    // SCENARIO 1: Full lifecycle
    // ============================================================
    if (scenarios.includes("full")) {
      t = Date.now();
      const { data: ride, error: e } = await insertRide({});
      if (e || !ride) {
        record("1a_create_ride", "failed", t, e?.message);
      } else {
        createdRideIds.push(ride.id);
        record("1a_create_ride", "ok", t, { ride_id: ride.id });
        await sleep(300);

        // Accept
        t = Date.now();
        const { data: acc, error: accErr } = await admin.rpc("accept_ride", {
          _ride_id: ride.id, _driver_profile_id: driver.id,
        });
        const accOk = !accErr && (acc as any)?.success === true;
        record("1b_accept_ride", accOk ? "ok" : "failed", t, accErr?.message || acc);

        if (accOk) {
          // Arrive
          t = Date.now();
          const { error: arrErr } = await admin.from("rides").update({
            status: "arrived", updated_at: new Date().toISOString(),
          }).eq("id", ride.id).eq("status", "accepted");
          record("1c_arrive", arrErr ? "failed" : "ok", t, arrErr?.message);

          // Start
          t = Date.now();
          const { error: startErr } = await admin.from("rides").update({
            status: "in_progress",
            started_at: new Date().toISOString(),
            meter_status: "running",
            meter_started_at: new Date().toISOString(),
          }).eq("id", ride.id).eq("status", "arrived");
          record("1d_start_trip", startErr ? "failed" : "ok", t, startErr?.message);

          // Complete + payment
          t = Date.now();
          const { error: compErr } = await admin.from("rides").update({
            status: "completed",
            completed_at: new Date().toISOString(),
            meter_ended_at: new Date().toISOString(),
            meter_status: "stopped",
            final_fare_cents: 1500,
            final_price: 15.00,
            distance_km: 3.2,
            duration_min: 8,
            payment_status: "paid",
            paid_at: new Date().toISOString(),
            captured_amount_cents: 1500,
          }).eq("id", ride.id).eq("status", "in_progress");
          record("1e_complete_and_pay", compErr ? "failed" : "ok", t, compErr?.message);

          // Audit
          t = Date.now();
          const { data: events } = await admin
            .from("ride_events")
            .select("event_type")
            .eq("ride_id", ride.id)
            .order("created_at");
          const actual = (events || []).map((e: any) => e.event_type);
          const expected = ["requested", "accepted", "arrived", "in_progress", "completed"];
          const ok = expected.every((e) => actual.includes(e));
          record("1f_audit_trail", ok ? "ok" : "failed", t, { expected, actual });
        }
      }
      // Cancel any leftover active state so next scenario can run
      if (createdRideIds.length) {
        const last = createdRideIds[createdRideIds.length - 1];
        const { data: r } = await admin.from("rides").select("status").eq("id", last).maybeSingle();
        if (r && ["requested", "accepted", "arrived", "in_progress"].includes((r as any).status)) {
          await cancelRide(last);
        }
      }
    }

    // ============================================================
    // SCENARIO 2: Cancellation
    // ============================================================
    if (scenarios.includes("cancel")) {
      t = Date.now();
      const { data: ride, error: e } = await insertRide({
        pickup_address: "Cancel Pickup",
      });
      if (e || !ride) {
        record("2a_create_for_cancel", "failed", t, e?.message);
      } else {
        createdRideIds.push(ride.id);
        record("2a_create_for_cancel", "ok", t, { ride_id: ride.id });

        t = Date.now();
        const { error: cErr } = await admin.from("rides").update({
          status: "cancelled",
          cancellation_reason: "Rider changed mind",
        }).eq("id", ride.id);
        record("2b_cancel", cErr ? "failed" : "ok", t, cErr?.message);

        // Verify event
        const { data: ev } = await admin.from("ride_events").select("event_type").eq("ride_id", ride.id);
        const types = (ev || []).map((x: any) => x.event_type);
        record("2c_cancel_event", types.includes("cancelled") ? "ok" : "failed", Date.now(), { types });
      }
    }

    // ============================================================
    // SCENARIO 3: Scheduled ride (does not block as "active")
    // ============================================================
    if (scenarios.includes("scheduled")) {
      t = Date.now();
      const future = new Date(Date.now() + 60 * 60 * 1000).toISOString();
      const { data: ride, error: e } = await insertRide({
        pickup_address: "Sched Pickup",
        scheduled_at: future,
        // Use a non-active status check: scheduled rides are still 'requested',
        // so cancel previous before creating
      });
      if (e || !ride) {
        record("3a_create_scheduled", "failed", t, e?.message);
      } else {
        createdRideIds.push(ride.id);
        record("3a_create_scheduled", "ok", t, { ride_id: ride.id, scheduled_at: future });
        // Verify
        const { data: r } = await admin.from("rides").select("scheduled_at, status").eq("id", ride.id).single();
        record("3b_verify_scheduled", (r as any)?.scheduled_at ? "ok" : "failed", Date.now(), r);
        await cancelRide(ride.id);
      }
    }

    // ============================================================
    // SCENARIO 4: Ride with stops
    // ============================================================
    if (scenarios.includes("stops")) {
      t = Date.now();
      const { data: ride, error: e } = await insertRide({
        pickup_address: "Origin",
        dropoff_address: "Final Dest",
        stops: [
          { address: "Stop A", lat: 62.458, lng: -114.378 },
          { address: "Stop B", lat: 62.464, lng: -114.385 },
        ],
      });
      if (e || !ride) {
        record("4a_create_with_stops", "failed", t, e?.message);
      } else {
        createdRideIds.push(ride.id);
        const { data: r } = await admin.from("rides").select("stops").eq("id", ride.id).single();
        const count = Array.isArray((r as any)?.stops) ? (r as any).stops.length : 0;
        record("4a_create_with_stops", count === 2 ? "ok" : "failed", t, { ride_id: ride.id, stop_count: count });
        await cancelRide(ride.id);
      }
    }

    // ============================================================
    // SCENARIO 5: Booking for someone else (guest)
    // ============================================================
    if (scenarios.includes("guest")) {
      t = Date.now();
      const { data: ride, error: e } = await insertRide({
        pickup_address: "Guest Pickup",
        booking_for: "guest",
        guest_name: "Jane Guest",
        guest_phone: "+18675551234",
      });
      if (e || !ride) {
        record("5a_create_guest", "failed", t, e?.message);
      } else {
        createdRideIds.push(ride.id);
        const { data: r } = await admin.from("rides").select("booking_for, guest_name, guest_phone").eq("id", ride.id).single();
        const ok = (r as any)?.booking_for === "guest" && !!(r as any)?.guest_name && !!(r as any)?.guest_phone;
        record("5a_create_guest", ok ? "ok" : "failed", t, r);
        await cancelRide(ride.id);
      }
    }

    // ============================================================
    // CLEANUP
    // ============================================================
    if (!skipCleanup && createdRideIds.length) {
      t = Date.now();
      await admin.from("notifications").delete().in("ride_id", createdRideIds);
      await admin.from("ride_events").delete().in("ride_id", createdRideIds);
      await admin.from("rides").delete().in("id", createdRideIds);
      record("99_cleanup", "ok", t, { deleted: createdRideIds.length });
    } else if (skipCleanup) {
      record("99_cleanup", "skipped", Date.now(), { ride_ids: createdRideIds });
    }

    const failed = steps.filter((s) => s.status === "failed");
    return jsonRes({
      result: failed.length === 0 ? "ALL_PASSED ✅" : `FAILED: ${failed.length} ❌`,
      failed_steps: failed.map((s) => ({ step: s.step, details: s.details })),
      steps,
      total_ms: Date.now() - totalStart,
    });
  } catch (err: any) {
    console.error("test-ride-flow error:", err.message);
    steps.push({ step: "unexpected_error", status: "failed", duration_ms: 0, details: err.message });
    return jsonRes({ result: "ERROR ❌", steps, total_ms: Date.now() - totalStart }, 500);
  }
});
