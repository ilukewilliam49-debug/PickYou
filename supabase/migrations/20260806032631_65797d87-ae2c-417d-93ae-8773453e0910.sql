DO $$
DECLARE
  fn text;
  fns text[] := ARRAY[
    'public.accept_ride(uuid, uuid)',
    'public.auto_offline_overdue_shifts()',
    'public.auto_offline_stale_drivers()',
    'public.check_notification_rate_limit(text, integer, integer)',
    'public.is_driver_live(uuid)',
    'public.touch_driver_seen()',
    'public.driver_can_serve(uuid, public.service_type)',
    'public.driver_shift_within_limit(uuid)',
    'public.authorize_realtime_channel(text, uuid)',
    'public.has_role(uuid, public.app_role)',
    'public.has_app_role(uuid, public.app_role)',
    'public.is_org_admin(uuid, uuid)',
    'public.ensure_ride_track_token(uuid)',
    'public.get_ride_stats(timestamptz, timestamptz, text, text)',
    'public.get_total_revenue()'
  ];
BEGIN
  FOREACH fn IN ARRAY fns LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', fn);
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM anon', fn);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO authenticated', fn);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role', fn);
  END LOOP;
END $$;