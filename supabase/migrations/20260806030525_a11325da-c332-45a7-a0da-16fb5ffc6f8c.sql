-- 1. Profiles: prevent self-elevation of capability/org fields
DROP POLICY IF EXISTS "Users can update own profile" ON public.profiles;
CREATE POLICY "Users can update own profile"
ON public.profiles FOR UPDATE TO authenticated
USING (auth.uid() = user_id)
WITH CHECK (
  auth.uid() = user_id
  AND commission_rate = (SELECT p.commission_rate FROM public.profiles p WHERE p.user_id = auth.uid())
  AND driver_balance_cents = (SELECT p.driver_balance_cents FROM public.profiles p WHERE p.user_id = auth.uid())
  AND standard_commission_rate = (SELECT p.standard_commission_rate FROM public.profiles p WHERE p.user_id = auth.uid())
  AND promo_commission_rate = (SELECT p.promo_commission_rate FROM public.profiles p WHERE p.user_id = auth.uid())
  AND driver_onboarding_complete = (SELECT p.driver_onboarding_complete FROM public.profiles p WHERE p.user_id = auth.uid())
  AND is_business = (SELECT p.is_business FROM public.profiles p WHERE p.user_id = auth.uid())
  AND business_onboarding_complete = (SELECT p.business_onboarding_complete FROM public.profiles p WHERE p.user_id = auth.uid())
  AND rider_onboarding_complete = (SELECT p.rider_onboarding_complete FROM public.profiles p WHERE p.user_id = auth.uid())
  AND is_driver = (SELECT p.is_driver FROM public.profiles p WHERE p.user_id = auth.uid())
  AND is_rider = (SELECT p.is_rider FROM public.profiles p WHERE p.user_id = auth.uid())
  AND can_taxi = (SELECT p.can_taxi FROM public.profiles p WHERE p.user_id = auth.uid())
  AND can_shuttle = (SELECT p.can_shuttle FROM public.profiles p WHERE p.user_id = auth.uid())
  AND can_courier = (SELECT p.can_courier FROM public.profiles p WHERE p.user_id = auth.uid())
  AND can_private_hire = (SELECT p.can_private_hire FROM public.profiles p WHERE p.user_id = auth.uid())
  AND organization_id IS NOT DISTINCT FROM (SELECT p.organization_id FROM public.profiles p WHERE p.user_id = auth.uid())
  AND role_in_org IS NOT DISTINCT FROM (SELECT p.role_in_org FROM public.profiles p WHERE p.user_id = auth.uid())
);

-- 2. Admin gate on revenue/stat definer functions
CREATE OR REPLACE FUNCTION public.get_total_revenue()
RETURNS numeric
LANGUAGE plpgsql
STABLE SECURITY DEFINER
SET search_path TO 'public'
AS $$
BEGIN
  IF NOT public.has_role(auth.uid(), 'admin'::public.app_role) THEN
    RAISE EXCEPTION 'Not authorized';
  END IF;
  RETURN (SELECT COALESCE(SUM(final_price), 0) FROM public.rides WHERE status = 'completed');
END;
$$;

CREATE OR REPLACE FUNCTION public.get_ride_stats(
  _date_from timestamp with time zone DEFAULT NULL,
  _date_to timestamp with time zone DEFAULT NULL,
  _status text DEFAULT NULL,
  _service_type text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE SECURITY DEFINER
SET search_path TO 'public'
AS $$
BEGIN
  IF NOT public.has_role(auth.uid(), 'admin'::public.app_role) THEN
    RAISE EXCEPTION 'Not authorized';
  END IF;
  RETURN (
    SELECT jsonb_build_object(
      'total_rides', COUNT(*),
      'completed_rides', COUNT(*) FILTER (WHERE status = 'completed'),
      'cancelled_rides', COUNT(*) FILTER (WHERE status = 'cancelled'),
      'total_revenue', COALESCE(SUM(COALESCE(final_price, 0)) FILTER (WHERE status = 'completed'), 0),
      'avg_fare', COALESCE(AVG(COALESCE(final_price, estimated_price)) FILTER (WHERE status = 'completed'), 0),
      'completion_rate', CASE WHEN COUNT(*) > 0
        THEN ROUND((COUNT(*) FILTER (WHERE status = 'completed'))::numeric / COUNT(*) * 100, 1)
        ELSE 0 END,
      'scheduled_count', COUNT(*) FILTER (WHERE scheduled_at IS NOT NULL)
    )
    FROM public.rides
    WHERE (_date_from IS NULL OR created_at >= _date_from)
      AND (_date_to IS NULL OR created_at <= _date_to + interval '1 day')
      AND (_status IS NULL OR status::text = _status)
      AND (_service_type IS NULL OR service_type::text = _service_type)
  );
END;
$$;

-- 3. Revoke EXECUTE on internal / system-only SECURITY DEFINER functions
REVOKE EXECUTE ON FUNCTION public.handle_new_user() FROM anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.log_ride_event() FROM anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.notify_ride_status_change() FROM anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.prevent_last_admin_revoke() FROM anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.recalculate_driver_rating() FROM anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.enqueue_email(text, jsonb) FROM anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.delete_email(text, bigint) FROM anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.read_email_batch(text, integer, integer) FROM anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.move_to_dlq(text, text, bigint, jsonb) FROM anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.auto_offline_overdue_shifts() FROM anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.auto_offline_stale_drivers() FROM anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.check_notification_rate_limit(text, integer, integer) FROM anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.check_password_reset_rate_limit(text) FROM anon, authenticated;

-- Helpers that must stay usable by signed-in users only
REVOKE EXECUTE ON FUNCTION public.accept_ride(uuid, uuid) FROM anon;
REVOKE EXECUTE ON FUNCTION public.authorize_realtime_channel(text, uuid) FROM anon;
REVOKE EXECUTE ON FUNCTION public.driver_can_serve(uuid, public.service_type) FROM anon;
REVOKE EXECUTE ON FUNCTION public.driver_shift_within_limit(uuid) FROM anon;
REVOKE EXECUTE ON FUNCTION public.ensure_ride_track_token(uuid) FROM anon;
REVOKE EXECUTE ON FUNCTION public.get_ride_stats(timestamptz, timestamptz, text, text) FROM anon;
REVOKE EXECUTE ON FUNCTION public.get_total_revenue() FROM anon;
REVOKE EXECUTE ON FUNCTION public.has_role(uuid, public.app_role) FROM anon;
REVOKE EXECUTE ON FUNCTION public.has_app_role(uuid, public.app_role) FROM anon;
REVOKE EXECUTE ON FUNCTION public.is_driver_live(uuid) FROM anon;
REVOKE EXECUTE ON FUNCTION public.is_org_admin(uuid, uuid) FROM anon;
REVOKE EXECUTE ON FUNCTION public.provision_capability(text) FROM anon;
REVOKE EXECUTE ON FUNCTION public.touch_driver_seen() FROM anon;
REVOKE EXECUTE ON FUNCTION public._test_find_other_driver() FROM anon;
REVOKE EXECUTE ON FUNCTION public._test_cleanup_lifecycle_ride(uuid) FROM anon;
REVOKE EXECUTE ON FUNCTION public._test_seed_lifecycle_ride(uuid, public.service_type, public.ride_status) FROM anon;

-- 4. Remove anon table visibility except genuinely public reference data
REVOKE ALL ON public.admin_audit_log FROM anon;
REVOKE ALL ON public.delivery_bids FROM anon;
REVOKE ALL ON public.driver_application_drafts FROM anon;
REVOKE ALL ON public.driver_shift_events FROM anon;
REVOKE ALL ON public.email_send_log FROM anon;
REVOKE ALL ON public.email_send_state FROM anon, authenticated;
REVOKE ALL ON public.email_unsubscribe_tokens FROM anon, authenticated;
REVOKE ALL ON public.fare_estimate_audit_log FROM anon;
REVOKE ALL ON public.invoices FROM anon;
REVOKE ALL ON public.notification_logs FROM anon;
REVOKE ALL ON public.notification_rate_limits FROM anon, authenticated;
REVOKE ALL ON public.notifications FROM anon;
REVOKE ALL ON public.org_members FROM anon;
REVOKE ALL ON public.organization_applications FROM anon;
REVOKE ALL ON public.organizations FROM anon;
REVOKE ALL ON public.password_reset_attempts FROM anon, authenticated;
REVOKE ALL ON public.payout_requests FROM anon;
REVOKE ALL ON public.phone_otps FROM anon, authenticated;
REVOKE ALL ON public.platform_config FROM anon;
REVOKE ALL ON public.pricing_config FROM anon;
REVOKE ALL ON public.profiles FROM anon;
REVOKE ALL ON public.push_subscriptions FROM anon;
REVOKE ALL ON public.recent_locations FROM anon;
REVOKE ALL ON public.ride_events FROM anon;
REVOKE ALL ON public.ride_message_reactions FROM anon;
REVOKE ALL ON public.ride_messages FROM anon;
REVOKE ALL ON public.ride_ratings FROM anon;
REVOKE ALL ON public.rides FROM anon;
REVOKE ALL ON public.saved_places FROM anon;
REVOKE ALL ON public.service_pricing FROM anon;
REVOKE ALL ON public.shift_sessions FROM anon;
REVOKE ALL ON public.support_conversations FROM anon;
REVOKE ALL ON public.suppressed_emails FROM anon, authenticated;
REVOKE ALL ON public.user_roles FROM anon;
REVOKE ALL ON public.verifications FROM anon;
REVOKE ALL ON public.driver_rides FROM anon;

-- 5. Chat/voice storage reads must verify real ride participation
DROP POLICY IF EXISTS "Ride participants read chat-images" ON storage.objects;
CREATE POLICY "Ride participants read chat-images"
ON storage.objects FOR SELECT TO authenticated
USING (
  bucket_id = 'chat-images'
  AND (
    (storage.foldername(name))[1] = auth.uid()::text
    OR EXISTS (
      SELECT 1
      FROM public.ride_messages m
      JOIN public.rides r ON r.id = m.ride_id
      JOIN public.profiles p ON p.user_id = auth.uid()
      WHERE m.image_url LIKE '%' || storage.objects.name
        AND (r.rider_id = p.id OR r.driver_id = p.id)
    )
  )
);

DROP POLICY IF EXISTS "Users read own voice-messages" ON storage.objects;
CREATE POLICY "Users read own voice-messages"
ON storage.objects FOR SELECT TO authenticated
USING (
  bucket_id = 'voice-messages'
  AND (
    (storage.foldername(name))[1] = auth.uid()::text
    OR EXISTS (
      SELECT 1
      FROM public.ride_messages m
      JOIN public.rides r ON r.id = m.ride_id
      JOIN public.profiles p ON p.user_id = auth.uid()
      WHERE m.audio_url LIKE '%' || storage.objects.name
        AND (r.rider_id = p.id OR r.driver_id = p.id)
    )
  )
);