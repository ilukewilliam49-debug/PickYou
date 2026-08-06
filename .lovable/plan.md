Disconnect Lovable Cloud from project

## Goal
Disconnect the Lovable Cloud-managed backend from this project so it can be transferred to a new owner without carrying over the current database, auth, storage, and functions.

## Current state
- Lovable Cloud is **managed by Lovable** and currently **active and healthy**.
- The project uses Cloud-backed features: auth, database, storage, edge functions, and possibly configured secrets (Stripe, OneSignal, Twilio, Resend).
- Disconnecting is a destructive, irreversible action that will delete all cloud data.

## Steps

1. **Verify workspace admin access**
   - Only a workspace admin can disconnect Cloud.
   - Confirm you are an admin at: Workspace Settings → Access → People.

2. **Export / back up data you need to keep**
   - Open Cloud → Advanced → Export data to request a database export.
   - Manually download any critical storage files, edge function code, or secrets you want to preserve.

3. **Open the disconnect control**
   - Navigate to: Cloud → Overview → Advanced settings.
   - Click the **Disconnect** option for Lovable Cloud.

4. **Confirm disconnection and understand consequences**
   - Disconnecting permanently deletes:
     - Database tables and rows
     - Auth users and sessions
     - Storage buckets and files
     - Edge functions and secrets
   - Any app features that rely on these will stop working until a new backend is attached.

5. **Disable Cloud for future projects (optional)**
   - If you only want to prevent new projects from using Cloud, go to:
     Connectors → Lovable Cloud → Disable Cloud.
   - This does **not** remove Cloud from the current project.

6. **After disconnection, clean up app code (optional)**
   - Remove or guard Cloud-dependent UI paths (driver/rider dashboards, auth-gated pages, file uploads, etc.) if the project will run without a backend.
   - If a new owner will attach their own Supabase/Lovable Cloud later, leave the existing code and integrations in place; they can rebind the project after connecting.

## Technical details
- Cloud status: managed by Lovable, instance size Tiny, active and healthy.
- Disconnecting is done through the Lovable product UI, not via code changes in this repository.
- If the Disconnect button is unavailable because you are not a workspace admin, ask an admin to perform the disconnect.
- No migration or source-code edits are required before disconnecting; the operation removes backend bindings and cloud-hosted data only.

## Success criteria
- Lovable Cloud is disconnected from the project.
- Database, storage, auth, and functions are removed from the project.
- New owner can connect their own billing/credits/backend without inheriting the old cloud data.
