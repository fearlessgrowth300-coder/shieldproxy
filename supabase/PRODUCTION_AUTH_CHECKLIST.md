# Production authentication gate

These controls live in the Supabase project and cannot be enabled by an APK build.

- Configure dedicated SMTP and verify SPF, DKIM, bounce handling, and sender reputation.
- Keep email confirmation enabled and install `email-otp-template.html` for signup and login.
- Enable Supabase CAPTCHA/attack protection and integrate its public site key in the release client.
- Set OTP request and verification rate limits conservatively, then load-test in staging.
- Apply `schema.sql` and confirm RLS using two separate test users.
- Confirm the APK contains only the anon/publishable key, never a service-role key.
- Test expired and revoked sessions, offline logout, simultaneous first login, Drive-account mismatch,
  five wrong OTP attempts, resend cooldown, and SMTP throttling.

Do not launch publicly until every item is verified in the Supabase dashboard and staging project.
