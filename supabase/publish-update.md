# Publishing an app update (ShieldProxy / BlackBox)

Both apps check `latest.json` in the Supabase Storage bucket `app-releases` on launch. If its
`versionCode` is higher than the installed one, the app shows **"Update available"** and installs the
APK from the `apkUrl` (hosted on GitHub Releases, which has no file-size limit).

## Hosting layout
- **Metadata** (tiny): Supabase Storage, public bucket `app-releases`
  - `app-releases/shieldproxy/latest.json`
  - `app-releases/blackbox/latest.json`
- **APKs** (large): GitHub Releases in `legacybuilder0011/app-releases`
  - one release tag per version, e.g. `shieldproxy-14`, `blackbox-401`

## To release a new ShieldProxy version
1. Bump `versionCode` (must increase) + `versionName` in `app/build.gradle.kts`.
2. Build the arm64 APK:
   `./gradlew.bat :app:assembleDebug`  → `app/build/outputs/apk/debug/app-debug.apk`
3. Upload it to a new GitHub release (tag `shieldproxy-<versionCode>`), asset name
   `ShieldProxy-<versionName>.apk`. (GitHub token is in Windows Credential Manager,
   target `git:https://github.com`; upload via `Invoke-WebRequest -InFile` to
   `https://uploads.github.com/repos/legacybuilder0011/app-releases/releases/<id>/assets?name=<asset>`.)
4. Overwrite `app-releases/shieldproxy/latest.json` in Supabase Storage with the new
   `versionCode`, `versionName`, `apkUrl` (the GitHub browser_download_url), and `notes`.

That's it — every phone shows the update on next launch. BlackBox is identical with the `blackbox/`
path and tag `blackbox-<versionCode>`.

## latest.json shape
```json
{
  "versionCode": 14,
  "versionName": "8.6",
  "apkUrl": "https://github.com/legacybuilder0011/app-releases/releases/download/shieldproxy-14/ShieldProxy-8.6.apk",
  "notes": "What changed in this version."
}
```

## Notes
- `versionCode` is the ONLY thing that decides whether users are prompted — always bump it.
- Users must allow "install unknown apps" for the app once (Android prompts on first update install).
- Supabase Storage free tier caps files at 50 MB → that's why APKs live on GitHub, not Storage.
