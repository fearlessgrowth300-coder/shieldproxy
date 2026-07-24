# Publishing verified ShieldProxy and BlackBox updates

Both apps check `version.json` on the repository's GitHub Release tag named `latest`. A release is
offered only when all of these
are true:

- `versionCode` is greater than the installed app.
- `packageName` exactly matches the installed app.
- `apk` uses HTTPS.
- `sha256` contains the exact APK checksum.
- after download, the APK package, version, checksum, and signing certificate all match.

Android still asks the user to approve installation. A normal sideloaded app cannot silently update
itself.

## One-time GitHub repository secrets

Add these as **Actions secrets** in both source repositories. Never commit or paste them into app
source, Gradle files, issue comments, or release notes.

- `SUITE_KEYSTORE_BASE64`: Base64 of the permanent release `.jks` file.
- `SHIELD_SUITE_STORE_PASSWORD`
- `SHIELD_SUITE_KEY_ALIAS`
- `SHIELD_SUITE_KEY_PASSWORD`
- `SUPABASE_SECRET_KEY`: used only by GitHub Actions to keep older installed app versions compatible
  during the transition to GitHub metadata.

Keep at least two offline encrypted backups of the permanent keystore and its credentials. Losing
the key permanently prevents updates from installing over every copy already distributed.

## Publish an update

1. Make and test the code change.
2. Increase `versionName` when the user-facing release changes. `versionCode` is generated
   automatically from seconds since 2020 and pinned once by the release workflow.
3. Merge the reviewed change into the repository's protected release branch.
4. In GitHub, open **Actions**, select **Publish verified ... update**, and choose **Run workflow**.
5. Enter the release notes and run it.

The workflow tests the project, creates a release-signed APK, verifies its signature, publishes an
immutable GitHub Release, calculates SHA-256, and only then replaces `ShieldProxy.apk` or
`BlackBox.apk` plus `version.json` on the `latest` tag. Supabase metadata is also updated for older
installations. If any step fails, users are not pointed at the incomplete update.

## Required metadata shape

ShieldProxy:

```json
{
  "versionCode": 207071884,
  "versionName": "9.3",
  "apk": "https://github.com/OWNER/shieldproxy/releases/download/latest/ShieldProxy.apk",
  "packageName": "com.privacyshield.proxy",
  "apkUrl": "https://github.com/OWNER/shieldproxy/releases/download/shieldproxy-207071884/ShieldProxy-9.3.apk",
  "sha256": "64 lowercase hexadecimal characters",
  "notes": "What changed in this version."
}
```

BlackBox uses package `top.niunaijun.blackbox`, tag `blackbox-<versionCode>`, and a universal APK.

## Never do these

- Never build a distributable debug or release APK without the permanent suite signing key.
- Never change or regenerate the release key after distribution.
- Never place the Supabase service-role key or keystore passwords inside an APK.
- Never upload `version.json` before the signed APK is uploaded and independently verified.
