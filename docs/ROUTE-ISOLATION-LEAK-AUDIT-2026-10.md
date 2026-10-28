# ShieldProxy route-isolation leak audit

Date: 2026-10-28
Scope: this repository only (`com.privacyshield.proxy`, package sources, `app/libs/clashcore.aar`, `supabase/schema.sql`, `supabase-android-schema.sql`).
Question: on one phone running ShieldProxy next to Blackbox, how can route 1's traffic or identity leak into or be linked to route 2, and how can an app or a network observer tell that both routes are the same phone?

This system is **not leak-free**. Several linking channels are visible in this repo. The channels that would actually carry a clone's packets (the in-guest hook, and any hev-socks5-tunnel) are **not in this repo**, so their behavior is unverified.

## How a route is built

Two different paths exist, and they do not share a packet engine.

| Path | Who it covers | Where it is decided | Engine in this repo |
| --- | --- | --- | --- |
| Phone apps | Packages in `RoutingConfig.appMap` | `ShieldVpnService.startTunnel` builds a TUN and `RoutingConfig.toClashYaml` emits UID rules | Mihomo inside `app/libs/clashcore.aar` (`libgojni.so` strings include `mihomo`, `sing-tun`, `gvisor`). No `hev-socks5` / `hev_socks5` string in the arm64 binary. |
| Blackbox clones | Tags `bb:<authority>:<userId>:<pkg>` in `RoutingConfig.bbMap` | Pushed over a content-provider call. The VPN **excludes** the container packages. | Not in this repo. Comments in `ShieldVpnService.startTunnel` and `ProxyGuardService` describe a native `connect()` redirect inside the container. |

`ProxyEditActivity.assignToBlackBox` states the constraint directly: clones share one Android UID, so the external VPN cannot split them. `ShieldVpnService.startTunnel` then calls `addDisallowedApplication` for `top.niunaijun.blackbox`, `com.novspace.box`, `app.cloudvault.multi`, and `io.prismhub.clone`, plus ShieldProxy itself.

A Blackbox profile is meant to leave through its own proxy. In this codebase that happens only if Blackbox honors `setProxy` / `assignAndVerifyRoute`. ShieldProxy can observe the result of those calls. It cannot see the sockets.

## Severity

- **High** — a realistic way for one route's traffic, identity, or account to be tied to the other route, or to the phone, on the path operators actually use (a clone per route).
- **Medium** — linking that needs an extra condition, or a leak that is real for the phone-app VPN and only hypothetical for clones.
- **Low** — a weak or latent signal.

"Verified" means the behavior is in this repo's source or in the bundled Mihomo binary's strings. "Unverified" means the enforcement lives in Blackbox, in Android, or in the Supabase dashboard, and this tree does not prove it.

## Ranked findings

### 1. Clone traffic never enters the only tunnel this app controls

- **Severity:** High
- **Channel:** Per-route traffic separation. Every clone socket is outside ShieldProxy's TUN.
- **Where:** `ShieldVpnService.startTunnel` (`addDisallowedApplication` for the four container packages and for `packageName`). Mapping is `RoutingConfig.bbMap`, documented there as never emitted into the Mihomo config. Assignment is `BlackBoxBridge.setCloneProxy`, `canSetCloneProxy`, `assignAndVerifyRoute`.
- **What is verified:** UID rules in `RoutingConfig.toClashYaml` cannot separate clones. They share the container UID, and that UID is excluded from the VPN, so a missed hook exits on the phone's real network interface. There is no second tun, no per-UID `VpnService`, and no hev-socks5-tunnel in source or in `libgojni.so`.
- **Unverified:** Whether Blackbox's hook is `connect()` only (the comment's words) or a full tun. A libc `connect()` hook misses `sendto` / `sendmsg` (DNS, QUIC, STUN, WebRTC media), raw syscalls, sockets opened before the hook, and IPv6 if the hook is v4-only. Startup packets before the hook is installed are also unverified. `BlackBoxBridge.prepareRoute` says proxy setup runs before the guest `Application`; this repo cannot see that code.
- **Fix:** Treat Blackbox as in-scope for this audit and review its hook (seccomp or a per-user tun, not a `connect()` plt hook). Until that review, do not describe clone routes as isolated. If the hook stays in Blackbox, return a per-socket proof (TCP and UDP, v4 and v6) that ShieldProxy fails closed on, instead of a single `ok` boolean.

### 2. Proxy death and leak-guard failure leave the clone running

- **Severity:** High
- **Channel:** Fail-open versus kill switch, including restart and the gap while the monitor is frozen.
- **Where:** `ProxyGuardService.onProxyDead`, `ProxyGuardService.runTests`, `ProxyGuardService.isConfirmedRouteIdentityViolation`. The policy is locked in by `ProxyGuardRoutePolicyTest.geoAndProbeFailuresNeverCloseAnUnchangedRoute`, which expects `GEO_GUARD_FAILED`, `EXIT_CHECK_FAILED`, and `LEAK_GUARD_FAILED` to leave the route up. `onRouteViolation` runs only for a blank expected route id, a changed route id, `ROUTE_MISMATCH`, or `CONFIG_MISSING`.
- **What is verified:** After three failed probes (`FAIL_STRIKES`, 60s apart) the service sets state `down`, shows "network paused", and does not call `stopClone`. A reachable proxy whose exit IP cannot be read (`Result.reachableOnly`) does not add a strike. A `verifyRoute` result with `ok == false` and a matching route id is logged as a soft failure and the clone stays up. `runTests` also does not compare `route.exitIp` to `Armed.expectedExitIp` when `ok` is true. The manifest property on `ProxyGuardService` still says the service "closes the app if the proxy drops". The class KDoc says the native hook returns `ECONNREFUSED` with no direct fallback. That hook is not here.
- **OEM freeze:** `scheduleHeartbeat` exists because a foreground service was observed frozen (`mHiberReason='frozen'`) so the 1s ticker stopped. The alarm period is 60s (`HEARTBEAT_SECS`). Between thaw cycles nobody rechecks the route. `failClosedGuardRestore` only logs; a corrupt monitor file does not stop clones.
- **Unverified:** That Blackbox actually fails closed for the whole outage, including UDP and the seconds before the hook is reinstalled after `warmClone`.
- **Fix:** On proxy unreachable, `LEAK_GUARD_FAILED`, missing `kernelGuard` / `sensorGuard`, or exit IP equal to the phone's direct IP, call `BlackBoxBridge.stopClone` and refuse `warmClone`. Compare `exitIp` to the armed exit in ShieldProxy, so a soft `ok` from the bridge cannot pass a different exit. Make the alarm the only scheduler and shorten it. If the encrypted monitor cannot be read, stop every configured clone.

### 3. Both routes leave the phone from the same real IP, in cleartext SOCKS/HTTP

- **Severity:** High
- **Channel:** Shared uplink. An ISP, a Wi-Fi AP, or one proxy vendor sees both routes as one device.
- **Where:** `ShieldVpnService.startTunnel` excludes the containers, so clone proxy sockets use the underlying network. `ProxyNode.tls` defaults to `false`. `BlackBoxBridge.setCloneProxy` and `assignAndVerifyRoute` send `type`, `server`, `port`, `username`, and `password`. They do not send `tls`, `udp`, or `extraLines`. `ProxyTester.socks5Connect` / `httpConnect` speak cleartext SOCKS5 and HTTP CONNECT, and HTTP basic auth is the username and password.
- **What is verified:** SOCKS5 CONNECT and HTTP CONNECT carry the destination host in the clear on the path from the phone to the proxy. Both routes' tunnels, and ShieldProxy's own health checks, originate from the phone's public address. Nothing in `AssignmentRules` rejects two nodes that share `server`, `port`, or `username`. `ProxyNode` documents SOAX usernames of the form `package-<id>-country-..-sessionid-..`. The same `package-<id>` on two routes is one customer at the provider. `withNewSession` is only referenced from the commented body of `MainActivity.launchCloneLegacy`, so the app never mints a distinct session per route.
- **Why this links the routes:** The observer does not need a bug in the guest. The source address is the phone. If both nodes are the same gateway, that gateway also sees both authenticated usernames. If the username is not wrapped in TLS, the local network sees the destination names too.
- **Fix:** Wrap every upstream in TLS (or a real VPN) before it hits the radio, with a different outer hop per route if the threat model includes the ISP. Reject saves when two routes share server, username, or `package-<id>`. Pass `tls` and `udp` across the bridge. Generate the sticky session id in ShieldProxy when the node is created, and refuse to copy one session onto a second clone.

### 4. Timezone, locale, and GPS are not held to the exit IP

- **Severity:** High
- **Channel:** Geo consistency. An app compares IP geolocation with `TimeZone`, `Locale`, and location.
- **Where:** The strict launch path is `MainActivity.launchClone`. It requires `ProxyTester.Result.geoVerified` (country, latitude, longitude, and a known timezone id from ipwho.is) and passes those fields to `BlackBoxBridge.assignAndVerifyRoute`. `ProfileEditActivity.commitPerApp` calls `setCloneProxy` with the node only, so the country is whatever `countryIsoHint()` parsed from the username, and latitude, longitude, and timezone are omitted. `ProxyEditActivity.assignToBlackBox` omits them too. `ProxyGuardService` country migration calls `setCloneProxy` with the country code alone, and only while the clone is not running. No file in this repo sets the guest locale. `AccountSettingsActivity` formats dates with `Locale.getDefault()`, which is the phone locale.
- **Enforcement gap:** `isConfirmedRouteIdentityViolation` treats `GEO_GUARD_FAILED` as keep-open. After launch, an exit-IP rotation inside one sticky session updates `Armed.ip` and does not push a new timezone or coordinate. ipwho.is coordinates are a database point for the exit IP, not a GPS fix, and every probe uses `User-Agent: ShieldProxy`.
- **Unverified:** That Blackbox applies the bundle to the guest clock, locale, and `LocationManager`. This repo has no mock-location code of its own. If the guest still sees Africa/Lagos (or whatever the handset is set to) while the exit is `country-gb`, the app sees the mismatch on each route, and it sees the **same** locale and language on both routes.
- **Fix:** Pass locale plus verified timezone and coordinates on every `setProxy`, not only on `launchClone`. Re-bind them when the observed exit country changes, and stop the clone until the bind succeeds. Have `verifyRoute` return the guest's effective timezone, locale, and a coarse location bucket, and treat a mismatch as `onRouteViolation`. Keep the phone's real locale off the guest.

### 5. Same-phone identity is only partly policed, and the scan overclaims

- **Severity:** High
- **Channel:** Device identity shared by both guests: virtual user, GMS, kernel ids, sensors, LAN, WebRTC host addresses, TLS stack.
- **Where:**
  - `AssignmentRules.SENSITIVE` is only `com.instagram.android`, `com.instagram.lite`, `com.whatsapp`, `com.whatsapp.w4b`. Any other pair may share one Blackbox user (one Android id, one GMS, one sensor set) and still save.
  - `MainActivity.enableKeepAlive` calls `setKeepAlive` and `GmsShareStore.setEnabled(..., true)` for every user in the list. `AssignmentRules.gmsProxyInconsistencies` then forces those clones onto one node name. Shared GMS is an intentional identity join for push. A failed `userSecurityState` is treated as shared (`!remote.ok || remote.sharedGmsActive`), which is fail-closed for the proxy choice and still means "assume one identity".
  - `BlackBoxBridge.verifyRoute` reads `kernelGuard` and `sensorGuard`. `MainActivity.launchClone` never reads them. `LeakTestActivity.scanClone` never reads them either, then writes the success string "Remote DNS · Direct fallback blocked · Kernel ID isolated · Sensor calibration isolated".
  - `LeakTestActivity` duplicate `identityDigest` handling sets a card to "Launch blocked until fixed". Nothing writes that result anywhere `launchClone` consults. The digest itself is a good idea: `identityStatus` returns a digest, not the raw id.
  - Clones are VPN-excluded, so they keep the phone's real interfaces. mDNS, SSDP, ARP, and `WifiManager` (SSID, BSSID, gateway MAC) are same-phone signals unless Blackbox hides them. There is no WebRTC, ICE, or STUN filter anywhere in `app/src`.
- **Unverified:** Blackbox's per-user spoof of android id, IMEI, GAID, DRM id, sensor noise, build fingerprint, and Wi-Fi. Play Integrity on a shared or per-user GMS can still attest the real device. WebRTC host candidates gathered inside the guest would be the phone's LAN address on both routes; a STUN packet that misses the hook would be the phone's public address on both routes.
- **Fix:** Block launch when `kernelGuard` or `sensorGuard` is false, when `identityDigest` collides across users, or when `userSecurityState` says GMS is shared across two routes that must look unrelated. Extend the one-user rule past Instagram and WhatsApp. Isolate or disable the LAN for guests. Strip ICE host candidates per route. Stop the privacy scan from asserting checks it did not perform.

### 6. One Supabase user holds every route, in plaintext

- **Severity:** High
- **Channel:** Backend linkage. Device and route records sit in one row family keyed by `auth.uid()`.
- **Where:** `SupaSync.push` reads `proxies.json`, `profiles.json`, and `routing.json` through `SecureFileStore.readText` (decrypted) and `Supabase.pushBackup` upserts them as `app='shieldproxy'`. The KDoc on `SupaSync` says the blob is decrypted on purpose. Those files contain node usernames, passwords, server, port, and `bbMap` (authority, virtual user id, package, node name). `MainActivity.backupNow` calls `SupaSync.pushAsync` and the encrypted Drive backup together. Drive ciphertext is not the only copy.
- **RLS, verified in `supabase/schema.sql`:** `app_backups` and `crash_reports` enable RLS. Select, insert, update, and delete on `app_backups` require `auth.uid() = user_id`. `crash_reports` allows insert and select on the same condition, with no client update or delete. There is no view, no `security definer` function, and no policy that uses `user_metadata` for authorization. The client embeds the anon JWT only (`Supabase.ANON`); `supabase/PRODUCTION_AUTH_CHECKLIST.md` says the service-role key must not ship in the APK, and it does not appear in the Kotlin sources.
- **What RLS does not do:** It isolates customer A from customer B. It does not isolate route 1 from route 2. Both are one JSON document. Anyone who can read that row (the account, a stolen refresh token, a service-role dashboard, a database backup) gets both routes' proxy credentials and the clone-to-node map. `Supabase` keeps the local session until `signOut`; a refresh failure does not clear it (`validateStoredSession`).
- **Recovery key:** `Supabase.getBackupKeyCandidates` stores a 32-byte key in `app_backups` under `app='_shieldbox_recovery_key_v1'`. If `user_metadata.shieldbox_backup_key_v1` is already present, that legacy value stays primary. Supabase puts `user_metadata` into the access token, so a legacy key rides in `Authorization` on later calls. `raw_user_meta_data` is also user-editable. This is a secret-handling bug and a cross-route link: one key unwraps every route's Drive history.
- **Schema drift:** `supabase-android-schema.sql` targets a different project ref (`pnhzsteoouhngjdgsfeh`), creates `app_backups` only, and says to turn email confirmation off. `supabase/schema.sql` targets `oqyrbdvehvqdcpglaojo` (the URL in `Supabase.URL`) and says to keep confirmation on. The Android file also creates a private `clone-sessions` bucket whose policy is `bucket_id = 'clone-sessions'` and folder `[1] = auth.uid()`. This app never uploads to that bucket. If Blackbox does, every clone's session objects share one user prefix. Whether that bucket exists in production is unverified (it is not in `schema.sql`).
- **Dashboard items this repo cannot prove:** that RLS is actually applied, that the tables are not in the realtime publication, that `FORCE ROW LEVEL SECURITY` is set (it is not in the SQL), that grants to `anon` were revoked as defense in depth, and that the live project matches `schema.sql` rather than the other file. `PRODUCTION_AUTH_CHECKLIST.md` already says these are dashboard checks and are not done by an APK build.
- **Fix:** Stop uploading decrypted route material. Put an encrypted blob in `app_backups`, one row per route id if the server must not see the join, or accept that the account is the correlation handle and document it. Move the recovery key out of `user_metadata` and delete the legacy claim. Add `revoke all on public.app_backups, public.crash_reports from anon` plus explicit grants to `authenticated`, and `force row level security`. Delete or clearly deprecate `supabase-android-schema.sql`. Confirm in the dashboard, with two test users, that one JWT cannot read the other user's row.

### 7. Crash reports and failure telemetry tie the routes to one handset

- **Severity:** High
- **Channel:** Telemetry. Same `user_id`, same device string, clone coordinates in the report body.
- **Where:** `CrashReporter.capture` and `CrashReporter.reportFailure`. `ShieldApp.onCreate` installs the handler and calls `flushAsync`. `Supabase.uploadCrashes` posts each queued object as `{app:'shieldproxy', report}` to `public.crash_reports`. `user_id` is the JWT default.
- **What is uploaded:** `device` is `Build.MANUFACTURER + " " + Build.MODEL`, plus Android release, app version, `ramMb`, `freeRamMb`, `lowMem`, and `ts`. `ProxyGuardService.warmForPush` and `onProxyDead` pass extras `pkg`, `userId` (the Blackbox user), and `proxyType`. `scrub` redacts `sessionid-…`, `package-<digits>`, password-like assignments, JWTs, emails, IPv4, and a simple IPv6 pattern. It leaves package names (`com.instagram.android`), Blackbox user ids, proxy hostnames inside exception text, and the device model.
- **What it does not upload:** `ANDROID_ID`, the throttle `key` (the clone tag), or the proxy password, if `scrub` saw them. The tag is used only as a local throttle key.
- **Why it links routes:** Two `route_down` rows for user 3 / Instagram and user 4 / WhatsApp share a `user_id`, a device model, a RAM size, and timestamps from one clock. That is enough to say both routes are one phone, even when the exit IPs differ.
- **Fix:** Drop `device`, RAM, `pkg`, and `userId` from the payload, or replace them with a per-route random id that is not stable across routes. Round timestamps. Scrub hostnames. Keep the queue on the device if the only consumer is the same account that already has the plaintext backup.

### 8. Routes can be installed, and clones opened, without the strict check

- **Severity:** High
- **Channel:** Startup and bypass of the launch gate. Traffic that never went through `launchClone`.
- **Where:**
  - `MainActivity.launchClone` is the strict path: exit IP required, geo required, `assignAndVerifyRoute` required, `stopClone` if `ok` is false or the route id or exit IP string is blank, then `ProxyGuardService.arm`. It still does not require `verified.exitIp == tested.ip`, `kernelGuard`, or `sensorGuard`.
  - `MainActivity.startCloneActivity` starts `top.niunaijun.blackboxa.view.main.ShortcutActivity` with `pkg` and `userId` and no proxy check. Anything that can fire that intent, including Blackbox's own icon after a profile save, skips the gate. `commitPerApp` tells the user "Reopen them in their app to apply."
  - `ProxyEditActivity.assignToBlackBox` calls `setProxy` with credentials and no geo, no `assignAndVerifyRoute`, and no `bbMap` update, so `ProxyGuardService.restoreArmedState` will not claim the tag.
  - `ProfileEditActivity` "Keep and save" leaves `BlackBoxBridge.configuredRoutes` that no list claims. "Route all" (`save` when `routeAll` is checked) writes a profile whose `finalTarget` is one node and whose `bbMap` is empty, and it does not call `clearCloneProxy`. Previous clone routes stay in the container, unmonitored.
  - `clearAndDeleteEmptyProfile` is the path that does clear Blackbox when the last route is removed. The toast then says the clone uses the phone network. That is a deliberate direct path.
- **Unverified:** The race between `assignAndVerifyRoute` returning and `ShortcutActivity` creating the process the user actually sees. If that is a new process, the first packets depend on Blackbox.
- **Fix:** Make Blackbox refuse to start a guest that has no verified route, including launches from its own UI. Remove `assignToBlackBox`'s direct `setProxy` or run it through `assignAndVerifyRoute`. On "route all" and on "keep and save", clear or re-verify every configured route. Compare the in-guest exit IP to the preflight exit IP before `startCloneActivity`.

### 9. DNS can leave on the real network; guest DoH is unproven

- **Severity:** Medium for the phone VPN, High for clones if the guest resolver is not hooked. Ranked medium overall because the clone half is unverified.
- **Channel:** System resolver and the guest's own DoH.
- **Where:** `RoutingConfig.toClashYaml` sets `dns.enhanced-mode: fake-ip`, `fake-ip-range: 198.18.0.1/16`, `dns-hijack: any:53`, `respect-rules: true`, `use-hosts: false`, `use-system-hosts: false`, `prefer-h3: false`, and DoH at `https://1.1.1.1/dns-query` and `https://8.8.8.8/dns-query`. The same function sets `default-nameserver` and `proxy-server-nameserver` to `223.5.5.5` (AliDNS) and `8.8.8.8`. The comment above those lines says they resolve directly, to avoid a deadlock. `ShieldVpnService.startTunnel`'s `serverResolver` calls `InetAddress.getByName` in the VPN process, which is `addDisallowedApplication(packageName)`, so that lookup uses the phone's system resolver and the real uplink.
- **Phone-app path, verified from config:** Port-53 DNS from captured apps is hijacked. With `respect-rules: true`, an app mapped to a node should send its DoH through that node. The one Mihomo process has one DNS cache (`profile.store-selected: true` and a single `dns:` block). A shared cache across two phone apps on two nodes is a known class of cross-route answer reuse; whether this binary's cache key includes the outbound policy was not confirmed by reading Go sources (the sources jar is not a readable tree). Mark that cache split as unverified.
- **Clone path:** No DNS rule is emitted for `bbMap`. `LeakTestActivity` does not resolve a name inside the guest. A guest using its own DoH (Chrome, Instagram, a hardcoded 1.1.1.1) bypasses port-53 hijack that does not exist on this path anyway.
- **Fix:** Resolve proxy hostnames through a DNS path that is not the carrier resolver and not a single shared third party for every route. For clones, hijack UDP/53, TCP/53, and known DoH IPs inside the guest, or force every name lookup through the per-route proxy. Split DNS caches per outbound. Add an in-guest test that resolves a unique name and checks which resolver saw it.

### 10. IPv6 is blocked on the VPN path and untouched for clones

- **Severity:** Medium for phone apps, High if a clone can open a v6 socket. Ranked here because the dangerous half is the exclusion in finding 1, and the VPN half is implemented.
- **Channel:** IPv6 leak of the phone's real address.
- **Where:** `ShieldVpnService.startTunnel` adds `fdfe:dcba:9876::1/126` and `::/0`. `RoutingConfig` defaults `ipv6` to false and `blockIpv6WhenOff` to true, and `toClashYaml` emits `IP-CIDR6,::/0,REJECT-DROP,no-resolve` in that case. The comment explains why `::/0` is always installed: omitting it lets v6 bypass an v4-only VPN.
- **Clone gap:** The container is disallowed, so that reject rule never sees clone v6. `LeakTestActivity.ipv6Reachable` connects to `2606:4700:4700::1111:443` from the ShieldProxy process, which is outside the VPN, so a "GUARDED" card means the **phone** has v6, not that the clone blocked it. `ProxyTester` only reads `api.ipify.org`, which is IPv4, so an IPv6 exit is never compared.
- **Fix:** Block v6 inside each guest, and fail the route when an in-guest v6 connect succeeds. Probe an IPv6 echo through the proxy as well as v4. Keep the VPN `::/0` capture for phone apps.

### 11. QUIC, UDP, and WebRTC are only partly covered, and only for captured apps

- **Severity:** Medium (VPN). High for a clone whose UDP misses the hook (see finding 1).
- **Channel:** QUIC/HTTP3, SOCKS UDP, STUN/WebRTC.
- **Where:** `RoutingConfig.toClashYaml` emits `AND,((NETWORK,udp),(DST-PORT,443)),REJECT-DROP` when `blockQuic` is true (the default). For a mapped app whose node fails `ProxyNode.carriesUdp()`, it emits `AND,((UID,<uid>),(NETWORK,udp)),REJECT-DROP` or the same with `PROCESS-NAME`. HTTP and HTTPS nodes return `carriesUdp() == false`. SOCKS5 returns the node's `udp` flag, which defaults to true. The final-target UDP reject is skipped when `finalTarget` is `DIRECT`.
- **What still passes the VPN rules:** UDP that is not port 443 (STUN 3478 and 19302, QUIC on 80 or 8443, DNS if hijack misses it) to a node with `udp: true`. The bridge does not receive the `udp` flag, so a node saved as `udp: false` can still be handed to Blackbox as a plain SOCKS5. `libgojni.so` contains `socks5 UDP ASSOCIATE is disabled`, which is consistent with Mihomo refusing UDP when the node disables it; it does not prove a direct-IP fallback. There is no STUN or WebRTC handling.
- **WebRTC:** Even when the server-reflexive candidate is proxied, the host candidate is chosen from local interfaces (`172.19.0.1` on the VPN path, the Wi-Fi LAN address for an excluded clone). The same LAN address on two routes is a same-phone signal. mDNS ICE hostnames reduce this on some stacks. Unverified inside the guest.
- **Fix:** For every clone, drop all UDP that the proxy cannot carry, not only UDP/443, and do it in the guest. Force `udp: false` on the bridge unless UDP associate was tested. Disable non-proxied ICE, or replace host candidates per route. Add a WebRTC leak check to the privacy scan that runs inside the guest.

### 12. Phone-app catch-all and VPN restart are fail-open

- **Severity:** Medium. This is the phone-app path. Clones are already outside it (finding 1).
- **Channel:** Traffic that skips the tunnel, and traffic during startup or reconnect.
- **Where:** `RoutingConfig.finalTarget` defaults to `"DIRECT"`. `ProfileEditActivity.commitPerApp` sets `finalTarget = "DIRECT"`. Unmapped phone apps, and any flow that misses UID and process rules, hit `MATCH,DIRECT`. `ShieldVpnService`'s `UidQuery` returns `-1` on failure. With `find-process-mode: always`, a missed UID does not by itself prove a drop; the following rule in the generated file is `MATCH,<finalTarget>`.
- **Restart gap:** `scheduleWatchdog` calls `stopEngineOnly` (closes the TUN) and then `startTunnel`. `onStartCommand` uses `START_STICKY`. The manifest requests the VPN binder permission and does not declare always-on lockdown. While the TUN is down, Android sends captured apps out the real network unless the user turned on "Block connections without VPN". The app never checks that setting. `setBlocking(false)` makes the fd non-blocking; it is not a leak by itself. Packets leak when no VPN is established.
- **ShieldProxy's own sockets** are disallowed: Supabase, crash upload, `LeakTestActivity.directRealIp` (`https://api.ipify.org`), and proxy preflight. That is why the preflight can see the real IP. It is also why those calls are a stable real-IP signal next to the proxy tunnels.
- **Local inbound:** `toClashYaml` sets `mixed-port: 7890` and `allow-lan: false`, and the `PROXY` group lists every node plus `DIRECT`. If a guest shares the host network namespace and can connect to `127.0.0.1:7890`, it can use that shared inbound. Whether Blackbox's loopback is the host loopback is unverified.
- **Fix:** Default the catch-all to `REJECT-DROP` whenever any per-app route is installed. On UID query failure, reject the flow. Require always-on VPN with lockdown before starting phone-app routes, and keep the old TUN up until the new one is established. Bind the mixed port only where guests cannot reach it, or do not publish `DIRECT` on it.

### 13. The routes share a clock, a poll, and a reconnect

- **Severity:** Medium
- **Channel:** Timing correlation.
- **Where:** `ProxyGuardService.runTests` walks every armed clone on one 60s cadence (`POLL_SECS` and `ROUTE_VERIFY_SECS`). `ticker` and `scheduleHeartbeat` are process-wide. `openAllApps` launches clones 1.2s apart through the same `launchClone` preflight. `warmForPush` restarts every dead clone's push on that same pass, after the same OEM thaw. Mihomo `keep-alive-interval: 30` and `keep-alive-idle: 600` are global to the one VPN process (phone apps, not clones).
- **What an observer sees:** Health checks to `api.ipify.org` and `ipwho.is` with `User-Agent: ShieldProxy`, through each proxy, in the same minute, from one source IP. Push sessions for several accounts come back in one burst after a freeze. `openAllApps` puts first-launch traffic of every account within a few seconds.
- **Fix:** Jitter each route's probe and push restart with an independent schedule. Stagger mass launch by minutes, not 1.2s, and do not let a health check use a distinctive user agent on the route's exit.

### 14. TLS and HTTP fingerprints are one stack for every route

- **Severity:** Medium
- **Channel:** Identical client fingerprints.
- **Where:** No uTLS, no per-route client hello, no per-route HTTP stack in this repo. `ProxyTester` uses `SSLSocketFactory.getDefault()` and the header `User-Agent: ShieldProxy` for both ipify and ipwho.is. Guest TLS is the phone's stack inside every clone. `ProxyNode.extraLines` can carry Mihomo fields such as `client-fingerprint` for the **phone VPN** node, but `setCloneProxy` does not forward `extraLines`.
- **Unverified:** The guest WebView / OkHttp / Cronet fingerprint Blackbox leaves in place. Two current Instagram clients on the same OS build, with the same TLS library and the same device model string, are linkable even when the exit IPs differ.
- **Fix:** If the product claim is "two phones", the guest needs a per-route TLS fingerprint, user agent, and header order that matches the spoofed device, not the host. Forward any fingerprint fields to Blackbox. Stop sending a product-named user agent on the exit path.

### 15. Cross-app identifiers passed to Blackbox

- **Severity:** Medium
- **Channel:** Shared identifiers between the two apps.
- **Where:** `BlackBoxBridge` and `ShieldBridgeProvider`.
  - `VaultKeyStore.ownerHash` is the first 12 bytes of SHA-256 of the normalized email, hex-encoded. `ShieldBridgeProvider.call` returns it on `status`. `BlackBoxBridge.connectionStatus` requires the remote `ownerHash` to match. That binds every clone route to one account across both apps. It does not put the email on the wire.
  - `setCloneProxy` / `assignAndVerifyRoute` put the proxy username and password in the provider `Bundle`, plus user id, package, country, city, region, latitude, longitude, timezone, and (on verify) the expected exit IP. `configuredRoutes` is documented as not returning credentials. `identityStatus` returns a digest.
  - The bridge authorities are `top.niunaijun.blackbox.bridge`, `com.novspace.box.bridge`, `app.cloudvault.multi.bridge`, and `io.prismhub.clone.bridge`. ShieldProxy's own provider requires the signature permission `com.privacyshield.proxy.permission.BRIDGE`. Whether Blackbox's provider is signature-only is unverified. Both apps are built to the same suite keystore (`app/build.gradle.kts`), so any app signed with that key can hold the permission.
- **Fix:** Confirm Blackbox's provider is `signature` protection and rejects a bundle whose route was not verified. Avoid passing the long-term proxy password through a `Bundle` that other suite apps can read; pass a per-route handle. Keep `ownerHash` out of guest-visible properties and out of Blackbox's own telemetry.

### 16. Captive-portal and platform connectivity checks

- **Severity:** Low for destination leakage, medium as a same-phone presence signal next to finding 3.
- **Channel:** Connectivity checks on the real network.
- **Where:** No captive-portal, `NetworkMonitor`, or `setHttpProxy` handling in the app. Platform probes from `system_server` use the underlying network on current Android and do not enter a third-party VPN. That behavior is platform knowledge, not something this repo demonstrates. The checks hit Google connectivity URLs from the phone's real IP. They do not carry clone destinations. They do line up in time with both proxy logins.
- **Fix:** Nothing in ShieldProxy hides this while the radio is the phone's own SIM or Wi-Fi. Lockdown mode does not stop `system_server` probes. Treat it as an accepted same-uplink signal, or move each route's uplink off the shared radio (finding 3).

### 17. Latent cleartext allowance and other weak signals

- **Severity:** Low
- **Channel:** Miscellaneous same-client signals.
- **Where:**
  - `app/src/main/res/xml/network_security_config.xml` permits cleartext to `ip-api.com`. No Kotlin caller references that host. `ProxyTester.lookupInfo` uses HTTPS `ipwho.is`. The allowance is unused.
  - The VPN address `172.19.0.1/30` and ULA `fdfe:dcba:9876::1` are the same on every install. A WebRTC host candidate of `172.19.0.1` says "this phone runs this VPN", not which route.
  - `fake-ip-range: 198.18.0.1/16` is shared by every captured app inside the one Mihomo process. It is not guest-visible for excluded clones.
  - `CrashReporter.scrub` can miss a hostname or an IPv6 address that does not match its regex. That matters only when such a string is already inside an exception message.
- **Fix:** Remove the ip-api cleartext domain. Do not rely on the VPN addresses as secrets.

## What this repo does enforce

These are real controls. They do not cancel the findings above.

- `MainActivity.launchClone` will not start a clone when the proxy test fails or geo metadata is incomplete, and it calls `stopClone` when `assignAndVerifyRoute` fails.
- `AssignmentRules` blocks saving two Instagram/WhatsApp packages on one virtual user, blocks one clone tag in two profiles unless the user moves it, and blocks two node names on a user marked as shared-GMS.
- The phone-app VPN captures `0.0.0.0/0` and `::/0`, hijacks port 53, defaults to dropping IPv6 destinations and UDP/443, and drops all UDP for HTTP proxies.
- `CrashReporter.scrub` removes emails, JWTs, IPv4 literals, and SOAX-style session tokens before upload.
- `supabase/schema.sql` turns RLS on for both tables and scopes policies to `auth.uid() = user_id`. The APK's Supabase client uses the anon key, not a service-role key.
- `ShieldBridgeProvider` returns a truncated hash, not the email or the backup key.
- Local route files are encrypted with `SecureFileStore`. The plaintext copy is the Supabase backup in finding 6, not the local file.

## What this audit could not verify

- Blackbox's hook, tun, DNS, IPv6, UDP, kill switch, timezone, locale, GPS, sensor, and device-id spoofing. There is no Blackbox source in this workspace.
- hev-socks5-tunnel. It is not a source tree and not a string in `libgojni.so`. The phone engine is Mihomo / sing-tun.
- A live packet capture, a guest WebRTC sample, or an in-guest DoH lookup.
- The Supabase dashboard: applied SQL, realtime, grants, email confirmation, captcha, and whether `clone-sessions` exists.
- Mihomo's internal DNS cache key and the exact drop-versus-direct behavior when `getConnectionOwnerUid` returns -1. The YAML `MATCH` line is verified; the native matcher was not read as source.
- That a guest shares the host network namespace (relevant to LAN leaks and to `127.0.0.1:7890`).

## Order to fix

1. Put each clone in a network path this app can fail closed, or audit Blackbox's hook with the same standard and block launch on a failed in-guest UDP, DNS, and IPv6 proof.
2. Stop the clone when the proxy or the leak guard is unverified. Compare exit IPs in ShieldProxy.
3. Stop publishing both routes' destinations in cleartext from one source IP. Reject shared provider accounts and shared session ids.
4. Bind timezone, locale, and location on every assign, and enforce them after launch.
5. Stop storing decrypted multi-route configs and device-linked crash rows under one `user_id`.
6. Make the privacy scan report only the booleans it actually received.
