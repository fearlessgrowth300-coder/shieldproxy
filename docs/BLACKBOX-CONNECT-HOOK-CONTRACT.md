# Blackbox connect() hook contract

ShieldProxy cannot see the hook. It lives in the legacy-falcons-blackbox repo. This is the behavior that hook must implement before a clone route is actually forced onto its assigned exit. Until the hook does this, ShieldProxy can only reject container traffic that reaches the VPN, and a hook that still dials the upstream proxy directly will be rejected too.

## One route per Blackbox user

A Blackbox user is one exit. Instagram, Play Store, and Google services in that user are not separate routes. ShieldProxy publishes:

- `scope=user` on `setProxy`, `canSetProxy`, and `assignAndVerifyRoute`.
- `localPort`, `localHost`, `socksUser`, and `socksPassword` for the user listener `bb:<authority>:<userId>:*`. Every package in the user dials that listener.
- `packageLocalPort` for the older per-package listener. It pins the same node. New hooks must use `localPort`.
- The same bundle again for `com.android.vending`, `com.google.android.gms`, and `com.google.android.gsf` (and the other Google packages in that user). A package with no file of its own must not fail with `Assigned proxy is not ready: INVALID_CONFIG` when the user already has a route.

Blackbox applies that user route when a package file is missing, instead of treating the package as unconfigured. Two packages in one user must not be given two nodes. ShieldProxy rejects that conflict.

The privacy scan does not call `prepareRoute` or `verifyRoute`. Those calls were starting a guest per route and leaving the screen on "Scanning…". The scan checks the proxy exit, that exits are not shared and are not the phone IP, that the user listener accepts a connection, and that the tunnel config keeps containers outside the VPN, rejects IPv6, rejects UDP 443, and fails closed. Each route has an 8 second limit. Four routes run at a time.

## What ShieldProxy publishes

For every saved clone tag `bb:<authority>:<userId>:<package>` the running Mihomo config contains:

- A SOCKS5 listener on `127.0.0.1` at a stable port in `20000..27999`. The port, username, and password are in the `setProxy`, `canSetProxy`, and `assignAndVerifyRoute` bundles as `localPort`, `localHost`, `socksUser`, and `socksPassword`.
- `proxy:` on that listener, so every accepted connection is pinned to that clone's node.
- An `IN-NAME,bbp<port>,<node>` rule for the same pin.
- `tls` and `udp` from the node. When `tls` is true, Mihomo speaks SOCKS-over-TLS or HTTPS to the upstream. The hook does not do that itself.
- `countryIso`, `city`, `region`, `latitude`, `longitude`, `timezoneId`, and `locale`. `locale` is derived from the exit country (for example `fr-FR`), not from the phone.

The Blackbox container packages stay outside the VPN (`addDisallowedApplication`), including while clone routes are configured. Putting them inside the tunnel rewrote their DNS. With strict Private DNS that surfaces as `PRIVATE_DNS_BROKEN` and every in-clone exit check fails. A `REJECT-DROP` UID rule is still emitted for any container packet that does reach the TUN.

Loopback to `127.0.0.1` does not enter the TUN. That is the only path that reaches the assigned upstream.

## What the hook must do

For the clone identified by `userId` + `package`:

1. Redirect every outbound TCP `connect` and every UDP `sendto` / `sendmsg` to `127.0.0.1:localPort`, authenticated with `socksUser` / `socksPassword`.
2. Resolve names through that SOCKS connection (domain CONNECT or SOCKS UDP), not through the phone resolver, netd, or a guest DoH server.
3. Do not fall back to a direct socket, to the upstream proxy, or to another clone's port when the listener refuses the connection, the password is wrong, or the port is closed. Return `ECONNREFUSED` or drop the datagram.
4. Apply this before the guest `Application` runs, including sockets opened by native code. A libc-only hook is not enough if the guest uses raw syscalls.
5. Apply `timezoneId`, `locale`, and the latitude/longitude as the guest clock, locale, and location. Do not leave the phone's locale or GPS in place.
6. Honor `setKeepAlive` per clone. The default from ShieldProxy is off. Do not install a shared GMS identity unless that clone was opted in.
7. `verifyRoute` must report the exit IP actually observed inside the guest, plus `kernelGuard` and `sensorGuard` only when those isolations are really on. ShieldProxy compares that exit IP to the armed exit and stops the clone when they differ, unless the user has turned the kill switch off.

## Work profile

ShieldProxy is installed in both the personal user and the Android work profile. They are different Android users, so each has its own process, UID, `VpnService`, Mihomo home directory, preferences, Android Keystore keys, Supabase session, and backup row. User 0 keeps the historical row names `shieldproxy` and `_shieldbox_recovery_key_v1`. Any other user uses `shieldproxy-u<id>` and `_shieldbox_recovery_key_v1-u<id>`.

The hook in a work profile must use the listener published by the ShieldProxy running in that same user. A listener on the personal user's `127.0.0.1` is not the work profile's loopback. Package queries and `addDisallowedApplication` apply only to the user whose VPN is up.

Each profile has its own kill switch, stored in that profile's app data, and it defaults to on. Always-on VPN and "Block connections without VPN" are optional system settings. Leave them off: while they are on, Android waits for this tunnel and the phone loses its connection if the tunnel is not up.

`tools/profile-instances.sh` and `tools/profile-instances.ps1` print each instance's user, UID, and last exit IP from logcat tag `ShieldProfile`.

## What this does not cover

ShieldProxy does not ship the hook. A phone test has to show one clone's packets arriving on its own listener and the other clone's packets arriving on the other, and a socket that bypasses the hook dying with `ECONNREFUSED` rather than leaving from the phone's address. Always-on VPN lockdown is still a system setting this app cannot turn on by itself. While the VPN process is down, Android will send the container out the real network unless that setting is on.
