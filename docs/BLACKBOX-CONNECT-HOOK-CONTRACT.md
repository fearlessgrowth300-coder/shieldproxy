# Blackbox connect() hook contract

ShieldProxy cannot see the hook. It lives in the legacy-falcons-blackbox repo. This is the behavior that hook must implement before a clone route is actually forced onto its assigned exit. Until the hook does this, ShieldProxy can only reject container traffic that reaches the VPN, and a hook that still dials the upstream proxy directly will be rejected too.

## What ShieldProxy publishes

For every saved clone tag `bb:<authority>:<userId>:<package>` the running Mihomo config contains:

- A SOCKS5 listener on `127.0.0.1` at a stable port in `20000..27999`. The port, username, and password are in the `setProxy`, `canSetProxy`, and `assignAndVerifyRoute` bundles as `localPort`, `localHost`, `socksUser`, and `socksPassword`.
- `proxy:` on that listener, so every accepted connection is pinned to that clone's node.
- An `IN-NAME,bbp<port>,<node>` rule for the same pin.
- `tls` and `udp` from the node. When `tls` is true, Mihomo speaks SOCKS-over-TLS or HTTPS to the upstream. The hook does not do that itself.
- `countryIso`, `city`, `region`, `latitude`, `longitude`, `timezoneId`, and `locale`. `locale` is derived from the exit country (for example `fr-FR`), not from the phone.

While any clone route is configured, the Blackbox container packages are inside the VPN. Their UID is `REJECT-DROP` for anything that arrives on the TUN.

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

Each profile needs its own Always-on VPN and "Block connections without VPN" under that profile's Settings → VPN. The kill switch is stored in that profile's app data and defaults to on.

`tools/profile-instances.sh` and `tools/profile-instances.ps1` print each instance's user, UID, and last exit IP from logcat tag `ShieldProfile`.

## What this does not cover

ShieldProxy does not ship the hook. A phone test has to show one clone's packets arriving on its own listener and the other clone's packets arriving on the other, and a socket that bypasses the hook dying with `ECONNREFUSED` rather than leaving from the phone's address. Always-on VPN lockdown is still a system setting this app cannot turn on by itself. While the VPN process is down, Android will send the container out the real network unless that setting is on.
