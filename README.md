# pmtud

Path MTU discovery tool for macOS

## Examples

### icmp / icmpv6

> [!IMPORTANT]
> Path MTU discovery using ICMP and ICMPv6 requires superuser privileges on macOS. This is because the tool needs to set DF (do not fragment) bit in IP header using raw sockets, which is not possible without elevated permissions.

> [!NOTE]
> `ping` and `ping6` binaries bundled with macOS have special Apple entitlement `com.apple.private.network.management.data.development` which allows them to bypass this restriction.

#### Fragmentation Needed / Too Big packet support

```
# pmtud
icmp 8.8.8.8
  probe[0] size=1500: from=10.62.184.3, fragmentation needed, next_hop=1472
  probe[1] size=1472: from=8.8.8.8, ok
  path mtu: 1472

icmpv6 [2001:4860:4860::8888]
  probe[0] size=1500: from=2001:4860:4860::8888, ok
  path mtu: 1500
```

#### Bisect search for networks with ICMP blackhole

```
# pmtud -6 cloudflare.com
warning: cloudflare.com has multiple IPv6 addresses

icmpv6 [2606:4700::6810:85e5]
  probe[0] size=1500: timed out
  probe[1] size=1390: from=2606:4700::6810:85e5, ok
  probe[2] size=1445: timed out
  probe[3] size=1417: from=2606:4700::6810:85e5, ok
  probe[4] size=1431: timed out
  probe[5] size=1424: timed out
  probe[6] size=1420: from=2606:4700::6810:85e5, ok
  probe[7] size=1422: timed out
  probe[8] size=1421: timed out
  path mtu: 1420
```

### tcp-mss

> [!WARNING]
> Path MTU discovered via TCP-MSS are usually smaller than actual path MTU, and therefore should only be considered as estimates.

> [!NOTE]
> Path MTU discovery using TCP-MSS does not need superuser privileges to run on macOS.

#### Default TCP/443 (HTTPS) port

```
$ pmtud --tcp
tcp-mss 8.8.8.8:443
  probe: peer=8.8.8.8, mss=1392, timestamps=true
  estimated path mtu: 1432

tcp-mss [2001:4860:4860::8888]:443
  probe: peer=2001:4860:4860::8888, mss=1440, timestamps=true
  estimated path mtu: 1500
```

#### Custom TCP port

```
$ pmtud --tcp 80 cloudflare.com
warning: cloudflare.com has multiple IPv4 addresses
warning: cloudflare.com has multiple IPv6 addresses

tcp-mss 104.16.132.229:80
  probe: peer=104.16.132.229, mss=1380, timestamps=true
  estimated path mtu: 1420

tcp-mss [2606:4700::6810:85e5]:80
  probe: peer=2606:4700::6810:85e5, mss=1360, timestamps=true
  estimated path mtu: 1420
```
