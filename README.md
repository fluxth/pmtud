# pmtud

Path MTU discovery tool for macOS

## Examples

### icmp / icmpv6

> [!IMPORTANT]
> Path MTU discovery using ICMP and ICMPv6 requires superuser privileges on macOS. This is because the tool needs to set DF (do not fragment) bit in IP header using raw sockets, which is not possible without elevated permissions.

> [!NOTE]
> `ping` and `ping6` binaries bundled with macOS have special Apple entitlement `com.apple.private.network.management.data.development` which allows them to bypass this restriction.

```
# pmtud thitat.net
warning: thitat.net has multiple IPv4 addresses
warning: thitat.net has multiple IPv6 addresses

icmp 54.239.163.89
  probe[0] mtu=1500: timed out
  probe[1] mtu=1038: from=54.239.163.89, ok
  probe[2] mtu=1269: from=54.239.163.89, ok
  probe[3] mtu=1384: from=54.239.163.89, ok
  probe[4] mtu=1442: from=54.239.163.89, ok
  probe[5] mtu=1471: timed out
  probe[6] mtu=1456: timed out
  probe[7] mtu=1449: from=54.239.163.89, ok
  probe[8] mtu=1452: from=54.239.163.89, ok
  probe[9] mtu=1454: from=54.239.163.89, ok
  probe[10] mtu=1455: timed out
  path mtu: 1454

icmpv6 [2600:9000:21b6:a600:b:2117:2cc0:93a1]
  probe[0] mtu=1500: timed out
  probe[1] mtu=1390: from=2600:9000:21b6:a600:b:2117:2cc0:93a1, ok
  probe[2] mtu=1445: timed out
  probe[3] mtu=1417: timed out
  probe[4] mtu=1403: timed out
  probe[5] mtu=1396: from=2600:9000:21b6:a600:b:2117:2cc0:93a1, ok
  probe[6] mtu=1399: from=2600:9000:21b6:a600:b:2117:2cc0:93a1, ok
  probe[7] mtu=1401: timed out
  probe[8] mtu=1400: from=2600:9000:21b6:a600:b:2117:2cc0:93a1, ok
  path mtu: 1400
```

### tcp-mss

> [!WARNING]
> Path MTU discovered via TCP-MSS are usually smaller than actual path MTU, and therefore should only be considered as estimates.

> [!NOTE]
> Path MTU discovery using TCP-MSS does not need superuser privileges to run on macOS.

```
$ pmtud --tcp 443 thitat.net
warning: thitat.net has multiple IPv4 addresses
warning: thitat.net has multiple IPv6 addresses

tcp-mss 54.239.163.89:443
  probe: from=54.239.163.89, mss=1414, timestamps=true
  estimated path mtu: 1454

tcp-mss [2600:9000:21b6:a600:b:2117:2cc0:93a1]:443
  probe: from=2600:9000:21b6:a600:b:2117:2cc0:93a1, mss=1340, timestamps=true
  estimated path mtu: 1400
```
