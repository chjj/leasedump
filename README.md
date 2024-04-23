# leasedump

CLI tool for dumping dhcpcd `.lease` files.

## Background

Life is not easy for those of us who set `nohook resolv.conf` in `dhcpcd.conf`,
especially when accessing a gated wifi (i.e. hotels and airlines).

On my system, dhcpcd places the raw DHCP lease replies in
`/var/lib/dhcpcd/[if]-[ssid].lease{,6}` (emphasis on _raw_).

So far, I've only found a few not-so-great methods of determining the router's
DNS servers and subsequently determined that it would be easier to simply parse
the `.lease` files directly. Is there a CLI tool for this? Apparently not.

[dhcpdump] and [dchprobe] come close, but don't allow one to parse a DHCP
message file directly.

_leasedump_ repurposes some code from [dhcpdump] to parse DHCP messages. It
does no network I/O and links to nothing other than libc, so you can mostly
rest easy about running it as root (`/var/lib/dhcpcd` requires root access on
my system). If you're extra paranoid, you can copy the `.lease` file and give
it regular user permissions first.

Furthermore, unlike dchpdump/dhcprobe, leasedump also supports DHCPv6 messages.

## Usage

``` sh
$ leasedump /var/lib/dhcpcd/wlan0-MySSID.lease
```

## Output

```
    OP: 2 (BOOTPREPLY)
 HTYPE: 1 (Ethernet)
  HLEN: 6
  HOPS: 0
   XID: fe3d0f32
  SECS: 0
 FLAGS: 0
CIADDR: 0.0.0.0
YIADDR: 192.168.0.144
SIADDR: 0.0.0.0
GIADDR: 0.0.0.0
CHADDR: 12:14:25:11:78:e1:00:00:00:00:00:00:00:00:00:00
 SNAME: .
 FNAME: .
OPTION:  53 (  1) DHCP message type         5 (DHCPACK)
OPTION:  54 (  4) DHCP Server identifier    192.168.0.1
OPTION:  51 (  4) IP address leasetime      172800 (2d)
OPTION:   1 (  4) Subnet mask               255.255.255.0
OPTION:   3 (  4) Router                    192.168.0.1
OPTION:   6 (  4) DNS server                192.168.0.2
OPTION:  58 (  4) Renewal Time T1           86400 (24h)
OPTION:  59 (  4) Rebinding Time T2         151200 (1d18h)
```

## Alternatives

These are the (messy) alternatives I've found so far:

dhcpcd:

``` sh
# Requests a new lease, may try to run the daemon again?
$ dhcpcd -o domain_name_servers -T | grep name_servers
```

dhclient (no longer [maintained][dhclient]):

``` sh
# Requests a new lease and starts a daemon, probably not what you want.
$ dhclient wlan0
$ cat /var/lib/dhclient/dhclient.leases
$ killall dhclient
```

nmap:

``` sh
# Scans for dhcp servers. Requires root.
$ nmap --script broadcast-dhcp-discover
```

[dhcpdump]:

``` sh
# Uses pcap to watch for and dump dhcp messages. Requires root.
$ dhcpdump wlan0
```

[dhcprobe]:

``` sh
# Requests a lease from specified server directly and dumps configuration.
$ dhcprobe -v -s 172.20.205.1
```

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2024, Christopher Jeffrey (MIT License).

Parts of this software are based on [dhcpdump]:

- Copyright (c) 2001-2024, Edwin Groothuis (BSD 2-Clause).
- Copyright (c) 2023-2024, Boian Bonev (BSD 2-Clause).

See [LICENSE] for more info.

[dhcpdump]: https://github.com/bbonev/dhcpdump
[dhcprobe]: https://github.com/JohannesBuchner/DHCProbe
[dhclient]: https://www.isc.org/dhcp/
[eom]: https://www.isc.org/blogs/dhcp-client-relay-eom/
[LICENSE]: https://github.com/chjj/leasedump/blob/master/LICENSE
