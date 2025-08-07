snmpproxy
====================

## Description

This software is designed to save the computing resource of network devices polled by a large number of different monitoring systems.
It is a transparent caching proxy that intercepts requests to network devices and responds to monitoring systems instead of them.
In this way, the number of requests to the devices themselves can be significantly reduced.
At this time it works only under Linux.

## Quick start

At first you need a linux host which has snmp access to your devices to query them.
Since by default all processes that need access to ports <1024 must have root access, this software must be run as root.

After starting snmpproxy you should redirect incoming UDP packet with dport=161 to snmpproxy. For example with iptables&iprules:
```
ip route add local default dev lo table 100
ip rule add fwmark 1 table 100
iptables -t mangle -N DIVERT
iptables -t mangle -A PREROUTING -p udp -m socket -j DIVERT
iptables -t mangle -A DIVERT -j MARK --set-mark 1
iptables -t mangle -A DIVERT -j ACCEPT
iptables -t mangle -A PREROUTING -p udp --dport 161 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 161
```

After that you should forward all SNMP packets from all your monitoring systems to snmpproxy by any apprepriate way for your network.
For example you can use policy based routing on incoming interfaces to redirect all SNMP packets (proto udp and dst port 161) into new mpls l3vpn, and establesh default route in that vpn to then snmpproxy host.

Now the snmpproxy will be receiving all SNMP requests, query your devices only when necessary and send spoofed answers to all monitoring systems.

## Configuration

Configuration can be done via CLI options:

* --intercept - Intercept socket configuration, [ip[:port]][@device/fibno] [default: 0.0.0.0:161] - where snmpproxy get intercepted queries from monitorings
* --response  - Response spoofed socket configuration, [ip[:port]][@device/fibno] - where from snmpproxy will send spoofed responses to monitorings
* --query     - Device query socket configuration, [ip[:port]][@device/fibno] - where from snmpproxy will send queries to real devices
* --cache-value-lifetime - Cached values life time [default: 5m] - time to cache values
* --blacklist-duration   - Host auto-ignore duration [default: 15m] - time to ignore queries from monitoring, when it queries non-accessible device
* --snmp-timeout         - SNMP query to device timeout [default: 30s] - time to wait for reply from device
* --snmp-repeat          - SNMP retries count [default: 3] - how many tries snmpproxy does to query device
* --max-parallel-queries-per-host - Maximum parallel queries per host [default: 100] - when single monitoring system floods, further queries will silently ignored

Logging can be set up via environment var RUST_LOG. RUST_LOG=snmpproxy=trace will be maximum.

## License

[MIT OR Apache-2.0](LICENSE)
