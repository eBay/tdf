transparent-dns-forwarder - Transparent DNS Forwarding for CGroups
==============================================================

Transparent DNS Forwarder (tdf) provides DNS forwarding in
cgroup contexts (such as Kubernetes pods) transparently.

DNS forwarding is done in a "zero config" manner.

tdf removes the need to manage changes to /etc/resolv.conf.

tdf removes the need to manage changes to /etc/resolv.conf inside of containers.

No changes are required to the root ns context or in any other process context
(such as to dnsPolicy for k8s pods).

tdf mangles outgoing DNS requests using eBPF to redirect them to any listening
DNS server (this should be something like a local pdns-recursor server or
another DNS service).

tdf is particularly useful for setting up a caching DNS tier.


How it works
------------
tdf keeps track of socket cookies to mangle back the UDP messages back
to the correct origin.

Dependencies
------------

Required:

- libelf
- zlib

Optional:

- libbfd
- libcap
- kernel BTF information
- clang/LLVM

### tdf usage

Get started:

```console
# tdf -h
```

Standard usage, forward all DNS traffic to 192.168.1.172 while it is available.

```console
# tdf -c /sys/fs/cgroup -s 192.168.1.172
```

Exclude DNS traffic to IP's 8.8.8.8 and 1.1.1.1.

```console
# tdf -s $(hostname -i) -c /sys/fs/cgroup -e 8.8.8.8 -e 1.1.1.1
```
