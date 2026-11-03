# Security Web Gateway local DNS cache.
# Listens on loopback only and forwards to the configured enterprise DNS servers.
server:
    interface: 127.0.0.1
    port: 53
    access-control: 127.0.0.0/8 allow
    do-daemonize: no
    hide-identity: yes
    hide-version: yes
    prefetch: yes
    prefetch-key: yes
    cache-min-ttl: 15
    cache-max-ttl: 3600
    msg-cache-size: 64m
    rrset-cache-size: 128m
    num-threads: 1
    verbosity: 1

forward-zone:
    name: "."
__UNBOUND_FORWARD_ADDRS__
