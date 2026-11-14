#!/usr/bin/env bash
# Runs as root inside the test VM, started by systemd after boot. Installs
# Netoxide as dist/README.md describes, then checks it as a firewall between
# an inside client and an outside server, across a daemon crash and a reboot.
#
# eth0 inside port of the box     eth1 the client's card (same wire as eth0)
# eth2 outside port of the box    eth3 the server's card (same wire as eth2)
exec >/dev/console 2>&1
T=/mnt/t
STATE=/var/lib/vmtest
fails=0
CLIENT_MAC=52:54:00:00:00:02

ok() { echo "ok $*"; }
bad() { echo "FAIL $*"; fails=$((fails + 1)); }
note() { echo "# $*"; }
# check <name> <command...>: the command must succeed.
check() {
    local name=$1
    shift
    # A command that hangs fails the check and the run goes on.
    [ "$(type -t "$1")" = file ] && set -- timeout 45 "$@"
    if "$@" >/tmp/out 2>&1; then ok "$name"; else
        bad "$name"
        tail -n 15 /tmp/out | sed 's/^/    /'
    fi
}
# refute <name> <command...>: the command must fail.
refute() {
    local name=$1
    shift
    if "$@" >/tmp/out 2>&1; then
        bad "$name"
        tail -n 15 /tmp/out | sed 's/^/    /'
    else ok "$name"; fi
}
cli() { ip netns exec cli "$@"; }
srv() { ip netns exec srv "$@"; }
cfetch() { cli curl -s -g --max-time 4 "$@"; }
sfetch() { srv curl -s -g --max-time 4 "$@"; }
# The firewall drops, it does not refuse: curl must run out of time (exit 28).
times_out() {
    "$@"
    [ $? -eq 28 ]
}
says() {
    local got
    got=$("${@:2}" 2>&1)
    [ "$got" = "$1" ] || { echo "wanted '$1', got '$got'"; return 1; }
}
# The dnsmasq the daemon started, not the test's own pretend resolver.
box_dnsmasq() { pgrep -x dnsmasq -P "$(systemctl show -p MainPID --value oxd)"; }
wait_for() { # wait_for <seconds> <command...>
    local n=$(($1 * 5))
    shift
    while [ $n -gt 0 ]; do
        "$@" >/dev/null 2>&1 && return 0
        sleep 0.2
        n=$((n - 1))
    done
    return 1
}
finish() {
    if [ "$fails" -eq 0 ]; then echo "VMTEST PASS"; else
        echo "VMTEST FAIL ($fails)"
        journalctl -u oxd --no-pager -n 60 | sed 's/^/    /'
        journalctl -k --no-pager -n 4 | sed 's/^/    /'
        # Where each of the daemon's threads is, in case it hangs.
        for t in /proc/"$(systemctl show -p MainPID --value oxd)"/task/*; do
            echo "    thread $(cat "$t/comm") syscall $(cut -d' ' -f1-3 "$t/syscall" 2>/dev/null)"
            head -n 7 "$t/stack" 2>/dev/null | sed 's/^/        /'
        done
        ps -eo pid,ppid,stat,comm | grep -E "dnsmasq|modprobe|oxd" | sed 's/^/    /'
    fi
    sync
    systemctl poweroff
    exit 0
}

# The client and the server live in their own network namespaces, each with
# one of the VM's network cards.
lab() {
    ip netns add cli
    ip netns add srv
    ip link set eth1 netns cli
    ip link set eth3 netns srv
    ip -n cli link set lo up
    ip -n srv link set lo up
    ip -n srv link set eth3 up
    ip -n srv addr add 203.0.113.2/24 dev eth3
    ip -n srv -6 addr add 2001:db8:113::2/64 dev eth3 nodad
    # A way in for the outside, so that what stops it is the firewall.
    ip -n srv route add 192.168.50.0/24 via 203.0.113.10
    # No address translation for IPv6, so the server needs the way back.
    ip -n srv -6 route add 2001:db8:50::/64 via 2001:db8:113::10
    mkdir -p /tmp/srv /tmp/cli
    echo outside >/tmp/srv/index.html
    echo inside >/tmp/cli/index.html
    srv python3 -u -m http.server 80 --bind :: -d /tmp/srv >/tmp/srv-80.log 2>&1 &
    srv python3 -u -m http.server 8081 --bind :: -d /tmp/srv >/tmp/srv-8081.log 2>&1 &
    cli python3 -u -m http.server 80 --bind :: -d /tmp/cli >/tmp/cli-80.log 2>&1 &
    cli python3 -u -m http.server 8082 --bind :: -d /tmp/cli >/tmp/cli-8082.log 2>&1 &
    # Addresses beyond the outside network, reachable only through a router.
    ip -n srv addr add 198.51.100.1/32 dev lo
    ip -n srv -6 addr add 2001:db8:ffff::1/128 dev lo
    # The pretend provider: the resolver the box forwards to, and the DHCP
    # server that gives the box its outside address and names the router.
    srv dnsmasq --keep-in-foreground --user=root --pid-file= --no-resolv --no-hosts \
        --bind-interfaces --listen-address=203.0.113.2 \
        --address=/example.test/203.0.113.2 \
        --dhcp-range=203.0.113.50,203.0.113.99,255.255.255.0,2m \
        --dhcp-host=52:54:00:00:01:01,203.0.113.10 --dhcp-option=3,203.0.113.2 \
        --dhcp-leasefile=/tmp/srv.leases >/tmp/srv-dns.log 2>&1 &
}

# A second Netoxide daemon in the server's namespace plays a laptop
# somewhere on the internet that connects to the box's VPN.
remote() { OX_SOCKET=$STATE/remote.sock ox "$@"; }
remote_up() {
    srv oxd --state-dir $STATE/remote --socket $STATE/remote.sock >/tmp/remote.log 2>&1 &
    wait_for 5 remote status
}
vpn_checks() {
    local when=$1
    check "$when: the VPN device reaches the inside web server through the tunnel" wait_for 20 says inside sfetch http://192.168.50.50/
    check "$when: it resolves a local name through the box" says 192.168.50.7 srv dig +short +time=2 +tries=1 @10.90.0.1 printer.home.arpa
    check "$when: the tunnel does not open the box's admin port" times_out srv curl -sk --max-time 3 https://10.90.0.1:8443/v1/status
    check "$when: ox vpn shows the device as connected" bash -c 'ox vpn | grep laptop | grep -q connected'
}

# The client asks the box for an address and takes what it is given.
client_up() {
    ip -n cli link set eth1 up
    local lease
    lease=$(cli python3 $T/dhcp_client.py eth1 $CLIENT_MAC client) || return 1
    set -- $lease
    echo "$1" >/tmp/client-addr
    ip -n cli addr replace "$1/24" dev eth1
    ip -n cli route replace default via "$2"
}

traffic_checks() {
    local when=$1
    check "$when: inside client reaches the outside web server" says outside cfetch http://203.0.113.2/
    check "$when: the server sees the box's address, not the client's" grep -q '203.0.113.10 .*GET' /tmp/srv-80.log
    refute "$when: the client's own address never reaches the server" grep -q '192.168.50' /tmp/srv-80.log
    check "$when: the same over IPv6" says outside cfetch 'http://[2001:db8:113::2]/'
    check "$when: a server beyond the provider's router is reached" says outside cfetch http://198.51.100.1/
    check "$when: and over IPv6" says outside cfetch 'http://[2001:db8:ffff::1]/'
    check "$when: a port no rule allows is dropped" times_out cfetch http://203.0.113.2:8081/
    check "$when: and dropped over IPv6" times_out cfetch 'http://[2001:db8:113::2]:8081/'
    check "$when: the forwarded port reaches the inside server" says inside sfetch http://203.0.113.10:8080/
    if [ ! -e $STATE/vpn ]; then
        check "$when: the outside cannot reach another inside port" times_out sfetch http://192.168.50.50:8082/
    fi
    check "$when: inside can ping the box" cli ping -c1 -W2 192.168.50.1
    refute "$when: outside cannot ping the box" srv ping -c1 -W2 203.0.113.10
    check "$when: the box answers a local name" says 192.168.50.7 cli dig +short +time=2 +tries=1 @192.168.50.1 printer.home.arpa
    check "$when: the box resolves an outside name through its upstream" says 203.0.113.2 cli dig +short +time=2 +tries=1 @192.168.50.1 example.test
    refute "$when: outside cannot use the box's DNS" srv dig +short +time=2 +tries=1 @203.0.113.10 printer.home.arpa
}

mkdir -p $STATE
stage=$(cat $STATE/stage 2>/dev/null || echo 1)
note "stage $stage on $(uname -r), systemd $(systemctl --version | head -n1 | cut -d' ' -f2)"

if [ "$stage" = 1 ]; then
    # --- install, as dist/README.md says ---
    install -m 0755 $T/bin/oxd $T/bin/ox /usr/bin/
    install -m 0644 $T/dist/oxd.service /etc/systemd/system/oxd.service
    systemctl daemon-reload
    check "install: systemctl enable --now oxd" systemctl enable --now oxd
    check "install: the daemon answers" wait_for 5 ox status
    note "$(systemd-analyze security oxd --no-pager 2>/dev/null | tail -n1)"
    refute "install: nothing is loaded before the first commit" bash -c 'nft list tables | grep -q netoxide'

    lab

    # --- first commit ---
    check "commit: the config is accepted as a candidate" ox candidate save box $T/box.toml
    check "commit: plan" ox plan box
    check "commit: commit with an undo timer" ox commit box --confirm 2m --reason "vm test"
    check "commit: confirm" ox confirm
    check "commit: the inside port has its addresses" bash -c 'ip -br addr show eth0 | grep -q 192.168.50.1/24 && ip -br addr show eth0 | grep -q 2001:db8:50::1/64'
    check "wan: the outside port has its fixed IPv6 address" bash -c 'ip -br addr show eth2 | grep -q 2001:db8:113::10/64'
    check "wan: the box gets its IPv4 address from the provider" wait_for 15 bash -c 'ip -br addr show eth2 | grep -q 203.0.113.10/24'
    check "wan: the default route goes through the router the provider named" bash -c 'ip route | grep -q "default via 203.0.113.2 dev eth2"'
    check "wan: the IPv6 default route goes through the configured gateway" bash -c 'ip -6 route | grep -q "default via 2001:db8:113::2 dev eth2"'
    check "wan: ox status shows the address" bash -c 'ox status | grep -q "203.0.113.10/24 from the network"'
    check "commit: IPv4 forwarding is on" says 1 cat /proc/sys/net/ipv4/ip_forward
    check "commit: IPv6 forwarding is on" says 1 cat /proc/sys/net/ipv6/conf/all/forwarding
    check "commit: dnsmasq runs" wait_for 5 box_dnsmasq
    check "commit: dnsmasq runs as its own user, not root" says dnsmasq ps -o user= -p "$(box_dnsmasq)"

    check "dhcp: the client gets an address" client_up
    check "dhcp: it is the fixed address for its hardware address" says 192.168.50.50 cat /tmp/client-addr
    check "ipv6: the client gives itself an address from the announced network" wait_for 15 bash -c 'ip -n cli -6 addr show dev eth1 scope global | grep -q 2001:db8:50:'
    wait_for 5 bash -c 'ip -n cli -6 route | grep -q default'
    # Let duplicate address detection finish before using the address.
    wait_for 10 bash -c '! ip -n cli -6 addr show dev eth1 | grep -q tentative'

    traffic_checks "first commit"
    check "explain agrees: web is accepted" bash -c 'ox explain --src 192.168.50.50 --dst 203.0.113.2 --proto tcp --dport 80 --in eth0 | grep -q ACCEPT'
    check "explain agrees: 8081 is dropped" bash -c 'ox explain --src 192.168.50.50 --dst 203.0.113.2 --proto tcp --dport 8081 --in eth0 | grep -q DROP'
    check "leases: the client is listed" bash -c 'ox leases | grep -q 192.168.50.50'
    check "audit: the log verifies" ox audit

    # --- undo timer ---
    ox candidate save noweb $T/box-noweb.toml >/dev/null
    check "undo: commit a change that cuts web access, 10 second timer" ox commit noweb --confirm 10s
    check "undo: web access is cut" times_out cfetch http://203.0.113.2/
    sleep 13
    check "undo: nobody confirmed, so web access is back" says outside cfetch http://203.0.113.2/
    refute "undo: no commit is left waiting" bash -c 'ox status | grep -qi "waiting\|pending"'

    # --- the daemon dies ---
    systemctl kill -s KILL oxd
    check "crash: traffic still flows while the daemon is dead" says outside cfetch http://203.0.113.2/
    check "crash: systemd starts it again" wait_for 10 ox status
    check "crash: dnsmasq is back" wait_for 10 box_dnsmasq
    check "crash: the box still answers DNS" wait_for 5 says 192.168.50.7 cli dig +short +time=1 +tries=1 @192.168.50.1 printer.home.arpa

    check "crash with a commit waiting: commit" ox commit noweb --confirm 5m
    check "crash with a commit waiting: web access is cut" times_out cfetch http://203.0.113.2/
    systemctl kill -s KILL oxd
    wait_for 10 ox status
    check "crash with a commit waiting: the restart undoes it" wait_for 5 says outside cfetch http://203.0.113.2/

    # --- VPN: one command on the box, then a device connects ---
    touch $STATE/vpn
    check "vpn: the laptop's daemon starts" remote_up
    laptop_key=$(remote vpn --key wg0)
    check "vpn: add the laptop with its own public key" bash -c "ox vpn add laptop --endpoint 203.0.113.10 --public-key '$laptop_key' >/tmp/vpn-add.txt"
    check "vpn: the device config names the box and the inside network" bash -c 'grep -q "Endpoint = 203.0.113.10:51820" /tmp/vpn-add.txt && grep -q "AllowedIPs = 10.90.0.0/24, 192.168.50.0/24" /tmp/vpn-add.txt && grep -q "DNS = 10.90.0.1" /tmp/vpn-add.txt'
    check "vpn: commit on the box" ox commit vpn-laptop --reason "vpn"
    # Everything after this needs the daemon to answer.
    [ "$fails" -eq 0 ] || finish
    check "vpn: the tunnel interface exists under the unit's sandbox" ip link show wg0
    box_key=$(ox vpn --key wg0)
    # The laptop's side, written from what the device config says.
    cat >/tmp/laptop.toml <<TOML
schema = 1
hostname = "laptop"
[zones.wan]
[zones.vpn]
[interfaces.eth3]
zone = "wan"
addresses = ["203.0.113.2/24"]
[wireguard.wg0]
zone = "vpn"
addresses = ["10.90.0.2/32"]
[[wireguard.wg0.peer]]
name = "home"
public_key = "$box_key"
allowed = ["10.90.0.0/24", "192.168.50.0/24"]
endpoint = "203.0.113.10:51820"
keepalive = 25
# This namespace also plays the provider, so it takes what the box sends it.
[[policy]]
from = "wan"
to = "self"
[[policy.rule]]
id = "r-provider"
name = "The pretend provider's own services"
action = "accept"
TOML
    # Without the tunnel the laptop would reach the inside network by the
    # plain route the earlier checks use.
    ip -n srv route del 192.168.50.0/24
    check "vpn: the laptop's config is accepted" remote candidate save vpn /tmp/laptop.toml
    check "vpn: the laptop brings its tunnel up" remote commit vpn
    vpn_checks "vpn"
    check "vpn: a commit that does not touch the tunnel leaves it connected" bash -c 'ox running >/tmp/now.toml && ox candidate save again /tmp/now.toml && ox commit again --reason "no change" && ox vpn | grep laptop | grep -q connected'
    check "vpn: and traffic still flows right after it" says inside sfetch http://192.168.50.50/

    # --- HTTPS and tokens ---
    mkdir -p /etc/netoxide
    echo 'OXD_ARGS=--listen [::]:8443' >/etc/netoxide/oxd.env
    systemctl restart oxd
    check "https: daemon restarts with the listener" wait_for 10 ox status
    token=$(ox token create vm --role viewer --days 1 | grep -o 'ox_[0-9a-f]*')
    code() { cli curl -sk -o /dev/null -w '%{http_code}' --max-time 4 "$@"; }
    check "https: a token gets in from the inside" says 200 code -H "Authorization: Bearer $token" https://192.168.50.1:8443/v1/status
    check "https: over IPv6 too" says 200 code -g -H "Authorization: Bearer $token" 'https://[2001:db8:50::1]:8443/v1/status'
    check "https: no token, no entry" says 401 code https://192.168.50.1:8443/v1/status
    check "https: a viewer may not commit" says 403 code -X POST -H "Authorization: Bearer $token" -H "Content-Type: application/json" -d "{}" https://192.168.50.1:8443/v1/candidates/box/commit
    check "https: the outside cannot reach the listener" times_out srv curl -sk --max-time 3 https://203.0.113.10:8443/v1/status
    traffic_checks "after restarts"

    check "wan: the box asked to keep its address and got it" wait_for 80 bash -c '[ "$(journalctl -u oxd --no-pager | grep -c "eth2 has 203.0.113.10/24 from the network")" -ge 2 ]'

    ox status | head -n 3 >$STATE/status-before
    echo 2 >$STATE/stage
    [ "$fails" -eq 0 ] || finish
    note "rebooting"
    sync
    systemctl reboot
    exit 0
fi

# --- after the reboot ---
check "reboot: the daemon started at boot" wait_for 10 ox status
check "reboot: the same commit is running" bash -c "ox status | head -n 3 | diff - $STATE/status-before"
check "reboot: the rules are loaded" bash -c 'ox kernel | grep -q r-web'
check "reboot: the inside port has its addresses again" bash -c 'ip -br addr show eth0 | grep -q 192.168.50.1/24'
check "reboot: forwarding is on" says 1 cat /proc/sys/net/ipv4/ip_forward
check "reboot: dnsmasq runs" wait_for 5 box_dnsmasq
lab
check "reboot: the box gets its outside address again" wait_for 20 bash -c 'ip -br addr show eth2 | grep -q 203.0.113.10/24'
check "reboot: the client gets its address" client_up
wait_for 15 bash -c 'ip -n cli -6 addr show dev eth1 scope global | grep -q 2001:db8:50:'
wait_for 10 bash -c '! ip -n cli -6 addr show dev eth1 | grep -q tentative'
check "reboot: the laptop's daemon starts again" remote_up
traffic_checks "after reboot"
vpn_checks "after reboot"
check "reboot: the audit log still verifies" ox audit

# The pretend laptop's daemon is not part of the install.
pkill -f "oxd --state-dir $STATE/remote"
sleep 1

# --- remove it, as dist/README.md says ---
systemctl disable --now oxd
nft delete table inet netoxide
rm /etc/systemd/system/oxd.service /usr/bin/oxd /usr/bin/ox
rm -r /var/lib/netoxide
ip link del wg0
refute "remove: no daemon left" pgrep -x oxd
refute "remove: no dnsmasq of ours left" pgrep -f 'dnsmasq.*netoxide'
refute "remove: no tunnel left" ip link show wg0
refute "remove: no rules left" bash -c 'nft list tables | grep -q netoxide'
finish
