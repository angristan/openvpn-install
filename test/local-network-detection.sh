#!/bin/bash
# shellcheck disable=SC1091,SC2034
# SC1091: The installer path is provided by the test environment.
# SC2034: VPN subnet globals are consumed by sourced installer functions.
set -euo pipefail

INSTALLER=${1:-/opt/openvpn-install.sh}
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

cat >"$TEMP_DIR/ip" <<'EOF'
#!/bin/bash
case "$*" in
"-4 -o route show type unicast")
	cat <<'ROUTES'
default via 167.172.176.1 dev public0
10.8.0.0/24 dev tun-test proto kernel scope link
10.19.0.0/16 dev public0 proto kernel scope link src 10.19.0.5
10.135.0.0/16 dev eth1 proto kernel scope link src 10.135.0.2
10.135.0.0/16 dev eth1 proto kernel scope link src 10.135.0.2
10.200.0.0/16 via 10.135.0.1 dev eth1
100.64.0.0/10 dev tailscale0 proto kernel scope link
169.254.0.0/16 dev eth1 proto kernel scope link
172.20.0.0/16 dev docker0 proto kernel scope link
192.168.50.0/24 dev lan0 proto kernel scope link
203.0.113.0/24 dev public0 proto kernel scope link
ROUTES
	;;
"-6 -o route show type unicast")
	cat <<'ROUTES'
default via fe80::1 dev public0
fc00:1::/64 via fd12:3456::1 dev lan0
fd12:3456::/64 dev lan0 proto kernel metric 256
fe80::/64 dev public0 proto kernel metric 256
2001:db8::/64 dev public0 proto kernel metric 256
ROUTES
	;;
"-4 -o address show dev public0 scope global")
	cat <<'ADDRESSES'
2: public0 inet 203.0.113.10/24 brd 203.0.113.255 scope global public0
2: public0 inet 10.19.0.5/16 brd 10.19.255.255 scope global public0
ADDRESSES
	;;
"-4 -o address show dev eth1 scope global")
	echo "3: eth1 inet 10.135.0.2/16 brd 10.135.255.255 scope global eth1"
	;;
esac
EOF
chmod +x "$TEMP_DIR/ip"

export FORCE_COLOR=0 LOG_FILE="" NON_INTERACTIVE_INSTALL=n OUTPUT_FORMAT=table
# shellcheck source=../openvpn-install.sh
source "$INSTALLER"
PATH="$TEMP_DIR:$PATH"

VPN_SUBNET_IPV4=10.8.0.0
VPN_SUBNET_IPV6=fd42:42:42:42::

assert_equal() {
	local expected="$1" actual="$2" description="$3"
	if [[ $actual != "$expected" ]]; then
		echo "FAIL: $description" >&2
		echo "Expected: $expected" >&2
		echo "Actual:   $actual" >&2
		exit 1
	fi
}

assert_equal \
	"10.135.0.0/16,172.20.0.0/16,192.168.50.0/24,fd12:3456::/64" \
	"$(detect_private_local_networks y y)" \
	"detects unique, directly connected RFC1918 and ULA networks"
assert_equal \
	"10.135.0.0/16,172.20.0.0/16,192.168.50.0/24" \
	"$(detect_private_local_networks y n)" \
	"honors IPv4-only client configuration"
assert_equal \
	"fd12:3456::/64" \
	"$(detect_private_local_networks n y)" \
	"honors IPv6-only client configuration"
assert_equal "" "$(detect_private_local_networks n n)" "returns an empty list when both families are disabled"

if is_private_ipv4_network 10.0.0.0/7; then
	echo "FAIL: IPv4 network broader than RFC1918 space was accepted" >&2
	exit 1
fi
if is_private_ipv6_network fc00::/6; then
	echo "FAIL: IPv6 network broader than ULA space was accepted" >&2
	exit 1
fi

echo "PASS: Local network candidate detection"
