#!/bin/bash
set -e

echo "=== OpenVPN Client Container ==="

# Create TUN device if it doesn't exist
if [ ! -c /dev/net/tun ]; then
	mkdir -p /dev/net
	mknod /dev/net/tun c 10 200
	chmod 600 /dev/net/tun
fi

echo "TUN device ready"

WAIT_TIMEOUT_SIGNAL="${WAIT_TIMEOUT_SIGNAL:-300}"
WAIT_TIMEOUT_VPN="${WAIT_TIMEOUT_VPN:-120}"
WAIT_TIMEOUT_GATEWAY="${WAIT_TIMEOUT_GATEWAY:-120}"
WAIT_TIMEOUT_REVOKE="${WAIT_TIMEOUT_REVOKE:-60}"

wait_until() {
	local description="$1"
	local timeout="$2"
	local interval="$3"
	shift 3

	local start elapsed
	start=$(date +%s)
	until "$@"; do
		elapsed=$(($(date +%s) - start))
		if [ "$elapsed" -ge "$timeout" ]; then
			echo "FAIL: Timed out after ${timeout}s waiting for $description"
			return 1
		fi
		echo "Waiting for $description... (${elapsed}/${timeout}s)"
		sleep "$interval"
	done
}

wait_for_file() {
	local path="$1"
	local description="$2"
	local timeout="${3:-$WAIT_TIMEOUT_SIGNAL}"

	wait_until "$description" "$timeout" 2 test -f "$path"
}

tun_has_ipv4() {
	ip addr show tun0 2>/dev/null | grep -q "inet "
}

wait_for_tun_ipv4() {
	local description="$1"
	local log_file="$2"
	local timeout="${3:-$WAIT_TIMEOUT_VPN}"
	local elapsed=0

	until tun_has_ipv4; do
		if [ "$elapsed" -ge "$timeout" ]; then
			echo "FAIL: Timed out after ${timeout}s waiting for $description"
			ip addr show 2>&1 || true
			if [ -f "$log_file" ]; then
				echo "OpenVPN log tail:"
				tail -50 "$log_file"
			fi
			exit 1
		fi
		echo "Waiting for tun0... (${elapsed}/${timeout}s)"
		if [ -f "$log_file" ]; then
			tail -3 "$log_file"
		fi
		sleep 2
		elapsed=$((elapsed + 2))
	done
}

gateway_ping_ok() {
	ping -c 3 -W 2 "$VPN_GATEWAY" >/dev/null 2>&1
}

gateway_unreachable() {
	! ping -c 1 -W 2 "$VPN_GATEWAY" >/dev/null 2>&1
}

wait_for_gateway_ping() {
	local description="$1"

	if ! wait_until "$description" "$WAIT_TIMEOUT_GATEWAY" 3 gateway_ping_ok; then
		echo "FAIL: Cannot ping $VPN_GATEWAY"
		ip addr show 2>&1 || true
		ip route show 2>&1 || true
		exit 1
	fi
	echo "PASS: Can ping $description"
}

wait_for_revoked_reconnect_rejected() {
	local log_file="$1"
	local timeout="${2:-$WAIT_TIMEOUT_VPN}"
	local elapsed=0

	while [ "$elapsed" -le "$timeout" ]; do
		if tun_has_ipv4; then
			echo "FAIL: Connection succeeded with revoked certificate!"
			cat "$log_file" 2>/dev/null || true
			exit 1
		fi

		if [ -f "$log_file" ] && grep -qi "certificate verify failed\|TLS Error\|AUTH_FAILED\|certificate revoked" "$log_file"; then
			echo "Connection correctly rejected (certificate revoked)"
			return 0
		fi

		if [ "$elapsed" -ge "$timeout" ]; then
			echo "FAIL: Timed out after ${timeout}s waiting for revoked certificate rejection"
			cat "$log_file" 2>/dev/null || true
			exit 1
		fi

		echo "Checking revoked connection status... (${elapsed}/${timeout}s)"
		if [ -f "$log_file" ]; then
			tail -3 "$log_file"
		fi
		sleep 2
		elapsed=$((elapsed + 2))
	done

	echo "FAIL: Timed out after ${timeout}s waiting for revoked certificate rejection"
	cat "$log_file" 2>/dev/null || true
	exit 1
}

test_dns_resolution() {
	local label="$1"
	local success=false
	echo "$label: Testing DNS resolution via Unbound ($VPN_GATEWAY)..."
	for i in $(seq 1 10); do
		DIG_OUTPUT=$(dig @"$VPN_GATEWAY" example.com +short +time=5 2>&1)
		if [ -n "$DIG_OUTPUT" ] && ! echo "$DIG_OUTPUT" | grep -qi "timed out\|SERVFAIL\|connection refused"; then
			success=true
			break
		fi
		echo "DNS attempt $i failed:"
		echo "$DIG_OUTPUT"
		sleep 2
	done
	if [ "$success" = true ]; then
		echo "PASS: DNS resolution through Unbound works"
	else
		echo "FAIL: DNS resolution through Unbound failed after 10 attempts"
		dig @"$VPN_GATEWAY" example.com +time=5 || true
		exit 1
	fi
}

# Wait for client config to be available
echo "Waiting for client config..."
wait_for_file /shared/client.ovpn "client config"

echo "Client config found!"
cat /shared/client.ovpn

# Load VPN network config from server
if [ -f /shared/vpn-config.env ]; then
	# shellcheck source=/dev/null
	source /shared/vpn-config.env
	echo "VPN config loaded: VPN_SUBNET_IPV4=$VPN_SUBNET_IPV4, VPN_GATEWAY=$VPN_GATEWAY"
	if [ "${CLIENT_IPV6:-n}" = "y" ]; then
		# shellcheck disable=SC2153 # Variables are sourced from vpn-config.env
		echo "IPv6 enabled: VPN_SUBNET_IPV6=$VPN_SUBNET_IPV6, VPN_GATEWAY_IPV6=$VPN_GATEWAY_IPV6"
	fi
else
	echo "WARNING: vpn-config.env not found, using defaults"
	VPN_SUBNET_IPV4="10.8.0.0"
	VPN_GATEWAY="10.8.0.1"
	CLIENT_IPV6="n"
fi

# Connect to VPN
echo "Connecting to OpenVPN server..."
openvpn --config /shared/client.ovpn --daemon --log /var/log/openvpn.log

# Wait for connection
echo "Waiting for VPN connection..."
wait_for_tun_ipv4 "VPN connection" /var/log/openvpn.log

echo "=== VPN Connected! ==="
ip addr show tun0

# Allow routing tables to stabilize before running tests
# This prevents race conditions where tun0 is up but routing isn't ready
echo "Waiting for routing to stabilize..."
sleep 5

# Run connectivity tests
echo ""
echo "=== Running connectivity tests ==="

# Test 1: Check tun0 interface (IPv4)
echo "Test 1: Checking tun0 interface (IPv4)..."
# Extract base of subnet (e.g., "10.9.0" from "10.9.0.0")
VPN_SUBNET_BASE="${VPN_SUBNET_IPV4%.*}"
if ip addr show tun0 | grep -q "$VPN_SUBNET_BASE"; then
	echo "PASS: tun0 interface has correct IPv4 range (${VPN_SUBNET_BASE}.x)"
else
	echo "FAIL: tun0 interface doesn't have expected IPv4"
	exit 1
fi

# Test 1b: Check tun0 IPv6 address (if IPv6 enabled)
if [ "${CLIENT_IPV6:-n}" = "y" ]; then
	echo "Test 1b: Checking tun0 interface (IPv6)..."
	# Extract prefix of subnet (e.g., "fd42:42:42:42" from "fd42:42:42:42::")
	VPN_SUBNET_IPV6_PREFIX="${VPN_SUBNET_IPV6%::}"
	if ip -6 addr show tun0 | grep -q "$VPN_SUBNET_IPV6_PREFIX"; then
		echo "PASS: tun0 interface has correct IPv6 range (${VPN_SUBNET_IPV6_PREFIX}::x)"
	else
		echo "FAIL: tun0 interface doesn't have expected IPv6"
		ip -6 addr show tun0
		exit 1
	fi
fi

# Test 2: Ping VPN gateway (IPv4)
echo "Test 2: Pinging VPN gateway (IPv4) ($VPN_GATEWAY)..."
wait_for_gateway_ping "VPN gateway (IPv4)"

# Test 2b: Ping VPN gateway (IPv6, if enabled)
if [ "${CLIENT_IPV6:-n}" = "y" ]; then
	echo "Test 2b: Pinging VPN gateway (IPv6) ($VPN_GATEWAY_IPV6)..."
	if ping6 -c 5 "$VPN_GATEWAY_IPV6"; then
		echo "PASS: Can ping VPN gateway (IPv6)"
	else
		echo "FAIL: Cannot ping VPN gateway (IPv6)"
		exit 1
	fi
fi

# Test 3: DNS resolution through Unbound
test_dns_resolution "Test 3"

echo ""
echo "=== Initial connectivity tests PASSED ==="

# Signal server that initial tests passed
touch /shared/initial-tests-passed

# =====================================================
# Post-renewal connectivity tests
# =====================================================
echo ""
echo "=== Waiting for post-renewal config ==="
wait_for_file /shared/renewal-config-ready "renewal config"

echo "Renewal config ready, reconnecting..."
pkill openvpn || true
sleep 2

openvpn --config /shared/client.ovpn --daemon --log /var/log/openvpn-renewal.log

echo "Waiting for VPN connection after renewal..."
wait_for_tun_ipv4 "VPN connection after renewal" /var/log/openvpn-renewal.log

echo "=== VPN Connected after renewal! ==="
ip addr show tun0

echo "Waiting for routing to stabilize..."
sleep 5

echo "Test: Pinging VPN gateway after renewal ($VPN_GATEWAY)..."
wait_for_gateway_ping "VPN gateway after renewal"

test_dns_resolution "Test: Post-renewal DNS"

echo ""
echo "=== Post-renewal connectivity tests PASSED ==="
touch /shared/renewal-tests-passed

# =====================================================
# Certificate Revocation E2E Tests
# =====================================================
echo ""
echo "=== Starting Certificate Revocation E2E Tests ==="

REVOKE_CLIENT="revoketest"

# Wait for revoke test client config
echo "Waiting for revoke test client config..."
wait_for_file /shared/revoke-client-config-ready "revoke test config"

if [ ! -f "/shared/$REVOKE_CLIENT.ovpn" ]; then
	echo "FAIL: Revoke test client config file not found"
	exit 1
fi

echo "Revoke test client config found!"

# Disconnect current VPN (testclient) before connecting with revoke test client
echo "Disconnecting current VPN connection..."
pkill openvpn || true
sleep 2

# Connect with revoke test client
echo "Connecting with '$REVOKE_CLIENT' certificate..."
openvpn --config "/shared/$REVOKE_CLIENT.ovpn" --daemon --log /var/log/openvpn-revoke.log

# Wait for connection
echo "Waiting for VPN connection with revoke test client..."
wait_for_tun_ipv4 "VPN connection with revoke test client" /var/log/openvpn-revoke.log

echo "PASS: Connected with '$REVOKE_CLIENT' certificate"
ip addr show tun0

# Verify connectivity
wait_for_gateway_ping "VPN gateway with revoke test client"

# Signal server that we're connected with revoke test client
touch /shared/revoke-client-connected

# Wait for server to revoke and auto-disconnect us via management interface
# We detect disconnect by checking if ping to VPN gateway fails
echo "Waiting for server to revoke certificate and disconnect us..."
if wait_until "server to revoke and disconnect client" "$WAIT_TIMEOUT_REVOKE" 1 gateway_unreachable; then
	echo "Disconnect detected: cannot ping VPN gateway"
	echo "PASS: Client was auto-disconnected by revoke"
	# Kill openvpn process to clean up
	pkill openvpn 2>/dev/null || true
	sleep 1
else
	echo "FAIL: Client was not disconnected within 60 seconds"
	exit 1
fi

# Signal server that we detected the disconnect
touch /shared/revoke-client-disconnected

# Wait for server to signal us to try reconnecting
echo "Waiting for server to signal reconnect attempt..."
wait_for_file /shared/revoke-try-reconnect "reconnect signal"

# Try to reconnect with the now-revoked certificate (should fail)
echo "Attempting to reconnect with revoked certificate (should fail)..."
rm -f /var/log/openvpn-revoke-fail.log
openvpn --config "/shared/$REVOKE_CLIENT.ovpn" --daemon --log /var/log/openvpn-revoke-fail.log

# Wait and check if connection fails
# The connection should fail due to certificate being revoked
echo "Waiting to verify connection is rejected..."
wait_for_revoked_reconnect_rejected /var/log/openvpn-revoke-fail.log

# Kill any remaining openvpn process
pkill openvpn 2>/dev/null || true
sleep 1

# Even if we didn't see explicit error, verify tun0 is not up
if ip addr show tun0 2>/dev/null | grep -q "inet "; then
	echo "FAIL: tun0 interface exists - revoked cert may have connected"
	exit 1
fi

echo "PASS: Connection with revoked certificate was correctly rejected"

# Signal server that reconnect with revoked cert failed
touch /shared/revoke-reconnect-failed

# =====================================================
# Test connecting with new certificate (same name)
# =====================================================
echo ""
echo "=== Testing connection with recreated certificate ==="

# Wait for server to create new cert and signal us
echo "Waiting for new client config with same name..."
wait_for_file /shared/new-client-config-ready "new client config"

if [ ! -f "/shared/$REVOKE_CLIENT-new.ovpn" ]; then
	echo "FAIL: New client config file not found"
	exit 1
fi

echo "New client config found!"

# Connect with the new certificate
echo "Connecting with new '$REVOKE_CLIENT' certificate..."
rm -f /var/log/openvpn-new.log
openvpn --config "/shared/$REVOKE_CLIENT-new.ovpn" --daemon --log /var/log/openvpn-new.log

# Wait for connection
echo "Waiting for VPN connection with new certificate..."
wait_for_tun_ipv4 "VPN connection with new certificate" /var/log/openvpn-new.log

echo "PASS: Connected with new '$REVOKE_CLIENT' certificate"
ip addr show tun0

# Verify connectivity
wait_for_gateway_ping "VPN gateway with new certificate"

# Signal server that we connected with new cert
touch /shared/new-client-connected

echo ""
echo "=== Certificate Revocation E2E Tests PASSED ==="

# =====================================================
# Test PASSPHRASE-protected client connection
# =====================================================
echo ""
echo "=== Testing PASSPHRASE-protected Client Connection ==="

PASSPHRASE_CLIENT="passphrasetest"

# Wait for passphrase test client config
echo "Waiting for passphrase test client config..."
wait_for_file /shared/passphrase-client-config-ready "passphrase test config"

if [ ! -f "/shared/$PASSPHRASE_CLIENT.ovpn" ]; then
	echo "FAIL: Passphrase test client config file not found"
	exit 1
fi

if [ ! -f "/shared/$PASSPHRASE_CLIENT.pass" ]; then
	echo "FAIL: Passphrase file not found"
	exit 1
fi

echo "Passphrase test client config found!"

# Disconnect current VPN before connecting with passphrase client
echo "Disconnecting current VPN connection..."
pkill openvpn || true
sleep 2

# Connect with passphrase-protected client using --askpass
echo "Connecting with '$PASSPHRASE_CLIENT' certificate (passphrase-protected)..."
openvpn --config "/shared/$PASSPHRASE_CLIENT.ovpn" --askpass "/shared/$PASSPHRASE_CLIENT.pass" --daemon --log /var/log/openvpn-passphrase.log

# Wait for connection
echo "Waiting for VPN connection with passphrase-protected client..."
wait_for_tun_ipv4 "VPN connection with passphrase-protected client" /var/log/openvpn-passphrase.log

echo "PASS: Connected with passphrase-protected '$PASSPHRASE_CLIENT' certificate"
ip addr show tun0

# Verify connectivity
wait_for_gateway_ping "VPN gateway with passphrase-protected client"

# Signal server that we connected with passphrase client
touch /shared/passphrase-client-connected

echo ""
echo "=== PASSPHRASE-protected Client Tests PASSED ==="

echo ""
echo "=========================================="
echo "  ALL TESTS PASSED!"
echo "=========================================="

# Keep container running for debugging if needed
exec tail -f /var/log/openvpn-new.log 2>/dev/null || tail -f /var/log/openvpn.log 2>/dev/null || sleep infinity
