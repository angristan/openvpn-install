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

# Wait for client config to be available
echo "Waiting for client config..."
MAX_WAIT=120
WAITED=0
while [ ! -f /shared/client.ovpn ] && [ $WAITED -lt $MAX_WAIT ]; do
	sleep 2
	WAITED=$((WAITED + 2))
	echo "Waiting... ($WAITED/$MAX_WAIT seconds)"
done

if [ ! -f /shared/client.ovpn ]; then
	echo "ERROR: Client config not found after ${MAX_WAIT}s"
	exit 1
fi

echo "Client config found!"
cat /shared/client.ovpn

# Load VPN network config from server
if [ -f /shared/vpn-config.env ]; then
	# shellcheck source=/dev/null
	source /shared/vpn-config.env
	echo "VPN config loaded: VPN_SUBNET=$VPN_SUBNET, VPN_GATEWAY=$VPN_GATEWAY"
else
	echo "WARNING: vpn-config.env not found, using defaults"
	VPN_SUBNET="10.8.0.0"
	VPN_GATEWAY="10.8.0.1"
fi

# Connect to VPN
echo "Connecting to OpenVPN server..."
openvpn --config /shared/client.ovpn --daemon --log /var/log/openvpn.log

# Wait for connection
echo "Waiting for VPN connection..."
MAX_WAIT=60
WAITED=0
while ! ip addr show tun0 2>/dev/null | grep -q "inet " && [ $WAITED -lt $MAX_WAIT ]; do
	sleep 2
	WAITED=$((WAITED + 2))
	echo "Waiting for tun0... ($WAITED/$MAX_WAIT seconds)"

	# Check for errors
	if [ -f /var/log/openvpn.log ]; then
		tail -5 /var/log/openvpn.log
	fi
done

if ! ip addr show tun0 2>/dev/null | grep -q "inet "; then
	echo "ERROR: VPN connection failed"
	echo "=== OpenVPN log ==="
	cat /var/log/openvpn.log || true
	exit 1
fi

echo "=== VPN Connected! ==="
ip addr show tun0

# Run connectivity tests
echo ""
echo "=== Running connectivity tests ==="

# Test 1: Check tun0 interface
echo "Test 1: Checking tun0 interface..."
# Extract base of subnet (e.g., "10.9.0" from "10.9.0.0")
VPN_SUBNET_BASE="${VPN_SUBNET%.*}"
if ip addr show tun0 | grep -q "$VPN_SUBNET_BASE"; then
	echo "PASS: tun0 interface has correct IP range (${VPN_SUBNET_BASE}.x)"
else
	echo "FAIL: tun0 interface doesn't have expected IP"
	exit 1
fi

# Test 2: Ping VPN gateway
echo "Test 2: Pinging VPN gateway ($VPN_GATEWAY)..."
if ping -c 10 "$VPN_GATEWAY"; then
	echo "PASS: Can ping VPN gateway"
else
	echo "FAIL: Cannot ping VPN gateway"
	exit 1
fi

# Test 3: DNS resolution through Unbound
echo "Test 3: Testing DNS resolution via Unbound ($VPN_GATEWAY)..."
DNS_SUCCESS=false
DNS_MAX_RETRIES=10
for i in $(seq 1 $DNS_MAX_RETRIES); do
	DIG_OUTPUT=$(dig @"$VPN_GATEWAY" example.com +short +time=5 2>&1)
	if [ -n "$DIG_OUTPUT" ] && ! echo "$DIG_OUTPUT" | grep -qi "timed out\|SERVFAIL\|connection refused"; then
		DNS_SUCCESS=true
		break
	fi
	echo "DNS attempt $i failed:"
	echo "$DIG_OUTPUT"
	sleep 2
done
if [ "$DNS_SUCCESS" = true ]; then
	echo "PASS: DNS resolution through Unbound works"
	echo "Resolved example.com to: $(dig @"$VPN_GATEWAY" example.com +short +time=5)"
else
	echo "FAIL: DNS resolution through Unbound failed after $DNS_MAX_RETRIES attempts"
	dig @"$VPN_GATEWAY" example.com +time=5 || true
	exit 1
fi

echo ""
echo "=== Initial connectivity tests PASSED ==="

# Signal server that initial tests passed
touch /shared/initial-tests-passed

# =====================================================
# Certificate Revocation E2E Tests
# =====================================================
echo ""
echo "=== Starting Certificate Revocation E2E Tests ==="

REVOKE_CLIENT="revoketest"

# Wait for revoke test client config
echo "Waiting for revoke test client config..."
MAX_WAIT=120
WAITED=0
while [ ! -f /shared/revoke-client-config-ready ] && [ $WAITED -lt $MAX_WAIT ]; do
	sleep 2
	WAITED=$((WAITED + 2))
	echo "Waiting for revoke test config... ($WAITED/$MAX_WAIT seconds)"
done

if [ ! -f /shared/revoke-client-config-ready ]; then
	echo "FAIL: Revoke test client config not ready in time"
	exit 1
fi

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
MAX_WAIT=60
WAITED=0
while ! ip addr show tun0 2>/dev/null | grep -q "inet " && [ $WAITED -lt $MAX_WAIT ]; do
	sleep 2
	WAITED=$((WAITED + 2))
	echo "Waiting for tun0... ($WAITED/$MAX_WAIT seconds)"
	if [ -f /var/log/openvpn-revoke.log ]; then
		tail -3 /var/log/openvpn-revoke.log
	fi
done

if ! ip addr show tun0 2>/dev/null | grep -q "inet "; then
	echo "FAIL: VPN connection with revoke test client failed"
	cat /var/log/openvpn-revoke.log || true
	exit 1
fi

echo "PASS: Connected with '$REVOKE_CLIENT' certificate"
ip addr show tun0

# Verify connectivity
if ping -c 2 "$VPN_GATEWAY" >/dev/null 2>&1; then
	echo "PASS: Can ping VPN gateway with revoke test client"
else
	echo "FAIL: Cannot ping VPN gateway with revoke test client"
	exit 1
fi

# Signal server that we're connected with revoke test client
touch /shared/revoke-client-connected

# Wait for server to signal us to disconnect
echo "Waiting for server to signal disconnect..."
MAX_WAIT=60
WAITED=0
while [ ! -f /shared/revoke-client-disconnect ] && [ $WAITED -lt $MAX_WAIT ]; do
	sleep 2
	WAITED=$((WAITED + 2))
done

if [ ! -f /shared/revoke-client-disconnect ]; then
	echo "FAIL: Server did not signal disconnect"
	exit 1
fi

# Disconnect
echo "Disconnecting revoke test client..."
pkill openvpn || true

# Wait for openvpn to fully exit and tun0 to be released
WAITED=0
MAX_WAIT_DISCONNECT=10
while (pgrep openvpn >/dev/null || ip addr show tun0 2>/dev/null | grep -q "inet ") && [ $WAITED -lt $MAX_WAIT_DISCONNECT ]; do
	sleep 1
	WAITED=$((WAITED + 1))
done

# Verify disconnected
if ip addr show tun0 2>/dev/null | grep -q "inet "; then
	echo "FAIL: tun0 still has IP after disconnect"
	exit 1
fi
echo "PASS: Disconnected successfully"

# Signal server that we're disconnected
touch /shared/revoke-client-disconnected

# Wait for server to revoke the certificate and signal us to reconnect
echo "Waiting for server to revoke certificate and signal reconnect..."
MAX_WAIT=60
WAITED=0
while [ ! -f /shared/revoke-try-reconnect ] && [ $WAITED -lt $MAX_WAIT ]; do
	sleep 2
	WAITED=$((WAITED + 2))
done

if [ ! -f /shared/revoke-try-reconnect ]; then
	echo "FAIL: Server did not signal to try reconnect"
	exit 1
fi

# Try to reconnect with the now-revoked certificate (should fail)
echo "Attempting to reconnect with revoked certificate (should fail)..."
rm -f /var/log/openvpn-revoke-fail.log
openvpn --config "/shared/$REVOKE_CLIENT.ovpn" --daemon --log /var/log/openvpn-revoke-fail.log

# Wait and check if connection fails
# The connection should fail due to certificate being revoked
echo "Waiting to verify connection is rejected..."
CONNECT_FAILED=false
MAX_WAIT=30
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
	sleep 2
	WAITED=$((WAITED + 2))

	# Check if tun0 came up (would mean revocation didn't work)
	if ip addr show tun0 2>/dev/null | grep -q "inet "; then
		echo "FAIL: Connection succeeded with revoked certificate!"
		cat /var/log/openvpn-revoke-fail.log || true
		exit 1
	fi

	# Check for certificate verification failure in log
	if [ -f /var/log/openvpn-revoke-fail.log ]; then
		if grep -qi "certificate verify failed\|TLS Error\|AUTH_FAILED\|certificate revoked" /var/log/openvpn-revoke-fail.log; then
			echo "Connection correctly rejected (certificate revoked)"
			CONNECT_FAILED=true
			break
		fi
	fi

	echo "Checking connection status... ($WAITED/$MAX_WAIT seconds)"
	if [ -f /var/log/openvpn-revoke-fail.log ]; then
		tail -3 /var/log/openvpn-revoke-fail.log
	fi
done

# Kill any remaining openvpn process
pkill openvpn 2>/dev/null || true
sleep 1

# Even if we didn't see explicit error, verify tun0 is not up
if ip addr show tun0 2>/dev/null | grep -q "inet "; then
	echo "FAIL: tun0 interface exists - revoked cert may have connected"
	exit 1
fi

if [ "$CONNECT_FAILED" = true ]; then
	echo "PASS: Connection with revoked certificate was correctly rejected"
else
	echo "PASS: Connection with revoked certificate did not succeed (no tun0)"
	echo "OpenVPN log:"
	cat /var/log/openvpn-revoke-fail.log || true
fi

# Signal server that reconnect with revoked cert failed
touch /shared/revoke-reconnect-failed

# =====================================================
# Test connecting with new certificate (same name)
# =====================================================
echo ""
echo "=== Testing connection with recreated certificate ==="

# Wait for server to create new cert and signal us
echo "Waiting for new client config with same name..."
MAX_WAIT=120
WAITED=0
while [ ! -f /shared/new-client-config-ready ] && [ $WAITED -lt $MAX_WAIT ]; do
	sleep 2
	WAITED=$((WAITED + 2))
	echo "Waiting for new config... ($WAITED/$MAX_WAIT seconds)"
done

if [ ! -f /shared/new-client-config-ready ]; then
	echo "FAIL: New client config not ready in time"
	exit 1
fi

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
MAX_WAIT=60
WAITED=0
while ! ip addr show tun0 2>/dev/null | grep -q "inet " && [ $WAITED -lt $MAX_WAIT ]; do
	sleep 2
	WAITED=$((WAITED + 2))
	echo "Waiting for tun0... ($WAITED/$MAX_WAIT seconds)"
	if [ -f /var/log/openvpn-new.log ]; then
		tail -3 /var/log/openvpn-new.log
	fi
done

if ! ip addr show tun0 2>/dev/null | grep -q "inet "; then
	echo "FAIL: VPN connection with new certificate failed"
	cat /var/log/openvpn-new.log || true
	exit 1
fi

echo "PASS: Connected with new '$REVOKE_CLIENT' certificate"
ip addr show tun0

# Verify connectivity
if ping -c 2 "$VPN_GATEWAY" >/dev/null 2>&1; then
	echo "PASS: Can ping VPN gateway with new certificate"
else
	echo "FAIL: Cannot ping VPN gateway with new certificate"
	exit 1
fi

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
MAX_WAIT=120
WAITED=0
while [ ! -f /shared/passphrase-client-config-ready ] && [ $WAITED -lt $MAX_WAIT ]; do
	sleep 2
	WAITED=$((WAITED + 2))
	echo "Waiting for passphrase test config... ($WAITED/$MAX_WAIT seconds)"
done

if [ ! -f /shared/passphrase-client-config-ready ]; then
	echo "FAIL: Passphrase test client config not ready in time"
	exit 1
fi

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
MAX_WAIT=60
WAITED=0
while ! ip addr show tun0 2>/dev/null | grep -q "inet " && [ $WAITED -lt $MAX_WAIT ]; do
	sleep 2
	WAITED=$((WAITED + 2))
	echo "Waiting for tun0... ($WAITED/$MAX_WAIT seconds)"
	if [ -f /var/log/openvpn-passphrase.log ]; then
		tail -3 /var/log/openvpn-passphrase.log
	fi
done

if ! ip addr show tun0 2>/dev/null | grep -q "inet "; then
	echo "FAIL: VPN connection with passphrase-protected client failed"
	cat /var/log/openvpn-passphrase.log || true
	exit 1
fi

echo "PASS: Connected with passphrase-protected '$PASSPHRASE_CLIENT' certificate"
ip addr show tun0

# Verify connectivity
if ping -c 2 "$VPN_GATEWAY" >/dev/null 2>&1; then
	echo "PASS: Can ping VPN gateway with passphrase-protected client"
else
	echo "FAIL: Cannot ping VPN gateway with passphrase-protected client"
	exit 1
fi

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
