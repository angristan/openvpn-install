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
if ip addr show tun0 | grep -q "10.8.0"; then
	echo "PASS: tun0 interface has correct IP range (10.8.0.x)"
else
	echo "FAIL: tun0 interface doesn't have expected IP"
	exit 1
fi

# Test 2: Ping VPN gateway
echo "Test 2: Pinging VPN gateway (10.8.0.1)..."
if ping -c 3 10.8.0.1; then
	echo "PASS: Can ping VPN gateway"
else
	echo "FAIL: Cannot ping VPN gateway"
	exit 1
fi

# Test 3: DNS resolution through Unbound
echo "Test 3: Testing DNS resolution via Unbound (10.8.0.1)..."
DNS_SUCCESS=false
for i in 1 2 3; do
	if dig @10.8.0.1 example.com +short +time=5 >/dev/null 2>&1; then
		DNS_SUCCESS=true
		break
	fi
	echo "DNS attempt $i failed, retrying..."
	sleep 2
done
if [ "$DNS_SUCCESS" = true ]; then
	echo "PASS: DNS resolution through Unbound works"
	echo "Resolved example.com to: $(dig @10.8.0.1 example.com +short +time=5)"
else
	echo "FAIL: DNS resolution through Unbound failed after 3 attempts"
	dig @10.8.0.1 example.com +time=5 || true
	exit 1
fi

echo ""
echo "=========================================="
echo "  ALL TESTS PASSED!"
echo "=========================================="

# Keep container running for debugging if needed
exec tail -f /var/log/openvpn.log
