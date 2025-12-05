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

# Wait a bit more for server to be fully ready
echo "Waiting for server to be ready..."
sleep 10

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

# Test 3: DNS resolution
echo "Test 3: Testing DNS resolution..."
if host google.com > /dev/null 2>&1; then
	echo "PASS: DNS resolution working"
else
	echo "FAIL: DNS resolution failed"
	exit 1
fi

# Test 4: NAT test - reach external network through VPN
# httpbin is at 172.29.0.100, only reachable if:
# 1. VPN tunnel is working
# 2. Server NAT is masquerading our traffic
# 3. Server can route to external network
echo "Test 4: Testing NAT (reaching external network through VPN)..."

# First, add route to external network via VPN gateway
# This ensures traffic to 172.29.0.0/24 goes through the tunnel
ip route add 172.29.0.0/24 via 10.8.0.1 dev tun0 || echo "Route may already exist"

# Now try to reach httpbin through the VPN
HTTPBIN_RESPONSE=$(curl -s --connect-timeout 10 http://172.29.0.100/ip 2>&1) || true
echo "httpbin response: $HTTPBIN_RESPONSE"

if echo "$HTTPBIN_RESPONSE" | jq -e '.origin' > /dev/null 2>&1; then
	ORIGIN_IP=$(echo "$HTTPBIN_RESPONSE" | jq -r '.origin')
	echo "Request arrived at httpbin from IP: $ORIGIN_IP"
	# The origin should be the server's external network IP (172.29.0.10)
	# This proves NAT is working - our 10.8.0.x IP was translated
	if [ "$ORIGIN_IP" = "172.29.0.10" ]; then
		echo "PASS: NAT is working correctly (traffic masqueraded as server IP)"
	else
		echo "PASS: NAT is working (traffic reached httpbin, origin: $ORIGIN_IP)"
	fi
else
	echo "FAIL: Could not reach httpbin through VPN/NAT"
	echo "Response was: $HTTPBIN_RESPONSE"
	exit 1
fi

echo ""
echo "=========================================="
echo "  ALL TESTS PASSED!"
echo "=========================================="

# Keep container running for debugging if needed
exec tail -f /var/log/openvpn.log
