#!/bin/bash
set -e

echo "=== OpenVPN Server Container ==="

# Create TUN device if it doesn't exist
if [ ! -c /dev/net/tun ]; then
	mkdir -p /dev/net
	mknod /dev/net/tun c 10 200
	chmod 600 /dev/net/tun
fi

echo "TUN device ready"

# Set up environment for auto-install
export AUTO_INSTALL=y
export APPROVE_INSTALL=y
export APPROVE_IP=y
export IPV6_SUPPORT=n
export PORT_CHOICE=1
export PROTOCOL_CHOICE=1
export DNS=9 # Google DNS (works in containers)
export COMPRESSION_ENABLED=n
export CUSTOMIZE_ENC=n
export CLIENT=testclient
export PASS=1
export ENDPOINT=openvpn-server

# Prepare script for container environment:
# - Replace systemctl calls with no-ops (systemd doesn't work in containers)
# This ensures the script won't fail silently on systemctl commands
sed 's/\bsystemctl /echo "[SKIPPED] systemctl " # /g' /opt/openvpn-install.sh >/tmp/openvpn-install.sh
chmod +x /tmp/openvpn-install.sh

echo "Running OpenVPN install script..."
# Run in subshell because the script calls 'exit 0' after generating client config
# Use || true to prevent set -e from exiting on failure, then check exit code
(bash -x /tmp/openvpn-install.sh) && INSTALL_EXIT_CODE=0 || INSTALL_EXIT_CODE=$?

echo "=== Installation complete (exit code: $INSTALL_EXIT_CODE) ==="

if [ "$INSTALL_EXIT_CODE" -ne 0 ]; then
	echo "ERROR: Install script failed with exit code $INSTALL_EXIT_CODE"
	exit 1
fi

# Verify all expected files were created
echo "Verifying installation..."
MISSING_FILES=0
for f in \
	/etc/openvpn/server.conf \
	/etc/openvpn/ca.crt \
	/etc/openvpn/ca.key \
	/etc/openvpn/tls-crypt.key \
	/etc/openvpn/crl.pem \
	/etc/openvpn/easy-rsa/pki/ca.crt \
	/etc/iptables/add-openvpn-rules.sh \
	/root/testclient.ovpn; do
	if [ ! -f "$f" ]; then
		echo "ERROR: Missing file: $f"
		MISSING_FILES=$((MISSING_FILES + 1))
	fi
done

if [ $MISSING_FILES -gt 0 ]; then
	echo "ERROR: $MISSING_FILES required files are missing"
	exit 1
fi

echo "All required files present"
echo ""
echo "Server config:"
cat /etc/openvpn/server.conf

# Copy client config to shared volume
cp /root/testclient.ovpn /shared/client.ovpn
# Modify remote address to use container hostname
sed -i 's/^remote .*/remote openvpn-server 1194/' /shared/client.ovpn
echo "Client config copied to /shared/client.ovpn"

# Start OpenVPN server manually (systemd doesn't work in containers)
echo "Starting OpenVPN server..."

# Apply iptables rules manually (systemd not available in containers)
echo "Applying iptables rules..."
bash /etc/iptables/add-openvpn-rules.sh

# Verify iptables NAT rules exist
echo "Verifying iptables NAT rules..."
if iptables -t nat -L POSTROUTING -n | grep -q "10.8.0.0"; then
	echo "PASS: NAT POSTROUTING rule for 10.8.0.0/24 exists"
else
	echo "FAIL: NAT POSTROUTING rule for 10.8.0.0/24 not found"
	echo "Current NAT rules:"
	iptables -t nat -L POSTROUTING -n -v
	exit 1
fi

# Enable IP forwarding (may already be set via docker-compose sysctls)
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
	echo 1 >/proc/sys/net/ipv4/ip_forward || {
		echo "ERROR: Failed to enable IP forwarding"
		exit 1
	}
fi

# Start OpenVPN in foreground (run from /etc/openvpn so relative paths work)
cd /etc/openvpn
exec openvpn --config /etc/openvpn/server.conf
