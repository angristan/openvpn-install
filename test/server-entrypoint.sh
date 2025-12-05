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
export DNS=9  # Google DNS (works in containers)
export COMPRESSION_ENABLED=n
export CUSTOMIZE_ENC=n
export CLIENT=testclient
export PASS=1
export ENDPOINT=openvpn-server

echo "Running OpenVPN install script..."
# Note: The script exits with 0 after generating client config, so we ignore the exit code
bash -x /opt/openvpn-install.sh || true

echo "=== Installation complete ==="

# Check if OpenVPN config was created
if [ ! -f /etc/openvpn/server.conf ]; then
    echo "ERROR: server.conf not created"
    exit 1
fi

echo "Server config created successfully"
cat /etc/openvpn/server.conf

# Copy client config to shared volume
if [ -f /root/testclient.ovpn ]; then
    cp /root/testclient.ovpn /shared/client.ovpn
    # Modify remote address to use container hostname
    sed -i 's/^remote .*/remote openvpn-server 1194/' /shared/client.ovpn
    echo "Client config copied to /shared/client.ovpn"
else
    echo "ERROR: Client config not found"
    exit 1
fi

# Start OpenVPN server manually (systemd doesn't work in containers)
echo "Starting OpenVPN server..."

# Apply iptables rules manually
if [ -f /etc/iptables/add-openvpn-rules.sh ]; then
    bash /etc/iptables/add-openvpn-rules.sh || echo "Warning: iptables rules failed (may be fine in container)"
fi

# Enable IP forwarding (may already be set via docker-compose sysctls)
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "IP forwarding already enabled via sysctls"

# Start OpenVPN in foreground (run from /etc/openvpn so relative paths work)
cd /etc/openvpn
exec openvpn --config /etc/openvpn/server.conf
