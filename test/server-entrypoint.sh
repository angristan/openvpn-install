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
export FORCE_COLOR=1
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
# Capture output to validate logging format, while still displaying it
# Use || true to prevent set -e from exiting on failure, then check exit code
INSTALL_OUTPUT="/tmp/install-output.log"
(bash /tmp/openvpn-install.sh) 2>&1 | tee "$INSTALL_OUTPUT"
INSTALL_EXIT_CODE=${PIPESTATUS[0]}

echo "=== Installation complete (exit code: $INSTALL_EXIT_CODE) ==="

# Validate that all output uses proper logging format (ANSI color codes)
echo "Validating output format..."
if /opt/test/validate-output.sh "$INSTALL_OUTPUT"; then
	echo "PASS: All script output uses proper log formatting"
else
	echo "FAIL: Script output contains unformatted lines"
	echo "This indicates echo statements that should use log_* functions"
	exit 1
fi

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

# =====================================================
# Test certificate renewal functionality
# =====================================================
echo ""
echo "=== Testing Certificate Renewal ==="

# Get the original certificate serial number for comparison
ORIG_CERT_SERIAL=$(openssl x509 -in /etc/openvpn/easy-rsa/pki/issued/testclient.crt -noout -serial | cut -d= -f2)
echo "Original client certificate serial: $ORIG_CERT_SERIAL"

# Test client certificate renewal using the script
echo "Testing client certificate renewal..."
RENEW_OUTPUT="/tmp/renew-client-output.log"
(MENU_OPTION=3 RENEW_OPTION=1 CLIENTNUMBER=1 bash /tmp/openvpn-install.sh) 2>&1 | tee "$RENEW_OUTPUT" || true

# Verify renewal succeeded
if grep -q "Certificate for client testclient renewed" "$RENEW_OUTPUT"; then
	echo "PASS: Client renewal completed successfully"
else
	echo "FAIL: Client renewal did not complete"
	cat "$RENEW_OUTPUT"
	exit 1
fi

# Verify new certificate has different serial
NEW_CERT_SERIAL=$(openssl x509 -in /etc/openvpn/easy-rsa/pki/issued/testclient.crt -noout -serial | cut -d= -f2)
echo "New client certificate serial: $NEW_CERT_SERIAL"
if [ "$ORIG_CERT_SERIAL" != "$NEW_CERT_SERIAL" ]; then
	echo "PASS: Certificate serial changed (renewal created new cert)"
else
	echo "FAIL: Certificate serial unchanged"
	exit 1
fi

# Verify renewed certificate has correct validity period
# The default is 3650 days, so the cert should be valid for ~10 years from now
CLIENT_CERT_NOT_AFTER=$(openssl x509 -in /etc/openvpn/easy-rsa/pki/issued/testclient.crt -noout -enddate | cut -d= -f2)
CLIENT_CERT_NOT_BEFORE=$(openssl x509 -in /etc/openvpn/easy-rsa/pki/issued/testclient.crt -noout -startdate | cut -d= -f2)
echo "Client certificate valid from: $CLIENT_CERT_NOT_BEFORE"
echo "Client certificate valid until: $CLIENT_CERT_NOT_AFTER"

# Calculate days until expiry (should be close to 3650)
CERT_END_EPOCH=$(date -d "$CLIENT_CERT_NOT_AFTER" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$CLIENT_CERT_NOT_AFTER" +%s 2>/dev/null)
NOW_EPOCH=$(date +%s)
DAYS_VALID_ACTUAL=$(((CERT_END_EPOCH - NOW_EPOCH) / 86400))
echo "Client certificate validity: $DAYS_VALID_ACTUAL days"

# Should be between 3640 and 3650 days (allowing some tolerance for timing)
if [ "$DAYS_VALID_ACTUAL" -ge 3640 ] && [ "$DAYS_VALID_ACTUAL" -le 3650 ]; then
	echo "PASS: Client certificate validity is correct (~3650 days)"
else
	echo "FAIL: Client certificate validity is unexpected: $DAYS_VALID_ACTUAL days (expected ~3650)"
	exit 1
fi

# Verify new .ovpn file was generated
if [ -f /root/testclient.ovpn ]; then
	echo "PASS: New .ovpn file generated"
else
	echo "FAIL: .ovpn file not found after renewal"
	exit 1
fi

# Verify CRL was updated
if [ -f /etc/openvpn/crl.pem ]; then
	echo "PASS: CRL file exists"
else
	echo "FAIL: CRL file missing after renewal"
	exit 1
fi

# Update shared client config with renewed certificate
cp /root/testclient.ovpn /shared/client.ovpn
sed -i 's/^remote .*/remote openvpn-server 1194/' /shared/client.ovpn
echo "Updated client config with renewed certificate"

echo "=== Client Certificate Renewal Tests PASSED ==="

# =====================================================
# Test server certificate renewal
# =====================================================
echo ""
echo "=== Testing Server Certificate Renewal ==="

# Get server certificate name and original serial
SERVER_NAME=$(grep '^cert ' /etc/openvpn/server.conf | cut -d ' ' -f 2 | sed 's/\.crt$//')
ORIG_SERVER_SERIAL=$(openssl x509 -in "/etc/openvpn/easy-rsa/pki/issued/$SERVER_NAME.crt" -noout -serial | cut -d= -f2)
echo "Server certificate: $SERVER_NAME"
echo "Original server certificate serial: $ORIG_SERVER_SERIAL"

# Test server certificate renewal
echo "Testing server certificate renewal..."
RENEW_SERVER_OUTPUT="/tmp/renew-server-output.log"
(MENU_OPTION=3 RENEW_OPTION=2 CONTINUE=y bash /tmp/openvpn-install.sh) 2>&1 | tee "$RENEW_SERVER_OUTPUT" || true

# Verify renewal succeeded
if grep -q "Server certificate renewed successfully" "$RENEW_SERVER_OUTPUT"; then
	echo "PASS: Server renewal completed successfully"
else
	echo "FAIL: Server renewal did not complete"
	cat "$RENEW_SERVER_OUTPUT"
	exit 1
fi

# Verify new certificate has different serial
NEW_SERVER_SERIAL=$(openssl x509 -in "/etc/openvpn/easy-rsa/pki/issued/$SERVER_NAME.crt" -noout -serial | cut -d= -f2)
echo "New server certificate serial: $NEW_SERVER_SERIAL"
if [ "$ORIG_SERVER_SERIAL" != "$NEW_SERVER_SERIAL" ]; then
	echo "PASS: Server certificate serial changed (renewal created new cert)"
else
	echo "FAIL: Server certificate serial unchanged"
	exit 1
fi

# Verify renewed server certificate has correct validity period
SERVER_CERT_NOT_AFTER=$(openssl x509 -in "/etc/openvpn/easy-rsa/pki/issued/$SERVER_NAME.crt" -noout -enddate | cut -d= -f2)
SERVER_CERT_NOT_BEFORE=$(openssl x509 -in "/etc/openvpn/easy-rsa/pki/issued/$SERVER_NAME.crt" -noout -startdate | cut -d= -f2)
echo "Server certificate valid from: $SERVER_CERT_NOT_BEFORE"
echo "Server certificate valid until: $SERVER_CERT_NOT_AFTER"

# Calculate days until expiry (should be close to 3650)
SERVER_END_EPOCH=$(date -d "$SERVER_CERT_NOT_AFTER" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$SERVER_CERT_NOT_AFTER" +%s 2>/dev/null)
SERVER_DAYS_VALID=$(((SERVER_END_EPOCH - NOW_EPOCH) / 86400))
echo "Server certificate validity: $SERVER_DAYS_VALID days"

if [ "$SERVER_DAYS_VALID" -ge 3640 ] && [ "$SERVER_DAYS_VALID" -le 3650 ]; then
	echo "PASS: Server certificate validity is correct (~3650 days)"
else
	echo "FAIL: Server certificate validity is unexpected: $SERVER_DAYS_VALID days (expected ~3650)"
	exit 1
fi

# Verify the new certificate was copied to /etc/openvpn/
if [ -f "/etc/openvpn/$SERVER_NAME.crt" ]; then
	DEPLOYED_SERIAL=$(openssl x509 -in "/etc/openvpn/$SERVER_NAME.crt" -noout -serial | cut -d= -f2)
	if [ "$NEW_SERVER_SERIAL" = "$DEPLOYED_SERIAL" ]; then
		echo "PASS: New server certificate deployed to /etc/openvpn/"
	else
		echo "FAIL: Deployed certificate doesn't match renewed certificate"
		exit 1
	fi
else
	echo "FAIL: Server certificate not found in /etc/openvpn/"
	exit 1
fi

echo "=== Server Certificate Renewal Tests PASSED ==="
echo ""
echo "=== All Certificate Renewal Tests PASSED ==="
echo ""

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
