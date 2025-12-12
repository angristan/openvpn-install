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
export DNS=2 # Self-hosted Unbound DNS resolver
export COMPRESSION_ENABLED=n
export CUSTOMIZE_ENC=n
export CLIENT=testclient
export PASS=1
export ENDPOINT=openvpn-server

# Prepare script for container environment:
# - Replace systemctl calls with no-ops (systemd doesn't work in containers)
# - Skip Unbound startup validation (we start Unbound manually later)
# This ensures the script won't fail silently on systemctl commands
sed -e 's/\bsystemctl /echo "[SKIPPED] systemctl " # /g' \
	-e 's/log_fatal "Unbound failed to start/return 0 # [SKIPPED] /g' \
	/opt/openvpn-install.sh >/tmp/openvpn-install.sh
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
	/etc/openvpn/server/server.conf \
	/etc/openvpn/server/ca.crt \
	/etc/openvpn/server/ca.key \
	/etc/openvpn/server/tls-crypt.key \
	/etc/openvpn/server/crl.pem \
	/etc/openvpn/server/easy-rsa/pki/ca.crt \
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

# =====================================================
# Verify systemd service file configuration
# =====================================================
echo ""
echo "=== Verifying systemd service configuration ==="

# Check that the correct service file was created
SERVICE_FILE="/etc/systemd/system/openvpn-server@.service"
if [ -f "$SERVICE_FILE" ]; then
	echo "PASS: openvpn-server@.service exists at $SERVICE_FILE"
else
	echo "FAIL: openvpn-server@.service not found at $SERVICE_FILE"
	echo "Contents of /etc/systemd/system/:"
	find /etc/systemd/system/ -maxdepth 1 -name '*openvpn*' -ls 2>/dev/null || echo "No openvpn service files found"
	exit 1
fi

# Verify the service file points to /etc/openvpn/server/ (not patched back to /etc/openvpn/)
if grep -q "/etc/openvpn/server" "$SERVICE_FILE"; then
	echo "PASS: Service file uses correct path /etc/openvpn/server/"
else
	echo "FAIL: Service file does not reference /etc/openvpn/server/"
	echo "Service file contents:"
	cat "$SERVICE_FILE"
	exit 1
fi

# Verify the service file syntax is valid (if systemd-analyze is available)
if command -v systemd-analyze >/dev/null 2>&1; then
	echo "Validating service file syntax..."
	if systemd-analyze verify "$SERVICE_FILE" 2>&1 | tee /tmp/service-verify.log; then
		echo "PASS: Service file syntax is valid"
	else
		# systemd-analyze verify may return non-zero for warnings, check for actual errors
		if grep -qi "error" /tmp/service-verify.log; then
			echo "FAIL: Service file has syntax errors"
			cat /tmp/service-verify.log
			exit 1
		else
			echo "PASS: Service file syntax is valid (warnings only)"
		fi
	fi
else
	echo "SKIP: systemd-analyze not available, skipping syntax validation"
fi

# Verify the old service file pattern (openvpn@.service) was NOT created
OLD_SERVICE_FILE="/etc/systemd/system/openvpn@.service"
if [ -f "$OLD_SERVICE_FILE" ]; then
	echo "FAIL: Legacy openvpn@.service was created (should use openvpn-server@.service)"
	exit 1
else
	echo "PASS: Legacy openvpn@.service not present (correct)"
fi

echo "=== systemd service configuration verified ==="
echo ""
echo "Server config:"
cat /etc/openvpn/server/server.conf

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
ORIG_CERT_SERIAL=$(openssl x509 -in /etc/openvpn/server/easy-rsa/pki/issued/testclient.crt -noout -serial | cut -d= -f2)
echo "Original client certificate serial: $ORIG_CERT_SERIAL"

# Test client certificate renewal using the script
echo "Testing client certificate renewal..."
RENEW_OUTPUT="/tmp/renew-client-output.log"
(MENU_OPTION=3 RENEW_OPTION=1 CLIENTNUMBER=1 CLIENT_CERT_DURATION_DAYS=3650 bash /tmp/openvpn-install.sh) 2>&1 | tee "$RENEW_OUTPUT" || true

# Verify renewal succeeded
if grep -q "Certificate for client testclient renewed" "$RENEW_OUTPUT"; then
	echo "PASS: Client renewal completed successfully"
else
	echo "FAIL: Client renewal did not complete"
	cat "$RENEW_OUTPUT"
	exit 1
fi

# Verify new certificate has different serial
NEW_CERT_SERIAL=$(openssl x509 -in /etc/openvpn/server/easy-rsa/pki/issued/testclient.crt -noout -serial | cut -d= -f2)
echo "New client certificate serial: $NEW_CERT_SERIAL"
if [ "$ORIG_CERT_SERIAL" != "$NEW_CERT_SERIAL" ]; then
	echo "PASS: Certificate serial changed (renewal created new cert)"
else
	echo "FAIL: Certificate serial unchanged"
	exit 1
fi

# Verify renewed certificate has correct validity period
# The default is 3650 days, so the cert should be valid for ~10 years from now
CLIENT_CERT_NOT_AFTER=$(openssl x509 -in /etc/openvpn/server/easy-rsa/pki/issued/testclient.crt -noout -enddate | cut -d= -f2)
CLIENT_CERT_NOT_BEFORE=$(openssl x509 -in /etc/openvpn/server/easy-rsa/pki/issued/testclient.crt -noout -startdate | cut -d= -f2)
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
if [ -f /etc/openvpn/server/crl.pem ]; then
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

# Get server certificate name and original serial (extract basename since path may be relative)
SERVER_NAME=$(basename "$(grep '^cert ' /etc/openvpn/server/server.conf | cut -d ' ' -f 2)" .crt)
ORIG_SERVER_SERIAL=$(openssl x509 -in "/etc/openvpn/server/easy-rsa/pki/issued/$SERVER_NAME.crt" -noout -serial | cut -d= -f2)
echo "Server certificate: $SERVER_NAME"
echo "Original server certificate serial: $ORIG_SERVER_SERIAL"

# Test server certificate renewal
echo "Testing server certificate renewal..."
RENEW_SERVER_OUTPUT="/tmp/renew-server-output.log"
(MENU_OPTION=3 RENEW_OPTION=2 CONTINUE=y SERVER_CERT_DURATION_DAYS=3650 bash /tmp/openvpn-install.sh) 2>&1 | tee "$RENEW_SERVER_OUTPUT" || true

# Verify renewal succeeded
if grep -q "Server certificate renewed successfully" "$RENEW_SERVER_OUTPUT"; then
	echo "PASS: Server renewal completed successfully"
else
	echo "FAIL: Server renewal did not complete"
	cat "$RENEW_SERVER_OUTPUT"
	exit 1
fi

# Verify new certificate has different serial
NEW_SERVER_SERIAL=$(openssl x509 -in "/etc/openvpn/server/easy-rsa/pki/issued/$SERVER_NAME.crt" -noout -serial | cut -d= -f2)
echo "New server certificate serial: $NEW_SERVER_SERIAL"
if [ "$ORIG_SERVER_SERIAL" != "$NEW_SERVER_SERIAL" ]; then
	echo "PASS: Server certificate serial changed (renewal created new cert)"
else
	echo "FAIL: Server certificate serial unchanged"
	exit 1
fi

# Verify renewed server certificate has correct validity period
SERVER_CERT_NOT_AFTER=$(openssl x509 -in "/etc/openvpn/server/easy-rsa/pki/issued/$SERVER_NAME.crt" -noout -enddate | cut -d= -f2)
SERVER_CERT_NOT_BEFORE=$(openssl x509 -in "/etc/openvpn/server/easy-rsa/pki/issued/$SERVER_NAME.crt" -noout -startdate | cut -d= -f2)
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

# Verify the new certificate was copied to /etc/openvpn/server/
if [ -f "/etc/openvpn/server/$SERVER_NAME.crt" ]; then
	DEPLOYED_SERIAL=$(openssl x509 -in "/etc/openvpn/server/$SERVER_NAME.crt" -noout -serial | cut -d= -f2)
	if [ "$NEW_SERVER_SERIAL" = "$DEPLOYED_SERIAL" ]; then
		echo "PASS: New server certificate deployed to /etc/openvpn/server/"
	else
		echo "FAIL: Deployed certificate doesn't match renewed certificate"
		exit 1
	fi
else
	echo "FAIL: Server certificate not found in /etc/openvpn/server/"
	exit 1
fi

echo "=== Server Certificate Renewal Tests PASSED ==="
echo ""
echo "=== All Certificate Renewal Tests PASSED ==="
echo ""

# =====================================================
# Start and verify Unbound DNS resolver
# =====================================================
echo "=== Starting Unbound DNS Resolver ==="

# Start Unbound manually (systemctl commands are no-ops in container)
if [ -f /etc/unbound/unbound.conf ]; then
	echo "Starting Unbound DNS resolver..."

	# Create root key for DNSSEC if it doesn't exist
	# Normally, unbound.service's ExecStartPre copies /usr/share/dns/root.key to /var/lib/unbound/root.key
	# In Docker, policy-rc.d blocks service starts during apt install, so this never happens
	if [ ! -f /var/lib/unbound/root.key ] && [ -f /usr/share/dns/root.key ]; then
		mkdir -p /var/lib/unbound
		cp /usr/share/dns/root.key /var/lib/unbound/root.key
		chown -R unbound:unbound /var/lib/unbound 2>/dev/null || true
	fi

	unbound
	# Poll up to 10 seconds for Unbound to start
	for _ in $(seq 1 10); do
		if pgrep -x unbound >/dev/null; then
			echo "PASS: Unbound is running"
			break
		fi
		sleep 1
	done
	if ! pgrep -x unbound >/dev/null; then
		echo "FAIL: Unbound failed to start"
		# Show debug info
		unbound-checkconf /etc/unbound/unbound.conf 2>&1 || true
		exit 1
	fi
else
	echo "FAIL: /etc/unbound/unbound.conf not found"
	exit 1
fi

echo ""
echo "=== Verifying Unbound Installation ==="

# Verify Unbound config exists in conf.d directory
UNBOUND_OPENVPN_CONF="/etc/unbound/unbound.conf.d/openvpn.conf"
if [ -f "$UNBOUND_OPENVPN_CONF" ]; then
	echo "PASS: Found Unbound config at $UNBOUND_OPENVPN_CONF"
else
	echo "FAIL: OpenVPN Unbound config not found at $UNBOUND_OPENVPN_CONF"
	echo "Contents of /etc/unbound/:"
	ls -la /etc/unbound/
	ls -la /etc/unbound/unbound.conf.d/ 2>/dev/null || true
	exit 1
fi

# Verify Unbound listens on VPN gateway
if grep -q "interface: 10.8.0.1" "$UNBOUND_OPENVPN_CONF"; then
	echo "PASS: Unbound configured to listen on 10.8.0.1"
else
	echo "FAIL: Unbound not configured for 10.8.0.1"
	cat "$UNBOUND_OPENVPN_CONF"
	exit 1
fi

# Verify OpenVPN pushes correct DNS
if grep -q 'push "dhcp-option DNS 10.8.0.1"' /etc/openvpn/server/server.conf; then
	echo "PASS: OpenVPN configured to push Unbound DNS"
else
	echo "FAIL: OpenVPN not configured to push Unbound DNS"
	grep "dhcp-option DNS" /etc/openvpn/server/server.conf || echo "No DNS push found"
	exit 1
fi

echo "=== Unbound Installation Verified ==="
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

# Start OpenVPN in background (run from /etc/openvpn/server so relative paths work)
cd /etc/openvpn/server
openvpn --config /etc/openvpn/server/server.conf --log /var/log/openvpn-server.log &
OPENVPN_PID=$!

# Wait for OpenVPN to start
echo "Waiting for OpenVPN server to start..."
for _ in $(seq 1 30); do
	if pgrep -f "openvpn --config" >/dev/null; then
		echo "OpenVPN server started (PID: $OPENVPN_PID)"
		break
	fi
	sleep 1
done

if ! pgrep -f "openvpn --config" >/dev/null; then
	echo "FAIL: OpenVPN server failed to start"
	cat /var/log/openvpn-server.log || true
	exit 1
fi

# =====================================================
# Wait for initial client tests to complete
# =====================================================
echo ""
echo "=== Waiting for initial client connectivity tests ==="
MAX_WAIT=120
WAITED=0
while [ ! -f /shared/initial-tests-passed ] && [ $WAITED -lt $MAX_WAIT ]; do
	sleep 2
	WAITED=$((WAITED + 2))
	echo "Waiting for initial tests... ($WAITED/$MAX_WAIT seconds)"
done

if [ ! -f /shared/initial-tests-passed ]; then
	echo "ERROR: Initial client tests did not complete in time"
	exit 1
fi
echo "Initial client tests passed, proceeding with revocation tests"

# =====================================================
# Test certificate revocation functionality
# =====================================================
echo ""
echo "=== Testing Certificate Revocation ==="

# Create a new client for revocation testing
REVOKE_CLIENT="revoketest"
echo "Creating client '$REVOKE_CLIENT' for revocation testing..."
REVOKE_CREATE_OUTPUT="/tmp/revoke-create-output.log"
(MENU_OPTION=1 CLIENT=$REVOKE_CLIENT PASS=1 CLIENT_CERT_DURATION_DAYS=3650 bash /tmp/openvpn-install.sh) 2>&1 | tee "$REVOKE_CREATE_OUTPUT" || true

if [ -f "/root/$REVOKE_CLIENT.ovpn" ]; then
	echo "PASS: Client '$REVOKE_CLIENT' created successfully"
else
	echo "FAIL: Failed to create client '$REVOKE_CLIENT'"
	cat "$REVOKE_CREATE_OUTPUT"
	exit 1
fi

# Copy config for revocation test client
cp "/root/$REVOKE_CLIENT.ovpn" "/shared/$REVOKE_CLIENT.ovpn"
sed -i 's/^remote .*/remote openvpn-server 1194/' "/shared/$REVOKE_CLIENT.ovpn"
echo "Copied $REVOKE_CLIENT config to /shared/"

# Signal client that revoke test config is ready
touch /shared/revoke-client-config-ready

# Wait for client to confirm connection with revoke test client
echo "Waiting for client to connect with '$REVOKE_CLIENT' certificate..."
MAX_WAIT=60
WAITED=0
while [ ! -f /shared/revoke-client-connected ] && [ $WAITED -lt $MAX_WAIT ]; do
	sleep 2
	WAITED=$((WAITED + 2))
	echo "Waiting for revoke test connection... ($WAITED/$MAX_WAIT seconds)"
done

if [ ! -f /shared/revoke-client-connected ]; then
	echo "ERROR: Client did not connect with revoke test certificate"
	exit 1
fi
echo "PASS: Client connected with '$REVOKE_CLIENT' certificate"

# Signal client to disconnect before revocation
touch /shared/revoke-client-disconnect

# Wait for client to disconnect
echo "Waiting for client to disconnect..."
MAX_WAIT=30
WAITED=0
while [ ! -f /shared/revoke-client-disconnected ] && [ $WAITED -lt $MAX_WAIT ]; do
	sleep 2
	WAITED=$((WAITED + 2))
done

if [ ! -f /shared/revoke-client-disconnected ]; then
	echo "ERROR: Client did not signal disconnect"
	exit 1
fi
echo "Client disconnected"

# Now revoke the certificate
echo "Revoking certificate for '$REVOKE_CLIENT'..."
REVOKE_OUTPUT="/tmp/revoke-output.log"
# MENU_OPTION=2 is revoke, CLIENTNUMBER is dynamically determined from index.txt
# We need to find the client number for revoketest
REVOKE_CLIENT_NUM=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | grep -n "CN=$REVOKE_CLIENT\$" | cut -d: -f1)
if [ -z "$REVOKE_CLIENT_NUM" ]; then
	echo "ERROR: Could not find client number for '$REVOKE_CLIENT'"
	cat /etc/openvpn/server/easy-rsa/pki/index.txt
	exit 1
fi
echo "Revoke client number: $REVOKE_CLIENT_NUM"
(MENU_OPTION=2 CLIENTNUMBER=$REVOKE_CLIENT_NUM bash /tmp/openvpn-install.sh) 2>&1 | tee "$REVOKE_OUTPUT" || true

if grep -q "Certificate for client $REVOKE_CLIENT revoked" "$REVOKE_OUTPUT"; then
	echo "PASS: Certificate for '$REVOKE_CLIENT' revoked successfully"
else
	echo "FAIL: Failed to revoke certificate"
	cat "$REVOKE_OUTPUT"
	exit 1
fi

# Verify certificate is marked as revoked in index.txt
if tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -q "^R.*CN=$REVOKE_CLIENT\$"; then
	echo "PASS: Certificate marked as revoked in index.txt"
else
	echo "FAIL: Certificate not marked as revoked"
	cat /etc/openvpn/server/easy-rsa/pki/index.txt
	exit 1
fi

# Signal client to try reconnecting (should fail)
touch /shared/revoke-try-reconnect

# Wait for client to confirm that connection with revoked cert failed
echo "Waiting for client to confirm revoked cert connection failure..."
MAX_WAIT=60
WAITED=0
while [ ! -f /shared/revoke-reconnect-failed ] && [ $WAITED -lt $MAX_WAIT ]; do
	sleep 2
	WAITED=$((WAITED + 2))
	echo "Waiting for reconnect failure confirmation... ($WAITED/$MAX_WAIT seconds)"
done

if [ ! -f /shared/revoke-reconnect-failed ]; then
	echo "ERROR: Client did not confirm that revoked cert connection failed"
	exit 1
fi
echo "PASS: Connection with revoked certificate correctly rejected"

echo "=== Certificate Revocation Tests PASSED ==="

# =====================================================
# Test reusing revoked client name
# =====================================================
echo ""
echo "=== Testing Reuse of Revoked Client Name ==="

# Create a new certificate with the same name as the revoked one
echo "Creating new client with same name '$REVOKE_CLIENT'..."
RECREATE_OUTPUT="/tmp/recreate-output.log"
(MENU_OPTION=1 CLIENT=$REVOKE_CLIENT PASS=1 CLIENT_CERT_DURATION_DAYS=3650 bash /tmp/openvpn-install.sh) 2>&1 | tee "$RECREATE_OUTPUT" || true

if [ -f "/root/$REVOKE_CLIENT.ovpn" ]; then
	echo "PASS: New client '$REVOKE_CLIENT' created successfully (reusing revoked name)"
else
	echo "FAIL: Failed to create client with revoked name"
	cat "$RECREATE_OUTPUT"
	exit 1
fi

# Verify the new certificate is valid (V) in index.txt
if tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -q "^V.*CN=$REVOKE_CLIENT\$"; then
	echo "PASS: New certificate is valid in index.txt"
else
	echo "FAIL: New certificate not marked as valid"
	cat /etc/openvpn/server/easy-rsa/pki/index.txt
	exit 1
fi

# Verify there's also a revoked entry (both should exist)
REVOKED_COUNT=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^R.*CN=$REVOKE_CLIENT\$")
VALID_COUNT=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V.*CN=$REVOKE_CLIENT\$")
echo "Certificates for '$REVOKE_CLIENT': $REVOKED_COUNT revoked, $VALID_COUNT valid"
if [ "$REVOKED_COUNT" -ge 1 ] && [ "$VALID_COUNT" -eq 1 ]; then
	echo "PASS: Both revoked and new valid certificate entries exist"
else
	echo "FAIL: Unexpected certificate state"
	cat /etc/openvpn/server/easy-rsa/pki/index.txt
	exit 1
fi

# Copy the new config
cp "/root/$REVOKE_CLIENT.ovpn" "/shared/$REVOKE_CLIENT-new.ovpn"
sed -i 's/^remote .*/remote openvpn-server 1194/' "/shared/$REVOKE_CLIENT-new.ovpn"
echo "Copied new $REVOKE_CLIENT config to /shared/"

# Signal client that new config is ready
touch /shared/new-client-config-ready

# Wait for client to confirm successful connection with new cert
echo "Waiting for client to connect with new '$REVOKE_CLIENT' certificate..."
MAX_WAIT=60
WAITED=0
while [ ! -f /shared/new-client-connected ] && [ $WAITED -lt $MAX_WAIT ]; do
	sleep 2
	WAITED=$((WAITED + 2))
	echo "Waiting for new cert connection... ($WAITED/$MAX_WAIT seconds)"
done

if [ ! -f /shared/new-client-connected ]; then
	echo "ERROR: Client did not connect with new certificate"
	exit 1
fi
echo "PASS: Client connected with new '$REVOKE_CLIENT' certificate"

echo "=== Reuse of Revoked Client Name Tests PASSED ==="
echo ""
echo "=== All Revocation Tests PASSED ==="

# Keep server running for any remaining client tests
echo "Server waiting for client to complete all tests..."
wait $OPENVPN_PID
