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

# Configuration for install
export FORCE_COLOR=1
VPN_SUBNET_IPV4=10.9.0.0 # Custom subnet to test configurability

# Calculate VPN gateway from subnet (first usable IP)
VPN_GATEWAY="${VPN_SUBNET_IPV4%.*}.1"
export VPN_GATEWAY

# IPv6 configuration (optional)
# CLIENT_IPV6: y/n to enable IPv6 for VPN clients
# VPN_SUBNET_IPV6: IPv6 subnet (ULA prefix, e.g., fd42:42:42:42::)
CLIENT_IPV6="${CLIENT_IPV6:-n}"
VPN_SUBNET_IPV6="${VPN_SUBNET_IPV6:-fd42:42:42:42::}"

# Calculate IPv6 gateway from subnet
VPN_GATEWAY_IPV6="${VPN_SUBNET_IPV6}1"
export VPN_GATEWAY_IPV6

# TLS key type configuration (default: tls-crypt-v2)
# TLS_SIG: crypt-v2, crypt, auth
# TLS_KEY_FILE: the expected key file name for verification
TLS_SIG="${TLS_SIG:-crypt-v2}"
TLS_KEY_FILE="${TLS_KEY_FILE:-tls-crypt-v2.key}"

# TLS 1.3 configuration
# TLS_VERSION_MIN: 1.2 or 1.3
# TLS13_CIPHERSUITES: colon-separated list of TLS 1.3 cipher suites
TLS_VERSION_MIN="${TLS_VERSION_MIN:-1.2}"
TLS13_CIPHERSUITES="${TLS13_CIPHERSUITES:-TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256}"

# Authentication mode configuration
# AUTH_MODE: pki (default, CA-based) or fingerprint (peer-fingerprint, OpenVPN 2.6+)
AUTH_MODE="${AUTH_MODE:-pki}"

# Build install command with CLI flags (using array for proper quoting)
INSTALL_CMD=(/opt/openvpn-install.sh install)
INSTALL_CMD+=(--endpoint openvpn-server)
INSTALL_CMD+=(--dns unbound)
INSTALL_CMD+=(--subnet-ipv4 "$VPN_SUBNET_IPV4")
INSTALL_CMD+=(--mtu 1400)
INSTALL_CMD+=(--client testclient)

# Add IPv6 client support if enabled
if [ "$CLIENT_IPV6" = "y" ]; then
	INSTALL_CMD+=(--client-ipv6)
	INSTALL_CMD+=(--subnet-ipv6 "$VPN_SUBNET_IPV6")
	echo "Testing with IPv6 client support enabled (subnet: $VPN_SUBNET_IPV6)"
fi

# Add TLS signature mode if non-default
if [ "$TLS_SIG" != "crypt-v2" ]; then
	INSTALL_CMD+=(--tls-sig "$TLS_SIG")
	echo "Testing TLS key type: $TLS_SIG (key file: $TLS_KEY_FILE)"
fi

# Add TLS version if non-default
if [ "$TLS_VERSION_MIN" != "1.2" ]; then
	INSTALL_CMD+=(--tls-version-min "$TLS_VERSION_MIN")
	echo "Testing TLS version min: $TLS_VERSION_MIN"
fi

# Add TLS 1.3 ciphersuites if non-default
if [ "$TLS13_CIPHERSUITES" != "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256" ]; then
	INSTALL_CMD+=(--tls-ciphersuites "$TLS13_CIPHERSUITES")
	echo "Testing TLS 1.3 ciphersuites: $TLS13_CIPHERSUITES"
fi

# Add auth mode if non-default
if [ "$AUTH_MODE" != "pki" ]; then
	INSTALL_CMD+=(--auth-mode "$AUTH_MODE")
	echo "Testing authentication mode: $AUTH_MODE"
fi

echo "Running OpenVPN install script..."
echo "Command: ${INSTALL_CMD[*]}"
# Run in subshell because the script calls 'exit 0' after generating client config
# Capture output to validate logging format, while still displaying it
# Use || true to prevent set -e from exiting on failure, then check exit code
INSTALL_OUTPUT="/tmp/install-output.log"
("${INSTALL_CMD[@]}") 2>&1 | tee "$INSTALL_OUTPUT"
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
# Build list of required files based on auth mode
REQUIRED_FILES=(
	/etc/openvpn/server/server.conf
	"/etc/openvpn/server/$TLS_KEY_FILE"
	/root/testclient.ovpn
)
if [ "$AUTH_MODE" = "pki" ]; then
	# PKI mode requires CA and CRL files
	REQUIRED_FILES+=(
		/etc/openvpn/server/ca.crt
		/etc/openvpn/server/ca.key
		/etc/openvpn/server/crl.pem
		/etc/openvpn/server/easy-rsa/pki/ca.crt
	)
else
	# Fingerprint mode requires server fingerprint file
	REQUIRED_FILES+=(
		/etc/openvpn/server/server-fingerprint
	)
fi
# Only check for iptables script if firewalld and nftables are not active
if ! systemctl is-active --quiet firewalld && ! systemctl is-active --quiet nftables; then
	REQUIRED_FILES+=(/etc/iptables/add-openvpn-rules.sh)
elif systemctl is-active --quiet nftables; then
	REQUIRED_FILES+=(/etc/nftables/openvpn.nft)
fi

for f in "${REQUIRED_FILES[@]}"; do
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
# Verify management interface configuration
# =====================================================
echo ""
echo "=== Verifying Management Interface Configuration ==="

# Verify management socket is configured in server.conf
if grep -q "management /var/run/openvpn/server.sock unix" /etc/openvpn/server/server.conf; then
	echo "PASS: Management interface configured in server.conf"
else
	echo "FAIL: Management interface not found in server.conf"
	grep "management" /etc/openvpn/server/server.conf || echo "No management directive found"
	exit 1
fi

# Verify management socket directory exists
if [ -d /var/run/openvpn ]; then
	echo "PASS: Management socket directory exists"
else
	echo "FAIL: Management socket directory /var/run/openvpn not found"
	exit 1
fi

# Verify socat is available (needed for management interface communication)
if command -v socat >/dev/null 2>&1; then
	echo "PASS: socat is available"
else
	echo "FAIL: socat is not installed (required for management interface)"
	exit 1
fi

echo "=== Management Interface Configuration Verified ==="

# =====================================================
# Test duplicate client name handling
# =====================================================
echo ""
echo "=== Testing Duplicate Client Name Handling ==="
DUPLICATE_CLIENT="testclient"
DUPLICATE_OUTPUT="/tmp/duplicate-client-output.log"
(bash /opt/openvpn-install.sh client add "$DUPLICATE_CLIENT" --cert-days 3650) 2>&1 | tee "$DUPLICATE_OUTPUT" || true
DUPLICATE_EXIT_CODE=${PIPESTATUS[0]}

if [ "$DUPLICATE_EXIT_CODE" -ne 1 ]; then
	echo "FAIL: Expected exit code 1 for duplicate client name, got $DUPLICATE_EXIT_CODE"
	cat "$DUPLICATE_OUTPUT"
	exit 1
fi
if grep -q "The specified client CN was already found" "$DUPLICATE_OUTPUT"; then
	echo "PASS: Duplicate client name correctly rejected with exit code 1"
else
	echo "FAIL: Expected error message for duplicate client name not found"
	cat "$DUPLICATE_OUTPUT"
	exit 1
fi

# Copy client config to shared volume for the client container
cp /root/testclient.ovpn /shared/client.ovpn
sed -i 's/^remote .*/remote openvpn-server 1194/' /shared/client.ovpn
echo "Client config copied to /shared/client.ovpn"

# Write VPN network info to shared volume for client tests
{
	echo "VPN_SUBNET_IPV4=$VPN_SUBNET_IPV4"
	echo "VPN_GATEWAY=$VPN_GATEWAY"
	echo "CLIENT_IPV6=$CLIENT_IPV6"
	echo "AUTH_MODE=$AUTH_MODE"
	if [ "$CLIENT_IPV6" = "y" ]; then
		echo "VPN_SUBNET_IPV6=$VPN_SUBNET_IPV6"
		echo "VPN_GATEWAY_IPV6=$VPN_GATEWAY_IPV6"
	fi
} >/shared/vpn-config.env
echo "VPN config written to /shared/vpn-config.env"

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

# =====================================================
# Verify MTU configuration
# =====================================================
echo "=== Verifying MTU configuration ==="

# Verify MTU in server config
if grep -q "tun-mtu 1400" /etc/openvpn/server/server.conf; then
	echo "PASS: Server config has tun-mtu 1400"
else
	echo "FAIL: Server config missing tun-mtu 1400"
	grep "tun-mtu" /etc/openvpn/server/server.conf || echo "No tun-mtu directive found"
	exit 1
fi

# Verify MTU in client template
if grep -q "tun-mtu 1400" /etc/openvpn/server/client-template.txt; then
	echo "PASS: Client template has tun-mtu 1400"
else
	echo "FAIL: Client template missing tun-mtu 1400"
	grep "tun-mtu" /etc/openvpn/server/client-template.txt || echo "No tun-mtu directive found"
	exit 1
fi

echo "=== MTU configuration verified ==="
echo ""
echo "Server config:"
cat /etc/openvpn/server/server.conf

# =====================================================
# Verify TLS 1.3 configuration
# =====================================================
echo ""
echo "=== Verifying TLS 1.3 Configuration ==="

# Verify tls-version-min is set correctly
if grep -q "tls-version-min $TLS_VERSION_MIN" /etc/openvpn/server/server.conf; then
	echo "PASS: tls-version-min is set to $TLS_VERSION_MIN"
else
	echo "FAIL: tls-version-min is not set correctly"
	grep "tls-version-min" /etc/openvpn/server/server.conf || echo "tls-version-min not found"
	exit 1
fi

# Verify tls-ciphersuites is set
if grep -q "tls-ciphersuites $TLS13_CIPHERSUITES" /etc/openvpn/server/server.conf; then
	echo "PASS: tls-ciphersuites is configured correctly"
else
	echo "FAIL: tls-ciphersuites is not configured correctly"
	grep "tls-ciphersuites" /etc/openvpn/server/server.conf || echo "tls-ciphersuites not found"
	exit 1
fi

# Verify client template also has TLS 1.3 settings
if grep -q "tls-version-min $TLS_VERSION_MIN" /etc/openvpn/server/client-template.txt; then
	echo "PASS: Client template has correct tls-version-min"
else
	echo "FAIL: Client template missing tls-version-min"
	exit 1
fi

if grep -q "tls-ciphersuites $TLS13_CIPHERSUITES" /etc/openvpn/server/client-template.txt; then
	echo "PASS: Client template has correct tls-ciphersuites"
else
	echo "FAIL: Client template missing tls-ciphersuites"
	exit 1
fi

echo "=== TLS 1.3 Configuration Verified ==="

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
(bash /opt/openvpn-install.sh client renew testclient --cert-days 3650) 2>&1 | tee "$RENEW_OUTPUT" || true

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

# Verify CRL was updated (PKI mode only)
if [ "$AUTH_MODE" = "pki" ]; then
	if [ -f /etc/openvpn/server/crl.pem ]; then
		echo "PASS: CRL file exists"
	else
		echo "FAIL: CRL file missing after renewal"
		exit 1
	fi
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
(bash /opt/openvpn-install.sh server renew --cert-days 3650 --force) 2>&1 | tee "$RENEW_SERVER_OUTPUT" || true

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

# Wait for OpenVPN to be fully ready after server certificate renewal
# The renewal process restarts OpenVPN, so we need to verify it's back up
echo "Verifying OpenVPN is running after certificate renewal..."
for _ in $(seq 1 30); do
	if pgrep -f "openvpn.*server.conf" >/dev/null; then
		break
	fi
	sleep 1
done

if ! pgrep -f "openvpn.*server.conf" >/dev/null; then
	echo "FAIL: OpenVPN not running after server certificate renewal"
	systemctl status openvpn-server@server 2>&1 || true
	exit 1
fi

# Wait for tun0 to be ready after restart
echo "Waiting for tun0 to be ready after certificate renewal..."
for i in $(seq 1 30); do
	if ip addr show tun0 2>/dev/null | grep -q "inet $VPN_GATEWAY"; then
		echo "OpenVPN tun0 interface ready after renewal"
		break
	fi
	sleep 1
done

# Allow routing to stabilize after renewal restart
sleep 3

# Update shared client config after server renewal (fingerprint changed)
cp /root/testclient.ovpn /shared/client.ovpn
sed -i 's/^remote .*/remote openvpn-server 1194/' /shared/client.ovpn
echo "Updated client config with new server fingerprint"

# =====================================================
# Verify Unbound DNS resolver (started by systemd via install script)
# =====================================================
echo "=== Verifying Unbound DNS Resolver ==="

if [ -f /etc/unbound/unbound.conf ]; then
	# Verify Unbound is running (started by systemctl in install script)
	echo "Checking Unbound service status..."
	for _ in $(seq 1 30); do
		if pgrep -x unbound >/dev/null; then
			echo "PASS: Unbound is running"
			break
		fi
		sleep 1
	done
	if ! pgrep -x unbound >/dev/null; then
		echo "FAIL: Unbound is not running"
		systemctl status unbound 2>&1 || true
		journalctl -u unbound --no-pager -n 50 2>&1 || true
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
if grep -q "interface: $VPN_GATEWAY" "$UNBOUND_OPENVPN_CONF"; then
	echo "PASS: Unbound configured to listen on $VPN_GATEWAY"
else
	echo "FAIL: Unbound not configured for $VPN_GATEWAY"
	cat "$UNBOUND_OPENVPN_CONF"
	exit 1
fi

# Verify OpenVPN pushes correct DNS
if grep -q "push \"dhcp-option DNS $VPN_GATEWAY\"" /etc/openvpn/server/server.conf; then
	echo "PASS: OpenVPN configured to push Unbound DNS"
else
	echo "FAIL: OpenVPN not configured to push Unbound DNS"
	grep "dhcp-option DNS" /etc/openvpn/server/server.conf || echo "No DNS push found"
	exit 1
fi

echo "=== Unbound Installation Verified ==="
echo ""

# Verify OpenVPN server (started by systemd via install script)
echo "Verifying OpenVPN server..."

# Verify firewall rules exist
echo "Verifying firewall rules..."
if systemctl is-active --quiet firewalld; then
	# firewalld is active - verify masquerade is enabled
	echo "firewalld detected, checking masquerade..."
	for _ in $(seq 1 10); do
		if firewall-cmd --query-masquerade 2>/dev/null; then
			echo "PASS: firewalld masquerade is enabled"
			break
		fi
		sleep 1
	done
	if ! firewall-cmd --query-masquerade 2>/dev/null; then
		echo "FAIL: firewalld masquerade is not enabled"
		echo "Current firewalld config:"
		firewall-cmd --list-all 2>&1 || true
		exit 1
	fi
	# Verify port is open
	if firewall-cmd --list-ports | grep -q "1194/udp"; then
		echo "PASS: OpenVPN port is open in firewalld"
	else
		echo "FAIL: OpenVPN port not found in firewalld"
		firewall-cmd --list-ports
		exit 1
	fi
	# Verify VPN subnet rich rule exists (source-based rules work reliably across firewalld backends)
	if firewall-cmd --list-rich-rules | grep -q "source address=\"$VPN_SUBNET_IPV4/24\""; then
		echo "PASS: VPN subnet rich rule is configured"
	else
		echo "FAIL: VPN subnet rich rule not found in firewalld"
		echo "Current rich rules:"
		firewall-cmd --list-rich-rules
		exit 1
	fi
elif systemctl is-active --quiet nftables; then
	# nftables mode - verify OpenVPN tables exist
	echo "nftables detected, checking OpenVPN tables..."
	for _ in $(seq 1 10); do
		if nft list table inet openvpn >/dev/null 2>&1; then
			echo "PASS: nftables 'inet openvpn' table exists"
			break
		fi
		sleep 1
	done
	if ! nft list table inet openvpn >/dev/null 2>&1; then
		echo "FAIL: nftables 'inet openvpn' table not found"
		echo "Current nftables ruleset:"
		nft list ruleset 2>&1 || true
		exit 1
	fi
	# Verify NAT table exists
	if nft list table ip openvpn-nat >/dev/null 2>&1; then
		echo "PASS: nftables 'ip openvpn-nat' table exists"
	else
		echo "FAIL: nftables 'ip openvpn-nat' table not found"
		nft list ruleset 2>&1 || true
		exit 1
	fi
	# Verify masquerade rule exists
	if nft list table ip openvpn-nat | grep -q "masquerade"; then
		echo "PASS: nftables masquerade rule exists"
	else
		echo "FAIL: nftables masquerade rule not found"
		nft list table ip openvpn-nat 2>&1 || true
		exit 1
	fi
	# Verify include in nftables.conf
	if grep -q 'include.*/etc/nftables/openvpn.nft' /etc/nftables.conf; then
		echo "PASS: OpenVPN rules included in nftables.conf"
	else
		echo "FAIL: OpenVPN rules not included in nftables.conf"
		cat /etc/nftables.conf 2>&1 || true
		exit 1
	fi
else
	# iptables mode - verify NAT rules
	echo "iptables mode, checking NAT rules..."
	for _ in $(seq 1 10); do
		if iptables -t nat -L POSTROUTING -n | grep -q "$VPN_SUBNET_IPV4"; then
			echo "PASS: NAT POSTROUTING rule for $VPN_SUBNET_IPV4/24 exists"
			break
		fi
		sleep 1
	done
	if ! iptables -t nat -L POSTROUTING -n | grep -q "$VPN_SUBNET_IPV4"; then
		echo "FAIL: NAT POSTROUTING rule for $VPN_SUBNET_IPV4/24 not found"
		echo "Current NAT rules:"
		iptables -t nat -L POSTROUTING -n -v
		systemctl status iptables-openvpn 2>&1 || true
		exit 1
	fi
fi

# Verify IP forwarding is enabled
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
	echo "ERROR: IP forwarding is not enabled"
	exit 1
fi

# Wait for OpenVPN to start (started by systemctl in install script)
echo "Waiting for OpenVPN server to start..."
for _ in $(seq 1 30); do
	if pgrep -f "openvpn.*server.conf" >/dev/null; then
		echo "PASS: OpenVPN server is running"
		break
	fi
	sleep 1
done

if ! pgrep -f "openvpn.*server.conf" >/dev/null; then
	echo "FAIL: OpenVPN server is not running"
	systemctl status openvpn-server@server 2>&1 || true
	journalctl -u openvpn-server@server --no-pager -n 50 2>&1 || true
	exit 1
fi

# Wait for server tun interface to be ready with correct IP
# This prevents race conditions where OpenVPN is running but tun0 isn't configured
echo "Waiting for server tun0 interface to be ready..."
TUN_READY=false
for i in $(seq 1 30); do
	if ip addr show tun0 2>/dev/null | grep -q "inet $VPN_GATEWAY"; then
		echo "PASS: Server tun0 interface ready with $VPN_GATEWAY"
		TUN_READY=true
		break
	fi
	echo "Waiting for tun0... ($i/30)"
	sleep 1
done

if [ "$TUN_READY" = false ]; then
	echo "FAIL: Server tun0 interface not ready after 30 seconds"
	ip addr show 2>&1 || true
	exit 1
fi

# Allow routing tables to stabilize
echo "Allowing routing to stabilize..."
sleep 3

# =====================================================
# Wait for initial client tests to complete
# =====================================================
echo ""
echo "=== Waiting for initial client connectivity tests ==="
while [ ! -f /shared/initial-tests-passed ]; do
	sleep 2
	echo "Waiting for initial tests..."
done
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
(bash /opt/openvpn-install.sh client add "$REVOKE_CLIENT" --cert-days 3650) 2>&1 | tee "$REVOKE_CREATE_OUTPUT" || true

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
while [ ! -f /shared/revoke-client-connected ]; do
	sleep 2
	echo "Waiting for revoke test connection..."
done
echo "PASS: Client connected with '$REVOKE_CLIENT' certificate"

# =====================================================
# Test server status command
# =====================================================
echo ""
echo "=== Testing Server Status ==="

# Note: OpenVPN status file updates periodically (default: 1 min)
# so we just verify the command works, not that a specific client is visible

# Test table output
STATUS_OUTPUT="/tmp/server-status-output.log"
(bash /opt/openvpn-install.sh server status) 2>&1 | tee "$STATUS_OUTPUT" || true

if grep -q "Connected Clients" "$STATUS_OUTPUT"; then
	echo "PASS: Server status shows header"
else
	echo "FAIL: Server status missing header"
	cat "$STATUS_OUTPUT"
	exit 1
fi

# Test JSON output
STATUS_JSON_OUTPUT="/tmp/server-status-json-output.log"
(bash /opt/openvpn-install.sh server status --format json) 2>&1 | tee "$STATUS_JSON_OUTPUT" || true

# Validate JSON structure (clients array exists, even if empty)
if jq -e '.clients' "$STATUS_JSON_OUTPUT" >/dev/null 2>&1; then
	echo "PASS: Server status JSON is valid"
else
	echo "FAIL: Server status JSON is invalid"
	cat "$STATUS_JSON_OUTPUT"
	exit 1
fi

echo "=== Server Status Tests PASSED ==="

# Now revoke the certificate (this should auto-disconnect the client via management interface)
echo "Revoking certificate for '$REVOKE_CLIENT' (should auto-disconnect client)..."
REVOKE_OUTPUT="/tmp/revoke-output.log"
(bash /opt/openvpn-install.sh client revoke "$REVOKE_CLIENT" --force) 2>&1 | tee "$REVOKE_OUTPUT" || true

if grep -q "Certificate for client $REVOKE_CLIENT revoked" "$REVOKE_OUTPUT"; then
	echo "PASS: Certificate for '$REVOKE_CLIENT' revoked successfully"
else
	echo "FAIL: Failed to revoke certificate"
	cat "$REVOKE_OUTPUT"
	exit 1
fi

# Verify revocation was applied correctly
if [ "$AUTH_MODE" = "pki" ]; then
	# PKI mode: verify certificate is marked as revoked in index.txt
	if tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -q "^R.*CN=$REVOKE_CLIENT\$"; then
		echo "PASS: Certificate marked as revoked in index.txt"
	else
		echo "FAIL: Certificate not marked as revoked"
		cat /etc/openvpn/server/easy-rsa/pki/index.txt
		exit 1
	fi
else
	# Fingerprint mode: verify fingerprint was removed from server.conf
	if ! grep -q "# $REVOKE_CLIENT\$" /etc/openvpn/server/server.conf; then
		echo "PASS: Client fingerprint removed from server.conf"
	else
		echo "FAIL: Client fingerprint still present in server.conf"
		grep "$REVOKE_CLIENT" /etc/openvpn/server/server.conf || true
		exit 1
	fi
fi

# Wait for client to confirm it was disconnected by the revoke
echo "Waiting for client to confirm auto-disconnect..."
DISCONNECT_WAIT=0
while [ ! -f /shared/revoke-client-disconnected ] && [ $DISCONNECT_WAIT -lt 60 ]; do
	sleep 2
	DISCONNECT_WAIT=$((DISCONNECT_WAIT + 2))
	echo "Waiting for disconnect confirmation... ($DISCONNECT_WAIT/60s)"
done

if [ -f /shared/revoke-client-disconnected ]; then
	echo "PASS: Client was auto-disconnected by revoke command"
else
	echo "FAIL: Client was not disconnected within 60 seconds"
	exit 1
fi

# Signal client to try reconnecting (should fail)
touch /shared/revoke-try-reconnect

# Wait for client to confirm that connection with revoked cert failed
echo "Waiting for client to confirm revoked cert connection failure..."
while [ ! -f /shared/revoke-reconnect-failed ]; do
	sleep 2
	echo "Waiting for reconnect failure confirmation..."
done
echo "PASS: Connection with revoked certificate correctly rejected"

echo "=== Certificate Revocation Tests PASSED ==="

# =====================================================
# Test listing client certificates
# =====================================================
echo ""
echo "=== Testing List Client Certificates ==="

# At this point we have 3 client certificates:
# - testclient (Valid) - the renewed certificate
# - testclient (Revoked) - the old certificate revoked during renewal
# - revoketest (Revoked) - the revoked certificate
LIST_OUTPUT="/tmp/list-clients-output.log"
(bash /opt/openvpn-install.sh client list) 2>&1 | tee "$LIST_OUTPUT" || true

# Verify list output contains expected clients
if grep -q "testclient" "$LIST_OUTPUT" && grep -q "Valid" "$LIST_OUTPUT"; then
	echo "PASS: List shows testclient as Valid"
else
	echo "FAIL: List does not show testclient correctly"
	cat "$LIST_OUTPUT"
	exit 1
fi

if grep -q "$REVOKE_CLIENT" "$LIST_OUTPUT" && grep -q "Revoked" "$LIST_OUTPUT"; then
	echo "PASS: List shows $REVOKE_CLIENT as Revoked"
else
	echo "FAIL: List does not show $REVOKE_CLIENT correctly"
	cat "$LIST_OUTPUT"
	exit 1
fi

# Verify certificate count (varies by auth mode)
if [ "$AUTH_MODE" = "pki" ]; then
	# PKI mode: 3 certs (testclient valid, testclient revoked from renewal, revoketest revoked)
	if grep -q "Found 3 client certificate(s)" "$LIST_OUTPUT"; then
		echo "PASS: List shows correct certificate count"
	else
		echo "FAIL: List does not show correct certificate count"
		cat "$LIST_OUTPUT"
		exit 1
	fi
else
	# Fingerprint mode: 2 certs (testclient valid, revoketest revoked)
	# In fingerprint mode, renewal doesn't create a separate revoked entry
	if grep -q "Found [23] client certificate(s)" "$LIST_OUTPUT"; then
		echo "PASS: List shows correct certificate count for fingerprint mode"
	else
		echo "FAIL: List does not show correct certificate count"
		cat "$LIST_OUTPUT"
		exit 1
	fi
fi

# Test JSON output
echo "Testing client list JSON output..."
LIST_JSON_OUTPUT="/tmp/list-clients-json-output.log"
(bash /opt/openvpn-install.sh client list --format json) 2>&1 | tee "$LIST_JSON_OUTPUT" || true

# Validate JSON structure
if jq -e '.clients' "$LIST_JSON_OUTPUT" >/dev/null 2>&1; then
	echo "PASS: Client list JSON is valid"
else
	echo "FAIL: Client list JSON is invalid"
	cat "$LIST_JSON_OUTPUT"
	exit 1
fi

# Verify client count in JSON (varies by auth mode)
JSON_CLIENT_COUNT=$(jq '.clients | length' "$LIST_JSON_OUTPUT")
if [ "$AUTH_MODE" = "pki" ]; then
	if [ "$JSON_CLIENT_COUNT" -eq 3 ]; then
		echo "PASS: Client list JSON has correct count ($JSON_CLIENT_COUNT)"
	else
		echo "FAIL: Client list JSON has wrong count: $JSON_CLIENT_COUNT (expected 3)"
		cat "$LIST_JSON_OUTPUT"
		exit 1
	fi
else
	# Fingerprint mode may have fewer entries
	if [ "$JSON_CLIENT_COUNT" -ge 2 ] && [ "$JSON_CLIENT_COUNT" -le 3 ]; then
		echo "PASS: Client list JSON has correct count for fingerprint mode ($JSON_CLIENT_COUNT)"
	else
		echo "FAIL: Client list JSON has wrong count: $JSON_CLIENT_COUNT (expected 2-3)"
		cat "$LIST_JSON_OUTPUT"
		exit 1
	fi
fi

# Verify valid client in JSON
if jq -e '.clients[] | select(.name == "testclient" and .status == "valid")' "$LIST_JSON_OUTPUT" >/dev/null 2>&1; then
	echo "PASS: Client list JSON shows testclient as valid"
else
	echo "FAIL: Client list JSON does not show testclient correctly"
	cat "$LIST_JSON_OUTPUT"
	exit 1
fi

# Verify revoked client in JSON
if jq -e ".clients[] | select(.name == \"$REVOKE_CLIENT\" and .status == \"revoked\")" "$LIST_JSON_OUTPUT" >/dev/null 2>&1; then
	echo "PASS: Client list JSON shows $REVOKE_CLIENT as revoked"
else
	echo "FAIL: Client list JSON does not show $REVOKE_CLIENT correctly"
	cat "$LIST_JSON_OUTPUT"
	exit 1
fi

echo "=== List Client Certificates Tests PASSED ==="

# =====================================================
# Test reusing revoked client name
# =====================================================
echo ""
echo "=== Testing Reuse of Revoked Client Name ==="

# Create a new certificate with the same name as the revoked one
echo "Creating new client with same name '$REVOKE_CLIENT'..."
RECREATE_OUTPUT="/tmp/recreate-output.log"
(bash /opt/openvpn-install.sh client add "$REVOKE_CLIENT" --cert-days 3650) 2>&1 | tee "$RECREATE_OUTPUT" || true

if [ -f "/root/$REVOKE_CLIENT.ovpn" ]; then
	echo "PASS: New client '$REVOKE_CLIENT' created successfully (reusing revoked name)"
else
	echo "FAIL: Failed to create client with revoked name"
	cat "$RECREATE_OUTPUT"
	exit 1
fi

# Verify the new certificate is valid
if [ "$AUTH_MODE" = "pki" ]; then
	# PKI mode: verify in index.txt
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
else
	# Fingerprint mode: verify fingerprint was added back to server.conf
	if grep -q "# $REVOKE_CLIENT\$" /etc/openvpn/server/server.conf; then
		echo "PASS: New client fingerprint added to server.conf"
	else
		echo "FAIL: New client fingerprint not found in server.conf"
		cat /etc/openvpn/server/server.conf | grep -A5 "<peer-fingerprint>" || true
		exit 1
	fi
fi

# Copy the new config
cp "/root/$REVOKE_CLIENT.ovpn" "/shared/$REVOKE_CLIENT-new.ovpn"
sed -i 's/^remote .*/remote openvpn-server 1194/' "/shared/$REVOKE_CLIENT-new.ovpn"
echo "Copied new $REVOKE_CLIENT config to /shared/"

# Signal client that new config is ready
touch /shared/new-client-config-ready

# Wait for client to confirm successful connection with new cert
echo "Waiting for client to connect with new '$REVOKE_CLIENT' certificate..."
while [ ! -f /shared/new-client-connected ]; do
	sleep 2
	echo "Waiting for new cert connection..."
done
echo "PASS: Client connected with new '$REVOKE_CLIENT' certificate"

echo "=== Reuse of Revoked Client Name Tests PASSED ==="

# =====================================================
# Test PASSPHRASE support for headless client creation
# =====================================================
echo ""
echo "=== Testing PASSPHRASE Support ==="

PASSPHRASE_CLIENT="passphrasetest"
TEST_PASSPHRASE="TestP@ssw0rd#123"
echo "Creating client '$PASSPHRASE_CLIENT' with passphrase in headless mode..."
PASSPHRASE_OUTPUT="/tmp/passphrase-output.log"
(bash /opt/openvpn-install.sh client add "$PASSPHRASE_CLIENT" --password "$TEST_PASSPHRASE" --cert-days 3650) 2>&1 | tee "$PASSPHRASE_OUTPUT" || true

# Verify client was created
if [ -f "/root/$PASSPHRASE_CLIENT.ovpn" ]; then
	echo "PASS: Client '$PASSPHRASE_CLIENT' with passphrase created successfully"
else
	echo "FAIL: Failed to create client '$PASSPHRASE_CLIENT' with passphrase"
	cat "$PASSPHRASE_OUTPUT"
	exit 1
fi

# Verify the passphrase is NOT leaked in the output
if grep -q "$TEST_PASSPHRASE" "$PASSPHRASE_OUTPUT"; then
	echo "FAIL: Passphrase was leaked in command output!"
	exit 1
else
	echo "PASS: Passphrase not leaked in command output"
fi

# Verify the log file doesn't contain the passphrase
if [ -f /opt/openvpn-install.log ] && grep -q "$TEST_PASSPHRASE" /opt/openvpn-install.log; then
	echo "FAIL: Passphrase was leaked in log file!"
	exit 1
else
	echo "PASS: Passphrase not leaked in log file"
fi

# Verify certificate was created with encryption (key should be encrypted)
CLIENT_KEY="/etc/openvpn/server/easy-rsa/pki/private/$PASSPHRASE_CLIENT.key"
if [ -f "$CLIENT_KEY" ]; then
	if grep -q "ENCRYPTED" "$CLIENT_KEY"; then
		echo "PASS: Client key is encrypted"
	else
		echo "FAIL: Client key is not encrypted"
		exit 1
	fi
else
	echo "FAIL: Client key not found at $CLIENT_KEY"
	exit 1
fi

# Copy config for passphrase client connectivity test
cp "/root/$PASSPHRASE_CLIENT.ovpn" "/shared/$PASSPHRASE_CLIENT.ovpn"
sed -i 's/^remote .*/remote openvpn-server 1194/' "/shared/$PASSPHRASE_CLIENT.ovpn"
# Write passphrase to a file for client to use with --askpass
echo "$TEST_PASSPHRASE" >"/shared/$PASSPHRASE_CLIENT.pass"
echo "Copied $PASSPHRASE_CLIENT config and passphrase to /shared/"

# Signal client that passphrase test config is ready
touch /shared/passphrase-client-config-ready

# Wait for client to confirm connection with passphrase client
echo "Waiting for client to connect with '$PASSPHRASE_CLIENT' certificate..."
while [ ! -f /shared/passphrase-client-connected ]; do
	sleep 2
	echo "Waiting for passphrase client connection..."
done
echo "PASS: Client connected with passphrase-protected certificate"

echo "=== PASSPHRASE Support Tests PASSED ==="

# =====================================================
# Test management interface is running
# =====================================================
echo ""
echo "=== Testing Management Interface ==="

MGMT_SOCKET="/var/run/openvpn/server.sock"

# Verify management socket exists and is accessible
if [ -S "$MGMT_SOCKET" ]; then
	echo "PASS: Management socket exists at $MGMT_SOCKET"
else
	echo "FAIL: Management socket not found at $MGMT_SOCKET"
	ls -la /var/run/openvpn/ || true
	exit 1
fi

# Test that we can communicate with the management interface
echo "Testing management interface communication..."
MGMT_STATUS=$(echo "status" | socat - UNIX-CONNECT:"$MGMT_SOCKET" 2>&1 | head -20)
if echo "$MGMT_STATUS" | grep -q "CLIENT LIST"; then
	echo "PASS: Management interface is responsive"
	echo "Status output:"
	echo "$MGMT_STATUS"
else
	echo "FAIL: Management interface not responding correctly"
	echo "Response: $MGMT_STATUS"
	exit 1
fi

echo "=== Management Interface Tests PASSED ==="

echo ""
echo "=== All Tests PASSED ==="

# Server tests complete - systemd keeps the container running via /sbin/init
# OpenVPN service (openvpn-server@server) continues independently
echo "Server tests complete. Container will remain running via systemd."
echo "OpenVPN is managed by: systemctl status openvpn-server@server"
