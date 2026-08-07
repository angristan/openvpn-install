#!/bin/bash
# shellcheck disable=SC1091,SC2034
# SC1091: The installer path is provided by the test environment.
# SC2034: Configuration globals are consumed by sourced installer functions.
set -euo pipefail

INSTALLER=${1:-/opt/openvpn-install.sh}

export FORCE_COLOR=0 LOG_FILE="" NON_INTERACTIVE_INSTALL=n OUTPUT_FORMAT=table
# shellcheck source=../openvpn-install.sh
source "$INSTALLER"

fail() {
	echo "FAIL: $1" >&2
	exit 1
}

# Exercise command orchestration without touching the host system.
isOpenVPNInstalled() {
	return 1
}

installQuestions() {
	CLIENT_IPV4=y
	CLIENT_IPV6=n
	VPN_SUBNET_IPV4=10.8.0.0
	ROUTE_INTERNET=y
}

validate_configuration() {
	CONFIG_VALIDATED=y
}

installOpenVPN() {
	[[ ${CONFIG_VALIDATED:-n} == y ]] || fail "interactive configuration was not validated"
	[[ ${VPN_GATEWAY_IPV4:-} == 10.8.0.1 ]] || fail "IPv4 gateway was not prepared before installation"
	[[ ${IPV6_SUPPORT:-} == n ]] || fail "legacy IPv6 support value was not prepared before installation"
	INSTALL_CALLED=y
}

cmd_interactive

[[ ${INSTALL_CALLED:-n} == y ]] || fail "interactive installation was not started"

echo "PASS: Interactive command uses the canonical installation flow"
