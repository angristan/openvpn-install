#!/bin/bash
# shellcheck disable=SC1091,SC2034
# SC1091: The installer path is provided by the test environment.
# SC2034: Configuration globals are consumed by sourced installer functions.
set -euo pipefail

INSTALLER=${1:-/opt/openvpn-install.sh}
export FORCE_COLOR=0 LOG_FILE="" NON_INTERACTIVE_INSTALL=n OUTPUT_FORMAT=table
# shellcheck source=../openvpn-install.sh
source "$INSTALLER"

questions_called=n
validation_called=n
install_called=n

isOpenVPNInstalled() {
	return 1
}

requireNoOpenVPN() {
	return 0
}

installQuestions() {
	questions_called=y
	VPN_SUBNET_IPV4=10.23.0.0
	VPN_SUBNET_IPV6=fd42:23::
	CLIENT_IPV6=n
	ROUTE_INTERNET=y
}

validate_configuration() {
	validation_called=y
}

installOpenVPN() {
	install_called=y
	if [[ ${VPN_GATEWAY_IPV4:-} != "10.23.0.1" ]]; then
		echo "FAIL: Interactive install did not prepare the IPv4 VPN gateway" >&2
		exit 1
	fi
	if [[ ${IPV6_SUPPORT:-} != "n" ]]; then
		echo "FAIL: Interactive install did not prepare legacy IPv6 state" >&2
		exit 1
	fi
}

cmd_interactive

for state in \
	"questions_called:$questions_called" \
	"validation_called:$validation_called" \
	"install_called:$install_called"; do
	if [[ ${state#*:} != "y" ]]; then
		echo "FAIL: Interactive install skipped ${state%%:*}" >&2
		exit 1
	fi
done

echo "PASS: Interactive install prepares derived network configuration"
