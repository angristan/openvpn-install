#!/bin/bash
# shellcheck disable=SC1091,SC2034
# SC1091: Not following /etc/os-release (sourced dynamically)
# SC2034: Variables used indirectly or exported for subprocesses

# Secure OpenVPN server installer for Debian, Ubuntu, CentOS, Amazon Linux 2023, Fedora, Oracle Linux, Arch Linux, Rocky Linux and AlmaLinux.
# https://github.com/angristan/openvpn-install

# Configuration constants
readonly DEFAULT_CERT_VALIDITY_DURATION_DAYS=3650 # 10 years
readonly DEFAULT_CRL_VALIDITY_DURATION_DAYS=5475  # 15 years
readonly EASYRSA_VERSION="3.2.5"
readonly EASYRSA_SHA256="662ee3b453155aeb1dff7096ec052cd83176c460cfa82ac130ef8568ec4df490"

# =============================================================================
# Logging Configuration
# =============================================================================
# Set VERBOSE=1 to see command output, VERBOSE=0 (default) for quiet mode
# Set LOG_FILE to customize log location (default: openvpn-install.log in current dir)
# Set LOG_FILE="" to disable file logging
VERBOSE=${VERBOSE:-0}
LOG_FILE=${LOG_FILE:-openvpn-install.log}

# Color definitions (disabled if not a terminal, unless FORCE_COLOR=1)
if [[ -t 1 ]] || [[ $FORCE_COLOR == "1" ]]; then
	readonly COLOR_RESET='\033[0m'
	readonly COLOR_RED='\033[0;31m'
	readonly COLOR_GREEN='\033[0;32m'
	readonly COLOR_YELLOW='\033[0;33m'
	readonly COLOR_BLUE='\033[0;34m'
	readonly COLOR_CYAN='\033[0;36m'
	readonly COLOR_DIM='\033[0;90m'
	readonly COLOR_BOLD='\033[1m'
else
	readonly COLOR_RESET=''
	readonly COLOR_RED=''
	readonly COLOR_GREEN=''
	readonly COLOR_YELLOW=''
	readonly COLOR_BLUE=''
	readonly COLOR_CYAN=''
	readonly COLOR_DIM=''
	readonly COLOR_BOLD=''
fi

# Write to log file (no colors, with timestamp)
_log_to_file() {
	if [[ -n "$LOG_FILE" ]]; then
		echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >>"$LOG_FILE"
	fi
}

# Logging functions
log_info() {
	echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $*"
	_log_to_file "[INFO] $*"
}

log_warn() {
	echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $*"
	_log_to_file "[WARN] $*"
}

log_error() {
	echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $*" >&2
	_log_to_file "[ERROR] $*"
	if [[ -n "$LOG_FILE" ]]; then
		echo -e "${COLOR_YELLOW}        Check the log file for details: ${LOG_FILE}${COLOR_RESET}" >&2
	fi
}

log_fatal() {
	echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $*" >&2
	_log_to_file "[FATAL] $*"
	if [[ -n "$LOG_FILE" ]]; then
		echo -e "${COLOR_YELLOW}        Check the log file for details: ${LOG_FILE}${COLOR_RESET}" >&2
		_log_to_file "Script exited with error"
	fi
	exit 1
}

log_success() {
	echo -e "${COLOR_GREEN}[OK]${COLOR_RESET} $*"
	_log_to_file "[OK] $*"
}

log_debug() {
	if [[ $VERBOSE -eq 1 ]]; then
		echo -e "${COLOR_DIM}[DEBUG]${COLOR_RESET} $*"
	fi
	_log_to_file "[DEBUG] $*"
}

log_prompt() {
	# For user-facing prompts/questions (no prefix, just cyan)
	# Skip display in auto-install mode
	if [[ $AUTO_INSTALL != "y" ]]; then
		echo -e "${COLOR_CYAN}$*${COLOR_RESET}"
	fi
	_log_to_file "[PROMPT] $*"
}

log_header() {
	# For section headers
	# Skip display in auto-install mode
	if [[ $AUTO_INSTALL != "y" ]]; then
		echo ""
		echo -e "${COLOR_BOLD}${COLOR_BLUE}=== $* ===${COLOR_RESET}"
		echo ""
	fi
	_log_to_file "=== $* ==="
}

log_menu() {
	# For menu options - only show in interactive mode
	if [[ $AUTO_INSTALL != "y" ]]; then
		echo "$@"
	fi
}

# Run a command with optional output suppression
# Usage: run_cmd "description" command [args...]
run_cmd() {
	local desc="$1"
	shift
	# Display the command being run
	echo -e "${COLOR_DIM}> $*${COLOR_RESET}"
	_log_to_file "[CMD] $*"
	if [[ $VERBOSE -eq 1 ]]; then
		if [[ -n "$LOG_FILE" ]]; then
			"$@" 2>&1 | tee -a "$LOG_FILE"
		else
			"$@"
		fi
	else
		if [[ -n "$LOG_FILE" ]]; then
			"$@" >>"$LOG_FILE" 2>&1
		else
			"$@" >/dev/null 2>&1
		fi
	fi
	local ret=$?
	if [[ $ret -eq 0 ]]; then
		log_debug "$desc completed successfully"
	else
		log_error "$desc failed with exit code $ret"
	fi
	return $ret
}

# Run a command that must succeed, exit on failure
# Usage: run_cmd_fatal "description" command [args...]
run_cmd_fatal() {
	local desc="$1"
	shift
	if ! run_cmd "$desc" "$@"; then
		log_fatal "$desc failed"
	fi
}

function isRoot() {
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}

function tunAvailable() {
	if [ ! -e /dev/net/tun ]; then
		return 1
	fi
}

function checkOS() {
	if [[ -e /etc/debian_version ]]; then
		OS="debian"
		source /etc/os-release

		if [[ $ID == "debian" || $ID == "raspbian" ]]; then
			if [[ $VERSION_ID -lt 11 ]]; then
				log_warn "Your version of Debian is not supported."
				log_info "However, if you're using Debian >= 11 or unstable/testing, you can continue at your own risk."
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		elif [[ $ID == "ubuntu" ]]; then
			OS="ubuntu"
			MAJOR_UBUNTU_VERSION=$(echo "$VERSION_ID" | cut -d '.' -f1)
			if [[ $MAJOR_UBUNTU_VERSION -lt 18 ]]; then
				log_warn "Your version of Ubuntu is not supported."
				log_info "However, if you're using Ubuntu >= 18.04 or beta, you can continue at your own risk."
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		fi
	elif [[ -e /etc/os-release ]]; then
		source /etc/os-release
		if [[ $ID == "fedora" || $ID_LIKE == "fedora" ]]; then
			OS="fedora"
		fi
		if [[ $ID == "opensuse-tumbleweed" ]]; then
			OS="opensuse"
		fi
		if [[ $ID == "opensuse-leap" ]]; then
			OS="opensuse"
			if [[ ${VERSION_ID%.*} -lt 16 ]]; then
				log_info "The script only supports openSUSE Leap 16+."
				log_fatal "Your version of openSUSE Leap is not supported."
			fi
		fi
		if [[ $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]]; then
			OS="centos"
		fi
		if [[ $ID == "ol" ]]; then
			OS="oracle"
		fi
		if [[ $OS =~ (centos|oracle) ]] && [[ ${VERSION_ID%.*} -lt 8 ]]; then
			log_info "The script only supports CentOS Stream / Rocky Linux / AlmaLinux / Oracle Linux version 8+."
			log_fatal "Your version is not supported."
		fi
		if [[ $ID == "amzn" ]]; then
			if [[ "$(echo "$PRETTY_NAME" | cut -c 1-18)" == "Amazon Linux 2023." ]] && [[ "$(echo "$PRETTY_NAME" | cut -c 19)" -ge 6 ]]; then
				OS="amzn2023"
			else
				log_info "The script only supports Amazon Linux 2023.6+"
				log_info "Amazon Linux 2 is EOL and no longer supported."
				log_fatal "Your version of Amazon Linux is not supported."
			fi
		fi
		if [[ $ID == "arch" ]]; then
			OS="arch"
		fi
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		log_fatal "It looks like you aren't running this installer on a Debian, Ubuntu, Fedora, openSUSE, CentOS, Amazon Linux 2023, Oracle Linux, Arch Linux, Rocky Linux or AlmaLinux system."
	fi
}

function checkArchPendingKernelUpgrade() {
	if [[ $OS != "arch" ]]; then
		return 0
	fi

	# Check if running kernel's modules are available
	# (detects if kernel was upgraded but system not rebooted)
	# Skip this check in containers - they share host kernel but have their own /lib/modules
	if [[ -f /.dockerenv ]] || grep -qE '(docker|lxc|containerd)' /proc/1/cgroup 2>/dev/null; then
		log_info "Running in container, skipping kernel modules check"
	else
		local running_kernel
		running_kernel=$(uname -r)
		if [[ ! -d "/lib/modules/${running_kernel}" ]]; then
			log_error "Kernel modules for running kernel ($running_kernel) not found!"
			log_info "This usually means the kernel was upgraded but the system wasn't rebooted."
			log_fatal "Please reboot your system and run this script again."
		fi
	fi

	log_info "Checking for pending kernel upgrades on Arch Linux..."

	# Sync package database to check for updates
	if ! pacman -Sy &>/dev/null; then
		log_warn "Failed to sync package database, skipping kernel upgrade check"
		return 0
	fi

	# Check for pending linux kernel upgrades
	local pending_kernels
	pending_kernels=$(pacman -Qu 2>/dev/null | grep -E '^linux' || true)

	if [[ -n "$pending_kernels" ]]; then
		log_warn "Linux kernel upgrade(s) pending:"
		echo "$pending_kernels" | while read -r line; do
			log_info "  $line"
		done
		echo ""
		log_info "This script uses 'pacman -Syu' which will upgrade your kernel."
		log_info "After a kernel upgrade, the TUN module won't be available until you reboot."
		echo ""
		log_info "Please upgrade your system and reboot first:"
		log_info "  sudo pacman -Syu"
		log_info "  sudo reboot"
		echo ""
		log_fatal "Aborting. Run this script again after upgrading and rebooting."
	fi

	log_success "No pending kernel upgrades"
}

function initialCheck() {
	log_debug "Checking root privileges..."
	if ! isRoot; then
		log_fatal "Sorry, you need to run this script as root."
	fi
	log_debug "Root check passed"

	log_debug "Checking TUN device availability..."
	if ! tunAvailable; then
		log_fatal "TUN is not available."
	fi
	log_debug "TUN device available at /dev/net/tun"

	log_debug "Detecting operating system..."
	checkOS
	log_info "Detected OS: $OS (${PRETTY_NAME:-unknown})"
	checkArchPendingKernelUpgrade
}

# Check if OpenVPN version is at least the specified version
# Usage: openvpnVersionAtLeast "2.5"
# Returns 0 if version is >= specified, 1 otherwise
function openvpnVersionAtLeast() {
	local required_version="$1"
	local installed_version

	if ! command -v openvpn &>/dev/null; then
		return 1
	fi

	installed_version=$(openvpn --version 2>/dev/null | head -1 | awk '{print $2}')
	if [[ -z "$installed_version" ]]; then
		return 1
	fi

	# Compare versions using sort -V
	if [[ "$(printf '%s\n' "$required_version" "$installed_version" | sort -V | head -n1)" == "$required_version" ]]; then
		return 0
	fi
	return 1
}

# Check if kernel version is at least the specified version
# Usage: kernelVersionAtLeast "6.16"
# Returns 0 if version is >= specified, 1 otherwise
function kernelVersionAtLeast() {
	local required_version="$1"
	local kernel_version

	kernel_version=$(uname -r | cut -d'-' -f1)
	if [[ -z "$kernel_version" ]]; then
		return 1
	fi

	if [[ "$(printf '%s\n' "$required_version" "$kernel_version" | sort -V | head -n1)" == "$required_version" ]]; then
		return 0
	fi
	return 1
}

# Check if Data Channel Offload (DCO) is available
# DCO requires: OpenVPN 2.6+, kernel support (Linux 6.16+ or ovpn-dco module)
# Returns 0 if DCO is available, 1 otherwise
function isDCOAvailable() {
	# DCO requires OpenVPN 2.6+
	if ! openvpnVersionAtLeast "2.6"; then
		return 1
	fi

	# DCO is built into Linux 6.16+, or available via ovpn-dco module
	if kernelVersionAtLeast "6.16"; then
		return 0
	elif lsmod 2>/dev/null | grep -q "^ovpn_dco" || modinfo ovpn-dco &>/dev/null; then
		return 0
	fi
	return 1
}

function installOpenVPNRepo() {
	log_info "Setting up official OpenVPN repository..."

	if [[ $OS =~ (debian|ubuntu) ]]; then
		run_cmd "Update package lists" apt-get update
		run_cmd_fatal "Installing prerequisites" apt-get install -y ca-certificates curl

		# Create keyrings directory
		run_cmd "Creating keyrings directory" mkdir -p /etc/apt/keyrings

		# Download and install GPG key
		if ! run_cmd "Downloading OpenVPN GPG key" curl -fsSL https://swupdate.openvpn.net/repos/repo-public.gpg -o /etc/apt/keyrings/openvpn-repo-public.asc; then
			log_fatal "Failed to download OpenVPN repository GPG key"
		fi

		# Add repository - using stable release
		if [[ -z "${VERSION_CODENAME}" ]]; then
			log_fatal "VERSION_CODENAME is not set. Unable to configure OpenVPN repository."
		fi
		echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/openvpn-repo-public.asc] https://build.openvpn.net/debian/openvpn/stable ${VERSION_CODENAME} main" >/etc/apt/sources.list.d/openvpn-aptrepo.list

		log_info "Updating package lists with new repository..."
		run_cmd "Update package lists" apt-get update

		log_info "OpenVPN official repository configured"

	elif [[ $OS =~ (centos|oracle) ]]; then
		# For RHEL-based systems, use Fedora Copr (OpenVPN 2.6 stable)
		# EPEL is required for pkcs11-helper dependency
		log_info "Configuring OpenVPN Copr repository for RHEL-based system..."

		# Oracle Linux uses oracle-epel-release-el* instead of epel-release
		if [[ $OS == "oracle" ]]; then
			EPEL_PACKAGE="oracle-epel-release-el${VERSION_ID%.*}"
		else
			EPEL_PACKAGE="epel-release"
		fi

		if ! command -v dnf &>/dev/null; then
			run_cmd_fatal "Installing EPEL repository" yum install -y "$EPEL_PACKAGE"
			run_cmd_fatal "Installing yum-plugin-copr" yum install -y yum-plugin-copr
			run_cmd_fatal "Enabling OpenVPN Copr repo" yum copr enable -y @OpenVPN/openvpn-release-2.6
		else
			run_cmd_fatal "Installing EPEL repository" dnf install -y "$EPEL_PACKAGE"
			run_cmd_fatal "Installing dnf-plugins-core" dnf install -y dnf-plugins-core
			run_cmd_fatal "Enabling OpenVPN Copr repo" dnf copr enable -y @OpenVPN/openvpn-release-2.6
		fi

		log_info "OpenVPN Copr repository configured"

	elif [[ $OS == "fedora" ]]; then
		# Fedora already ships with recent OpenVPN 2.6.x, no Copr needed
		log_info "Fedora already has recent OpenVPN packages, using distribution version"

	else
		log_info "No official OpenVPN repository available for this OS, using distribution packages"
	fi
}

function installUnbound() {
	log_info "Installing Unbound DNS resolver..."

	# Install Unbound if not present
	if [[ ! -e /etc/unbound/unbound.conf ]]; then
		if [[ $OS =~ (debian|ubuntu) ]]; then
			run_cmd_fatal "Installing Unbound" apt-get install -y unbound
		elif [[ $OS =~ (centos|oracle) ]]; then
			run_cmd_fatal "Installing Unbound" yum install -y unbound
		elif [[ $OS =~ (fedora|amzn2023) ]]; then
			run_cmd_fatal "Installing Unbound" dnf install -y unbound
		elif [[ $OS == "opensuse" ]]; then
			run_cmd_fatal "Installing Unbound" zypper install -y unbound
		elif [[ $OS == "arch" ]]; then
			run_cmd_fatal "Installing Unbound" pacman -Syu --noconfirm unbound
		fi
	fi

	# Configure Unbound for OpenVPN (runs whether freshly installed or pre-existing)
	# Create conf.d directory (works on all distros)
	run_cmd "Creating Unbound config directory" mkdir -p /etc/unbound/unbound.conf.d

	# Ensure main config includes conf.d directory
	# Modern Debian/Ubuntu use include-toplevel, others need include directive
	if ! grep -qE "include(-toplevel)?:\s*.*/etc/unbound/unbound.conf.d" /etc/unbound/unbound.conf 2>/dev/null; then
		# Add include directive for conf.d if not present
		echo 'include: "/etc/unbound/unbound.conf.d/*.conf"' >>/etc/unbound/unbound.conf
	fi

	# Generate OpenVPN-specific Unbound configuration
	# Using consistent best-practice settings across all distros
	{
		echo 'server:'
		echo '    # OpenVPN DNS resolver configuration'
		echo '    interface: 10.8.0.1'
		echo '    access-control: 10.8.0.0/24 allow'
		echo ''
		echo '    # Security hardening'
		echo '    hide-identity: yes'
		echo '    hide-version: yes'
		echo '    harden-glue: yes'
		echo '    harden-dnssec-stripped: yes'
		echo ''
		echo '    # Performance optimizations'
		echo '    prefetch: yes'
		echo '    use-caps-for-id: yes'
		echo '    qname-minimisation: yes'
		echo ''
		echo '    # Allow binding before tun interface exists'
		echo '    ip-freebind: yes'
		echo ''
		echo '    # DNS rebinding protection'
		echo '    private-address: 10.0.0.0/8'
		echo '    private-address: 172.16.0.0/12'
		echo '    private-address: 192.168.0.0/16'
		echo '    private-address: 169.254.0.0/16'
		echo '    private-address: 127.0.0.0/8'
		echo '    private-address: fd00::/8'
		echo '    private-address: fe80::/10'
		echo '    private-address: ::ffff:0:0/96'

		# IPv6 support
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo ''
			echo '    # IPv6 VPN support'
			echo '    interface: fd42:42:42:42::1'
			echo '    access-control: fd42:42:42:42::/112 allow'
			echo '    private-address: fd42:42:42:42::/112'
		fi

		# Disable remote-control (requires SSL certs on openSUSE)
		if [[ $OS == "opensuse" ]]; then
			echo ''
			echo 'remote-control:'
			echo '    control-enable: no'
		fi
	} >/etc/unbound/unbound.conf.d/openvpn.conf

	run_cmd "Enabling Unbound service" systemctl enable unbound
	run_cmd "Starting Unbound service" systemctl restart unbound

	# Validate Unbound is running
	for i in {1..10}; do
		if pgrep -x unbound >/dev/null; then
			return 0
		fi
		sleep 1
	done
	log_fatal "Unbound failed to start. Check 'journalctl -u unbound' for details."
}

function resolvePublicIP() {
	# IP version flags, we'll use as default the IPv4
	CURL_IP_VERSION_FLAG="-4"
	DIG_IP_VERSION_FLAG="-4"

	# Behind NAT, we'll default to the publicly reachable IPv4/IPv6.
	if [[ $IPV6_SUPPORT == "y" ]]; then
		CURL_IP_VERSION_FLAG=""
		DIG_IP_VERSION_FLAG="-6"
	fi

	# If there is no public ip yet, we'll try to solve it using: https://api.seeip.org
	if [[ -z $PUBLIC_IP ]]; then
		PUBLIC_IP=$(curl -f -m 5 -sS --retry 2 --retry-connrefused "$CURL_IP_VERSION_FLAG" https://api.seeip.org 2>/dev/null)
	fi

	# If there is no public ip yet, we'll try to solve it using: https://ifconfig.me
	if [[ -z $PUBLIC_IP ]]; then
		PUBLIC_IP=$(curl -f -m 5 -sS --retry 2 --retry-connrefused "$CURL_IP_VERSION_FLAG" https://ifconfig.me 2>/dev/null)
	fi

	# If there is no public ip yet, we'll try to solve it using: https://api.ipify.org
	if [[ -z $PUBLIC_IP ]]; then
		PUBLIC_IP=$(curl -f -m 5 -sS --retry 2 --retry-connrefused "$CURL_IP_VERSION_FLAG" https://api.ipify.org 2>/dev/null)
	fi

	# If there is no public ip yet, we'll try to solve it using: ns1.google.com
	if [[ -z $PUBLIC_IP ]]; then
		PUBLIC_IP=$(dig $DIG_IP_VERSION_FLAG TXT +short o-o.myaddr.l.google.com @ns1.google.com | tr -d '"')
	fi

	if [[ -z $PUBLIC_IP ]]; then
		log_fatal "Couldn't solve the public IP"
	fi

	echo "$PUBLIC_IP"
}

function installQuestions() {
	log_header "OpenVPN Installer"
	log_prompt "The git repository is available at: https://github.com/angristan/openvpn-install"

	log_prompt "I need to ask you a few questions before starting the setup."
	log_prompt "You can leave the default options and just press enter if you are okay with them."
	log_menu ""
	log_prompt "I need to know the IPv4 address of the network interface you want OpenVPN listening to."
	log_prompt "Unless your server is behind NAT, it should be your public IPv4 address."

	# Detect public IPv4 address and pre-fill for the user
	IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)

	if [[ -z $IP ]]; then
		# Detect public IPv6 address
		IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	APPROVE_IP=${APPROVE_IP:-n}
	if [[ $APPROVE_IP =~ n ]]; then
		read -rp "IP address: " -e -i "$IP" IP
	fi
	# If $IP is a private IP address, the server must be behind NAT
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		log_menu ""
		log_prompt "It seems this server is behind NAT. What is its public IPv4 address or hostname?"
		log_prompt "We need it for the clients to connect to the server."

		if [[ -z $ENDPOINT ]]; then
			DEFAULT_ENDPOINT=$(resolvePublicIP)
		fi

		until [[ $ENDPOINT != "" ]]; do
			read -rp "Public IPv4 address or hostname: " -e -i "$DEFAULT_ENDPOINT" ENDPOINT
		done
	fi

	log_menu ""
	log_prompt "Checking for IPv6 connectivity..."
	# "ping6" and "ping -6" availability varies depending on the distribution
	if type ping6 >/dev/null 2>&1; then
		PING6="ping6 -c3 ipv6.google.com > /dev/null 2>&1"
	else
		PING6="ping -6 -c3 ipv6.google.com > /dev/null 2>&1"
	fi
	if eval "$PING6"; then
		log_prompt "Your host appears to have IPv6 connectivity."
		SUGGESTION="y"
	else
		log_prompt "Your host does not appear to have IPv6 connectivity."
		SUGGESTION="n"
	fi
	log_menu ""
	# Ask the user if they want to enable IPv6 regardless its availability.
	until [[ $IPV6_SUPPORT =~ (y|n) ]]; do
		read -rp "Do you want to enable IPv6 support (NAT)? [y/n]: " -e -i $SUGGESTION IPV6_SUPPORT
	done
	log_menu ""
	log_prompt "What port do you want OpenVPN to listen to?"
	log_menu "   1) Default: 1194"
	log_menu "   2) Custom"
	log_menu "   3) Random [49152-65535]"
	until [[ $PORT_CHOICE =~ ^[1-3]$ ]]; do
		read -rp "Port choice [1-3]: " -e -i 1 PORT_CHOICE
	done
	case $PORT_CHOICE in
	1)
		PORT="1194"
		;;
	2)
		until [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
			read -rp "Custom port [1-65535]: " -e -i 1194 PORT
		done
		;;
	3)
		# Generate random number within private ports range
		PORT=$(shuf -i49152-65535 -n1)
		log_info "Random Port: $PORT"
		;;
	esac
	log_menu ""
	log_prompt "What protocol do you want OpenVPN to use?"
	log_prompt "UDP is faster. Unless it is not available, you shouldn't use TCP."
	log_menu "   1) UDP"
	log_menu "   2) TCP"
	until [[ $PROTOCOL_CHOICE =~ ^[1-2]$ ]]; do
		read -rp "Protocol [1-2]: " -e -i 1 PROTOCOL_CHOICE
	done
	case $PROTOCOL_CHOICE in
	1)
		PROTOCOL="udp"
		;;
	2)
		PROTOCOL="tcp"
		;;
	esac
	log_menu ""
	log_prompt "What DNS resolvers do you want to use with the VPN?"
	log_menu "   1) Current system resolvers (from /etc/resolv.conf)"
	log_menu "   2) Self-hosted DNS Resolver (Unbound)"
	log_menu "   3) Cloudflare (Anycast: worldwide)"
	log_menu "   4) Quad9 (Anycast: worldwide)"
	log_menu "   5) Quad9 uncensored (Anycast: worldwide)"
	log_menu "   6) FDN (France)"
	log_menu "   7) DNS.WATCH (Germany)"
	log_menu "   8) OpenDNS (Anycast: worldwide)"
	log_menu "   9) Google (Anycast: worldwide)"
	log_menu "   10) Yandex Basic (Russia)"
	log_menu "   11) AdGuard DNS (Anycast: worldwide)"
	log_menu "   12) NextDNS (Anycast: worldwide)"
	log_menu "   13) Custom"
	until [[ $DNS =~ ^[0-9]+$ ]] && [ "$DNS" -ge 1 ] && [ "$DNS" -le 13 ]; do
		read -rp "DNS [1-13]: " -e -i 3 DNS
		if [[ $DNS == 2 ]] && [[ -e /etc/unbound/unbound.conf ]]; then
			log_menu ""
			log_prompt "Unbound is already installed."
			log_prompt "You can allow the script to configure it in order to use it from your OpenVPN clients"
			log_prompt "We will simply add a second server to /etc/unbound/unbound.conf for the OpenVPN subnet."
			log_prompt "No changes are made to the current configuration."
			log_menu ""

			until [[ $CONTINUE =~ (y|n) ]]; do
				read -rp "Apply configuration changes to Unbound? [y/n]: " -e CONTINUE
			done
			if [[ $CONTINUE == "n" ]]; then
				# Break the loop and cleanup
				unset DNS
				unset CONTINUE
			fi
		elif [[ $DNS == "13" ]]; then
			until [[ $DNS1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "Primary DNS: " -e DNS1
			done
			until [[ $DNS2 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "Secondary DNS (optional): " -e DNS2
				if [[ $DNS2 == "" ]]; then
					break
				fi
			done
		fi
	done
	log_menu ""
	log_prompt "Do you want to allow a single .ovpn profile to be used on multiple devices simultaneously?"
	log_prompt "Note: Enabling this disables persistent IP addresses for clients."
	until [[ $MULTI_CLIENT =~ (y|n) ]]; do
		read -rp "Allow multiple devices per client? [y/n]: " -e -i n MULTI_CLIENT
	done
	log_menu ""
	log_prompt "Do you want to use compression? It is not recommended since the VORACLE attack makes use of it."
	until [[ $COMPRESSION_ENABLED =~ (y|n) ]]; do
		read -rp "Enable compression? [y/n]: " -e -i n COMPRESSION_ENABLED
	done
	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		log_prompt "Choose which compression algorithm you want to use: (they are ordered by efficiency)"
		log_menu "   1) LZ4-v2"
		log_menu "   2) LZ4"
		log_menu "   3) LZ0"
		until [[ $COMPRESSION_CHOICE =~ ^[1-3]$ ]]; do
			read -rp "Compression algorithm [1-3]: " -e -i 1 COMPRESSION_CHOICE
		done
		case $COMPRESSION_CHOICE in
		1)
			COMPRESSION_ALG="lz4-v2"
			;;
		2)
			COMPRESSION_ALG="lz4"
			;;
		3)
			COMPRESSION_ALG="lzo"
			;;
		esac
	fi
	log_menu ""
	log_prompt "Do you want to customize encryption settings?"
	log_prompt "Unless you know what you're doing, you should stick with the default parameters provided by the script."
	log_prompt "Note that whatever you choose, all the choices presented in the script are safe (unlike OpenVPN's defaults)."
	log_prompt "See https://github.com/angristan/openvpn-install#security-and-encryption to learn more."
	log_menu ""
	until [[ $CUSTOMIZE_ENC =~ (y|n) ]]; do
		read -rp "Customize encryption settings? [y/n]: " -e -i n CUSTOMIZE_ENC
	done
	if [[ $CUSTOMIZE_ENC == "n" ]]; then
		# Use default, sane and fast parameters
		CIPHER="AES-128-GCM"
		CERT_TYPE="1" # ECDSA
		CERT_CURVE="prime256v1"
		CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
		DH_TYPE="1" # ECDH
		DH_CURVE="prime256v1"
		HMAC_ALG="SHA256"
		TLS_SIG="1" # tls-crypt-v2
	else
		log_menu ""
		log_prompt "Choose which cipher you want to use for the data channel:"
		log_menu "   1) AES-128-GCM (recommended)"
		log_menu "   2) AES-192-GCM"
		log_menu "   3) AES-256-GCM"
		log_menu "   4) AES-128-CBC"
		log_menu "   5) AES-192-CBC"
		log_menu "   6) AES-256-CBC"
		log_menu "   7) CHACHA20-POLY1305 (requires OpenVPN 2.5+, good for devices without AES-NI)"
		until [[ $CIPHER_CHOICE =~ ^[1-7]$ ]]; do
			read -rp "Cipher [1-7]: " -e -i 1 CIPHER_CHOICE
		done
		case $CIPHER_CHOICE in
		1)
			CIPHER="AES-128-GCM"
			;;
		2)
			CIPHER="AES-192-GCM"
			;;
		3)
			CIPHER="AES-256-GCM"
			;;
		4)
			CIPHER="AES-128-CBC"
			;;
		5)
			CIPHER="AES-192-CBC"
			;;
		6)
			CIPHER="AES-256-CBC"
			;;
		7)
			CIPHER="CHACHA20-POLY1305"
			;;
		esac
		log_menu ""
		log_prompt "Choose what kind of certificate you want to use:"
		log_menu "   1) ECDSA (recommended)"
		log_menu "   2) RSA"
		until [[ $CERT_TYPE =~ ^[1-2]$ ]]; do
			read -rp "Certificate key type [1-2]: " -e -i 1 CERT_TYPE
		done
		case $CERT_TYPE in
		1)
			log_menu ""
			log_prompt "Choose which curve you want to use for the certificate's key:"
			log_menu "   1) prime256v1 (recommended)"
			log_menu "   2) secp384r1"
			log_menu "   3) secp521r1"
			until [[ $CERT_CURVE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "Curve [1-3]: " -e -i 1 CERT_CURVE_CHOICE
			done
			case $CERT_CURVE_CHOICE in
			1)
				CERT_CURVE="prime256v1"
				;;
			2)
				CERT_CURVE="secp384r1"
				;;
			3)
				CERT_CURVE="secp521r1"
				;;
			esac
			;;
		2)
			log_menu ""
			log_prompt "Choose which size you want to use for the certificate's RSA key:"
			log_menu "   1) 2048 bits (recommended)"
			log_menu "   2) 3072 bits"
			log_menu "   3) 4096 bits"
			until [[ $RSA_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "RSA key size [1-3]: " -e -i 1 RSA_KEY_SIZE_CHOICE
			done
			case $RSA_KEY_SIZE_CHOICE in
			1)
				RSA_KEY_SIZE="2048"
				;;
			2)
				RSA_KEY_SIZE="3072"
				;;
			3)
				RSA_KEY_SIZE="4096"
				;;
			esac
			;;
		esac
		log_menu ""
		log_prompt "Choose which cipher you want to use for the control channel:"
		case $CERT_TYPE in
		1)
			log_menu "   1) ECDHE-ECDSA-AES-128-GCM-SHA256 (recommended)"
			log_menu "   2) ECDHE-ECDSA-AES-256-GCM-SHA384"
			log_menu "   3) ECDHE-ECDSA-CHACHA20-POLY1305 (requires OpenVPN 2.5+)"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "Control channel cipher [1-3]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
				;;
			3)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256"
				;;
			esac
			;;
		2)
			log_menu "   1) ECDHE-RSA-AES-128-GCM-SHA256 (recommended)"
			log_menu "   2) ECDHE-RSA-AES-256-GCM-SHA384"
			log_menu "   3) ECDHE-RSA-CHACHA20-POLY1305 (requires OpenVPN 2.5+)"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "Control channel cipher [1-3]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"
				;;
			3)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256"
				;;
			esac
			;;
		esac
		log_menu ""
		log_prompt "Choose what kind of Diffie-Hellman key you want to use:"
		log_menu "   1) ECDH (recommended)"
		log_menu "   2) DH"
		until [[ $DH_TYPE =~ [1-2] ]]; do
			read -rp "DH key type [1-2]: " -e -i 1 DH_TYPE
		done
		case $DH_TYPE in
		1)
			log_menu ""
			log_prompt "Choose which curve you want to use for the ECDH key:"
			log_menu "   1) prime256v1 (recommended)"
			log_menu "   2) secp384r1"
			log_menu "   3) secp521r1"
			while [[ $DH_CURVE_CHOICE != "1" && $DH_CURVE_CHOICE != "2" && $DH_CURVE_CHOICE != "3" ]]; do
				read -rp "Curve [1-3]: " -e -i 1 DH_CURVE_CHOICE
			done
			case $DH_CURVE_CHOICE in
			1)
				DH_CURVE="prime256v1"
				;;
			2)
				DH_CURVE="secp384r1"
				;;
			3)
				DH_CURVE="secp521r1"
				;;
			esac
			;;
		2)
			log_menu ""
			log_prompt "Choose what size of Diffie-Hellman key you want to use:"
			log_menu "   1) 2048 bits (recommended)"
			log_menu "   2) 3072 bits"
			log_menu "   3) 4096 bits"
			until [[ $DH_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "DH key size [1-3]: " -e -i 1 DH_KEY_SIZE_CHOICE
			done
			case $DH_KEY_SIZE_CHOICE in
			1)
				DH_KEY_SIZE="2048"
				;;
			2)
				DH_KEY_SIZE="3072"
				;;
			3)
				DH_KEY_SIZE="4096"
				;;
			esac
			;;
		esac
		log_menu ""
		# The "auth" options behaves differently with AEAD ciphers (GCM, ChaCha20-Poly1305)
		if [[ $CIPHER =~ CBC$ ]]; then
			log_prompt "The digest algorithm authenticates data channel packets and tls-auth packets from the control channel."
		elif [[ $CIPHER =~ GCM$ ]] || [[ $CIPHER == "CHACHA20-POLY1305" ]]; then
			log_prompt "The digest algorithm authenticates tls-auth packets from the control channel."
		fi
		log_prompt "Which digest algorithm do you want to use for HMAC?"
		log_menu "   1) SHA-256 (recommended)"
		log_menu "   2) SHA-384"
		log_menu "   3) SHA-512"
		until [[ $HMAC_ALG_CHOICE =~ ^[1-3]$ ]]; do
			read -rp "Digest algorithm [1-3]: " -e -i 1 HMAC_ALG_CHOICE
		done
		case $HMAC_ALG_CHOICE in
		1)
			HMAC_ALG="SHA256"
			;;
		2)
			HMAC_ALG="SHA384"
			;;
		3)
			HMAC_ALG="SHA512"
			;;
		esac
		log_menu ""
		log_prompt "You can add an additional layer of security to the control channel."
		log_menu "   1) tls-crypt-v2 (recommended): Encrypts control channel, unique key per client"
		log_menu "   2) tls-crypt: Encrypts control channel, shared key for all clients"
		log_menu "   3) tls-auth: Authenticates control channel, no encryption"
		until [[ $TLS_SIG =~ ^[1-3]$ ]]; do
			read -rp "Control channel additional security mechanism [1-3]: " -e -i 1 TLS_SIG
		done
	fi
	log_menu ""
	log_prompt "Okay, that was all I needed. We are ready to setup your OpenVPN server now."
	log_prompt "You will be able to generate a client at the end of the installation."
	APPROVE_INSTALL=${APPROVE_INSTALL:-n}
	if [[ $APPROVE_INSTALL =~ n ]]; then
		read -n1 -r -p "Press any key to continue..."
	fi
}

function installOpenVPN() {
	if [[ $AUTO_INSTALL == "y" ]]; then
		# Set default choices so that no questions will be asked.
		APPROVE_INSTALL=${APPROVE_INSTALL:-y}
		APPROVE_IP=${APPROVE_IP:-y}
		IPV6_SUPPORT=${IPV6_SUPPORT:-n}
		PORT_CHOICE=${PORT_CHOICE:-1}
		PROTOCOL_CHOICE=${PROTOCOL_CHOICE:-1}
		DNS=${DNS:-3}
		COMPRESSION_ENABLED=${COMPRESSION_ENABLED:-n}
		MULTI_CLIENT=${MULTI_CLIENT:-n}
		CUSTOMIZE_ENC=${CUSTOMIZE_ENC:-n}
		CLIENT=${CLIENT:-client}
		PASS=${PASS:-1}
		CLIENT_CERT_DURATION_DAYS=${CLIENT_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}
		SERVER_CERT_DURATION_DAYS=${SERVER_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}
		CONTINUE=${CONTINUE:-y}
		NEW_CLIENT=${NEW_CLIENT:-y}

		if [[ -z $ENDPOINT ]]; then
			ENDPOINT=$(resolvePublicIP)
		fi

		# Log auto-install mode and parameters
		log_info "=== OpenVPN Auto-Install ==="
		log_info "Running in auto-install mode with the following settings:"
		log_info "  ENDPOINT=$ENDPOINT"
		log_info "  IPV6_SUPPORT=$IPV6_SUPPORT"
		log_info "  PORT_CHOICE=$PORT_CHOICE"
		log_info "  PROTOCOL_CHOICE=$PROTOCOL_CHOICE"
		log_info "  DNS=$DNS"
		log_info "  COMPRESSION_ENABLED=$COMPRESSION_ENABLED"
		log_info "  MULTI_CLIENT=$MULTI_CLIENT"
		log_info "  CUSTOMIZE_ENC=$CUSTOMIZE_ENC"
		log_info "  CLIENT=$CLIENT"
		log_info "  PASS=$PASS"
		log_info "  CLIENT_CERT_DURATION_DAYS=$CLIENT_CERT_DURATION_DAYS"
		log_info "  SERVER_CERT_DURATION_DAYS=$SERVER_CERT_DURATION_DAYS"
	fi

	# Run setup questions first, and set other variables if auto-install
	installQuestions

	# Get the "public" interface from the default route
	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
	if [[ -z $NIC ]] && [[ $IPV6_SUPPORT == 'y' ]]; then
		NIC=$(ip -6 route show default | sed -ne 's/^default .* dev \([^ ]*\) .*$/\1/p')
	fi

	# $NIC can not be empty for script rm-openvpn-rules.sh
	if [[ -z $NIC ]]; then
		log_warn "Could not detect public interface."
		log_info "This needs for setup MASQUERADE."
		until [[ $CONTINUE =~ (y|n) ]]; do
			read -rp "Continue? [y/n]: " -e CONTINUE
		done
		if [[ $CONTINUE == "n" ]]; then
			exit 1
		fi
	fi

	# If OpenVPN isn't installed yet, install it. This script is more-or-less
	# idempotent on multiple runs, but will only install OpenVPN from upstream
	# the first time.
	if [[ ! -e /etc/openvpn/server/server.conf ]]; then
		log_header "Installing OpenVPN"

		# Setup official OpenVPN repository for latest versions
		installOpenVPNRepo

		log_info "Installing OpenVPN and dependencies..."
		if [[ $OS =~ (debian|ubuntu) ]]; then
			run_cmd_fatal "Installing OpenVPN" apt-get install -y openvpn iptables openssl curl ca-certificates tar dnsutils
		elif [[ $OS == 'centos' ]]; then
			run_cmd_fatal "Installing OpenVPN" yum install -y openvpn iptables openssl ca-certificates curl tar bind-utils 'policycoreutils-python*'
		elif [[ $OS == 'oracle' ]]; then
			run_cmd_fatal "Installing OpenVPN" yum install -y openvpn iptables openssl ca-certificates curl tar bind-utils policycoreutils-python-utils
		elif [[ $OS == 'amzn2023' ]]; then
			run_cmd_fatal "Installing OpenVPN" dnf install -y openvpn iptables openssl ca-certificates curl tar bind-utils
		elif [[ $OS == 'fedora' ]]; then
			run_cmd_fatal "Installing OpenVPN" dnf install -y openvpn iptables openssl ca-certificates curl tar bind-utils policycoreutils-python-utils
		elif [[ $OS == 'opensuse' ]]; then
			run_cmd_fatal "Installing OpenVPN" zypper install -y openvpn iptables openssl ca-certificates curl tar bind-utils
		elif [[ $OS == 'arch' ]]; then
			run_cmd_fatal "Installing OpenVPN" pacman --needed --noconfirm -Syu openvpn iptables openssl ca-certificates curl tar bind
		fi

		# Verify ChaCha20-Poly1305 compatibility if selected
		if [[ $CIPHER == "CHACHA20-POLY1305" ]] || [[ $CC_CIPHER =~ CHACHA20 ]]; then
			local installed_version
			installed_version=$(openvpn --version 2>/dev/null | head -1 | awk '{print $2}')
			if ! openvpnVersionAtLeast "2.5"; then
				log_fatal "ChaCha20-Poly1305 requires OpenVPN 2.5 or later. Installed version: $installed_version"
			fi
			log_info "OpenVPN version supports ChaCha20-Poly1305"
		fi

		# Check Data Channel Offload (DCO) availability
		if isDCOAvailable; then
			# Check if configuration is DCO-compatible
			if [[ $PROTOCOL == "udp" ]] && [[ $COMPRESSION_ENABLED == "n" ]] && [[ $CIPHER =~ (GCM|CHACHA20-POLY1305) ]]; then
				log_info "Data Channel Offload (DCO) is available and will be used for improved performance"
			else
				log_info "Data Channel Offload (DCO) is available but not enabled (requires UDP, AEAD cipher, no compression)"
			fi
		else
			log_info "Data Channel Offload (DCO) is not available (requires OpenVPN 2.6+ and kernel support)"
		fi

		# Create the server directory (OpenVPN 2.4+ directory structure)
		run_cmd_fatal "Creating server directory" mkdir -p /etc/openvpn/server
	fi

	# Determine which user/group OpenVPN should run as
	# - Fedora/RHEL/Amazon create 'openvpn' user with 'openvpn' group
	# - Arch creates 'openvpn' user with 'network' group
	# - Debian/Ubuntu/openSUSE don't create a dedicated user, use 'nobody'
	#
	# Also check if the systemd service file already handles user/group switching.
	# If so, we shouldn't add user/group to config (would cause double privilege drop).
	SYSTEMD_HANDLES_USER=false
	for service_file in /usr/lib/systemd/system/openvpn-server@.service /lib/systemd/system/openvpn-server@.service; do
		if [[ -f "$service_file" ]] && grep -q "^User=" "$service_file"; then
			SYSTEMD_HANDLES_USER=true
			break
		fi
	done

	if id openvpn &>/dev/null; then
		OPENVPN_USER=openvpn
		# Get the openvpn user's primary group (e.g., 'openvpn' on Fedora, 'network' on Arch)
		OPENVPN_GROUP=$(id -gn openvpn 2>/dev/null || echo openvpn)
	else
		OPENVPN_USER=nobody
		if grep -qs "^nogroup:" /etc/group; then
			OPENVPN_GROUP=nogroup
		else
			OPENVPN_GROUP=nobody
		fi
	fi

	# Install the latest version of easy-rsa from source, if not already installed.
	if [[ ! -d /etc/openvpn/server/easy-rsa/ ]]; then
		run_cmd_fatal "Downloading Easy-RSA v${EASYRSA_VERSION}" curl -fL --retry 5 -o ~/easy-rsa.tgz "https://github.com/OpenVPN/easy-rsa/releases/download/v${EASYRSA_VERSION}/EasyRSA-${EASYRSA_VERSION}.tgz"
		log_info "Verifying Easy-RSA checksum..."
		CHECKSUM_OUTPUT=$(echo "${EASYRSA_SHA256}  $HOME/easy-rsa.tgz" | sha256sum -c 2>&1) || {
			_log_to_file "[CHECKSUM] $CHECKSUM_OUTPUT"
			run_cmd "Cleaning up failed download" rm -f ~/easy-rsa.tgz
			log_fatal "SHA256 checksum verification failed for easy-rsa download!"
		}
		_log_to_file "[CHECKSUM] $CHECKSUM_OUTPUT"
		run_cmd_fatal "Creating Easy-RSA directory" mkdir -p /etc/openvpn/server/easy-rsa
		run_cmd_fatal "Extracting Easy-RSA" tar xzf ~/easy-rsa.tgz --strip-components=1 --no-same-owner --directory /etc/openvpn/server/easy-rsa
		run_cmd "Cleaning up archive" rm -f ~/easy-rsa.tgz

		cd /etc/openvpn/server/easy-rsa/ || return
		case $CERT_TYPE in
		1)
			echo "set_var EASYRSA_ALGO ec" >vars
			echo "set_var EASYRSA_CURVE $CERT_CURVE" >>vars
			;;
		2)
			echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" >vars
			;;
		esac

		# Generate a random, alphanumeric identifier of 16 characters for CN and one for server name
		SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_CN" >SERVER_CN_GENERATED
		SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_NAME" >SERVER_NAME_GENERATED

		# Create the PKI, set up the CA, the DH params and the server certificate
		log_info "Initializing PKI..."
		run_cmd_fatal "Initializing PKI" ./easyrsa init-pki
		export EASYRSA_CA_EXPIRE=$DEFAULT_CERT_VALIDITY_DURATION_DAYS
		log_info "Building CA..."
		run_cmd_fatal "Building CA" ./easyrsa --batch --req-cn="$SERVER_CN" build-ca nopass

		if [[ $DH_TYPE == "2" ]]; then
			# ECDH keys are generated on-the-fly so we don't need to generate them beforehand
			run_cmd_fatal "Generating DH parameters (this may take a while)" openssl dhparam -out dh.pem "$DH_KEY_SIZE"
		fi

		export EASYRSA_CERT_EXPIRE=${SERVER_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}
		log_info "Building server certificate..."
		run_cmd_fatal "Building server certificate" ./easyrsa --batch build-server-full "$SERVER_NAME" nopass
		export EASYRSA_CRL_DAYS=$DEFAULT_CRL_VALIDITY_DURATION_DAYS
		run_cmd_fatal "Generating CRL" ./easyrsa gen-crl

		log_info "Generating TLS key..."
		case $TLS_SIG in
		1)
			# Generate tls-crypt-v2 server key
			run_cmd_fatal "Generating tls-crypt-v2 server key" openvpn --genkey tls-crypt-v2-server /etc/openvpn/server/tls-crypt-v2.key
			;;
		2)
			# Generate tls-crypt key
			run_cmd_fatal "Generating tls-crypt key" openvpn --genkey secret /etc/openvpn/server/tls-crypt.key
			;;
		3)
			# Generate tls-auth key
			run_cmd_fatal "Generating tls-auth key" openvpn --genkey secret /etc/openvpn/server/tls-auth.key
			;;
		esac
	else
		# If easy-rsa is already installed, grab the generated SERVER_NAME
		# for client configs
		cd /etc/openvpn/server/easy-rsa/ || return
		SERVER_NAME=$(cat SERVER_NAME_GENERATED)
	fi

	# Move all the generated files
	log_info "Copying certificates..."
	run_cmd_fatal "Copying certificates to /etc/openvpn/server" cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server
	if [[ $DH_TYPE == "2" ]]; then
		run_cmd_fatal "Copying DH parameters" cp dh.pem /etc/openvpn/server
	fi

	# Make cert revocation list readable for non-root
	run_cmd "Setting CRL permissions" chmod 644 /etc/openvpn/server/crl.pem

	# Generate server.conf
	log_info "Generating server configuration..."
	echo "port $PORT" >/etc/openvpn/server/server.conf
	if [[ $IPV6_SUPPORT == 'n' ]]; then
		echo "proto $PROTOCOL" >>/etc/openvpn/server/server.conf
	elif [[ $IPV6_SUPPORT == 'y' ]]; then
		echo "proto ${PROTOCOL}6" >>/etc/openvpn/server/server.conf
	fi

	if [[ $MULTI_CLIENT == "y" ]]; then
		echo "duplicate-cn" >>/etc/openvpn/server/server.conf
	fi

	echo "dev tun" >>/etc/openvpn/server/server.conf
	# Only add user/group if systemd doesn't handle it (avoids double privilege drop)
	if [[ $SYSTEMD_HANDLES_USER == "false" ]]; then
		echo "user $OPENVPN_USER
group $OPENVPN_GROUP" >>/etc/openvpn/server/server.conf
	fi
	echo "persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0" >>/etc/openvpn/server/server.conf

	# ifconfig-pool-persist is incompatible with duplicate-cn
	if [[ $MULTI_CLIENT != "y" ]]; then
		echo "ifconfig-pool-persist ipp.txt" >>/etc/openvpn/server/server.conf
	fi

	# DNS resolvers
	case $DNS in
	1) # Current system resolvers
		# Locate the proper resolv.conf
		# Needed for systems running systemd-resolved
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		sed -ne 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*$/\1/p' $RESOLVCONF | while read -r line; do
			# Copy, if it's a IPv4 |or| if IPv6 is enabled, IPv4/IPv6 does not matter
			if [[ $line =~ ^[0-9.]*$ ]] || [[ $IPV6_SUPPORT == 'y' ]]; then
				echo "push \"dhcp-option DNS $line\"" >>/etc/openvpn/server/server.conf
			fi
		done
		;;
	2) # Self-hosted DNS resolver (Unbound)
		echo 'push "dhcp-option DNS 10.8.0.1"' >>/etc/openvpn/server/server.conf
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'push "dhcp-option DNS fd42:42:42:42::1"' >>/etc/openvpn/server/server.conf
		fi
		;;
	3) # Cloudflare
		echo 'push "dhcp-option DNS 1.0.0.1"' >>/etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 1.1.1.1"' >>/etc/openvpn/server/server.conf
		;;
	4) # Quad9
		echo 'push "dhcp-option DNS 9.9.9.9"' >>/etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 149.112.112.112"' >>/etc/openvpn/server/server.conf
		;;
	5) # Quad9 uncensored
		echo 'push "dhcp-option DNS 9.9.9.10"' >>/etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 149.112.112.10"' >>/etc/openvpn/server/server.conf
		;;
	6) # FDN
		echo 'push "dhcp-option DNS 80.67.169.40"' >>/etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 80.67.169.12"' >>/etc/openvpn/server/server.conf
		;;
	7) # DNS.WATCH
		echo 'push "dhcp-option DNS 84.200.69.80"' >>/etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 84.200.70.40"' >>/etc/openvpn/server/server.conf
		;;
	8) # OpenDNS
		echo 'push "dhcp-option DNS 208.67.222.222"' >>/etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >>/etc/openvpn/server/server.conf
		;;
	9) # Google
		echo 'push "dhcp-option DNS 8.8.8.8"' >>/etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >>/etc/openvpn/server/server.conf
		;;
	10) # Yandex Basic
		echo 'push "dhcp-option DNS 77.88.8.8"' >>/etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 77.88.8.1"' >>/etc/openvpn/server/server.conf
		;;
	11) # AdGuard DNS
		echo 'push "dhcp-option DNS 94.140.14.14"' >>/etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 94.140.15.15"' >>/etc/openvpn/server/server.conf
		;;
	12) # NextDNS
		echo 'push "dhcp-option DNS 45.90.28.167"' >>/etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 45.90.30.167"' >>/etc/openvpn/server/server.conf
		;;
	13) # Custom DNS
		echo "push \"dhcp-option DNS $DNS1\"" >>/etc/openvpn/server/server.conf
		if [[ $DNS2 != "" ]]; then
			echo "push \"dhcp-option DNS $DNS2\"" >>/etc/openvpn/server/server.conf
		fi
		;;
	esac
	echo 'push "redirect-gateway def1 bypass-dhcp"' >>/etc/openvpn/server/server.conf

	# IPv6 network settings if needed
	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo 'server-ipv6 fd42:42:42:42::/112
tun-ipv6
push tun-ipv6
push "route-ipv6 2000::/3"
push "redirect-gateway ipv6"' >>/etc/openvpn/server/server.conf
	fi

	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "compress $COMPRESSION_ALG" >>/etc/openvpn/server/server.conf
	fi

	if [[ $DH_TYPE == "1" ]]; then
		echo "dh none" >>/etc/openvpn/server/server.conf
		echo "ecdh-curve $DH_CURVE" >>/etc/openvpn/server/server.conf
	elif [[ $DH_TYPE == "2" ]]; then
		echo "dh dh.pem" >>/etc/openvpn/server/server.conf
	fi

	case $TLS_SIG in
	1)
		echo "tls-crypt-v2 tls-crypt-v2.key" >>/etc/openvpn/server/server.conf
		;;
	2)
		echo "tls-crypt tls-crypt.key" >>/etc/openvpn/server/server.conf
		;;
	3)
		echo "tls-auth tls-auth.key 0" >>/etc/openvpn/server/server.conf
		;;
	esac

	echo "crl-verify crl.pem
ca ca.crt
cert $SERVER_NAME.crt
key $SERVER_NAME.key
auth $HMAC_ALG
cipher $CIPHER
ignore-unknown-option data-ciphers
data-ciphers $CIPHER
ncp-ciphers $CIPHER
tls-server
tls-version-min 1.2
remote-cert-tls client
tls-cipher $CC_CIPHER
client-config-dir ccd
status /var/log/openvpn/status.log
verb 3" >>/etc/openvpn/server/server.conf

	# Create client-config-dir dir
	run_cmd_fatal "Creating client config directory" mkdir -p /etc/openvpn/server/ccd
	# Create log dir
	run_cmd_fatal "Creating log directory" mkdir -p /var/log/openvpn

	# On distros that use a dedicated OpenVPN user (not "nobody"), e.g., Fedora, RHEL, Arch,
	# set ownership so OpenVPN can read config/certs and write to log directory
	if [[ $OPENVPN_USER != "nobody" ]]; then
		log_info "Setting ownership for OpenVPN user..."
		chown -R "$OPENVPN_USER:$OPENVPN_GROUP" /etc/openvpn/server
		chown "$OPENVPN_USER:$OPENVPN_GROUP" /var/log/openvpn
	fi

	# Enable routing
	log_info "Enabling IP forwarding..."
	run_cmd_fatal "Creating sysctl.d directory" mkdir -p /etc/sysctl.d
	echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo 'net.ipv6.conf.all.forwarding=1' >>/etc/sysctl.d/99-openvpn.conf
	fi
	# Apply sysctl rules
	run_cmd "Applying sysctl rules" sysctl --system

	# If SELinux is enabled and a custom port was selected, we need this
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ $PORT != '1194' ]]; then
				run_cmd "Configuring SELinux port" semanage port -a -t openvpn_port_t -p "$PROTOCOL" "$PORT"
			fi
		fi
	fi

	# Finally, restart and enable OpenVPN
	# OpenVPN 2.4+ uses openvpn-server@.service with config in /etc/openvpn/server/
	log_info "Configuring OpenVPN service..."

	# Find the service file (location and name vary by distro)
	# Modern distros: openvpn-server@.service in /usr/lib/systemd/system/ or /lib/systemd/system/
	# openSUSE: openvpn@.service (old-style) that we need to adapt
	if [[ -f /usr/lib/systemd/system/openvpn-server@.service ]]; then
		SERVICE_SOURCE="/usr/lib/systemd/system/openvpn-server@.service"
	elif [[ -f /lib/systemd/system/openvpn-server@.service ]]; then
		SERVICE_SOURCE="/lib/systemd/system/openvpn-server@.service"
	elif [[ -f /usr/lib/systemd/system/openvpn@.service ]]; then
		# openSUSE uses old-style service, we'll create our own openvpn-server@.service
		SERVICE_SOURCE="/usr/lib/systemd/system/openvpn@.service"
	elif [[ -f /lib/systemd/system/openvpn@.service ]]; then
		SERVICE_SOURCE="/lib/systemd/system/openvpn@.service"
	else
		log_fatal "Could not find openvpn-server@.service or openvpn@.service file"
	fi

	# Don't modify package-provided service, copy to /etc/systemd/system/
	run_cmd_fatal "Copying OpenVPN service file" cp "$SERVICE_SOURCE" /etc/systemd/system/openvpn-server@.service

	# Workaround to fix OpenVPN service on OpenVZ
	run_cmd "Patching service file (LimitNPROC)" sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn-server@.service

	# Ensure the service uses /etc/openvpn/server/ as working directory
	# This is needed for openSUSE which uses old-style paths by default
	if grep -q "cd /etc/openvpn/" /etc/systemd/system/openvpn-server@.service; then
		run_cmd "Patching service file (paths)" sed -i 's|/etc/openvpn/|/etc/openvpn/server/|g' /etc/systemd/system/openvpn-server@.service
	fi

	run_cmd "Reloading systemd" systemctl daemon-reload
	run_cmd "Enabling OpenVPN service" systemctl enable openvpn-server@server
	run_cmd "Starting OpenVPN service" systemctl restart openvpn-server@server

	if [[ $DNS == 2 ]]; then
		installUnbound
	fi

	# Configure firewall rules
	log_info "Configuring firewall rules..."

	if systemctl is-active --quiet firewalld; then
		# Use firewalld native commands for systems with firewalld active
		log_info "firewalld detected, using firewall-cmd..."
		run_cmd "Adding OpenVPN port to firewalld" firewall-cmd --permanent --add-port="$PORT/$PROTOCOL"
		run_cmd "Adding masquerade to firewalld" firewall-cmd --permanent --add-masquerade

		# Add rich rules for VPN traffic (source-based rules work reliably with dynamic tun0 interface)
		run_cmd "Adding VPN subnet rule" firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.8.0.0/24" accept'

		if [[ $IPV6_SUPPORT == 'y' ]]; then
			run_cmd "Adding IPv6 source rule" firewall-cmd --permanent --add-rich-rule='rule family="ipv6" source address="fd42:42:42:42::/112" accept'
		fi

		run_cmd "Reloading firewalld" firewall-cmd --reload
	else
		# Use iptables for systems without firewalld
		run_cmd_fatal "Creating iptables directory" mkdir -p /etc/iptables

		# Script to add rules
		echo "#!/bin/sh
iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -I INPUT 1 -i tun0 -j ACCEPT
iptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
iptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
iptables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/add-openvpn-rules.sh

		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo "ip6tables -t nat -I POSTROUTING 1 -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -I INPUT 1 -i tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
ip6tables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/add-openvpn-rules.sh
		fi

		# Script to remove rules
		echo "#!/bin/sh
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -D INPUT -i tun0 -j ACCEPT
iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/rm-openvpn-rules.sh

		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo "ip6tables -t nat -D POSTROUTING -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -D INPUT -i tun0 -j ACCEPT
ip6tables -D FORWARD -i $NIC -o tun0 -j ACCEPT
ip6tables -D FORWARD -i tun0 -o $NIC -j ACCEPT
ip6tables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/rm-openvpn-rules.sh
		fi

		run_cmd "Making add-openvpn-rules.sh executable" chmod +x /etc/iptables/add-openvpn-rules.sh
		run_cmd "Making rm-openvpn-rules.sh executable" chmod +x /etc/iptables/rm-openvpn-rules.sh

		# Handle the rules via a systemd script
		echo "[Unit]
Description=iptables rules for OpenVPN
After=firewalld.service
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" >/etc/systemd/system/iptables-openvpn.service

		# Enable service and apply rules
		run_cmd "Reloading systemd" systemctl daemon-reload
		run_cmd "Enabling iptables service" systemctl enable iptables-openvpn
		run_cmd "Starting iptables service" systemctl start iptables-openvpn
	fi

	# If the server is behind a NAT, use the correct IP address for the clients to connect to
	if [[ $ENDPOINT != "" ]]; then
		IP=$ENDPOINT
	fi

	# client-template.txt is created so we have a template to add further users later
	log_info "Creating client template..."
	echo "client" >/etc/openvpn/server/client-template.txt
	if [[ $PROTOCOL == 'udp' ]]; then
		echo "proto udp" >>/etc/openvpn/server/client-template.txt
		echo "explicit-exit-notify" >>/etc/openvpn/server/client-template.txt
	elif [[ $PROTOCOL == 'tcp' ]]; then
		echo "proto tcp-client" >>/etc/openvpn/server/client-template.txt
	fi
	echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name $SERVER_NAME name
auth $HMAC_ALG
auth-nocache
cipher $CIPHER
ignore-unknown-option data-ciphers
data-ciphers $CIPHER
ncp-ciphers $CIPHER
tls-client
tls-version-min 1.2
tls-cipher $CC_CIPHER
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns # Prevent Windows 10 DNS leak
verb 3" >>/etc/openvpn/server/client-template.txt

	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "compress $COMPRESSION_ALG" >>/etc/openvpn/server/client-template.txt
	fi

	# Generate the custom client.ovpn
	if [[ $NEW_CLIENT == "n" ]]; then
		log_info "No clients added. To add clients, simply run the script again."
	else
		log_info "Generating first client certificate..."
		newClient
		log_success "If you want to add more clients, you simply need to run this script another time!"
	fi
}

# Helper function to get the home directory for storing client configs
function getHomeDir() {
	local client="$1"
	if [ -d "/home/${client}" ]; then
		echo "/home/${client}"
	elif [ "${SUDO_USER}" ]; then
		if [ "${SUDO_USER}" == "root" ]; then
			echo "/root"
		else
			echo "/home/${SUDO_USER}"
		fi
	else
		echo "/root"
	fi
}

# Helper function to get the owner of a client config file (if client matches a system user)
function getClientOwner() {
	local client="$1"
	# Check if client name corresponds to an existing system user with a home directory
	if id "$client" &>/dev/null && [ -d "/home/${client}" ]; then
		echo "${client}"
	elif [ "${SUDO_USER}" ] && [ "${SUDO_USER}" != "root" ]; then
		echo "${SUDO_USER}"
	fi
}

# Helper function to set proper ownership and permissions on client config file
function setClientConfigPermissions() {
	local filepath="$1"
	local owner="$2"

	if [[ -n "$owner" ]]; then
		local owner_group
		owner_group=$(id -gn "$owner")
		chmod go-rw "$filepath"
		chown "$owner:$owner_group" "$filepath"
	fi
}

# Helper function to write client config file with proper path and permissions
# Usage: writeClientConfig <client_name>
# Uses CLIENT_FILEPATH env var if set, otherwise defaults to home directory
# Side effects: sets GENERATED_CONFIG_PATH global variable with the final path
function writeClientConfig() {
	local client="$1"
	local clientFilePath

	# Determine output file path
	if [[ -n "$CLIENT_FILEPATH" ]]; then
		clientFilePath="$CLIENT_FILEPATH"
		# Ensure parent directory exists for custom paths
		local parentDir
		parentDir=$(dirname "$clientFilePath")
		if [[ ! -d "$parentDir" ]]; then
			run_cmd_fatal "Creating directory $parentDir" mkdir -p "$parentDir"
		fi
	else
		local homeDir
		homeDir=$(getHomeDir "$client")
		clientFilePath="$homeDir/$client.ovpn"
	fi

	# Generate the .ovpn config file
	generateClientConfig "$client" "$clientFilePath"

	# Set proper ownership and permissions if client matches a system user
	local clientOwner
	clientOwner=$(getClientOwner "$client")
	setClientConfigPermissions "$clientFilePath" "$clientOwner"

	# Export path for caller to use
	GENERATED_CONFIG_PATH="$clientFilePath"
}

# Helper function to regenerate the CRL after certificate changes
function regenerateCRL() {
	export EASYRSA_CRL_DAYS=$DEFAULT_CRL_VALIDITY_DURATION_DAYS
	run_cmd_fatal "Regenerating CRL" ./easyrsa gen-crl
	run_cmd "Removing old CRL" rm -f /etc/openvpn/server/crl.pem
	run_cmd_fatal "Copying new CRL" cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
	run_cmd "Setting CRL permissions" chmod 644 /etc/openvpn/server/crl.pem
}

# Helper function to generate .ovpn client config file
# Usage: generateClientConfig <client_name> <filepath>
function generateClientConfig() {
	local client="$1"
	local filepath="$2"

	# Determine if we use tls-crypt-v2, tls-crypt, or tls-auth
	local tls_sig=""
	if grep -qs "^tls-crypt-v2" /etc/openvpn/server/server.conf; then
		tls_sig="1"
	elif grep -qs "^tls-crypt" /etc/openvpn/server/server.conf; then
		tls_sig="2"
	elif grep -qs "^tls-auth" /etc/openvpn/server/server.conf; then
		tls_sig="3"
	fi

	# Generate the custom client.ovpn
	run_cmd "Creating client config" cp /etc/openvpn/server/client-template.txt "$filepath"
	{
		echo "<ca>"
		cat "/etc/openvpn/server/easy-rsa/pki/ca.crt"
		echo "</ca>"

		echo "<cert>"
		awk '/BEGIN/,/END CERTIFICATE/' "/etc/openvpn/server/easy-rsa/pki/issued/$client.crt"
		echo "</cert>"

		echo "<key>"
		cat "/etc/openvpn/server/easy-rsa/pki/private/$client.key"
		echo "</key>"

		case $tls_sig in
		1)
			# Generate per-client tls-crypt-v2 key using secure temp file
			tls_crypt_v2_tmpfile=$(mktemp)
			if ! openvpn --tls-crypt-v2 /etc/openvpn/server/tls-crypt-v2.key \
				--genkey tls-crypt-v2-client "$tls_crypt_v2_tmpfile"; then
				rm -f "$tls_crypt_v2_tmpfile"
				log_error "Failed to generate tls-crypt-v2 client key"
				exit 1
			fi
			echo "<tls-crypt-v2>"
			cat "$tls_crypt_v2_tmpfile"
			echo "</tls-crypt-v2>"
			rm -f "$tls_crypt_v2_tmpfile"
			;;
		2)
			echo "<tls-crypt>"
			cat /etc/openvpn/server/tls-crypt.key
			echo "</tls-crypt>"
			;;
		3)
			echo "key-direction 1"
			echo "<tls-auth>"
			cat /etc/openvpn/server/tls-auth.key
			echo "</tls-auth>"
			;;
		esac
	} >>"$filepath"
}

# Helper function to list valid clients and select one
# Arguments: show_expiry (optional, "true" to show expiry info)
# Sets global variables:
#   CLIENT - the selected client name
#   CLIENTNUMBER - the selected client number (1-based index)
#   NUMBEROFCLIENTS - total count of valid clients
function selectClient() {
	local show_expiry="${1:-false}"
	local client_number

	NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ $NUMBEROFCLIENTS == '0' ]]; then
		log_fatal "You have no existing clients!"
	fi

	# If CLIENT is set, validate it exists as a valid client
	if [[ -n $CLIENT ]]; then
		if tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | grep -qx "$CLIENT"; then
			return
		else
			log_fatal "Client '$CLIENT' not found or not valid"
		fi
	fi

	if [[ $show_expiry == "true" ]]; then
		local i=1
		while read -r client; do
			local client_cert="/etc/openvpn/server/easy-rsa/pki/issued/$client.crt"
			local days
			days=$(getDaysUntilExpiry "$client_cert")
			local expiry
			expiry=$(formatExpiry "$days")
			echo "     $i) $client $expiry"
			((i++))
		done < <(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2)
	else
		tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
	fi

	until [[ ${CLIENTNUMBER:-$client_number} -ge 1 && ${CLIENTNUMBER:-$client_number} -le $NUMBEROFCLIENTS ]]; do
		if [[ $NUMBEROFCLIENTS == '1' ]]; then
			read -rp "Select one client [1]: " client_number
		else
			read -rp "Select one client [1-$NUMBEROFCLIENTS]: " client_number
		fi
	done
	CLIENTNUMBER="${CLIENTNUMBER:-$client_number}"
	CLIENT=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
}

function listClients() {
	log_header "Client Certificates"

	local index_file="/etc/openvpn/server/easy-rsa/pki/index.txt"
	local number_of_clients
	# Exclude server certificates (CN starting with server_)
	number_of_clients=$(tail -n +2 "$index_file" | grep "^[VR]" | grep -cv "/CN=server_")

	if [[ $number_of_clients == '0' ]]; then
		log_warn "You have no existing client certificates!"
		return
	fi

	log_info "Found $number_of_clients client certificate(s)"
	log_menu ""
	printf "   %-25s %-10s %-12s %s\n" "Name" "Status" "Expiry" "Remaining"
	printf "   %-25s %-10s %-12s %s\n" "----" "------" "------" "---------"

	local cert_dir="/etc/openvpn/server/easy-rsa/pki/issued"

	# Parse index.txt and sort by expiry date (oldest first)
	# Exclude server certificates (CN starting with server_)
	{
		while read -r line; do
			local status="${line:0:1}"
			local client_name
			client_name=$(echo "$line" | sed 's/.*\/CN=//')

			# Format status
			local status_text
			if [[ "$status" == "V" ]]; then
				status_text="Valid"
			elif [[ "$status" == "R" ]]; then
				status_text="Revoked"
			else
				status_text="Unknown"
			fi

			# Get expiry date from certificate file
			local cert_file="$cert_dir/$client_name.crt"
			local expiry_date="unknown"
			local relative="unknown"

			if [[ -f "$cert_file" ]]; then
				# Get expiry from certificate (format: notAfter=Mon DD HH:MM:SS YYYY GMT)
				local enddate
				enddate=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2)

				if [[ -n "$enddate" ]]; then
					# Parse date and convert to epoch
					local expiry_epoch
					expiry_epoch=$(date -d "$enddate" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$enddate" +%s 2>/dev/null)

					if [[ -n "$expiry_epoch" ]]; then
						# Format as YYYY-MM-DD
						expiry_date=$(date -d "@$expiry_epoch" +%Y-%m-%d 2>/dev/null || date -r "$expiry_epoch" +%Y-%m-%d 2>/dev/null)

						# Calculate days remaining
						local now_epoch days_remaining
						now_epoch=$(date +%s)
						days_remaining=$(((expiry_epoch - now_epoch) / 86400))

						if [[ $days_remaining -lt 0 ]]; then
							relative="$((-days_remaining)) days ago"
						elif [[ $days_remaining -eq 0 ]]; then
							relative="today"
						elif [[ $days_remaining -eq 1 ]]; then
							relative="1 day"
						else
							relative="$days_remaining days"
						fi
					fi
				fi
			fi

			printf "   %-25s %-10s %-12s %s\n" "$client_name" "$status_text" "$expiry_date" "$relative"
		done < <(tail -n +2 "$index_file" | grep "^[VR]" | grep -v "/CN=server_" | sort -t$'\t' -k2)
	}

	log_menu ""
}

function newClient() {
	log_header "New Client Setup"
	log_prompt "Tell me a name for the client."
	log_prompt "The name must consist of alphanumeric character. It may also include an underscore or a dash."

	until [[ $CLIENT =~ ^[a-zA-Z0-9_-]+$ ]]; do
		read -rp "Client name: " -e CLIENT
	done

	if [[ -z $CLIENT_CERT_DURATION_DAYS ]] || ! [[ $CLIENT_CERT_DURATION_DAYS =~ ^[0-9]+$ ]] || [[ $CLIENT_CERT_DURATION_DAYS -lt 1 ]]; then
		log_menu ""
		log_prompt "How many days should the client certificate be valid for?"
		until [[ $CLIENT_CERT_DURATION_DAYS =~ ^[0-9]+$ ]] && [[ $CLIENT_CERT_DURATION_DAYS -ge 1 ]]; do
			read -rp "Certificate validity (days): " -e -i $DEFAULT_CERT_VALIDITY_DURATION_DAYS CLIENT_CERT_DURATION_DAYS
		done
	fi

	log_menu ""
	log_prompt "Do you want to protect the configuration file with a password?"
	log_prompt "(e.g. encrypt the private key with a password)"
	log_menu "   1) Add a passwordless client"
	log_menu "   2) Use a password for the client"

	until [[ $PASS =~ ^[1-2]$ ]]; do
		read -rp "Select an option [1-2]: " -e -i 1 PASS
	done

	CLIENTEXISTS=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -E "^V" | grep -c -E "/CN=$CLIENT\$")
	if [[ $CLIENTEXISTS != '0' ]]; then
		log_error "The specified client CN was already found in easy-rsa, please choose another name."
		exit
	else
		cd /etc/openvpn/server/easy-rsa/ || return
		log_info "Generating client certificate..."
		export EASYRSA_CERT_EXPIRE=$CLIENT_CERT_DURATION_DAYS
		case $PASS in
		1)
			run_cmd_fatal "Building client certificate" ./easyrsa --batch build-client-full "$CLIENT" nopass
			;;
		2)
			if [[ -z "$PASSPHRASE" ]]; then
				log_warn "You will be asked for the client password below"
				# Run directly (not via run_cmd) so password prompt is visible to user
				if ! ./easyrsa --batch build-client-full "$CLIENT"; then
					log_fatal "Building client certificate failed"
				fi
			else
				log_info "Using provided passphrase for client certificate"
				# Use env var to avoid exposing passphrase in install log
				export EASYRSA_PASSPHRASE="$PASSPHRASE"
				run_cmd_fatal "Building client certificate" ./easyrsa --batch --passin=env:EASYRSA_PASSPHRASE --passout=env:EASYRSA_PASSPHRASE build-client-full "$CLIENT"
				unset EASYRSA_PASSPHRASE
			fi
			;;
		esac
		log_success "Client $CLIENT added and is valid for $CLIENT_CERT_DURATION_DAYS days."
	fi

	# Write the .ovpn config file with proper path and permissions
	writeClientConfig "$CLIENT"

	log_menu ""
	log_success "The configuration file has been written to $GENERATED_CONFIG_PATH."
	log_info "Download the .ovpn file and import it in your OpenVPN client."

	exit 0
}

function revokeClient() {
	log_header "Revoke Client"
	log_prompt "Select the existing client certificate you want to revoke"
	selectClient

	cd /etc/openvpn/server/easy-rsa/ || return
	log_info "Revoking certificate for $CLIENT..."
	run_cmd_fatal "Revoking certificate" ./easyrsa --batch revoke-issued "$CLIENT"
	regenerateCRL
	run_cmd "Removing client config from /home" find /home/ -maxdepth 2 -name "$CLIENT.ovpn" -delete
	run_cmd "Removing client config from /root" rm -f "/root/$CLIENT.ovpn"
	run_cmd "Removing IP assignment" sed -i "/^$CLIENT,.*/d" /etc/openvpn/server/ipp.txt
	run_cmd "Backing up index" cp /etc/openvpn/server/easy-rsa/pki/index.txt{,.bk}

	log_success "Certificate for client $CLIENT revoked."
}

function renewClient() {
	local client_cert_duration_days

	log_header "Renew Client Certificate"
	log_prompt "Select the existing client certificate you want to renew"
	selectClient "true"

	# Allow user to specify renewal duration (use CLIENT_CERT_DURATION_DAYS env var for headless mode)
	if [[ -z $CLIENT_CERT_DURATION_DAYS ]] || ! [[ $CLIENT_CERT_DURATION_DAYS =~ ^[0-9]+$ ]] || [[ $CLIENT_CERT_DURATION_DAYS -lt 1 ]]; then
		log_menu ""
		log_prompt "How many days should the renewed certificate be valid for?"
		until [[ $client_cert_duration_days =~ ^[0-9]+$ ]] && [[ $client_cert_duration_days -ge 1 ]]; do
			read -rp "Certificate validity (days): " -e -i $DEFAULT_CERT_VALIDITY_DURATION_DAYS client_cert_duration_days
		done
	else
		client_cert_duration_days=$CLIENT_CERT_DURATION_DAYS
	fi

	cd /etc/openvpn/server/easy-rsa/ || return
	log_info "Renewing certificate for $CLIENT..."

	# Backup the old certificate before renewal
	run_cmd "Backing up old certificate" cp "/etc/openvpn/server/easy-rsa/pki/issued/$CLIENT.crt" "/etc/openvpn/server/easy-rsa/pki/issued/$CLIENT.crt.bak"

	# Renew the certificate (keeps the same private key)
	export EASYRSA_CERT_EXPIRE=$client_cert_duration_days
	run_cmd_fatal "Renewing certificate" ./easyrsa --batch renew "$CLIENT"

	# Revoke the old certificate
	run_cmd_fatal "Revoking old certificate" ./easyrsa --batch revoke-renewed "$CLIENT"

	# Regenerate the CRL
	regenerateCRL

	# Write the .ovpn config file with proper path and permissions
	writeClientConfig "$CLIENT"

	log_menu ""
	log_success "Certificate for client $CLIENT renewed and is valid for $client_cert_duration_days days."
	log_info "The new configuration file has been written to $GENERATED_CONFIG_PATH."
	log_info "Download the new .ovpn file and import it in your OpenVPN client."
}

function renewServer() {
	local server_name server_cert_duration_days

	log_header "Renew Server Certificate"

	# Get the server name from the config (extract basename since path may be relative)
	server_name=$(basename "$(grep '^cert ' /etc/openvpn/server/server.conf | cut -d ' ' -f 2)" .crt)
	if [[ -z "$server_name" ]]; then
		log_fatal "Could not determine server certificate name from /etc/openvpn/server/server.conf"
	fi

	log_prompt "This will renew the server certificate: $server_name"
	log_warn "The OpenVPN service will be restarted after renewal."
	if [[ -z $CONTINUE ]]; then
		read -rp "Do you want to continue? [y/n]: " -e -i n CONTINUE
	fi
	if [[ $CONTINUE != "y" ]]; then
		log_info "Renewal aborted."
		return
	fi

	# Allow user to specify renewal duration (use SERVER_CERT_DURATION_DAYS env var for headless mode)
	if [[ -z $SERVER_CERT_DURATION_DAYS ]] || ! [[ $SERVER_CERT_DURATION_DAYS =~ ^[0-9]+$ ]] || [[ $SERVER_CERT_DURATION_DAYS -lt 1 ]]; then
		log_menu ""
		log_prompt "How many days should the renewed certificate be valid for?"
		until [[ $server_cert_duration_days =~ ^[0-9]+$ ]] && [[ $server_cert_duration_days -ge 1 ]]; do
			read -rp "Certificate validity (days): " -e -i $DEFAULT_CERT_VALIDITY_DURATION_DAYS server_cert_duration_days
		done
	else
		server_cert_duration_days=$SERVER_CERT_DURATION_DAYS
	fi

	cd /etc/openvpn/server/easy-rsa/ || return
	log_info "Renewing server certificate..."

	# Backup the old certificate before renewal
	run_cmd "Backing up old certificate" cp "/etc/openvpn/server/easy-rsa/pki/issued/$server_name.crt" "/etc/openvpn/server/easy-rsa/pki/issued/$server_name.crt.bak"

	# Renew the certificate (keeps the same private key)
	export EASYRSA_CERT_EXPIRE=$server_cert_duration_days
	run_cmd_fatal "Renewing certificate" ./easyrsa --batch renew "$server_name"

	# Revoke the old certificate
	run_cmd_fatal "Revoking old certificate" ./easyrsa --batch revoke-renewed "$server_name"

	# Regenerate the CRL
	regenerateCRL

	# Copy the new certificate to /etc/openvpn/server/
	run_cmd_fatal "Copying new certificate" cp "/etc/openvpn/server/easy-rsa/pki/issued/$server_name.crt" /etc/openvpn/server/

	# Restart OpenVPN
	log_info "Restarting OpenVPN service..."
	run_cmd "Restarting OpenVPN" systemctl restart openvpn-server@server

	log_success "Server certificate renewed successfully and is valid for $server_cert_duration_days days."
}

function getDaysUntilExpiry() {
	local cert_file="$1"
	if [[ -f "$cert_file" ]]; then
		local expiry_date
		expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate | cut -d= -f2)
		local expiry_epoch
		expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry_date" +%s 2>/dev/null)
		if [[ -z "$expiry_epoch" ]]; then
			echo "?"
			return
		fi
		local now_epoch
		now_epoch=$(date +%s)
		echo $(((expiry_epoch - now_epoch) / 86400))
	else
		echo "?"
	fi
}

function formatExpiry() {
	local days="$1"
	if [[ "$days" == "?" ]]; then
		echo "(unknown expiry)"
	elif [[ $days -lt 0 ]]; then
		echo "(EXPIRED $((-days)) days ago)"
	elif [[ $days -eq 0 ]]; then
		echo "(expires today)"
	elif [[ $days -eq 1 ]]; then
		echo "(expires in 1 day)"
	else
		echo "(expires in $days days)"
	fi
}

function renewMenu() {
	local server_name server_cert server_days server_expiry renew_option

	log_header "Certificate Renewal"

	# Get server certificate expiry for menu display (extract basename since path may be relative)
	server_name=$(basename "$(grep '^cert ' /etc/openvpn/server/server.conf | cut -d ' ' -f 2)" .crt)
	if [[ -z "$server_name" ]]; then
		server_expiry="(unknown expiry)"
	else
		server_cert="/etc/openvpn/server/easy-rsa/pki/issued/$server_name.crt"
		server_days=$(getDaysUntilExpiry "$server_cert")
		server_expiry=$(formatExpiry "$server_days")
	fi

	log_menu ""
	log_prompt "What do you want to renew?"
	log_menu "   1) Renew a client certificate"
	log_menu "   2) Renew the server certificate $server_expiry"
	log_menu "   3) Back to main menu"
	until [[ ${RENEW_OPTION:-$renew_option} =~ ^[1-3]$ ]]; do
		read -rp "Select an option [1-3]: " renew_option
	done
	renew_option="${RENEW_OPTION:-$renew_option}"

	case $renew_option in
	1)
		renewClient
		;;
	2)
		renewServer
		;;
	3)
		manageMenu
		;;
	esac
}

function removeUnbound() {
	run_cmd "Removing OpenVPN Unbound config" rm -f /etc/unbound/unbound.conf.d/openvpn.conf

	# Clean up include directive if conf.d directory is now empty
	if [[ -d /etc/unbound/unbound.conf.d ]] && [[ -z "$(ls -A /etc/unbound/unbound.conf.d)" ]]; then
		run_cmd "Cleaning up Unbound include directive" \
			sed -i '/^include: "\/etc\/unbound\/unbound\.conf\.d\/\*\.conf"$/d' /etc/unbound/unbound.conf
	fi

	until [[ $REMOVE_UNBOUND =~ (y|n) ]]; do
		log_info "If you were already using Unbound before installing OpenVPN, I removed the configuration related to OpenVPN."
		read -rp "Do you want to completely remove Unbound? [y/n]: " -e REMOVE_UNBOUND
	done

	if [[ $REMOVE_UNBOUND == 'y' ]]; then
		log_info "Removing Unbound..."
		run_cmd "Stopping Unbound" systemctl stop unbound

		if [[ $OS =~ (debian|ubuntu) ]]; then
			run_cmd "Removing Unbound" apt-get remove --purge -y unbound
		elif [[ $OS == 'arch' ]]; then
			run_cmd "Removing Unbound" pacman --noconfirm -R unbound
		elif [[ $OS =~ (centos|oracle) ]]; then
			run_cmd "Removing Unbound" yum remove -y unbound
		elif [[ $OS =~ (fedora|amzn2023) ]]; then
			run_cmd "Removing Unbound" dnf remove -y unbound
		elif [[ $OS == 'opensuse' ]]; then
			run_cmd "Removing Unbound" zypper remove -y unbound
		fi

		run_cmd "Removing Unbound config" rm -rf /etc/unbound/
		log_success "Unbound removed!"
	else
		run_cmd "Restarting Unbound" systemctl restart unbound
		log_info "Unbound wasn't removed."
	fi
}

function removeOpenVPN() {
	log_header "Remove OpenVPN"
	read -rp "Do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE
	if [[ $REMOVE == 'y' ]]; then
		# Get OpenVPN port from the configuration
		PORT=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
		PROTOCOL=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)

		# Stop OpenVPN
		log_info "Stopping OpenVPN service..."
		run_cmd "Disabling OpenVPN service" systemctl disable openvpn-server@server
		run_cmd "Stopping OpenVPN service" systemctl stop openvpn-server@server
		# Remove customised service
		run_cmd "Removing service file" rm -f /etc/systemd/system/openvpn-server@.service

		# Remove firewall rules
		log_info "Removing firewall rules..."
		if systemctl is-active --quiet firewalld && firewall-cmd --list-ports | grep -q "$PORT/$PROTOCOL"; then
			# firewalld was used
			run_cmd "Removing OpenVPN port from firewalld" firewall-cmd --permanent --remove-port="$PORT/$PROTOCOL"
			run_cmd "Removing masquerade from firewalld" firewall-cmd --permanent --remove-masquerade
			run_cmd "Removing VPN subnet rule" firewall-cmd --permanent --remove-rich-rule='rule family="ipv4" source address="10.8.0.0/24" accept' 2>/dev/null || true
			run_cmd "Removing IPv6 source rule" firewall-cmd --permanent --remove-rich-rule='rule family="ipv6" source address="fd42:42:42:42::/112" accept' 2>/dev/null || true
			run_cmd "Reloading firewalld" firewall-cmd --reload
		elif [[ -f /etc/systemd/system/iptables-openvpn.service ]]; then
			# iptables was used
			run_cmd "Stopping iptables service" systemctl stop iptables-openvpn
			run_cmd "Disabling iptables service" systemctl disable iptables-openvpn
			run_cmd "Removing iptables service file" rm /etc/systemd/system/iptables-openvpn.service
			run_cmd "Reloading systemd" systemctl daemon-reload
			run_cmd "Removing iptables add script" rm -f /etc/iptables/add-openvpn-rules.sh
			run_cmd "Removing iptables rm script" rm -f /etc/iptables/rm-openvpn-rules.sh
		fi

		# SELinux
		if hash sestatus 2>/dev/null; then
			if sestatus | grep "Current mode" | grep -qs "enforcing"; then
				if [[ $PORT != '1194' ]]; then
					run_cmd "Removing SELinux port" semanage port -d -t openvpn_port_t -p "$PROTOCOL" "$PORT"
				fi
			fi
		fi

		log_info "Removing OpenVPN package..."
		if [[ $OS =~ (debian|ubuntu) ]]; then
			run_cmd "Removing OpenVPN" apt-get remove --purge -y openvpn
			# Remove OpenVPN official repository and GPG key
			if [[ -e /etc/apt/sources.list.d/openvpn-aptrepo.list ]]; then
				run_cmd "Removing OpenVPN repo" rm /etc/apt/sources.list.d/openvpn-aptrepo.list
			fi
			if [[ -e /etc/apt/keyrings/openvpn-repo-public.asc ]]; then
				run_cmd "Removing OpenVPN GPG key" rm /etc/apt/keyrings/openvpn-repo-public.asc
			fi
			run_cmd "Updating package lists" apt-get update
		elif [[ $OS == 'arch' ]]; then
			run_cmd "Removing OpenVPN" pacman --noconfirm -R openvpn
		elif [[ $OS =~ (centos|oracle) ]]; then
			run_cmd "Removing OpenVPN" yum remove -y openvpn
			# Disable Copr repo if it was enabled
			if command -v dnf &>/dev/null; then
				run_cmd "Disabling OpenVPN Copr repo" dnf copr disable -y @OpenVPN/openvpn-release-2.6 2>/dev/null || true
			else
				run_cmd "Disabling OpenVPN Copr repo" yum copr disable -y @OpenVPN/openvpn-release-2.6 2>/dev/null || true
			fi
		elif [[ $OS == 'amzn2023' ]]; then
			run_cmd "Removing OpenVPN" dnf remove -y openvpn
		elif [[ $OS == 'fedora' ]]; then
			run_cmd "Removing OpenVPN" dnf remove -y openvpn
		elif [[ $OS == 'opensuse' ]]; then
			run_cmd "Removing OpenVPN" zypper remove -y openvpn
		fi

		# Cleanup
		run_cmd "Removing client configs from /home" find /home/ -maxdepth 2 -name "*.ovpn" -delete
		run_cmd "Removing client configs from /root" find /root/ -maxdepth 1 -name "*.ovpn" -delete
		run_cmd "Removing /etc/openvpn" rm -rf /etc/openvpn
		run_cmd "Removing OpenVPN docs" rm -rf /usr/share/doc/openvpn*
		run_cmd "Removing sysctl config" rm -f /etc/sysctl.d/99-openvpn.conf
		run_cmd "Removing OpenVPN logs" rm -rf /var/log/openvpn

		# Unbound
		if [[ -e /etc/unbound/unbound.conf.d/openvpn.conf ]]; then
			removeUnbound
		fi
		log_success "OpenVPN removed!"
	else
		log_info "Removal aborted!"
	fi
}

function manageMenu() {
	local menu_option

	log_header "OpenVPN Management"
	log_prompt "The git repository is available at: https://github.com/angristan/openvpn-install"
	log_success "OpenVPN is already installed."
	log_menu ""
	log_prompt "What do you want to do?"
	log_menu "   1) Add a new user"
	log_menu "   2) List client certificates"
	log_menu "   3) Revoke existing user"
	log_menu "   4) Renew certificate"
	log_menu "   5) Remove OpenVPN"
	log_menu "   6) Exit"
	until [[ ${MENU_OPTION:-$menu_option} =~ ^[1-6]$ ]]; do
		read -rp "Select an option [1-6]: " menu_option
	done
	menu_option="${MENU_OPTION:-$menu_option}"

	case $menu_option in
	1)
		newClient
		;;
	2)
		listClients
		;;
	3)
		revokeClient
		;;
	4)
		renewMenu
		;;
	5)
		removeOpenVPN
		;;
	6)
		exit 0
		;;
	esac
}

# Check for root, TUN, OS...
initialCheck

# Check if OpenVPN is already installed
if [[ -e /etc/openvpn/server/server.conf ]]; then
	manageMenu
else
	installOpenVPN
fi
