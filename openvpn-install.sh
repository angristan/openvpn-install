#!/bin/bash

# Secure OpenVPN server installer for Debian, Ubuntu, CentOS and Fedora
# https://github.com/Angristan/OpenVPN-install


# Verify root
if [[ "$EUID" -ne 0 ]]; then
	echo "Sorry, you need to run this as root"
	exit 1
fi

# Verify tun
if [[ ! -e /dev/net/tun ]]; then
	echo "TUN is not available"
	exit 2
fi

if [[ -e /etc/debian_version ]]; then
	OS="debian"
	# Getting the version number, to verify that a recent version of OpenVPN is available
	VERSION_ID=$(grep "VERSION_ID" /etc/os-release)
	IPTABLES='/etc/iptables/iptables.rules'
	if [[ "$VERSION_ID" != 'VERSION_ID="8"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="9"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="16.04"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="17.10"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="18.04"' ]]; then
		echo "Your version of Debian/Ubuntu is not supported."
		echo "I can't install a recent version of OpenVPN on your system."
		echo ""
		echo "However, if you're using Debian unstable/testing, or Ubuntu beta,"
		echo "then you can continue, a recent version of OpenVPN is available on these."
		echo "Keep in mind they are not supported, though."
		while [[ $CONTINUE != "y" && $CONTINUE != "n" ]]; do
			read -rp "Continue? [y/n]: " -e CONTINUE
		done
		if [[ "$CONTINUE" = "n" ]]; then
			echo "Ok, bye!"
			exit 4
		fi
	fi
elif [[ -e /etc/fedora-release ]]; then
	OS=fedora
	IPTABLES='/etc/iptables/iptables.rules'
elif [[ -e /etc/centos-release ]]; then
	if ! grep -qs "^CentOS Linux release 7" /etc/centos-release; then
		echo "Your version of CentOS is not supported."
		echo "The script only support CentOS 7."
		echo ""
		unset CONTINUE
		while [[ $CONTINUE != "y" && $CONTINUE != "n" ]]; do
			read -rp "Continue anyway? [y/n]: " -e CONTINUE
		done
		if [[ "$CONTINUE" = "n" ]]; then
			echo "Ok, bye!"
			exit 5
		fi
	fi
	OS=centos
	IPTABLES='/etc/iptables/iptables.rules'
else
	echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora or CentOS system"
	exit 4
fi


function newclient () {
	echo ""
	echo "Do you want to protect the configuration file with a password?"
	echo "(e.g. encrypt the private key with a password)"
	echo "   1) Add a passwordless client"
	echo "   2) Use a password for the client"

	until [[ "$pass" =~ ^[1-2]$ ]]; do
		read -rp "Select an option [1-2]: " -e -i 1 local pass
	done
	
	echo ""
	echo "Tell me a name for the client cert"
	echo "Use one word only, no special characters"

	until [[ "$client" =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Client name: " -e local client
	done

	cd /etc/openvpn/easy-rsa/ || return
	case $pass in
		1)
		./easyrsa build-client-full $client nopass
		;;
		2)
		echo "⚠️ You will be asked for the client password below ⚠️"
		./easyrsa build-client-full $client
		;;
	esac

	# Where to write the custom client.ovpn?
	if [ -e "/home/$client" ]; then  # if $1 is a user name
		homeDir="/home/$client"
	elif [ "${SUDO_USER}" ]; then   # if not, use SUDO_USER
		homeDir="/home/${SUDO_USER}"
	else  # if not SUDO_USER, use /root
		homeDir="/root"
	fi
	# Generates the custom client.ovpn
	cp /etc/openvpn/client-template.txt "$homeDir/$client.ovpn"
	{
		echo "<ca>"
		cat "/etc/openvpn/easy-rsa/pki/ca.crt"
		echo "</ca>"

		echo "<cert>"
		cat "/etc/openvpn/easy-rsa/pki/issued/$client.crt"
		echo "</cert>"

		echo "<key>"
		cat "/etc/openvpn/easy-rsa/pki/private/$client.key"
		echo "</key>"
		echo "key-direction 1"

		echo "<tls-auth>"
		cat "/etc/openvpn/tls-auth.key"
		echo "</tls-auth>"
	} >> "$homeDir/$client.ovpn"

	echo ""
	echo "Client $client added, certs available at $homeDir/$client.ovpn"
	exit
}

function installLocalDNS () {
	if [[ ! -e /etc/unbound/unbound.conf ]]; then

		if [[ "$OS" = "debian" ]]; then
			apt-get install -y unbound

			echo 'interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes' >> /etc/unbound/unbound.conf

		elif [[ "$OS" = "centos" ]]; then
			yum install -y unbound

			# Configuration
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
			sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
			sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
			sed -i 's|use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf

		elif [[ "$OS" = "fedora" ]]; then
			dnf install -y unbound

			# Configuration
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
			sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
			sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
			sed -i 's|# use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf
		fi

		if [[ ! "$OS" =~ (fedora|centos) ]];then
			# DNS Rebinding fix
			echo "private-address: 10.0.0.0/8
		private-address: 172.16.0.0/12
		private-address: 192.168.0.0/16
		private-address: 169.254.0.0/16
		private-address: fd00::/8
		private-address: fe80::/10
		private-address: 127.0.0.0/8
		private-address: ::ffff:0:0/96" >> /etc/unbound/unbound.conf
		fi
	else
		# Unbound is already installed
		echo 'include: /etc/unbound/openvpn.conf' >> /etc/unbound/unbound.conf

		# Add OpenVPN integration
		echo 'server:
interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes
private-address: 10.0.0.0/8
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96' > /etc/unbound/openvpn.conf
	fi

	if pgrep systemd-journal; then
		systemctl enable unbound
		systemctl start unbound
	else
		service unbound restart
	fi
}

# Get Internet network interface with default route
NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)

if [[ -e /etc/openvpn/server.conf ]]; then
	while :
	do
	clear
		echo "OpenVPN-install (github.com/Angristan/OpenVPN-install)"
		echo ""
		echo "Looks like OpenVPN is already installed"
		echo ""

		echo "What do you want to do?"
		echo "   1) Add a cert for a new user"
		echo "   2) Revoke existing user cert"
		echo "   3) Remove OpenVPN"
		echo "   4) Exit"
		read -rp "Select an option [1-4]: " option

		case $option in
			1)
			# Generates the custom client.ovpn
			newclient
			;;
			2)
			NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
				echo ""
				echo "You have no existing clients!"
				exit 5
			fi

			echo ""
			echo "Select the existing client certificate you want to revoke"
			tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
				read -rp "Select one client [1]: " CLIENTNUMBER
			else
				read -rp "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
			fi

			CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
			cd /etc/openvpn/easy-rsa/
			./easyrsa --batch revoke $CLIENT
			EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
			rm -f pki/reqs/$CLIENT.req
			rm -f pki/private/$CLIENT.key
			rm -f pki/issued/$CLIENT.crt
			rm -f /etc/openvpn/crl.pem
			cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
			chmod 644 /etc/openvpn/crl.pem
			rm -f $(find /home -maxdepth 2 | grep $CLIENT.ovpn) 2>/dev/null
			rm -f /root/$CLIENT.ovpn 2>/dev/null

			echo ""
			echo "Certificate for client $CLIENT revoked"
			echo "Exiting..."
			exit
			;;
			3)
			echo ""
			read -rp "Do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE
			if [[ "$REMOVE" = 'y' ]]; then
				PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)

				# Remove ipatbles rules related to the script
				systemctl stop iptables-openvpn
				# Cleanup
				systemctl disable iptables-openvpn
				rm /etc/systemd/system/iptables-openvpn.service
				systemctl daemon-reload
				rm /etc/iptables/add-openvpn-rules.sh
				rm /etc/iptables/rm-openvpn-rules.sh

				if hash sestatus 2>/dev/null; then
					if sestatus | grep "Current mode" | grep -qs "enforcing"; then
						if [[ "$PORT" != '1194' ]]; then
							semanage port -d -t openvpn_port_t -p udp $PORT
						fi
					fi
				fi
				if [[ "$OS" = 'debian' ]]; then
					apt-get autoremove --purge -y openvpn
				else
					yum remove openvpn -y
				fi
				OVPNS=$(ls /etc/openvpn/easy-rsa/pki/issued | awk -F "." {'print $1'})
				for i in $OVPNS;do
					rm $(find /home -maxdepth 2 | grep $i.ovpn) 2>/dev/null
					rm /root/$i.ovpn 2>/dev/null
				done
				rm -rf /etc/openvpn
				rm -rf /usr/share/doc/openvpn*
				rm -f /etc/sysctl.d/20-openvpn.conf

				if [[ -e /etc/unbound/openvpn.conf ]]; then

					# Remove OpenVPN-related config
					sed -i 's|include: \/etc\/unbound\/openvpn.conf||' /etc/unbound/unbound.conf
					rm /etc/unbound/openvpn.conf
					service unbound restart

					until [[ $REMOVE_UNBOUND == "y" || $REMOVE_UNBOUND == "n" ]]; do
						echo ""
						echo "If you were already using Unbound before installing OpenVPN, I removed the configuration related to OpenVPN."
						echo "You can keep using Unbound as before."
						read -rp "Do you want to completely remove Unbound? [y/n]: " -e REMOVE_UNBOUND
					done

					if [[ "$REMOVE_UNBOUND" = 'y' ]]; then
						if [[ "$OS" = 'debian' ]]; then
							apt-get autoremove --purge -y unbound
						else
							yum remove unbound -y
						fi

						echo ""
						echo "Unbound removed!"
					else
						echo ""
						echo "Unbound not removed!"
					fi
				fi
				echo ""
				echo "OpenVPN removed!"
			else
				echo ""
				echo "Removal aborted!"
			fi
			exit
			;;
			4) exit;;
		esac
	done
else
	clear
	echo "Welcome to the secure OpenVPN installer (github.com/Angristan/OpenVPN-install)"
	echo ""

	# OpenVPN setup and first user creation
	echo "I need to ask you a few questions before starting the setup"
	echo "You can leave the default options and just press enter if you are ok with them"
	echo ""
	echo "I need to know the IPv4 address of the network interface you want OpenVPN listening to."
	echo "If your server is running behind a NAT, (e.g. LowEndSpirit, Scaleway) leave the IP address as it is. (local/private IP)"
	echo "Otherwise, it should be your public IPv4 address."

	# Autodetect IP address and pre-fill for the user
	IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
	read -rp "IP address: " -e -i $IP IP
	# If $IP is a private IP address, the server must be behind NAT
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo ""
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		read -rp "Public IP address / hostname: " -e PUBLICIP
	fi
	echo ""
	echo "Checking for IPv6 connectivity..."
	ping6 -c4 ipv6.google.com > /dev/null 2>&1;
	echo ""
	if [[ $? == 0 ]]; then
		echo "Your host appears to have IPv6 connectivity."
	else
		echo "Your host does not appear to have IPv6 connectivity."
	fi
	echo ""
	while [[ $IPV6 != "y" && $IPV6 != "n" ]]; do
		read -rp "Do you want to enable IPv6 support? [y/n]: " -e IPV6
	done
	echo ""
	echo "What port do you want for OpenVPN?"
	echo "   1) Default: 1194"
	echo "   2) Custom"
	echo "   3) Random [49152-65535]"
	until [[ "$PORT_CHOICE" =~ ^[1-3]$ ]]; do
		read -p "Port choice [1-3]: " -e -i 1 PORT_CHOICE
	done
	case $PORT_CHOICE in
		1)
			PORT="1194"
		;;
		2)
			until [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 -a "$PORT" -le 65535 ]; do
				read -p "Custom port [1-65535]: " -e -i 1194 PORT
			done
		;;
		3)
			# Generate random number within private ports range
			PORT=$(shuf -i49152-65535 -n1)
			echo "Random Port: $PORT"
		;;
	esac
	echo ""
	echo "What protocol do you want for OpenVPN?"
	echo "Unless UDP is blocked, you should not use TCP (unnecessarily slower)"
	until [[ "$PROTOCOL" == "UDP" || "$PROTOCOL" == "TCP" ]]; do
		read -rp "Protocol [UDP/TCP]: " -e -i UDP PROTOCOL
	done
	echo ""
	echo "What DNS do you want to use with the VPN?"
	echo "   1) Current system resolvers (from /etc/resolv.conf)"
	echo "   2) Self-hosted DNS Resolver (Unbound)"
	echo "   3) Cloudflare (Anycast: worldwide)"
	echo "   4) Quad9 (Anycast: worldwide)"
	echo "   5) FDN (France)"
	echo "   6) DNS.WATCH (Germany)"
	echo "   7) OpenDNS (Anycast: worldwide)"
	echo "   8) Google (Anycast: worldwide)"
	echo "   9) Yandex Basic (Russia)"
	echo "   10) AdGuard DNS (Russia)"
	until [[ "$DNS" =~ ^[0-9]+$ ]] && [ "$DNS" -ge 1 -a "$DNS" -le 10 ]; do
		read -rp "DNS [1-10]: " -e -i 1 DNS
			if [[ $DNS == 2 ]] && [[ -e /etc/unbound/unbound.conf ]]; then
				echo ""
				echo "Unbound is already installed."
				echo "You can allow the script to configure it in order to use it from your OpenVPN clients"
				echo "We will simply add a second server to /etc/unbound/unbound.conf for the OpenVPN subnet."
				echo "No changes are made to the current configuration."
				echo ""

				while [[ $CONTINUE != "y" && $CONTINUE != "n" ]]; do
					read -rp "Apply configuration changes to Unbound? [y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE = "n" ]];then
					unset DNS
					unset CONTINUE
				fi
			fi
	done
	echo ""
	echo "See https://github.com/Angristan/OpenVPN-install#encryption to learn more about "
	echo "the encryption in OpenVPN and the choices I made in this script."
	echo "Please note that all the choices proposed are secure (to a different degree)"
	echo "and are still viable to date, unlike some default OpenVPN options"
	echo ''
	echo "Choose which cipher you want to use for the data channel:"
	echo "   1) AES-128-CBC (fastest and sufficiently secure for everyone, recommended)"
	echo "   2) AES-192-CBC"
	echo "   3) AES-256-CBC"
	echo "Alternatives to AES, use them only if you know what you're doing."
	echo "They are relatively slower but as secure as AES."
	echo "   4) CAMELLIA-128-CBC"
	echo "   5) CAMELLIA-192-CBC"
	echo "   6) CAMELLIA-256-CBC"
	echo "   7) SEED-CBC"
	until [[ "$CIPHER" =~ ^[0-9]+$ ]] && [ "$CIPHER" -ge 1 -a "$CIPHER" -le 7 ]; do
		read -rp "Cipher [1-7]: " -e -i 1 CIPHER
	done
	case $CIPHER in
		1)
		CIPHER="cipher AES-128-CBC"
		;;
		2)
		CIPHER="cipher AES-192-CBC"
		;;
		3)
		CIPHER="cipher AES-256-CBC"
		;;
		4)
		CIPHER="cipher CAMELLIA-128-CBC"
		;;
		5)
		CIPHER="cipher CAMELLIA-192-CBC"
		;;
		6)
		CIPHER="cipher CAMELLIA-256-CBC"
		;;
		7)
		CIPHER="cipher SEED-CBC"
		;;
	esac
	echo ""
	echo "Choose what size of Diffie-Hellman key you want to use:"
	echo "   1) 2048 bits (fastest)"
	echo "   2) 3072 bits (recommended, best compromise)"
	echo "   3) 4096 bits (most secure)"
	until [[ "$DH_KEY_SIZE" =~ ^[0-9]+$ ]] && [ "$DH_KEY_SIZE" -ge 1 -a "$DH_KEY_SIZE" -le 3 ]; do
		read -rp "DH key size [1-3]: " -e -i 2 DH_KEY_SIZE
	done
	case $DH_KEY_SIZE in
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
	echo ""
	echo "Choose what size of RSA key you want to use:"
	echo "   1) 2048 bits (fastest)"
	echo "   2) 3072 bits (recommended, best compromise)"
	echo "   3) 4096 bits (most secure)"
	until [[ "$RSA_KEY_SIZE" =~ ^[0-9]+$ ]] && [ "$RSA_KEY_SIZE" -ge 1 -a "$RSA_KEY_SIZE" -le 3 ]; do
		read -rp "RSA key size [1-3]: " -e -i 2 RSA_KEY_SIZE
	done
	case $RSA_KEY_SIZE in
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
	echo ""
	echo "Do you want to protect the configuration file with a password?"
	echo "(e.g. encrypt the private key with a password)"
	echo "   1) Add a passwordless client"
	echo "   2) Use a password for the client"
	until [[ "$pass" =~ ^[1-2]$ ]]; do
		read -rp "Select an option [1-2]: " -e -i 1 pass
	done
	echo ""
	echo "Finally, tell me a name for the client certificate and configuration"
	echo "Use one word only, no special characters"
	until [[ "$CLIENT" =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Client name: " -e -i client CLIENT
	done
	echo ""
	echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now"
	read -n1 -r -p "Press any key to continue..."

	if [[ "$OS" = 'debian' ]]; then
		apt-get update
		apt-get install ca-certificates gnupg -y
		# We add the OpenVPN repo to get the latest version.
		# Debian 8
		if [[ "$VERSION_ID" = 'VERSION_ID="8"' ]]; then
			echo "deb http://build.openvpn.net/debian/openvpn/stable jessie main" > /etc/apt/sources.list.d/openvpn.list
			wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
			apt-get update
		fi
		# Ubuntu >= 16.04 and Debian > 8 have OpenVPN > 2.3.3 without the need of a third party repository.
		# The we install OpenVPN
		apt-get install openvpn iptables openssl wget ca-certificates curl -y
	elif [[ "$OS" = 'centos' || "$OS" = 'fedora' ]]; then
		if [[ "$OS" = 'centos' ]]; then
			yum install epel-release -y
		fi
		yum install openvpn iptables openssl wget ca-certificates curl -y
	fi

	# Install iptables service
	mkdir /etc/iptables

	# Script to add rules
	echo "#!/bin/sh
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables -A INPUT -i tun0 -j ACCEPT
iptables -A FORWARD -i eth0 -o tun0 -j ACCEPT
iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT" > /etc/iptables/add-openvpn-rules.sh

	if [[ "$PROTOCOL" = 'UDP' ]]; then
		echo "iptables -A INPUT -i eth0 -p udp --dport $PORT -j ACCEPT" >> /etc/iptables/add-openvpn-rules.sh
	elif [[ "$PROTOCOL" = 'TCP' ]]; then
		echo "iptables -A INPUT -i eth0 -p tcp --dport $PORT -j ACCEPT" >> /etc/iptables/add-openvpn-rules.sh
	fi

	if [[ "$IPV6" = 'y' ]]; then
		echo "ip6tables -t nat -A POSTROUTING -s fd42:42:42:42::/112 -o eth0 -j MASQUERADE
ip6tables -A INPUT -i tun0 -j ACCEPT
ip6tables -A FORWARD -i eth0 -o tun0 -j ACCEPT
ip6tables -A FORWARD -i tun0 -o eth0 -j ACCEPT" >> /etc/iptables/add-openvpn-rules.sh
	fi

	# Script to remove rules
	echo "#!/bin/sh
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables -D INPUT -i tun0 -j ACCEPT
iptables -D FORWARD -i eth0 -o tun0 -j ACCEPT
iptables -D FORWARD -i tun0 -o eth0 -j ACCEPT" > /etc/iptables/rm-openvpn-rules.sh

	if [[ "$PROTOCOL" = 'UDP' ]]; then
		echo "iptables -D INPUT -i eth0 -p udp --dport $PORT -j ACCEPT" >> /etc/iptables/rm-openvpn-rules.sh
	elif [[ "$PROTOCOL" = 'TCP' ]]; then
		echo "iptables -D INPUT -i eth0 -p tcp --dport $PORT -j ACCEPT" >> /etc/iptables/rm-openvpn-rules.sh
	fi

	if [[ "$IPV6" = 'y' ]]; then
		echo "ip6tables -t nat -D POSTROUTING -s fd42:42:42:42::/112 -o eth0 -j MASQUERADE
ip6tables -D INPUT -i tun0 -j ACCEPT
ip6tables -D FORWARD -i eth0 -o tun0 -j ACCEPT
ip6tables -D FORWARD -i tun0 -o eth0 -j ACCEPT" >> /etc/iptables/rm-openvpn-rules.sh
	fi

	chmod +x /etc/iptables/add-openvpn-rules.sh
	chmod +x /etc/iptables/rm-openvpn-rules.sh

	# Handle the rules via a systemd script
	echo "[Unit]
Description=iptables rules for OpenVPN
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/iptables-openvpn.service

	# Enable service and apply rules
	systemctl daemon-reload
	systemctl enable iptables-openvpn
	systemctl start iptables-openvpn

	# Find out if the machine uses nogroup or nobody for the permissionless group
	if grep -qs "^nogroup:" /etc/group; then
		NOGROUP=nogroup
	else
		NOGROUP=nobody
	fi

	# An old version of easy-rsa was available by default in some openvpn packages
	if [[ -d /etc/openvpn/easy-rsa/ ]]; then
		rm -rf /etc/openvpn/easy-rsa/
	fi
	# Get easy-rsa
	wget -O ~/EasyRSA-3.0.4.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.4/EasyRSA-3.0.4.tgz
	tar xzf ~/EasyRSA-3.0.4.tgz -C ~/
	mv ~/EasyRSA-3.0.4/ /etc/openvpn/easy-rsa/
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -f ~/EasyRSA-3.0.4.tgz
	cd /etc/openvpn/easy-rsa/
	# Generate a random, alphanumeric identifier of 16 characters for CN and one for server name
	SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
	SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
	echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" > vars
	echo "set_var EASYRSA_REQ_CN $SERVER_CN" >> vars
	# Create the PKI, set up the CA, the DH params and the server + client certificates
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	openssl dhparam -out dh.pem $DH_KEY_SIZE
	./easyrsa build-server-full $SERVER_NAME nopass
	case $pass in
		1)
			./easyrsa build-client-full $CLIENT nopass
		;;
		2)
			echo "⚠️ You will be asked for the client password below ⚠️"
			./easyrsa build-client-full $CLIENT
		;;
	esac
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	# generate tls-auth key
	openvpn --genkey --secret /etc/openvpn/tls-auth.key
	# Move all the generated files
	cp pki/ca.crt pki/private/ca.key dh.pem pki/issued/$SERVER_NAME.crt pki/private/$SERVER_NAME.key /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
	# Make cert revocation list readable for non-root
	chmod 644 /etc/openvpn/crl.pem

	# Generate server.conf
	echo "port $PORT" > /etc/openvpn/server.conf
	if [[ "$IPV6" = 'n' ]]; then
		if [[ "$PROTOCOL" = 'UDP' ]]; then
			echo "proto udp" >> /etc/openvpn/server.conf
		elif [[ "$PROTOCOL" = 'TCP' ]]; then
			echo "proto tcp" >> /etc/openvpn/server.conf
		fi
	elif [[ "$IPV6" = 'y' ]]; then
		if [[ "$PROTOCOL" = 'UDP' ]]; then
			echo "proto udp6" >> /etc/openvpn/server.conf
		elif [[ "$PROTOCOL" = 'TCP' ]]; then
			echo "proto tcp6" >> /etc/openvpn/server.conf
		fi
	fi
	echo "dev tun
user nobody
group $NOGROUP
persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" >> /etc/openvpn/server.conf
	# DNS resolvers
	case $DNS in
		1)
		# Locate the proper resolv.conf
		# Needed for systems running systemd-resolved
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		grep -v '#' $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read -r line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
		done
		;;
		2)
		# Install Unbound
		installLocalDNS
		echo 'push "dhcp-option DNS 10.8.0.1"' >> /etc/openvpn/server.conf
		;;
		3) # Cloudflare
		echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server.conf	
		;;
		4) # Quad9
		echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server.conf
		;;
		5) # FDN
		echo 'push "dhcp-option DNS 80.67.169.40"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 80.67.169.12"' >> /etc/openvpn/server.conf
		;;
		6) # DNS.WATCH
		echo 'push "dhcp-option DNS 84.200.69.80"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 84.200.70.40"' >> /etc/openvpn/server.conf
		;;
		7) # OpenDNS
		echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server.conf
		;;
		8) # Google
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
		;;
		9) # Yandex Basic
		echo 'push "dhcp-option DNS 77.88.8.8"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 77.88.8.1"' >> /etc/openvpn/server.conf
		;;
		10) # AdGuard DNS
		echo 'push "dhcp-option DNS 176.103.130.130"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 176.103.130.131"' >> /etc/openvpn/server.conf
		;;
	esac
	echo 'push "redirect-gateway def1 bypass-dhcp" '>> /etc/openvpn/server.conf

	if [[ "$IPV6" = 'y' ]]; then
		echo 'server-ipv6 fd42:42:42:42::/112
tun-ipv6
push tun-ipv6
push "route-ipv6 2000::/3"
push "redirect-gateway ipv6"' >> /etc/openvpn/server.conf
	fi

	echo "crl-verify crl.pem
ca ca.crt
cert $SERVER_NAME.crt
key $SERVER_NAME.key
tls-auth tls-auth.key 0
dh dh.pem
auth SHA256
$CIPHER
tls-server
tls-version-min 1.2
tls-cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256
status /var/log/openvpn/status.log
verb 3" >> /etc/openvpn/server.conf

	# Create log dir
	mkdir -p /var/log/openvpn

	# Enable routing
	echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.d/20-openvpn.conf
	if [[ "$IPV6" = 'y' ]]; then
		echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.d/20-openvpn.conf
	fi

	# Avoid an unneeded reboot
	sysctl --system

	# If SELinux is enabled and a custom port was selected, we need this
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ "$PORT" != '1194' ]]; then
				# semanage isn't available in CentOS 6 by default
				if ! hash semanage 2>/dev/null; then
					yum install policycoreutils-python -y
				fi
				if [[ "$PROTOCOL" = 'UDP' ]]; then
					semanage port -a -t openvpn_port_t -p udp $PORT
				elif [[ "$PROTOCOL" = 'TCP' ]]; then
					semanage port -a -t openvpn_port_t -p tcp $PORT
				fi
			fi
		fi
	fi

	# And finally, restart OpenVPN
	if [[ "$OS" = 'debian' ]]; then
		# Little hack to check for systemd
		if pgrep systemd-journal; then
				#Workaround to fix OpenVPN service on OpenVZ
				sed -i 's|LimitNPROC|#LimitNPROC|' /lib/systemd/system/openvpn\@.service
				sed -i 's|/etc/openvpn/server|/etc/openvpn|' /lib/systemd/system/openvpn\@.service
				sed -i 's|%i.conf|server.conf|' /lib/systemd/system/openvpn\@.service
				systemctl daemon-reload
				systemctl restart openvpn
				systemctl enable openvpn
		else
			/etc/init.d/openvpn restart
		fi
	else
		if pgrep systemd-journal; then
			if [[ "$OS" = 'fedora' ]]; then
				# Workaround to avoid rewriting the entire script for Fedora
				sed -i 's|/etc/openvpn/server|/etc/openvpn|' /usr/lib/systemd/system/openvpn-server@.service
				sed -i 's|%i.conf|server.conf|' /usr/lib/systemd/system/openvpn-server@.service
				systemctl daemon-reload
				systemctl restart openvpn-server@openvpn.service
				systemctl enable openvpn-server@openvpn.service
			else
				systemctl restart openvpn@server.service
				systemctl enable openvpn@server.service
			fi
		else
			service openvpn restart
			chkconfig openvpn on
		fi
	fi

	# If the server is behind a NAT, use the correct IP address
	if [[ "$PUBLICIP" != "" ]]; then
		IP=$PUBLICIP
	fi
	
	# client-template.txt is created so we have a template to add further users later
	echo "client" > /etc/openvpn/client-template.txt
	if [[ "$PROTOCOL" = 'UDP' ]]; then
		echo "proto udp" >> /etc/openvpn/client-template.txt
	elif [[ "$PROTOCOL" = 'TCP' ]]; then
		echo "proto tcp-client" >> /etc/openvpn/client-template.txt
	fi
	echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name $SERVER_NAME name
auth SHA256
auth-nocache
$CIPHER
tls-client
tls-version-min 1.2
tls-cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256
setenv opt block-outside-dns
verb 3" >> /etc/openvpn/client-template.txt

	# Generate the custom client.ovpn
	newclient "$CLIENT"
	echo ""
	echo "Finished!"
	echo ""
	echo "Your client config is available at $homeDir/$CLIENT.ovpn"
	echo "If you want to add more clients, you simply need to run this script another time!"
fi
exit 0;
