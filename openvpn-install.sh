#!/bin/bash

# Secure OpenVPN server installer for Debian, Ubuntu, CentOS, Amazon Linux 2, Fedora and Arch Linux
# https://github.com/angristan/openvpn-install

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
		# shellcheck disable=SC1091
		source /etc/os-release

		if [[ $ID == "debian" || $ID == "raspbian" ]]; then
			if [[ $VERSION_ID -lt 8 ]]; then
				echo "⚠️ 你的Debian版本没有被支持。"
				echo ""
				echo "如果你用的是Debian8及以上的版本或者unstable/testing分支，你可以继续，但是风险自负。"
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "继续 [y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		elif [[ $ID == "ubuntu" ]]; then
			OS="ubuntu"
			MAJOR_UBUNTU_VERSION=$(echo "$VERSION_ID" | cut -d '.' -f1)
			if [[ $MAJOR_UBUNTU_VERSION -lt 16 ]]; then
				echo "⚠️ 你的Ubuntu版本没有被支持。"
				echo ""
				echo "如果你用的是Ubuntu16.04及以上的版本或beta分支，你可以继续，但是风险自负。"
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "继续 [y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		fi
	elif [[ -e /etc/system-release ]]; then
		# shellcheck disable=SC1091
		source /etc/os-release
		if [[ $ID == "fedora" ]]; then
			OS="fedora"
		fi
		if [[ $ID == "centos" ]]; then
			OS="centos"
			if [[ ! $VERSION_ID =~ (7|8) ]]; then
				echo "⚠️ 你的CentOS版本不被支持。"
				echo ""
				echo "本脚本仅支持CentOS7。"
				echo ""
				exit 1
			fi
		fi
		if [[ $ID == "amzn" ]]; then
			OS="amzn"
			if [[ $VERSION_ID != "2" ]]; then
				echo "⚠️ 你的Amazon Linux版本不被支持。"
				echo ""
				echo "本脚本仅支持Amazon Linux 2。"
				echo ""
				exit 1
			fi
		fi
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "看起来你并没有在 Debian, Ubuntu, Fedora, CentOS, Amazon Linux 2 或 Arch Linux 系统上运行本脚本。"
		exit 1
	fi
}

function initialCheck() {
	if ! isRoot; then
		echo "请以root身份运行这个脚本"
		exit 1
	fi
	if ! tunAvailable; then
		echo "你的设备不支持TUN"
		exit 1
	fi
	checkOS
}

function installQuestions() {
	echo "欢迎使用Openvpn部署工具！"
	echo "本脚本修改自angristan的安装脚本，项目地址：https://github.com/Nouko61/openvpn-install"
	echo "原项目地址：https://github.com/angristan/openvpn-install"
	echo ""

	echo "脚本会为你搭建一个专门用于局域网游戏的Openvpn服务器，"
	echo "在搭建之前，你需要回答几个问题，"
	echo "安装过程中你可以直接按回车来使用脚本的默认值。"
	echo ""
	echo "我们需要知道Openvpn监听的IP地址，"
	echo "除非你的服务器经过NAT（网络地址转换），否则它应该是你的公网IP。"

	# Detect public IPv4 address and pre-fill for the user
	IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	if [[ -z $IP ]]; then
		# Detect public IPv6 address
		IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	APPROVE_IP=${APPROVE_IP:-n}
	if [[ $APPROVE_IP =~ n ]]; then
		read -rp "IP地址: " -e -i "$IP" IP
	fi
	# If $IP is a private IP address, the server must be behind NAT
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo ""
		echo "看起来你的服务器经过了NAT（网络地址转换）。请问你的公网IP是什么？"
		echo "我们需要它来让客户端连接服务器。"
		until [[ $ENDPOINT != "" ]]; do
			read -rp "公网IP或域名: " -e ENDPOINT
		done
	fi

	echo ""
	echo "你想让Openvpn监听哪个端口"
	echo "   1) 默认: 1194"
	echo "   2) 自定义"
	echo "   3) 随机 [49152-65535]"
	until [[ $PORT_CHOICE =~ ^[1-3]$ ]]; do
		read -rp "选择端口 [1-3]: " -e -i 1 PORT_CHOICE
	done
	case $PORT_CHOICE in
	1)
		PORT="1194"
		;;
	2)
		until [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
			read -rp "自定义端口 [1-65535]: " -e -i 1194 PORT
		done
		;;
	3)
		# Generate random number within private ports range
		PORT=$(shuf -i49152-65535 -n1)
		echo "随机端口: $PORT"
		;;
	esac
	echo ""
	echo "你想让Openvpn使用哪种协议？"
	echo "UDP更加快速。除非你的机器被禁用UDP，否则不要使用TCP。"
	echo "   1) UDP"
	echo "   2) TCP"
	until [[ $PROTOCOL_CHOICE =~ ^[1-2]$ ]]; do
		read -rp "协议 [1-2]: " -e -i 1 PROTOCOL_CHOICE
	done
	case $PROTOCOL_CHOICE in
	1)
		PROTOCOL="udp"
		;;
	2)
		PROTOCOL="tcp"
		;;
	esac
	echo ""
	echo "你想开启压缩吗？开启后可以略微减少流量消耗但是容易遭受攻击。"
	until [[ $COMPRESSION_ENABLED =~ (y|n) ]]; do
		read -rp"开启压缩 [y/n]: " -e -i n COMPRESSION_ENABLED
	done
	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "选择一种压缩算法: (靠前的算法效率更高)"
		echo "   1) LZ4-v2"
		echo "   2) LZ4"
		echo "   3) LZ0"
		until [[ $COMPRESSION_CHOICE =~ ^[1-3]$ ]]; do
			read -rp"压缩算法 [1-3]: " -e -i 1 COMPRESSION_CHOICE
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
	echo ""
	echo "你想允许多人连接同一个账号吗？"
	until [[ $MULTI_USER =~ (y|n) ]]; do
		read -rp"允许多人 [y/n]: " -e -i n MULTI_USER
	done
	echo ""
	echo "你想自定义Openvpn的加密方式吗？"
	echo "除非你知道它们是做什么的，你应该使用脚本默认的加密方式。"
	echo "注意，本脚本中默认的选项永远都是最安全的。(而不像Openvpn的默认设置)"
	echo "访问 https://github.com/angristan/openvpn-install#security-and-encryption 了解更多"
	echo ""
	until [[ $CUSTOMIZE_ENC =~ (y|n) ]]; do
		read -rp "自定义加密方式 [y/n]: " -e -i n CUSTOMIZE_ENC
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
		TLS_SIG="1" # tls-crypt
	else
		echo ""
		echo "选择数据的加密算法："
		echo "   1) AES-128-GCM (推荐)"
		echo "   2) AES-192-GCM"
		echo "   3) AES-256-GCM"
		echo "   4) AES-128-CBC"
		echo "   5) AES-192-CBC"
		echo "   6) AES-256-CBC"
		until [[ $CIPHER_CHOICE =~ ^[1-6]$ ]]; do
			read -rp "加密算法 [1-6]: " -e -i 1 CIPHER_CHOICE
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
		esac
		echo ""
		echo "选择证书私钥的类型："
		echo "   1) ECDSA (推荐)"
		echo "   2) RSA"
		until [[ $CERT_TYPE =~ ^[1-2]$ ]]; do
			read -rp"私钥类型 [1-2]: " -e -i 1 CERT_TYPE
		done
		case $CERT_TYPE in
		1)
			echo ""
			echo "Choose which curve you want to use for the certificate's key:"
			echo "   1) prime256v1 (推荐)"
			echo "   2) secp384r1"
			echo "   3) secp521r1"
			until [[ $CERT_CURVE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp"Curve [1-3]: " -e -i 1 CERT_CURVE_CHOICE
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
			echo ""
			echo "选择证书的私钥长度："
			echo "   1) 2048 bits (推荐)"
			echo "   2) 3072 bits"
			echo "   3) 4096 bits"
			until [[ $RSA_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "私钥长度 [1-3]: " -e -i 1 RSA_KEY_SIZE_CHOICE
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
		echo ""
		echo "Choose which cipher you want to use for the control channel:"
		case $CERT_TYPE in
		1)
			echo "   1) ECDHE-ECDSA-AES-128-GCM-SHA256 (recommended)"
			echo "   2) ECDHE-ECDSA-AES-256-GCM-SHA384"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
				read -rp"Control channel cipher [1-2]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
				;;
			esac
			;;
		2)
			echo "   1) ECDHE-RSA-AES-128-GCM-SHA256 (recommended)"
			echo "   2) ECDHE-RSA-AES-256-GCM-SHA384"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
				read -rp"Control channel cipher [1-2]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"
				;;
			esac
			;;
		esac
		echo ""
		echo "Choose what kind of Diffie-Hellman key you want to use:"
		echo "   1) ECDH (recommended)"
		echo "   2) DH"
		until [[ $DH_TYPE =~ [1-2] ]]; do
			read -rp"DH key type [1-2]: " -e -i 1 DH_TYPE
		done
		case $DH_TYPE in
		1)
			echo ""
			echo "Choose which curve you want to use for the ECDH key:"
			echo "   1) prime256v1 (recommended)"
			echo "   2) secp384r1"
			echo "   3) secp521r1"
			while [[ $DH_CURVE_CHOICE != "1" && $DH_CURVE_CHOICE != "2" && $DH_CURVE_CHOICE != "3" ]]; do
				read -rp"Curve [1-3]: " -e -i 1 DH_CURVE_CHOICE
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
			echo ""
			echo "Choose what size of Diffie-Hellman key you want to use:"
			echo "   1) 2048 bits (recommended)"
			echo "   2) 3072 bits"
			echo "   3) 4096 bits"
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
		echo ""
		# The "auth" options behaves differently with AEAD ciphers
		if [[ $CIPHER =~ CBC$ ]]; then
			echo "The digest algorithm authenticates data channel packets and tls-auth packets from the control channel."
		elif [[ $CIPHER =~ GCM$ ]]; then
			echo "The digest algorithm authenticates tls-auth packets from the control channel."
		fi
		echo "Which digest algorithm do you want to use for HMAC?"
		echo "   1) SHA-256 (recommended)"
		echo "   2) SHA-384"
		echo "   3) SHA-512"
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
		echo ""
		echo "You can add an additional layer of security to the control channel with tls-auth and tls-crypt"
		echo "tls-auth authenticates the packets, while tls-crypt authenticate and encrypt them."
		echo "   1) tls-crypt (recommended)"
		echo "   2) tls-auth"
		until [[ $TLS_SIG =~ [1-2] ]]; do
			read -rp "Control channel additional security mechanism [1-2]: " -e -i 1 TLS_SIG
		done
	fi
	echo ""
	echo "好的，我们已经得到所有需要的信息，已经准备好为你部署Openvpn服务器了。"
	echo "脚本会在安装完成后生成客户端配置文件。"
	APPROVE_INSTALL=${APPROVE_INSTALL:-n}
	if [[ $APPROVE_INSTALL =~ n ]]; then
		read -n1 -r -p "按任意键继续。。。"
	fi
}

function installOpenVPN() {
	if [[ $AUTO_INSTALL == "y" ]]; then
		# Set default choices so that no questions will be asked.
		APPROVE_INSTALL=${APPROVE_INSTALL:-y}
		APPROVE_IP=${APPROVE_IP:-y}
		PORT_CHOICE=${PORT_CHOICE:-1}
		PROTOCOL_CHOICE=${PROTOCOL_CHOICE:-1}
		COMPRESSION_ENABLED=${COMPRESSION_ENABLED:-n}
		CUSTOMIZE_ENC=${CUSTOMIZE_ENC:-n}
		CLIENT=${CLIENT:-client}
		PASS=${PASS:-1}
		CONTINUE=${CONTINUE:-y}
		MULTI_USER=${CONTINUE:-y}

		# Behind NAT, we'll default to the publicly reachable IPv4/IPv6.
		PUBLIC_IP=$(curl -4 https://ifconfig.co)
		ENDPOINT=${ENDPOINT:-$PUBLIC_IP}
	fi

	# Run setup questions first, and set other variales if auto-install
	installQuestions

	# If OpenVPN isn't installed yet, install it. This script is more-or-less
	# idempotent on multiple runs, but will only install OpenVPN from upstream
	# the first time.
	if [[ ! -e /etc/openvpn/server.conf ]]; then
		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get update
			apt-get -y install ca-certificates gnupg
			# We add the OpenVPN repo to get the latest version.
			if [[ $VERSION_ID == "8" ]]; then
				echo "deb http://build.openvpn.net/debian/openvpn/stable jessie main" >/etc/apt/sources.list.d/openvpn.list
				wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
				apt-get update
			fi
			if [[ $VERSION_ID == "16.04" ]]; then
				echo "deb http://build.openvpn.net/debian/openvpn/stable xenial main" >/etc/apt/sources.list.d/openvpn.list
				wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
				apt-get update
			fi
			# Ubuntu > 16.04 and Debian > 8 have OpenVPN >= 2.4 without the need of a third party repository.
			apt-get install -y openvpn iptables openssl wget ca-certificates curl
		elif [[ $OS == 'centos' ]]; then
			yum install -y epel-release
			yum install -y openvpn iptables openssl wget ca-certificates curl tar 'policycoreutils-python*'
		elif [[ $OS == 'amzn' ]]; then
			amazon-linux-extras install -y epel
			yum install -y openvpn iptables openssl wget ca-certificates curl
		elif [[ $OS == 'fedora' ]]; then
			dnf install -y openvpn iptables openssl wget ca-certificates curl policycoreutils-python-utils
		elif [[ $OS == 'arch' ]]; then
			# Install required dependencies and upgrade the system
			pacman --needed --noconfirm -Syu openvpn iptables openssl wget ca-certificates curl
		fi
		# An old version of easy-rsa was available by default in some openvpn packages
		if [[ -d /etc/openvpn/easy-rsa/ ]]; then
			rm -rf /etc/openvpn/easy-rsa/
		fi
	fi

	# Find out if the machine uses nogroup or nobody for the permissionless group
	if grep -qs "^nogroup:" /etc/group; then
		NOGROUP=nogroup
	else
		NOGROUP=nobody
	fi

	# Install the latest version of easy-rsa from source, if not already installed.
	if [[ ! -d /etc/openvpn/easy-rsa/ ]]; then
		local version="3.0.7"
		wget -O ~/easy-rsa.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v${version}/EasyRSA-${version}.tgz
		mkdir /etc/openvpn/easy-rsa
		tar xzf ~/easy-rsa.tgz --strip-components=1 --directory /etc/openvpn/easy-rsa
		rm -f ~/easy-rsa.tgz

		cd /etc/openvpn/easy-rsa/ || return
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

		echo "set_var EASYRSA_REQ_CN $SERVER_CN" >>vars

		# Create the PKI, set up the CA, the DH params and the server certificate
		./easyrsa init-pki

		# Workaround to remove unharmful error until easy-rsa 3.0.7
		# https://github.com/OpenVPN/easy-rsa/issues/261
		sed -i 's/^RANDFILE/#RANDFILE/g' pki/openssl-easyrsa.cnf

		./easyrsa --batch build-ca nopass

		if [[ $DH_TYPE == "2" ]]; then
			# ECDH keys are generated on-the-fly so we don't need to generate them beforehand
			openssl dhparam -out dh.pem $DH_KEY_SIZE
		fi

		./easyrsa build-server-full "$SERVER_NAME" nopass
		EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

		case $TLS_SIG in
		1)
			# Generate tls-crypt key
			openvpn --genkey --secret /etc/openvpn/tls-crypt.key
			;;
		2)
			# Generate tls-auth key
			openvpn --genkey --secret /etc/openvpn/tls-auth.key
			;;
		esac
	else
		# If easy-rsa is already installed, grab the generated SERVER_NAME
		# for client configs
		cd /etc/openvpn/easy-rsa/ || return
		SERVER_NAME=$(cat SERVER_NAME_GENERATED)
	fi

	# Move all the generated files
	cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
	if [[ $DH_TYPE == "2" ]]; then
		cp dh.pem /etc/openvpn
	fi

	# Make cert revocation list readable for non-root
	chmod 644 /etc/openvpn/crl.pem

	# Generate server.conf
	echo "port $PORT" >/etc/openvpn/server.conf
	if [[ $IPV6_SUPPORT == 'n' ]]; then
		echo "proto $PROTOCOL" >>/etc/openvpn/server.conf
	elif [[ $IPV6_SUPPORT == 'y' ]]; then
		echo "proto ${PROTOCOL}6" >>/etc/openvpn/server.conf
	fi

	echo "dev tap
user nobody
group $NOGROUP
persist-key
persist-tun
keepalive 10 120
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" >>/etc/openvpn/server.conf

	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "compress $COMPRESSION_ALG" >>/etc/openvpn/server.conf
	fi
	
	if [[ $MULTI_USER == "y" ]]; then
		echo "duplicate-cn" >>/etc/openvpn/server.conf
	fi

	if [[ $DH_TYPE == "1" ]]; then
		echo "dh none" >>/etc/openvpn/server.conf
		echo "ecdh-curve $DH_CURVE" >>/etc/openvpn/server.conf
	elif [[ $DH_TYPE == "2" ]]; then
		echo "dh dh.pem" >>/etc/openvpn/server.conf
	fi

	case $TLS_SIG in
	1)
		echo "tls-crypt tls-crypt.key 0" >>/etc/openvpn/server.conf
		;;
	2)
		echo "tls-auth tls-auth.key 0" >>/etc/openvpn/server.conf
		;;
	esac

	echo "crl-verify crl.pem
ca ca.crt
cert $SERVER_NAME.crt
key $SERVER_NAME.key
auth $HMAC_ALG
cipher $CIPHER
ncp-ciphers $CIPHER
tls-server
tls-version-min 1.2
tls-cipher $CC_CIPHER
client-config-dir /etc/openvpn/ccd
status /var/log/openvpn/status.log
verb 3
client-to-client" >>/etc/openvpn/server.conf

	# Create client-config-dir dir
	mkdir -p /etc/openvpn/ccd
	# Create log dir
	mkdir -p /var/log/openvpn

	# If SELinux is enabled and a custom port was selected, we need this
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ $PORT != '1194' ]]; then
				semanage port -a -t openvpn_port_t -p "$PROTOCOL" "$PORT"
			fi
		fi
	fi

	# Finally, restart and enable OpenVPN
	if [[ $OS == 'arch' || $OS == 'fedora' || $OS == 'centos' ]]; then
		# Don't modify package-provided service
		cp /usr/lib/systemd/system/openvpn-server@.service /etc/systemd/system/openvpn-server@.service

		# Workaround to fix OpenVPN service on OpenVZ
		sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn-server@.service
		# Another workaround to keep using /etc/openvpn/
		sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn-server@.service
		# On fedora, the service hardcodes the ciphers. We want to manage the cipher ourselves, so we remove it from the service
		if [[ $OS == "fedora" ]]; then
			sed -i 's|--cipher AES-256-GCM --ncp-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC:BF-CBC||' /etc/systemd/system/openvpn-server@.service
		fi

		systemctl daemon-reload
		systemctl enable openvpn-server@server
		systemctl restart openvpn-server@server
	elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
		# On Ubuntu 16.04, we use the package from the OpenVPN repo
		# This package uses a sysvinit service
		systemctl enable openvpn
		systemctl start openvpn
	else
		# Don't modify package-provided service
		cp /lib/systemd/system/openvpn\@.service /etc/systemd/system/openvpn\@.service

		# Workaround to fix OpenVPN service on OpenVZ
		sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn\@.service
		# Another workaround to keep using /etc/openvpn/
		sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn\@.service

		systemctl daemon-reload
		systemctl enable openvpn@server
		systemctl restart openvpn@server
	fi

	# If the server is behind a NAT, use the correct IP address for the clients to connect to
	if [[ $ENDPOINT != "" ]]; then
		IP=$ENDPOINT
	fi

	# client-template.txt is created so we have a template to add further users later
	echo "client" >/etc/openvpn/client-template.txt
	if [[ $PROTOCOL == 'udp' ]]; then
		echo "proto udp" >>/etc/openvpn/client-template.txt
		echo "explicit-exit-notify" >>/etc/openvpn/client-template.txt
	elif [[ $PROTOCOL == 'tcp' ]]; then
		echo "proto tcp-client" >>/etc/openvpn/client-template.txt
	fi
	echo "remote $IP $PORT
dev tap
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name $SERVER_NAME name
auth $HMAC_ALG
auth-nocache
cipher $CIPHER
tls-client
tls-version-min 1.2
tls-cipher $CC_CIPHER" >>/etc/openvpn/client-template.txt

	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "compress $COMPRESSION_ALG" >>/etc/openvpn/client-template.txt
	fi

	# Generate the custom client.ovpn
	newClient
	echo "如果你想添加更多的账号，你可以重新运行本脚本！"
}

function newClient() {
	echo ""
	echo "请告诉我客户端名称。"
	echo "只能使用字母，不允许有特殊符号。"

	until [[ $CLIENT =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "客户端名称: " -e CLIENT
	done

	echo ""
	echo "你想用私钥加密你的配置文件吗？"
	echo "   1) 添加一个没有私钥的账号"
	echo "   2) 添加一个带私钥的账号"

	until [[ $PASS =~ ^[1-2]$ ]]; do
		read -rp "选项 [1-2]: " -e -i 1 PASS
	done

	CLIENTEXISTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c -E "/CN=$CLIENT\$")
	if [[ $CLIENTEXISTS == '1' ]]; then
		echo ""
		echo "这个客户端名称已被使用。"
		exit
	else
		cd /etc/openvpn/easy-rsa/ || return
		case $PASS in
		1)
			./easyrsa build-client-full "$CLIENT" nopass
			;;
		2)
			echo "⚠️ 下面会询问你的私钥 ⚠️"
			./easyrsa build-client-full "$CLIENT"
			;;
		esac
		echo "客户端 $CLIENT 已添加。"
	fi

	# Home directory of the user, where the client configuration (.ovpn) will be written
	if [ -e "/home/$CLIENT" ]; then # if $1 is a user name
		homeDir="/home/$CLIENT"
	elif [ "${SUDO_USER}" ]; then # if not, use SUDO_USER
		homeDir="/home/${SUDO_USER}"
	else # if not SUDO_USER, use /root
		homeDir="/root"
	fi

	# Determine if we use tls-auth or tls-crypt
	if grep -qs "^tls-crypt" /etc/openvpn/server.conf; then
		TLS_SIG="1"
	elif grep -qs "^tls-auth" /etc/openvpn/server.conf; then
		TLS_SIG="2"
	fi

	# Generates the custom client.ovpn
	cp /etc/openvpn/client-template.txt "$homeDir/$CLIENT.ovpn"
	{
		echo "<ca>"
		cat "/etc/openvpn/easy-rsa/pki/ca.crt"
		echo "</ca>"

		echo "<cert>"
		awk '/BEGIN/,/END/' "/etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt"
		echo "</cert>"

		echo "<key>"
		cat "/etc/openvpn/easy-rsa/pki/private/$CLIENT.key"
		echo "</key>"

		case $TLS_SIG in
		1)
			echo "<tls-crypt>"
			cat /etc/openvpn/tls-crypt.key
			echo "</tls-crypt>"
			;;
		2)
			echo "key-direction 1"
			echo "<tls-auth>"
			cat /etc/openvpn/tls-auth.key
			echo "</tls-auth>"
			;;
		esac
	} >>"$homeDir/$CLIENT.ovpn"

	echo ""
	echo "配置文件已经成功写入 $homeDir/$CLIENT.ovpn"
	echo "下载这个.ovpn文件然后导入你的客户端即可。"

	exit 0
}

function revokeClient() {
	NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ $NUMBEROFCLIENTS == '0' ]]; then
		echo ""
		echo "你还没有添加客户端！"
		exit 1
	fi

	echo ""
	echo "选择你想删除的客户端"
	tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
	until [[ $CLIENTNUMBER -ge 1 && $CLIENTNUMBER -le $NUMBEROFCLIENTS ]]; do
		if [[ $CLIENTNUMBER == '1' ]]; then
			read -rp "客户端 [1]: " CLIENTNUMBER
		else
			read -rp "客户端 [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
		fi
	done
	CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
	cd /etc/openvpn/easy-rsa/ || return
	./easyrsa --batch revoke "$CLIENT"
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	rm -f /etc/openvpn/crl.pem
	cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
	chmod 644 /etc/openvpn/crl.pem
	find /home/ -maxdepth 2 -name "$CLIENT.ovpn" -delete
	rm -f "/root/$CLIENT.ovpn"
	sed -i "/^$CLIENT,.*/d" /etc/openvpn/ipp.txt

	echo ""
	echo "$CLIENT 已被删除。"
}

function removeOpenVPN() {
	echo ""
	# shellcheck disable=SC2034
	read -rp "确定要卸载Openvpn吗？ [y/n]: " -e -i n REMOVE
	if [[ $REMOVE == 'y' ]]; then
		# Get OpenVPN port from the configuration
		PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
		PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)

		# Stop OpenVPN
		if [[ $OS =~ (fedora|arch|centos) ]]; then
			systemctl disable openvpn-server@server
			systemctl stop openvpn-server@server
			# Remove customised service
			rm /etc/systemd/system/openvpn-server@.service
		elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
			systemctl disable openvpn
			systemctl stop openvpn
		else
			systemctl disable openvpn@server
			systemctl stop openvpn@server
			# Remove customised service
			rm /etc/systemd/system/openvpn\@.service
		fi

		# Remove the iptables rules related to the script
		systemctl stop iptables-openvpn
		# Cleanup
		systemctl disable iptables-openvpn
		rm /etc/systemd/system/iptables-openvpn.service
		systemctl daemon-reload
		rm /etc/iptables/add-openvpn-rules.sh
		rm /etc/iptables/rm-openvpn-rules.sh

		# SELinux
		if hash sestatus 2>/dev/null; then
			if sestatus | grep "Current mode" | grep -qs "enforcing"; then
				if [[ $PORT != '1194' ]]; then
					semanage port -d -t openvpn_port_t -p "$PROTOCOL" "$PORT"
				fi
			fi
		fi

		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get autoremove --purge -y openvpn
			if [[ -e /etc/apt/sources.list.d/openvpn.list ]]; then
				rm /etc/apt/sources.list.d/openvpn.list
				apt-get update
			fi
		elif [[ $OS == 'arch' ]]; then
			pacman --noconfirm -R openvpn
		elif [[ $OS =~ (centos|amzn) ]]; then
			yum remove -y openvpn
		elif [[ $OS == 'fedora' ]]; then
			dnf remove -y openvpn
		fi

		# Cleanup
		find /home/ -maxdepth 2 -name "*.ovpn" -delete
		find /root/ -maxdepth 1 -name "*.ovpn" -delete
		rm -rf /etc/openvpn
		rm -rf /usr/share/doc/openvpn*
		rm -f /etc/sysctl.d/20-openvpn.conf
		rm -rf /var/log/openvpn

		echo ""
		echo "OpenVPN 卸载完成！"
	else
		echo ""
		echo "卸载已取消。"
	fi
}

function manageMenu() {
	echo "欢迎使用Openvpn部署工具！"
	echo "本脚本修改自angristan的安装脚本，项目地址：https://github.com/Nouko61/openvpn-install"
	echo "原项目地址：https://github.com/angristan/openvpn-install"
	echo ""
	echo "看起来你已经把Openvpn安装好了"
	echo ""
	echo "你想要做什么"
	echo "   1) 添加一个新账号"
	echo "   2) 删除一个现有的账号"
	echo "   3) 卸载Openvpn"
	echo "   4) 退出"
	until [[ $MENU_OPTION =~ ^[1-4]$ ]]; do
		read -rp "选项 [1-4]: " MENU_OPTION
	done

	case $MENU_OPTION in
	1)
		newClient
		;;
	2)
		revokeClient
		;;
	3)
		removeOpenVPN
		;;
	4)
		exit 0
		;;
	esac
}

# Check for root, TUN, OS...
initialCheck

# Check if OpenVPN is already installed
if [[ -e /etc/openvpn/server.conf && $AUTO_INSTALL != "y" ]]; then
	manageMenu
else
	installOpenVPN
fi
