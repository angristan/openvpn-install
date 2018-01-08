#!/bin/bash

# Secure OpenVPN server installer for Debian, Ubuntu, CentOS and Arch Linux
# https://github.com/Angristan/OpenVPN-install


if [[ "$EUID" -ne 0 ]]; then
	echo "Sorry, you need to run this as root"
	exit 1
fi

if [[ ! -e /dev/net/tun ]]; then
	echo "TUN is not available"
	exit 2
fi

if grep -qs "CentOS release 5" "/etc/redhat-release"; then
	echo "CentOS 5 is too old and not supported"
	exit 3
fi

## Global variables
dir_openvpn='/etc/openvpn'
dir_easy="${dir_openvpn}/easy-rsa"
dir_pki="${dir_easy}/pki"
file_index="${dir_pki}/index.txt"
bin_easy="${dir_easy}/easyrsa"
conf_client_tpl="${dir_openvpn}/client-template.txt"
conf_server="${dir_openvpn}/server.conf"
conf_iptables='/etc/sysconfig/iptables.rules'


## function: config the firewall
set_firewall(){

# Create the sysctl configuration file if needed (mainly for Arch Linux)
if [[ ! -e $SYSCTL ]]; then
	touch $SYSCTL
fi

# Enable net.ipv4.ip_forward for the system
sed -i '/\<net.ipv4.ip_forward\>/c\net.ipv4.ip_forward=1' $SYSCTL
if ! grep -q "\<net.ipv4.ip_forward\>" $SYSCTL; then
	echo 'net.ipv4.ip_forward=1' >> $SYSCTL
fi
# Avoid an unneeded reboot
echo 1 > /proc/sys/net/ipv4/ip_forward
# Set NAT for the VPN subnet
iptables -t nat -A POSTROUTING -o $NIC -s 10.8.0.0/24 -j MASQUERADE
# Save persitent iptables rules
iptables-save > $conf_iptables
if pgrep firewalld; then
	# We don't use --add-service=openvpn because that would only work with
	# the default port. Using both permanent and not permanent rules to
	# avoid a firewalld reload.
	firewall-cmd --zone=public --add-port=$PORT/${PROTOCOL}
	firewall-cmd --permanent --zone=public --add-port=$PORT/${PROTOCOL}
	firewall-cmd --zone=trusted --add-source=10.8.0.0/24
	firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
fi
if iptables -L -n | grep -qE 'REJECT|DROP'; then
	# If iptables has at least one REJECT rule, we asume this is needed.
	# Not the best approach but I can't think of other and this shouldn't
	# cause problems.
	iptables -I INPUT -p ${PROTOCOL} --dport $PORT -j ACCEPT
	iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
	iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
	# Save persitent OpenVPN rules
	iptables-save > $conf_iptables
fi
# If SELinux is enabled and a custom port was selected, we need this
if hash sestatus 2>/dev/null; then
	if sestatus | grep "Current mode" | grep -qs "enforcing"; then
		if [[ "$PORT" != '1194' ]]; then
			# semanage isn't available in CentOS 6 by default
			if ! hash semanage 2>/dev/null; then
				yum install policycoreutils-python -y
			fi
			semanage port -a -t openvpn_port_t -p ${PROTOCOL} $PORT
		fi
	fi
fi
}

## function: generate the new client??.ovpn
generate_newclient() {

# Generates the custom client.ovpn
# Where to write the custom client.ovpn?
if [ -e /home/$CLIENT ]; then  # if $CLIENT is a user name
	homeDir="/home/$CLIENT"
elif [ ${SUDO_USER} ]; then   # if not, use SUDO_USER
	homeDir="/home/${SUDO_USER}"
else  # if not SUDO_USER, use /root
	homeDir="${dir_openvpn}"
fi
# Generates the custom client.ovpn
file_client="$homeDir/$CLIENT.ovpn"
cp ${conf_client_tpl} ${file_client}
echo "<ca>" >> ${file_client}
cat ${dir_pki}/ca.crt >> ${file_client}
echo "</ca>" >> ${file_client}
echo "<cert>" >> ${file_client}
cat ${dir_pki}/issued/$CLIENT.crt >> ${file_client}
echo "</cert>" >> ${file_client}
echo "<key>" >> ${file_client}
cat ${dir_pki}/private/$CLIENT.key >> ${file_client}
echo "</key>" >> ${file_client}
echo "key-direction 1" >> ${file_client}
echo "<tls-auth>" >> ${file_client}
cat ${dir_openvpn}/tls-auth.key >> ${file_client}
echo "</tls-auth>" >> ${file_client}

echo ""
echo "Client $CLIENT added, certs available at $homeDir/$CLIENT.ovpn"

}

## function: revoke a exist client??.ovpn
revoke_openvpn_client(){

NUMBEROFCLIENTS=$(tail -n +2 ${file_index} | grep -c "^V")
if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
	echo ""
	echo "You have no existing clients!"
	exit 5
fi
echo ""
echo "Select the existing client certificate you want to revoke"
tail -n +2 ${file_index} | grep "^V" | cut -d '=' -f 2 | nl -s ') '
if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
	read -p "Select one client [1]: " CLIENTNUMBER
else
	read -p "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
fi
CLIENT=$(tail -n +2 ${file_index} | grep "^V" | cut -d '=' -f 2 | sed -n "${CLIENTNUMBER:?empty-var}"p)
cd ${dir_easy}
${bin_easy} --batch revoke $CLIENT
EASYRSA_CRL_DAYS=3650 ${bin_easy} gen-crl
rm -f ${dir_pki}/reqs/$CLIENT.req ${dir_pki}/private/$CLIENT.key ${dir_pki}/issued/$CLIENT.crt 
#rm -f ${dir_openvpn}/crl.pem
/bin/cp -f ${dir_pki}/crl.pem ${dir_openvpn}/crl.pem
chmod 644 ${dir_openvpn}/crl.pem
echo ""
echo "Certificate for client $CLIENT revoked"
echo "Exiting..."
}

## function: install easyrsa 3.0.3
install_easyrsa(){

# An old version of easy-rsa was available by default in some openvpn packages
rm -rf ${dir_easy}
mkdir -p ${dir_easy}
# Get easy-rsa
url_easy='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.3/EasyRSA-3.0.3.tgz'
file_easy=${url_easy##*/}
wget -c -O ~/${file_easy} ${url_easy}
tar xzf ~/${file_easy} -C ~/
mv ~/${file_easy%.tgz}/* ${dir_easy}/
chown -R root:root ${dir_easy}/
rm -rf ~/${file_easy}
}

## function: install iptables for debian
systemd_ipt_service(){

dir_ipt='/etc/iptables'
file_ipt_svc='/etc/systemd/system/iptables.service'
file_ipt_sh="${dir_ipt}/flush-iptables.sh"
# Install iptables service
if [[ ! -e ${file_ipt_svc} ]]; then
	mkdir ${dir_ipt}
	iptables-save > ${conf_iptables}
	echo "#!/bin/sh
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT" > ${file_ipt_sh}
	chmod +x ${file_ipt_sh}
	echo "[Unit]
Description=Packet Filtering Framework
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore ${conf_iptables}
ExecReload=/sbin/iptables-restore ${conf_iptables}
ExecStop=/etc/iptables/flush-iptables.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" > ${file_ipt_svc}
	systemctl daemon-reload
	systemctl enable iptables.service
	if [[ "$OS" = 'centos7' || "$OS" = 'fedora' ]]; then
		# Disable firewalld to allow iptables to start upon reboot
		systemctl disable firewalld
		systemctl mask firewalld
	fi
fi
}

##
config_iptables(){
	echo "Please manually set the firewall"
	read -p "press any key continue..."
}

##
config_firewalld(){
	echo "Please manually set the firewall"
	read -p "press any key continue..."
}

	
## function: install openvpn server
install_openvpn(){

clear
cat <<EOF
Welcome to the secure OpenVPN installer (github.com/Angristan/OpenVPN-install)

I need to ask you a few questions before starting the setup
You can leave the default options and just press enter if you are ok with them
"
I need to know the IPv4 address of the network interface you want OpenVPN listening to.
If your server is running behind a NAT, (e.g. LowEndSpirit, Scaleway) leave the IP address as it is. (local/private IP)
Otherwise, it should be your public IPv4 address.
EOF
read -p "IP address: " -e -i $IP IP

echo ""
echo "What port do you want for OpenVPN?"
read -p "Port: " -e -i 1194 PORT

echo ""
echo "1/6.What protocol do you want for OpenVPN?"
echo "Unless UDP is blocked, you should not use TCP (unnecessarily slower)"
while [[ $PROTOCOL != "udp" && $PROTOCOL != "tcp" ]]; do
	read -p "Protocol [udp/tcp]: " -e -i udp PROTOCOL
done

cat <<EOF
2/6.What DNS do you want to use with the VPN?
   1) Current system resolvers (from /etc/resolv.conf)
   2) Quad9 (Anycast: worldwide)
   3) FDN (France)
   4) DNS.WATCH (Germany)
   5) OpenDNS (Anycast: worldwide)
   6) Google (Anycast: worldwide)
   7) Yandex Basic (Russia)
   8) AdGuard DNS (Russia)
EOF
while [[ $DNS != [1-8] ]]; do
	read -p "DNS [1-8]: " -e -i 1 DNS
done

cat <<EOF
See https://github.com/Angristan/OpenVPN-install#encryption to learn more about 
the encryption in OpenVPN and the choices I made in this script.
Please note that all the choices proposed are secure (to a different degree)
and are still viable to date, unlike some default OpenVPN options

3/6.Choose which cipher you want to use for the data channel:
   1) AES-128-CBC (fastest and sufficiently secure for everyone, recommended)
   2) AES-192-CBC
   3) AES-256-CBC
Alternatives to AES, use them only if you know what you're doing.
They are relatively slower but as secure as AES.
   4) CAMELLIA-128-CBC
   5) CAMELLIA-192-CBC
   6) CAMELLIA-256-CBC
   7) SEED-CBC
EOF
while [[ $CIPHER != [1-7] ]]; do
	read -p "Cipher [1-7]: " -e -i 1 CIPHER
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
echo "4/6.Choose what size of Diffie-Hellman key you want to use:"
echo "   1) 2048 bits (fastest)"
echo "   2) 3072 bits (recommended, best compromise)"
echo "   3) 4096 bits (most secure)"
while [[ $DH_KEY_SIZE != [1-3] ]]; do
	read -p "DH key size [1-3]: " -e -i 2 DH_KEY_SIZE
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
echo "5/6.Choose what size of RSA key you want to use:"
echo "   1) 2048 bits (fastest)"
echo "   2) 3072 bits (recommended, best compromise)"
echo "   3) 4096 bits (most secure)"
while [[ $RSA_KEY_SIZE != [1-3] ]]; do
	read -p "RSA key size [1-3]: " -e -i 2 RSA_KEY_SIZE
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
echo "6/6.Finally, tell me a name for the client certificate and configuration"
while [[ $CLIENT = "" ]]; do
	echo "Please, use one word only, no special characters"
	read -p "Client name: " -e -i client CLIENT
done

echo ""
echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now"
read -n1 -r -p "Press any key to continue..."

if [[ "$OS" = 'debian' ]]; then
	apt-get install ca-certificates -y
	# We add the OpenVPN repo to get the latest version.
	case $VERSION_ID in 
	'7')  # Debian 7
		echo "deb http://build.openvpn.net/debian/openvpn/stable wheezy main" > /etc/apt/sources.list.d/openvpn.list
		wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
		apt-get update
		;;
	'8')  # Debian 8
		echo "deb http://build.openvpn.net/debian/openvpn/stable jessie main" > /etc/apt/sources.list.d/openvpn.list
		wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
		apt update
		;;
	'12.04')  # Ubuntu 12.04
		echo "deb http://build.openvpn.net/debian/openvpn/stable precise main" > /etc/apt/sources.list.d/openvpn.list
		wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
		apt-get update
		;;
	'14.04')  # Ubuntu 14.04
		echo "deb http://build.openvpn.net/debian/openvpn/stable trusty main" > /etc/apt/sources.list.d/openvpn.list
		wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
		apt-get update
	esac
	# Ubuntu >= 16.04 and Debian > 8 have OpenVPN > 2.3.3 without the need of a third party repository.
	## The we install OpenVPN
	apt-get install openvpn iptables openssl wget ca-certificates curl -y
	systemd_ipt_service ## call function
elif [[ "$OS" = 'centos6' || "$OS" = 'centos7' || "$OS" = 'fedora' ]]; then
	if [[ "$OS" != 'fedora' ]]; then
		yum install epel-release -y
	fi
	yum --enablerepo=epel install openvpn iptables openssl wget ca-certificates curl -y
	if [[ "$OS" = 'centos6' ]]; then 
		config_iptables ## call function
	else
		config_firewalld ## call function
	fi
else
	# Else, the distro is ArchLinux
	echo ""
	echo ""
	echo "As you're using ArchLinux, I need to update the packages on your system to install those I need."
	echo "Not doing that could cause problems between dependencies, or missing files in repositories."
	echo ""
	echo "Continuing will update your installed packages and install needed ones."
	while [[ $CONTINUE != [yn] ]]; do
		read -p "Continue ? [y/n]: " -e -i y CONTINUE
	done
	if [[ "$CONTINUE" = "n" ]]; then
		echo "Ok, bye !"
		exit 4
	fi

	if [[ "$OS" = 'arch' ]]; then
		# Install dependencies
		pacman -Syu openvpn iptables openssl wget ca-certificates curl --needed --noconfirm
		iptables-save > ${conf_iptables} # iptables won't start if this file does not exist
		systemctl daemon-reload
		systemctl enable iptables
		systemctl start iptables
	fi
fi


# Find out if the machine uses nogroup or nobody for the permissionless group
if grep -qs "^nogroup:" /etc/group; then
	NOGROUP=nogroup
else
	NOGROUP=nobody
fi

install_easyrsa ## call function 

cd ${dir_easy}/
echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" > vars
# Create the PKI, set up the CA, the DH params and the server + client certificates
${dir_easy}/easyrsa init-pki
${dir_easy}/easyrsa --batch build-ca nopass
openssl dhparam -out dh.pem $DH_KEY_SIZE
${dir_easy}/easyrsa build-server-full server nopass
${dir_easy}/easyrsa build-client-full $CLIENT nopass
EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
## generate tls-auth key
openvpn --genkey --secret ${dir_openvpn}/tls-auth.key
## Move all the generated files
cp ${dir_pki}/ca.crt ${dir_pki}/private/ca.key dh.pem ${dir_pki}/issued/server.crt ${dir_pki}/private/server.key ${dir_pki}/crl.pem ${dir_openvpn}/
## Make cert revocation list readable for non-root
chmod 644 ${dir_openvpn}/crl.pem

## Generate server.conf
echo "port $PORT
proto ${PROTOCOL}
dev tun
user nobody
group $NOGROUP
persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
#client-config-dir ccd
#route 10.8.0.0 255.255.255.252" >> ${conf_server}
# DNS resolvers
case $DNS in
	1)
	# Obtain the resolvers from resolv.conf and use them for OpenVPN
	grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | \
	while read line; do
		echo "push \"dhcp-option DNS $line\"" 
	done
	;;
	2) #Quad9
	echo 'push "dhcp-option DNS 9.9.9.9"' 
	;;
	3) #FDN
	echo 'push "dhcp-option DNS 80.67.169.12"'
	echo 'push "dhcp-option DNS 80.67.169.40"'
	;;
	4) #DNS.WATCH
	echo 'push "dhcp-option DNS 84.200.69.80"'
	echo 'push "dhcp-option DNS 84.200.70.40"'
	;;
	5) #OpenDNS
	echo 'push "dhcp-option DNS 208.67.222.222"'
	echo 'push "dhcp-option DNS 208.67.220.220"'
	;;
	6) #Google
	echo 'push "dhcp-option DNS 8.8.8.8"'
	echo 'push "dhcp-option DNS 8.8.4.4"'
	;;
	7) #Yandex Basic
	echo 'push "dhcp-option DNS 77.88.8.8"'
	echo 'push "dhcp-option DNS 77.88.8.1"'
	;;
	8) #AdGuard DNS
	echo 'push "dhcp-option DNS 176.103.130.130"'
	echo 'push "dhcp-option DNS 176.103.130.131"'
	;;
esac >> ${conf_server}
echo 'push "redirect-gateway def1 bypass-dhcp" '>> ${conf_server}
echo "client-to-client
crl-verify crl.pem
ca ca.crt
cert server.crt
key server.key
tls-auth tls-auth.key 0
dh dh.pem
auth SHA256
$CIPHER
tls-server
tls-version-min 1.2
tls-cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256
status openvpn-status.log
log openvpn.log
log-append openvpn.log
verb 3" >> ${conf_server}

set_firewall ## call function
	
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
		if [[ "$OS" = 'arch' || "$OS" = 'fedora' ]]; then
			#Workaround to avoid rewriting the entire script for Arch & Fedora
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

# Try to detect a NATed connection and ask about it to potential LowEndSpirit/Scaleway users
EXTERNALIP=$(wget -qO- ipv4.icanhazip.com)
if [[ "$IP" != "$EXTERNALIP" ]]; then
	echo ""
	echo "Looks like your server is behind a NAT!"
	echo ""
	echo "If your server is NATed (e.g. LowEndSpirit, Scaleway, or behind a router),"
	echo "then I need to know the address that can be used to access it from outside."
	echo "If that's not the case, just ignore this and leave the next field blank"
	read -p "External IP or domain name: " -e USEREXTERNALIP
	if [[ "$USEREXTERNALIP" != "" ]]; then
		IP=$USEREXTERNALIP
	fi
fi
	
# client-template.txt is created so we have a template to add further users later
echo "client" > ${conf_client_tpl}
if [[ "$PROTOCOL" = 'udp' ]]; then
	echo "proto ${PROTOCOL}" >> ${conf_client_tpl}
elif [[ "$PROTOCOL" = 'tcp' ]]; then
	echo "proto ${PROTOCOL}-client" >> ${conf_client_tpl}
fi
echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
auth-nocache
$CIPHER
tls-client
tls-version-min 1.2
tls-cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256
setenv opt block-outside-dns
verb 3" >> ${conf_client_tpl}

# call function Generate the custom client.ovpn
generate_newclient "$CLIENT"
echo ""
echo "Finished!"
echo ""
echo "Your client config is available at $homeDir/$CLIENT.ovpn"
echo "If you want to add more clients, you simply need to run this script again!"
}

## function: remove openvpn server and config dir 
remove_openvpn(){

echo ""
read -p "Do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE
if [[ 'y' = "$REMOVE" ]]; then
	PORT=$(grep '^port ' ${conf_server} | cut -d " " -f 2)
	PROTOCOL=$(grep '^proto ' ${conf_server} | cut -d " " -f 2)
	if pgrep firewalld; then
		# Using both permanent and not permanent rules to avoid a firewalld reload.
		firewall-cmd --zone=public --remove-port=$PORT/${PROTOCOL}
		firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
		firewall-cmd --permanent --zone=public --remove-port=$PORT/${PROTOCOL}
		firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
	fi
	if iptables -L -n | grep -qE 'REJECT|DROP'; then
		iptables -D INPUT -p ${PROTOCOL} --dport $PORT -j ACCEPT
		iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
		iptables-save > $conf_iptables
	fi
	iptables -t nat -D POSTROUTING -o $NIC -s 10.8.0.0/24 -j MASQUERADE
	iptables-save > $conf_iptables
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ "$PORT" != '1194' ]]; then
				semanage port -d -t openvpn_port_t -p ${PROTOCOL} $PORT
			fi
		fi
	fi
	if [[ "$OS" = 'debian' ]]; then
		systemctl stop openvpn@server
		apt-get autoremove --purge -y openvpn
	elif [[ "$OS" = 'arch' ]]; then
		pacman -R openvpn --noconfirm
	elif [[ "$OS" = 'centos7' ]]; then
		systemctl stop openvpn@server
		yum remove openvpn -y
	elif [[ "$OS" = 'centos6' ]]; then
		/etc/init.d/openvpn stop
		yum remove openvpn -y
	else
		yum remove openvpn -y
	fi
	rm -rf ${dir_openvpn} /usr/share/doc/openvpn*
	echo ""
	echo "OpenVPN removed!"
else
	echo ""
	echo "Removal aborted!"
fi
}

config_openvpn_server(){
:
}

config_openvpn_client(){
:
}

config_openvpn(){

while :
do
	clear
	cat <<EOF
OpenVPN-install (github.com/xiagw/OpenVPN-install)

Looks like OpenVPN is already installed

What do you want to do?
   1) Add a cert for a new user
   2) Revoke existing user cert
   3) Remove OpenVPN
   4) Exit
EOF

	read -p 'Select an option [1-4]: ' option
	case $option in
		1)
		echo ""
		echo "Tell me a name for the client cert"
		echo "Please, use one word only, no special characters"
		echo "Here are the files that already exist,do not repeat that"
		tail -n +2 ${file_index} | grep "^V" | cut -d '=' -f 2 | nl -s ') '
		read -p "Client name: " -e -i client CLIENT
		cd ${dir_easy}
		${bin_easy} build-client-full $CLIENT nopass
		generate_newclient
		exit
		;;
		2)
		revoke_openvpn_client
		exit
		;;
		3)
		remove_openvpn ## call function 
		exit
		;;
		4) exit;;
	esac
done

}

## function: determine the operating system version
detect_os_ver(){

if [[ -e /etc/debian_version ]]; then
	OS="debian"
	# Getting the version number, to verify that a recent version of OpenVPN is available
	# VERSION_ID=$(grep "VERSION_ID" /etc/os-release)
	source /etc/os-release
	SYSCTL='/etc/sysctl.conf'
	case "$VERSION_ID" in 
	7|8|9|12.04|14.04|16.04|16.10|17.04)
		:
		;;
	*)
		echo 'Your version of Debian/Ubuntu is not supported.'
		echo "I can't install a recent version of OpenVPN on your system."
		echo ''
		echo "However, if you're using Debian unstable/testing, or Ubuntu beta,"
		echo 'then you can continue, a recent version of OpenVPN is available on these.'
		echo 'Keep in mind they are not supported, though.'
		while [[ "$CONTINUE" != [yn]  ]]; do
			read -p 'Continue ? [y/n]: ' -e CONTINUE
		done
		if [[ 'n' = "$CONTINUE" ]]; then
			echo 'Ok, bye !'
			exit 4
		fi
	esac
	# fi
elif [[ -e /etc/centos-release || -e /etc/redhat-release && ! -e /etc/fedora-release ]]; then
	# rpm -q --queryformat '%{VERSION}' centos-release
	# rpm -q --queryformat '%{RELEASE}' redhat-release-server | awk -F. '{print $1}'
	# grep -oE '[0-9]+\.[0-9]+' /etc/redhat-release	
	OS="centos$(rpm -q --queryformat '%{VERSION}' centos-release)"
	SYSCTL='/etc/sysctl.conf'
elif [[ -e /etc/arch-release ]]; then
	OS='arch'
	SYSCTL='/etc/sysctl.d/openvpn.conf'
elif [[ -e /etc/fedora-release ]]; then
	OS='fedora'
	SYSCTL='/etc/sysctl.d/openvpn.conf'
else
	echo "Looks like you aren't running this installer on a Debian, Ubuntu, CentOS or ArchLinux system"
	exit 4
fi
}

detect_IP_NIC(){

# Try to get our IP from the system and fallback to the Internet.
# I do this to make the script compatible with NATed servers (LowEndSpirit/Scaleway)
# and to avoid getting an IPv6.
IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
if [[ "$IP" = "" ]]; then
	IP=$(wget -qO- ipv4.icanhazip.com)
fi
# Get Internet network interface with default route
NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
}

################################# main #################################
main(){
detect_os_ver ## call function
detect_IP_NIC ## call function

## OpenVPN setup and first user creation
if [[ -e ${conf_server} ]]; then
	config_openvpn ## call function
else
	install_openvpn ## call function
fi
}

main $@
