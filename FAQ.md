# FAQ

**Q:** The script has been updated since I installed OpenVPN. How do I update?

**A:** You can't. Managing updates and new features from the script would require way too much work. Your only solution is to uninstall OpenVPN and reinstall with the updated script.

You can, of course, it's even recommended, update the `openvpn` package with your package manager.

---

**Q:** How do I check for DNS leaks?

**A:** Go to [browserleaks.com](https://browserleaks.com/dns) or [ipleak.net](https://ipleak.net/) (both perform IPv4 and IPv6 check) with your browser. Your IP should not show up (test without and without the VPN). The DNS servers should be the ones you selected during the setup, not your IP address nor your ISP's DNS servers' addresses.

---

**Q:** How do I fix DNS leaks?

**A:** On Windows 10 DNS leaks are blocked by default with the `block-outside-dns` option.
On Linux you need to add these lines to your `.ovpn` file based on your Distribution.

Debian 9, 10 and Ubuntu 16.04, 18.04

```
script-security 2
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf
```

Centos 6, 7

```
script-security 2
up /usr/share/doc/openvpn-2.4.8/contrib/pull-resolv-conf/client.up
down /usr/share/doc/openvpn-2.4.8/contrib/pull-resolv-conf/client.down
```

Centos 8, Fedora 30, 31

```
script-security 2
up /usr/share/doc/openvpn/contrib/pull-resolv-conf/client.up
down /usr/share/doc/openvpn/contrib/pull-resolv-conf/client.down
```

Arch Linux

```
script-security 2
up /usr/share/openvpn/contrib/pull-resolv-conf/client.up
down /usr/share/openvpn/contrib/pull-resolv-conf/client.down
```

---

**Q:** Can I use an OpenVPN 2.3 client?

**A:** Yes. I really recommend using an up-to-date client, but if you really need it, choose the following options:

- No compression or LZ0
- RSA certificate
- DH Key
- AES CBC
- tls-auth

If your client is <2.3.3, remove `tls-version-min 1.2` from your `/etc/openvpn/server.conf` and `.ovpn` files.

---

**Q:** IPv6 is not working on my Hetzner VM

**A:** This an issue on their side. See <https://angristan.xyz/fix-ipv6-hetzner-cloud/>

---

**Q:** DNS is not working on my Linux client

**A:** See "How do I fix DNS leaks?" question

---

**Q:** What syctl and iptables changes are made by the script?

**A:** Iptables rules are saved at `/etc/iptables/add-openvpn-rules.sh` and `/etc/iptables/rm-openvpn-rules.sh`. They are managed by the service `/etc/systemd/system/iptables-openvpn.service`

Sysctl options are at `/etc/sysctl.d/20-openvpn.conf`

---

**Q:** How can I access other clients connected to the same OpenVPN server?

**A:** Add `client-to-client` to your `server.conf`

---

**Q:** My router can't connect

**A:**

- `Options error: No closing quotation (") in config.ovpn:46` :

  type `yes` when asked to customize encryption settings and choose `tls-auth`

- `Options error: Unrecognized option or missing parameter(s) in config.ovpn:36: tls-version-min (2.3.2)` :

  see question "Can I use an OpenVPN 2.3 client?"

---

**Q:** How can I access computers the OpenVPN server's remote LAN?

**A:** Add a route with the subnet of the remote network to `/etc/openvpn/server.conf` and restart openvpn. Example: `push "route 192.168.1.0 255.255.255.0"` if the server's LAN is `192.168.1.0/24`

---

**Q:** How can I add multiple users in one go?

**A:** Here is a sample bash script to achieve this:

```sh
userlist=(user1 user2 user3)

for i in ${userlist[@]};do
   MENU_OPTION=1 CLIENT=$i PASS=1 ./openvpn-install.sh
done
```

From a list in a text file:

```sh
while read USER
    do MENU_OPTION="1" CLIENT="$USER" PASS="1" ./openvpn-install.sh
done < users.txt
```

---

**Q:** How do I change the default `.ovpn` file created for future clients?

**A:** You can edit the template out of which `.ovpn` files are created by editing `/etc/openvpn/client-template.txt`

---

**Q:** For my clients - I want to set my internal network to pass through the VPN and the rest to go through my internet?

**A:** You would need to edit the `.ovpn` file. You can edit the template out of which those files are created by editing `/etc/openvpn/client-template.txt` file and adding

```sh
route-nopull
route 10.0.0.0 255.0.0.0
```

So for example - here it would route all traffic of `10.0.0.0/8` to the vpn. And the rest through the internet.

---

**Q:** I have enabled IPv6 and my VPN client gets an IPv6 address. Why do I reach the websites or other dual-stacked destionations via IPv4 only?

**A:** This is because inside the tunnel you don't get a publicly routable IPv6 address, instead you get an ULA (Unlique Local Lan) address. Operating systems don't prefer this all the time. You can fix this in your operating system policies as it's unrelated to the VPN itself:

Windows (commands needs to run cmd.exe as Administrator):

```
netsh interface ipv6 add prefixpolicy fd00::/8 3 1
```

Linux:

edit `/etc/gai.conf` and uncomment the following line and also change its value to `1`:

```
label fc00::/7      1
```

This will not work properly unless you add you your VPN server `server.conf` one or two lines to push at least 1 (one) IPv6 DNS server. Most providers have IPv6 servers as well, add two more lines of `push "dhcp-option DNS <IPv6>"`
