# FAQ

**Q:** The script has been updated since I installed OpenVPN. How do I update?

**A:** You can't. Managing updates and new features from the script would require way too much work. Your only solution is to uninstall OpenVPN and reinstall with the updated script.

You can, of course, it's even recommended, update the `openvpn` package with your package manager.

---

**Q:** How do I renew certificates before they expire?

**A:** Use the CLI commands to renew certificates:

```bash
# Renew a client certificate
./openvpn-install.sh client renew alice

# Renew with custom validity period (365 days)
./openvpn-install.sh client renew alice --cert-days 365

# Renew the server certificate
./openvpn-install.sh server renew
```

For client renewals, a new `.ovpn` file will be generated that you need to distribute to the client. For server renewals, the OpenVPN service will need to be restarted (the script will prompt you).

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

CentOS 6, 7

```
script-security 2
up /usr/share/doc/openvpn-2.4.8/contrib/pull-resolv-conf/client.up
down /usr/share/doc/openvpn-2.4.8/contrib/pull-resolv-conf/client.down
```

CentOS 8, Fedora 30, 31

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

**Q:** IPv6 is not working on my Hetzner VM

**A:** This an issue on their side. See <https://angristan.xyz/fix-ipv6-hetzner-cloud/>

---

**Q:** DNS is not working on my Linux client

**A:** See "How do I fix DNS leaks?" question

---

**Q:** What sysctl and firewall changes are made by the script?

**A:** If firewalld is active, the script uses `firewall-cmd --permanent` to configure port, masquerade, and rich rules. Otherwise, iptables rules are saved at `/etc/iptables/add-openvpn-rules.sh` and `/etc/iptables/rm-openvpn-rules.sh`, managed by `/etc/systemd/system/iptables-openvpn.service`.

Sysctl options are at `/etc/sysctl.d/99-openvpn.conf`

---

**Q:** How can I access other clients connected to the same OpenVPN server?

**A:** Add `client-to-client` to your `server.conf`

---

**Q:** My router can't connect

**A:**

- `Options error: No closing quotation (") in config.ovpn:46` :

  type `yes` when asked to customize encryption settings and choose `tls-auth`

---

**Q:** How can I access computers the OpenVPN server's remote LAN?

**A:** Add a route with the subnet of the remote network to `/etc/openvpn/server/server.conf` and restart OpenVPN. Example: `push "route 192.168.1.0 255.255.255.0"` if the server's LAN is `192.168.1.0/24`

---

**Q:** How can I add multiple users in one go?

**A:** Here is a sample Bash script to achieve this:

```bash
#!/bin/bash
userlist=(user1 user2 user3)

for user in "${userlist[@]}"; do
  ./openvpn-install.sh client add "$user"
done
```

From a list in a text file:

```bash
#!/bin/bash
while read -r user; do
  ./openvpn-install.sh client add "$user"
done < users.txt
```

To add password-protected clients:

```bash
#!/bin/bash
./openvpn-install.sh client add alice --password "secretpass123"
```

---

**Q:** How do I change the default `.ovpn` file created for future clients?

**A:** You can edit the template out of which `.ovpn` files are created by editing `/etc/openvpn/server/client-template.txt`

---

**Q:** For my clients - I want to set my internal network to pass through the VPN and the rest to go through my internet?

**A:** You would need to edit the `.ovpn` file. You can edit the template out of which those files are created by editing `/etc/openvpn/server/client-template.txt` file and adding

```sh
route-nopull
route 10.0.0.0 255.0.0.0
```

So for example - here it would route all traffic of `10.0.0.0/8` to the VPN. And the rest through the internet.

---

**Q:** I have enabled IPv6 and my VPN client gets an IPv6 address. Why do I reach the sites or other dual-stacked destinations via IPv4 only?

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
