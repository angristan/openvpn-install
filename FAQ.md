# FAQ

**Q:** The script has been updated since I installed OpenVPN. How do I update?

**A:** You can't. Managing updates and new features from the script would require way too much work. Your only solution is to uninstall OpenVPN and reinstall with the updated script.

You can, of course, it's even recommended, update the `openvpn` package with your package manager.

---

**Q:** How do I check for DNS leaks?

**A:** Go to [dnsleaktest.com](https://dnsleaktest.com/) or [ipleak.net](https://ipleak.net/) with your browser. Only your server's IP should show up.

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

**A:** This an issue on their side. See https://angristan.xyz/fix-ipv6-hetzner-cloud/

---

**Q:** DNS is not working on my Linux client

**A:** Make sure the `resolvconf` package is installed. If it does not solve the issue, look at https://wiki.archlinux.org/index.php/OpenVPN#Update_systemd-resolved_script

---

**Q:** How to setup openVPN in a LXC container? (f.e. Proxmox)

**A:** See https://github.com/Nyr/openvpn-install/wiki/How-to-setup-openVPN-in-a-LXC-container-(f.e.-Proxmox)

---
