# openvpn-install

OpenVPN installer for Debian, Ubuntu, Fedora and CentOS.

This script will let you setup your own secure VPN server in just a few minutes.

## Usage

First, get the script and make it executable :

```bash
wget https://raw.githubusercontent.com/Angristan/openvpn-install/master/openvpn-install.sh
chmod +x openvpn-install.sh
```

Then run it :

```sh
./openvpn-install.sh
```

You need to run the script as root and have the TUN module enabled.

The first time you run it, you'll have to follow the assistant and answer a few questions to setup your VPN server.

When OpenVPN is installed, you can run the script again, and you will get the choice to :

- Add a client
- Remove a client
- Uninstall OpenVPN

In your home directory, you will have `.ovpn` files. These are the client configuration files. Download them from your server and connect using your prefered OpenVPN client.

## Features

- Installs and configures a ready-to-use OpenVPN server
- Iptables rules and forwarding managed in a seamless way
- If needed, the script can cleanly remove OpenVPN, including configuration and iptables rules
- Customizable encryption settings, enhanced default settings
- Varitey of DNS resolvers to be pushed to the clients
- Choice to use a self-hosted resolver with Unbound (supports already existing Unboud installations)
- Choice between TCP and UDP
- NATed IPv6 support
- Compression disabled to prevent VORACLE
- Unprivileged mode: run as `nobody`/`nogroup`
- Block DNS leaks on Windows 10
- Randomized server certificate name
- Choice to protect clients with a password (private key encryption)
- Many other little things!

## Compatibility

The script supports these OS and architectures:

- **Debian 8** (i386, amd64)
- **Debian 9** (i386, amd64, armhf, arm64)
- **Ubuntu 16.04 LTS** (i386, amd64, armhf)
- **Ubuntu 17.10** (i386, amd64, armhf, arm64)
- **Ubuntu 18.04 LTS** (i386, amd64, armhf, arm64)
- **Fedora 27** (amd64)
- **Fedora 28** (amd64)
- **CentOS 7** (i386, amd64)

To be noted:

- It should also work on Debian unstable/testing and Ubuntu beta.
- The script requires `systemd`.
- The script is regularly tested against `amd64` only.

## Fork

This script is based on the great work of [Nyr and its contributors](https://github.com/Nyr/openvpn-install).

Since 2016, the two scripts have diverged and are not alike anymore, especially under the hood. The main goal of the script was enhanced security. But since then, the script has been completely rewritten and a lot a features have been added. The script is only comptaible with recent distributions though, so if you need to use a very old server or client, I advise using Nyr's script.

## FAQ

**Q:** Which provider do you recommend?

**A:** I recommend these:

- [Vultr](https://goo.gl/Xyd1Sc): Worldwide locations, IPv6 support, starting at $3.50/month
- [PulseHeberg](https://goo.gl/76yqW5): France, unlimited bandwidth, starting at €3/month
- [Digital Ocean](https://goo.gl/qXrNLK): Worldwide locations, IPv6 support, starting at $5/month

---

**Q:** The script has been udpated since I installed OpenVPN. How do I update?

**A:** You can't. Managing updates and new features from the script would require way too much work. Your only solution is to uninstall OpenVPN and reinstall with the updated script.

You can, of course, it's even recommended, update the `openvpn` package with your package manager.

---

**Q:** How do I check for DNS leaks?

**A:**  Go to [dnsleaktest.com](https://dnsleaktest.com/) or [ipleak.net](https://ipleak.net/) with your browser. Only your server's IP should show up.

---

**Q:** IPv6 is not working on my Hetzner VM

**A:** This an issue on their side. See [issue #295](https://github.com/angristan/openvpn-install/issues/295).

---

## Encryption

The main reason why I made this fork is to improve the encryption. Indeed, OpenVPN's default parameters are weak (and that's what [Nyr's script](https://github.com/Nyr/openvpn-install) uses).

I want to justify all my choices regarding the encryption settings I have chosen, to prove that I'm not some random noob as some may think. 😉

However I'm far from a crypto expert, so don't hesitate to doubt what I say (I put links to my sources anyway), and to open an issue to correct me.

OpenVPN 2.4 will be a great update on the encryption part, because we'll be able to use elliptic curves, so ECDSA and ECDH (as well for the control channel), and AES GCM. They are faster and more secure. I will, of course, update the script when it will be available.

**Note:** With OpenVPN's default parameters, you have a relatively weak encryption. Nonetheless, your trafic is still encrypted, so unless you're under surveillance, probably no one will try to decrypt it. Yet it's not a reason to use old and weak algorithm when there are much better ones available. 😉

### TLS version

OpenVPN uses TLS 1.0 by default, which is nearly [20 years old](https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_1.0).

With `tls-version-min 1.2` we use at least TLS 1.2, which the best protocol available currently. I could have used `tls-version-min highest` but this does not ensure we use TLS 1.2 which is the only secure protocol available.

[OpenVPN documentation for tls-version-min](https://community.openvpn.net/openvpn/wiki/Openvpn23ManPage#lbAK)

TLS 1.2 is only supported since OpenVPN 2.3.3. This is one of the reasons of the script uses third-party repositories, because some distributions have an older version of OpenVPN.

### Certificate

#### Key

OpenVPN uses an RSA certificate with a 2048 bits key [by default](https://github.com/OpenVPN/easy-rsa/blob/master/easyrsa3/vars.example#L97).

2048 bits is OK, but both [NSA](https://cryptome.org/2016/01/CNSA-Suite-and-Quantum-Computing-FAQ.pdf) and [ANSSI](https://www.ssi.gouv.fr/uploads/2015/01/RGS_v-2-0_B1.pdf) recommend at least a 3072 bits for a future-proof key. As the size of the key will have an impact on speed, I leave the choice to use 2048, 3072 or 4096 bits RSA key. 4096 bits is what's most used and recommened today, but 3072 bits is still good.

In OpenVPN 2.4, we will be able to use an ECDSA certificate. This algorithm uses elliptic curves instead of prime numbers' factorization for a reduced key size and calculation time, thus it's faster and more secure.

#### Signature hash

OpenVPN uses SHA-256 [by default](https://github.com/OpenVPN/easy-rsa/blob/master/easyrsa3/vars.example#L192).

It also supports SHA1 and MD5, which are unsafe, and all the SHA2 family. I didn't find any reason to use something other than SHA-256 in the SHA2 group, so the script still uses the default hash algorithm.

### Data channel's cipher

By default, OpenVPN uses `BF-CBC` as the data channel cipher. Blowfish is an old (1993) and weak alogorithm. What's *funny* is that even the official OpenVPN documentation admits it.

>The default is BF-CBC, an abbreviation for Blowfish in Cipher Block Chaining mode.
Using BF-CBC is no longer recommended, because of its 64-bit block size. This small block size allows attacks based on collisions, as demonstrated by SWEET32. See https://community.openvpn.net/openvpn/wiki/SWEET32 for details.

[Source](https://community.openvpn.net/openvpn/wiki/Openvpn23ManPage#lbAI)

>Security researchers at INRIA published an attack on 64-bit block ciphers, such as 3DES and Blowfish. They show that they are able to recover plaintext when the same data is sent often enough, and show how they can use cross-site scripting vulnerabilities to send data of interest often enough. This works over HTTPS, but also works for HTTP-over-OpenVPN. See ​https://sweet32.info/ for a much better and more elaborate explanation.
> OpenVPN's default cipher, BF-CBC, is affected by this attack.

[Source](https://community.openvpn.net/openvpn/wiki/SWEET32)

>Blowfish's use of a 64-bit block size (as opposed to e.g. AES's 128-bit block size) makes it vulnerable to birthday attacks, particularly in contexts like HTTPS. In 2016, the SWEET32 attack demonstrated how to leverage birthday attacks to perform plaintext recovery (i.e. decrypting ciphertext) against ciphers with a 64-bit block size such as Blowfish.[9]

>A reduced-round variant of Blowfish is known to be susceptible to known-plaintext attacks on reflectively weak keys. Blowfish implementations use 16 rounds of encryption, and are not susceptible to this attack. Blowfish users are encouraged by Bruce Schneier, Blowfish's creator, to use the more modern and computationally efficient alternative Twofish. He is quoted in 2007 as saying:

>"At this point, though, I'm amazed it's still being used. If people ask, I recommend Twofish instead."

[Source](https://en.wikipedia.org/wiki/Blowfish_(cipher)#Weakness_and_successors)

Convinced ?

The [SWEET32 vulnerability page](https://community.openvpn.net/openvpn/wiki/SWEET32) from OpenVPN's documentation says :
>The following ciphers are affected, and should no longer be used:

- BF-*
- DES* (including 3DES variants)
- RC2-*

>The following ciphers are *not* affected:

- AES-*
- CAMELLIA-*
- SEED-*

Indeed, AES is today's standard. It's the fastest and more secure cipher available today. [SEED](https://en.wikipedia.org/wiki/SEED) and [Camellia](https://en.wikipedia.org/wiki/Camellia_(cipher)) are not vulnerable to date but are slower than AES and relatively less trusted.

Currently AES is only available in its CBC mode, which is weaker than GCM.

To quote the [OpenVPN documentation](https://community.openvpn.net/openvpn/wiki/SWEET32) :

>Of the currently supported ciphers, OpenVPN currently recommends using AES-256-CBC or AES-128-CBC. OpenVPN 2.4 and newer will also support GCM. For 2.4+, we recommend using AES-256-GCM or AES-128-GCM.

Of course I will update the script to add AES-GCM mode (as well as ECDH and ECDSA) as soon as OpenVPN 2.4 is released.

For now, these cipher are available in the setup :

- AES-128-CBC
- AES-192-CBC
- AES-256-CBC

AES-256 is 40% slower than AES-128, and there isn't any real reason to use a 256 bits key over a 128 bits key with AES. (Source : [[1]](http://security.stackexchange.com/questions/14068/why-most-people-use-256-bit-encryption-instead-of-128-bit),[[2]](http://security.stackexchange.com/questions/6141/amount-of-simple-operations-that-is-safely-out-of-reach-for-all-humanity/6149#6149)).

Moreover, AES-256 is more vulnerable to [Timing attacks](https://en.wikipedia.org/wiki/Timing_attack).

Thus, the best data channel cipher currently available in OpenVPN is `AES-128-CBC`.

### Control channel's cipher

According to the [Hardening](https://community.openvpn.net/openvpn/wiki/Hardening#Useof--tls-cipher) page of the OpenVPN wiki, TLS 1.2 is not supported by OpenVPN <2.3.3, so it uses a TLS 1.0 cipher by default, which is insecure.

> The following are TLSv1.2 DHE + RSA choices, requiring a compatible peer running at least OpenVPN 2.3.3:
- TLS-DHE-RSA-WITH-AES-256-GCM-SHA384
- TLS-DHE-RSA-WITH-AES-256-CBC-SHA256
- TLS-DHE-RSA-WITH-AES-128-GCM-SHA256
- TLS-DHE-RSA-WITH-AES-128-CBC-SHA256

AES GCM is more secure than AES CBC, and AES 128 is secure enough today. I didn't find any security difference between SHA-256 and SHA-384 so we're going to use SHA-256.

Thus, I have chosen `TLS-DHE-RSA-WITH-AES-128-GCM-SHA256` as the control channel cipher.

### Diffie-Hellman key

OpenVPN uses a 2048 bits DH key [by default](https://github.com/OpenVPN/easy-rsa/blob/master/easyrsa3/vars.example#L97).

2048 bits is OK, but both [NSA](https://cryptome.org/2016/01/CNSA-Suite-and-Quantum-Computing-FAQ.pdf) and [ANSSI](https://www.ssi.gouv.fr/uploads/2015/01/RGS_v-2-0_B1.pdf) recommend at least a 3072 bits for a future-proof key. Like RSA, the size of the key will have an impact on speed, I leave the choice to use a 2048, 3072 or 4096 bits key. 4096 bits is what's most used and recommended today, but 3072 bits is still good.

In OpenVPN 2.4, we will be able to use ECDH key. It uses elliptic curves instead of prime numbers' factorization for a reduced key size and calculation time, thus it's faster and more secure.

### HMAC authentication algorithm

To quote the OpenVPN wiki :

>Authenticate packets with HMAC using message digest algorithm alg. (The default is SHA1 ). HMAC is a commonly used message authentication algorithm (MAC) that uses a data string, a secure hash algorithm, and a key, to produce a digital signature.
OpenVPN's usage of HMAC is to first encrypt a packet, then HMAC the resulting ciphertext.

SHA-1 is not safe anymore, so I use SHA-256 which is safe and widely used.

### TLS-Auth

>The --tls-auth option uses a static pre-shared key (PSK) that must be generated in advance and shared among all peers. This features adds "extra protection" to the TLS channel by requiring that incoming packets have a valid signature generated using the PSK key. If this key is ever changed, it must be changed on all peers at the same time (there is no support for rollover.)

>The primary benefit is that an unauthenticated client cannot cause the same CPU/crypto load against a server as the junk traffic can be dropped much sooner. This can aid in mitigating denial-of-service attempts.

>This feature by itself does not improve the TLS auth in any way, although it offers a 2nd line of defense if a future flaw is discovered in a particular TLS cipher-suite or implementation (such as CVE-2014-0160, Heartbleed, where the tls-auth key provided protection against attackers who did not have a copy). However, it offers no protection at all in the event of a complete cryptographic break that can allow decryption of a cipher-suite's traffic.

[Source](https://openvpn.net/index.php/open-source/documentation/howto.html#security)

TLS-Auth is not enabled by default by OpenVPN, but it is in this script.

## Say thanks

You can [say thanks](https://saythanks.io/to/Angristan) if you want!

## Credits & Licence

Thanks to the [contributors](https://github.com/Angristan/OpenVPN-install/graphs/contributors) and of course Nyr's orginal work.

[MIT Licence](https://raw.githubusercontent.com/Angristan/openvpn-install/master/LICENSE)
