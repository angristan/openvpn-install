# openvpn-install

一键部署一个用于局域网游戏的Openvpn服务器

自动设置Openvpn为TAP模式（为游戏优化）
去除NAT和DNS，仅保留局域网功能。

客户端下载（需要科学上网）https://openvpn.net/community-downloads/

有些选项实在是看不懂就没翻译。。

## 使用方法

第一步，下载脚本：

```bash
curl -O https://raw.githubusercontent.com/Nouko61/openvpn-install/master/openvpn-install.sh
chmod +x openvpn-install.sh
```

第二步，运行：

```sh
./openvpn-install.sh
```

## 更多

更多信息请前往[原项目](https://github.com/angristan/openvpn-install)

This project is under the [MIT Licence](https://raw.githubusercontent.com/Angristan/openvpn-install/master/LICENSE)
