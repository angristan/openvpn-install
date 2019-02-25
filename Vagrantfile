# Run the script in headless mode for each of the supported OS.

machines = [
  { hostname: 'openvpn-debian-9', box: 'debian/stretch64' },
  { hostname: 'openvpn-debian-8', box: 'debian/jessie64' },
  { hostname: 'openvpn-ubuntu-1604', box: 'ubuntu/bionic64' },
  { hostname: 'openvpn-ubuntu-1804', box: 'ubuntu/xenial64' },
  { hostname: 'openvpn-centos-7', box: 'centos/7' },
  { hostname: 'openvpn-fedora-29', box: 'fedora/29-cloud-base' },
  { hostname: 'openvpn-fedora-28', box: 'fedora/28-cloud-base' },
  { hostname: 'openvpn-archlinux', box: 'archlinux/archlinux' }
]

Vagrant.configure('2') do |config|
  machines.each do |machine|
    config.vm.provider 'virtualbox' do |v|
      v.memory = 1024
      v.cpus = 2
    end
    config.vm.define machine[:hostname] do |machineconfig|
      machineconfig.vm.hostname = machine[:hostname]
      machineconfig.vm.box = machine[:box]

      machineconfig.vm.provision 'shell', inline: <<-SHELL
        AUTO_INSTALL=y /vagrant/openvpn-install.sh
        ps aux | grep openvpn | grep -v grep > /dev/null 2>&1 && echo "Success: OpenVPN is running" && exit 0 || echo "Failure: OpenVPN is not running" && exit 1
      SHELL
    end
  end
end
