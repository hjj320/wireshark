# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

  # Base box is Ubuntu 16.04
  config.vm.box = "ubuntu/xenial64"

  # Bump the default resources as building is expensive
  config.vm.provider "virtualbox" do |v|
    v.memory = 2048
    v.cpus = 4
  end

  # Permit X11 forwarding so running the graphical Wireshark works
  config.ssh.forward_x11 = true

  # Install and build the various things (including wireshark!)
  config.vm.provision :shell, path: 'vagrant_provision.sh'
  config.vm.provision :shell, path: 'vagrant_build.sh', privileged: false
end
