# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrant box for testing
Vagrant.configure("2") do |config|
  config.vm.box = "fedora/34-cloud-base"
  memory = 6144
  cpus = 4

  config.vm.provider :virtualbox do |v|
    v.memory = memory
    v.cpus = cpus
  end

  config.vm.provider :libvirt do |v|
    v.memory = memory
    v.cpus = cpus
  end

  config.vm.provision "install-dependencies", type: "shell", run: "once" do |sh|
    sh.inline = <<~SHELL
      set -euxo pipefail

      cp /vagrant/build/syscallrecorder /usr/local/bin

      dnf install -y \
        go \
        podman

      cd /vagrant/hack/oci-hook
      go build -o /usr/local/bin/hook hook.go

      # podman run \
      #   --hooks-dir /vagrant/hack/oci-hook \
      #   --annotation io.containers.trace-syscall=/tmp/syscalls.txt alpine
    SHELL
  end
end
