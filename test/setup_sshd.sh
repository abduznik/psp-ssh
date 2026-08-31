#!/bin/bash
# CI setup for the integration test: install sshd, force lean algo set.
set -e
sudo apt-get update -qq
sudo apt-get install -y -qq openssh-server
sudo useradd --create-home --shell /bin/bash sshuser
echo 'sshuser:pspsshpass' | sudo chpasswd
sudo mkdir -p /run/sshd
sudo tee /etc/ssh/sshd_config.d/pspssh.conf > /dev/null <<'CONF'
PasswordAuthentication yes
KbdInteractiveAuthentication no
PermitEmptyPasswords no
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
HostKeyAlgorithms ssh-ed25519
Ciphers aes128-ctr
MACs hmac-sha2-256
UsePAM no
CONF
sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N '' -q 2>/dev/null || true
sudo /usr/sbin/sshd -p 2222
echo "sshd ready on 2222"