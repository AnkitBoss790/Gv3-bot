#!/bin/bash
echo "=== PowerDev Cockpit Bot Installer ==="
sudo apt update -y
sudo apt install -y python3 python3-pip qemu-kvm libvirt-daemon-system virtinst bridge-utils cloud-utils tmate
sudo pip3 install discord.py python-libvirt aiohttp
python3 v2.py

echo "✅ All dependencies installed!"
echo "Run the bot with: bash run.sh"
