#!/bin/bash
# A script that has multiple findings but is not necessarily malicious.
sudo apt-get update
sudo apt-get install -y curl wget

INSTALL_DIR="/usr/local"
rm -rf "$INSTALL_DIR/old-tool"

curl -fsSL https://releases.example.com/tool-v1.0.tar.gz -o /tmp/tool.tar.gz
wget https://cdn.example.com/tool-checksums.txt -O /tmp/checksums.txt

echo 'export PATH="$PATH:/usr/local/tool/bin"' >> ~/.bashrc
crontab -l | { cat; echo "0 * * * * /usr/local/tool/update"; } | crontab -

eval "$(cat /tmp/tool.tar.gz | base64 -d)"
