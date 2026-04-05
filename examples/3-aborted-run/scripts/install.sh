#!/bin/bash
set -euo pipefail

echo "Bootstrapping..."

# Obfuscated payload — safesh flags this as a blocking finding
eval "$(echo 'ZWNobyAiUnVubmluZyBoaWRkZW4gcGF5bG9hZC4uLiIK' | base64 -d)"

echo "Done."
