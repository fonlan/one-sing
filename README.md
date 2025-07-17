# one-sing

## Introduction

`one-sing.sh` is an all-in-one management script for sing-box server on Debian amd64 systems. It supports one-click installation, update, and uninstallation of sing-box, and allows you to easily add SS2022, VLESS Reality, and AnyTLS protocols.

## Features

- One-click install/update/uninstall sing-box
- Add Shadowsocks 2022, VLESS Reality, and AnyTLS protocols
- Auto-generate ports, passwords, and keys
- Auto-generate protocol connection URLs
- systemd service management
- Automatic dependency detection and installation
- User-friendly interactive menu

## Usage

1. **Run the command**
   ```bash
   bash <(curl -Ls https://raw.githubusercontent.com/fonlan/one-sing/refs/heads/main/one-sing.sh)
   ```

2. **Select an option from the menu**
   1. Add SS2022 protocol
   2. Add VLESS  protocol
   3. Add AnyTLS protocol
   4. View configurations
   5. Delete configurations
   6. Install/Update
   7. Uninstall service
   8. Restart service
   9. View service status
   0. Exit script

## Dependencies

- bash
- curl
- jq
- unzip
- openssl
- systemd
- Only supports Debian amd64 architecture

## FAQ

1. **The script must be run as root, otherwise it will exit with an error.**
2. **Only Debian systems and amd64 architecture are supported.**
3. **Config file path**: `/etc/one-sing/config.json`
4. **Service management**: systemd service name is `one-sing.service`
5. **If the service fails to start, check logs with `journalctl -u one-sing.service -n 50 --no-pager`.**

## Disclaimer

This script is for learning and testing purposes only. Do not use it for illegal activities. The user is solely responsible for any consequences arising from its use.