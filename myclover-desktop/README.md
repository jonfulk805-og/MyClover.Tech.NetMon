# MyClover.Tech Desktop Environment Package

A branded desktop experience for MyClover.Tech appliances, laptops, and servers running Ubuntu LTS.

## Features

- **Multiple DE support** — KDE Plasma, GNOME, XFCE, Cinnamon
- **Boot mode selector** — Headless (server) or Full Desktop
- **Branded experience** — Custom wallpapers, Plymouth boot splash, login screen
- **Suite launchers** — One-click access to all MyClover.Tech services
- **CLI management** — `myclover-desktop` tool for runtime control
- **Auto-start health check** — Verifies services on desktop login

## Quick Start

```bash
# Clone or copy the package to your server
git clone https://github.com/jonfulk805-og/MyClover.Tech.NetMon.git
cd myclover-desktop

# Run the installer (as root)
sudo bash install.sh
```

## Directory Structure

```
myclover-desktop/
├── install.sh                    # Main installer (interactive)
├── README.md                     # This file
├── branding/
│   ├── wallpapers/               # Desktop & login wallpapers
│   │   ├── default-bg.png        # Main desktop wallpaper
│   │   └── login-bg.png          # Login screen background
│   ├── plymouth-theme/
│   │   └── myclover/             # Boot splash animation
│   │       ├── myclover.plymouth
│   │       ├── myclover.script
│   │       └── myclover-logo.png # (add your logo here)
│   └── icons/                    # Suite application icons
│       ├── myclover-netmon.png
│       ├── myclover-sentrylog.png
│       └── ...
├── launchers/                    # .desktop files for all suite apps
│   ├── myclover-netmon.desktop
│   ├── myclover-sentrylog.desktop
│   ├── myclover-wazuh.desktop
│   ├── myclover-portainer.desktop
│   ├── myclover-guacamole.desktop
│   ├── myclover-snipeit.desktop
│   ├── myclover-gitea.desktop
│   ├── myclover-rustdesk.desktop
│   ├── myclover-ollama.desktop
│   ├── myclover-zammad.desktop
│   ├── myclover-wireguard.desktop
│   └── myclover-settings.desktop
├── scripts/
│   └── myclover-desktop-cli.sh   # CLI tool source
└── widgets/
    └── netmon-panel/             # KDE Plasmoid / GNOME extension (future)
```

## CLI Tool: `myclover-desktop`

After installation, the `myclover-desktop` command is available system-wide:

```bash
myclover-desktop status         # Current mode, DE, and service health
myclover-desktop desktop        # Switch to desktop boot mode
myclover-desktop headless       # Switch to headless (server) boot mode
myclover-desktop switch-de      # Install or switch desktop environment
myclover-desktop service-check  # Run health check on all services
myclover-desktop launchers      # List all suite launchers and URLs
myclover-desktop help           # Show help
```

### Runtime Switching (no reboot needed)

```bash
# Switch to desktop right now
sudo systemctl isolate graphical.target

# Switch to headless right now
sudo systemctl isolate multi-user.target
```

## Suite Launchers

The installer creates a *MyClover.Tech Suite* category in the application menu with:

| Launcher              | Service                | Default URL                    |
|-----------------------|------------------------|--------------------------------|
| NetMon Dashboard      | Network monitoring     | http://localhost:5000          |
| SentryLog (Graylog)   | Log management         | http://localhost:9000          |
| Wazuh Security        | SIEM / IDS             | https://localhost:443          |
| Portainer Containers  | Docker management      | https://localhost:9443         |
| Guacamole Remote      | Remote desktop gateway | http://localhost:8080/guacamole|
| Snipe-IT Assets       | Asset management       | http://localhost:8081          |
| Gitea Code Server     | Git repositories       | http://localhost:3000          |
| RustDesk Remote       | P2P remote desktop     | (native app)                   |
| Ollama AI             | Local LLM models       | http://localhost:11434         |
| Zammad Helpdesk       | Ticketing system       | http://localhost:8082          |
| WireGuard VPN         | VPN management         | http://localhost:51821         |
| MyClover.Tech Settings| Appliance config       | (terminal CLI)                 |

## Branding Customization

### Wallpapers
Place PNG files in `branding/wallpapers/`:
- `default-bg.png` — Main desktop wallpaper (recommended: 3840x2160)
- `login-bg.png` — Login screen background

### Boot Splash
Place `myclover-logo.png` (recommended: 256x256, transparent) in `branding/plymouth-theme/myclover/`.

### Icons
Place 128x128 PNG icons in `branding/icons/` named to match the `.desktop` files (e.g., `myclover-netmon.png`).

## Supported Platforms

- Ubuntu 22.04 LTS (Jammy)
- Ubuntu 24.04 LTS (Noble)
- Debian 12 (Bookworm) — should work, not fully tested

## Roadmap

- [ ] KDE Plasmoid widget showing live NetMon stats on the desktop panel
- [ ] GNOME extension for quick service status in the top bar
- [ ] Auto-theme switching (dark mode based on time of day)
- [ ] First-run setup wizard (graphical) for initial configuration
- [ ] OEM image builder for pre-configured desktop ISOs

## License

Proprietary — MyClover.Tech. All rights reserved.
Open-source components retain their original licenses.
