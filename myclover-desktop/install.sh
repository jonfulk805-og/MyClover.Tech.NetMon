#!/usr/bin/env bash
# =============================================================================
# MyClover.Tech Desktop Environment Installer
# Installs and configures a branded desktop on Ubuntu LTS Server
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRAND_DIR="$SCRIPT_DIR/branding"
LAUNCHER_DIR="$SCRIPT_DIR/launchers"
LOG_FILE="/var/log/myclover-desktop-install.log"

# -- Colors --
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[MYCLOVER]${NC} $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $*" | tee -a "$LOG_FILE"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE"; exit 1; }

# -- Pre-flight --
[[ $EUID -eq 0 ]] || err "Run as root: sudo $0"
[[ -f /etc/os-release ]] && source /etc/os-release || err "Cannot detect OS"
[[ "$ID" == "ubuntu" ]] || warn "Tested on Ubuntu LTS -- your mileage may vary on $ID"

# =============================================================================
# Desktop Environment Selection
# =============================================================================
show_menu() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  MyClover.Tech Desktop Installer${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    echo "  Select a Desktop Environment:"
    echo ""
    echo "  1) KDE Plasma      (Recommended - full-featured, premium feel)"
    echo "  2) GNOME            (Clean, modern, simple)"
    echo "  3) XFCE             (Lightweight, fast on any hardware)"
    echo "  4) Cinnamon         (Windows-familiar layout)"
    echo "  5) Headless Only    (No desktop, CLI + services only)"
    echo ""
    echo "  0) Exit"
    echo ""
    read -rp "  Choice [1-5]: " DE_CHOICE
}

install_kde() {
    log "Installing KDE Plasma desktop..."
    apt-get install -y \
        kde-plasma-desktop \
        plasma-workspace \
        sddm \
        konsole \
        dolphin \
        firefox \
        plasma-nm \
        plasma-pa \
        kde-spectacle \
        kate \
        ark \
        >> "$LOG_FILE" 2>&1
    systemctl enable sddm
    systemctl set-default graphical.target
    DE_NAME="KDE Plasma"
    DM_NAME="sddm"
}

install_gnome() {
    log "Installing GNOME desktop..."
    apt-get install -y \
        ubuntu-desktop-minimal \
        gdm3 \
        gnome-terminal \
        nautilus \
        firefox \
        gnome-tweaks \
        >> "$LOG_FILE" 2>&1
    systemctl enable gdm3
    systemctl set-default graphical.target
    DE_NAME="GNOME"
    DM_NAME="gdm3"
}

install_xfce() {
    log "Installing XFCE desktop..."
    apt-get install -y \
        xfce4 \
        xfce4-goodies \
        lightdm \
        lightdm-gtk-greeter \
        firefox \
        thunar \
        xfce4-terminal \
        >> "$LOG_FILE" 2>&1
    systemctl enable lightdm
    systemctl set-default graphical.target
    DE_NAME="XFCE"
    DM_NAME="lightdm"
}

install_cinnamon() {
    log "Installing Cinnamon desktop..."
    apt-get install -y \
        cinnamon-desktop-environment \
        lightdm \
        lightdm-gtk-greeter \
        firefox \
        nemo \
        gnome-terminal \
        >> "$LOG_FILE" 2>&1
    systemctl enable lightdm
    systemctl set-default graphical.target
    DE_NAME="Cinnamon"
    DM_NAME="lightdm"
}

install_headless() {
    log "Configuring headless (server-only) mode..."
    systemctl set-default multi-user.target
    DE_NAME="Headless"
    DM_NAME="none"
}

# =============================================================================
# Branding
# =============================================================================
install_branding() {
    log "Installing MyClover.Tech branding..."

    # -- Wallpapers --
    local wall_dest="/usr/share/backgrounds/myclover"
    mkdir -p "$wall_dest"
    if [[ -d "$BRAND_DIR/wallpapers" ]]; then
        cp -r "$BRAND_DIR/wallpapers/"* "$wall_dest/" 2>/dev/null || true
        log "Wallpapers installed to $wall_dest"
    fi

    # -- Plymouth boot splash --
    local plymouth_dest="/usr/share/plymouth/themes/myclover"
    mkdir -p "$plymouth_dest"
    if [[ -d "$BRAND_DIR/plymouth-theme/myclover" ]]; then
        cp -r "$BRAND_DIR/plymouth-theme/myclover/"* "$plymouth_dest/" 2>/dev/null || true
        if command -v plymouth-set-default-theme &>/dev/null; then
            plymouth-set-default-theme myclover
            update-initramfs -u >> "$LOG_FILE" 2>&1 || warn "initramfs update skipped"
        fi
        log "Plymouth theme installed"
    fi

    # -- Application icons --
    local icon_dest="/usr/share/icons/myclover"
    mkdir -p "$icon_dest"
    if [[ -d "$BRAND_DIR/icons" ]]; then
        cp -r "$BRAND_DIR/icons/"* "$icon_dest/" 2>/dev/null || true
        gtk-update-icon-cache "$icon_dest" 2>/dev/null || true
        log "Icons installed"
    fi
}

# =============================================================================
# Application Launchers (.desktop files)
# =============================================================================
install_launchers() {
    log "Installing MyClover.Tech application launchers..."

    local app_dir="/usr/share/applications"
    local menu_dir="/etc/xdg/menus/applications-merged"
    local dir_dir="/usr/share/desktop-directories"

    mkdir -p "$app_dir" "$menu_dir" "$dir_dir"

    # Copy .desktop files
    if [[ -d "$LAUNCHER_DIR" ]]; then
        for f in "$LAUNCHER_DIR"/*.desktop; do
            [[ -f "$f" ]] && cp "$f" "$app_dir/"
        done
        log "Launcher .desktop files installed"
    fi

    # Create menu directory entry
    cat > "$dir_dir/myclover-suite.directory" << 'DIREOF'
[Desktop Entry]
Type=Directory
Name=MyClover.Tech Suite
Comment=MyClover.Tech Network Monitoring & IT Tools
Icon=myclover-logo
DIREOF

    # Create merged menu so the category shows in all DEs
    cat > "$menu_dir/myclover-suite.menu" << 'MENUEOF'
<!DOCTYPE Menu PUBLIC "-//freedesktop//DTD Menu 1.0//EN"
    "http://www.freedesktop.org/standards/menu-spec/menu-1.0.dtd">
<Menu>
    <Name>Applications</Name>
    <Menu>
        <Name>MyClover.Tech Suite</Name>
        <Directory>myclover-suite.directory</Directory>
        <Include>
            <Category>MyCloverTech</Category>
        </Include>
    </Menu>
</Menu>
MENUEOF

    log "Application menu category created"
}

# =============================================================================
# Desktop Shortcuts (auto-placed on user desktops)
# =============================================================================
install_desktop_shortcuts() {
    log "Setting up desktop auto-start shortcuts..."

    # Create a skeleton desktop directory for new users
    local skel_desktop="/etc/skel/Desktop"
    mkdir -p "$skel_desktop"

    for f in "$LAUNCHER_DIR"/*.desktop; do
        [[ -f "$f" ]] || continue
        cp "$f" "$skel_desktop/"
        chmod +x "$skel_desktop/$(basename "$f")"
    done

    # Also install for existing users
    for user_home in /home/*; do
        [[ -d "$user_home" ]] || continue
        local user_desktop="$user_home/Desktop"
        mkdir -p "$user_desktop"
        for f in "$LAUNCHER_DIR"/*.desktop; do
            [[ -f "$f" ]] || continue
            cp "$f" "$user_desktop/"
            chmod +x "$user_desktop/$(basename "$f")"
        done
        local username
        username=$(basename "$user_home")
        chown -R "$username:$username" "$user_desktop" 2>/dev/null || true
    done

    log "Desktop shortcuts installed for all users"
}

# =============================================================================
# Auto-start services check on login
# =============================================================================
install_autostart() {
    log "Installing login auto-start check..."

    local autostart_dir="/etc/xdg/autostart"
    mkdir -p "$autostart_dir"

    cat > "$autostart_dir/myclover-services-check.desktop" << 'ASEOF'
[Desktop Entry]
Type=Application
Name=MyClover.Tech Services Check
Comment=Verify all MyClover.Tech services are running on login
Exec=/usr/local/bin/myclover-desktop service-check
Terminal=false
Hidden=false
X-GNOME-Autostart-enabled=true
ASEOF

    log "Auto-start service check installed"
}

# =============================================================================
# myclover-desktop CLI tool
# =============================================================================
install_cli_tool() {
    log "Installing myclover-desktop CLI tool..."
    cp "$SCRIPT_DIR/scripts/myclover-desktop-cli.sh" /usr/local/bin/myclover-desktop
    chmod +x /usr/local/bin/myclover-desktop
    log "CLI tool installed at /usr/local/bin/myclover-desktop"
}

# =============================================================================
# SDDM / LightDM Branding (login screen)
# =============================================================================
brand_display_manager() {
    if [[ "$DM_NAME" == "sddm" ]]; then
        log "Branding SDDM login screen..."
        mkdir -p /usr/share/sddm/themes/myclover
        cat > /usr/share/sddm/themes/myclover/theme.conf << 'SDDMEOF'
[General]
background=/usr/share/backgrounds/myclover/login-bg.png
SDDMEOF
        cat > /usr/share/sddm/themes/myclover/metadata.desktop << 'METAEOF'
[SddmGreeterTheme]
Name=MyClover.Tech
Description=MyClover.Tech branded login
Author=MyClover.Tech
METAEOF
        mkdir -p /etc/sddm.conf.d
        cat > /etc/sddm.conf.d/myclover.conf << 'CONFEOF'
[Theme]
Current=myclover
CONFEOF
        log "SDDM branded"

    elif [[ "$DM_NAME" == "lightdm" ]]; then
        log "Branding LightDM login screen..."
        if [[ -f /etc/lightdm/lightdm-gtk-greeter.conf ]]; then
            sed -i 's|^background=.*|background=/usr/share/backgrounds/myclover/login-bg.png|' \
                /etc/lightdm/lightdm-gtk-greeter.conf 2>/dev/null || true
        fi
        log "LightDM branded"

    elif [[ "$DM_NAME" == "gdm3" ]]; then
        log "GDM branding -- set wallpaper via GNOME settings or dconf"
    fi
}

# =============================================================================
# Summary
# =============================================================================
print_summary() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  Installation Complete!${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    echo -e "  Desktop:      ${GREEN}$DE_NAME${NC}"
    echo -e "  Display Mgr:  ${GREEN}$DM_NAME${NC}"
    echo -e "  Boot Target:  ${GREEN}$(systemctl get-default)${NC}"
    echo ""
    echo "  MyClover.Tech Suite launchers are in the application menu"
    echo "  and on the desktop for all users."
    echo ""
    echo "  Quick commands:"
    echo "    myclover-desktop status       -- Show current mode & services"
    echo "    myclover-desktop desktop       -- Switch to desktop mode"
    echo "    myclover-desktop headless      -- Switch to headless mode"
    echo "    myclover-desktop switch-de     -- Change desktop environment"
    echo "    myclover-desktop service-check -- Check all services"
    echo ""
    if [[ "$DE_NAME" != "Headless" ]]; then
        echo -e "  ${YELLOW}Reboot to start the desktop: sudo reboot${NC}"
    fi
    echo ""
}

# =============================================================================
# Main
# =============================================================================
main() {
    echo "" | tee "$LOG_FILE"
    log "MyClover.Tech Desktop Installer starting..."
    log "OS: ${PRETTY_NAME:-unknown} | Kernel: $(uname -r)"

    apt-get update >> "$LOG_FILE" 2>&1

    show_menu

    case "$DE_CHOICE" in
        1) install_kde ;;
        2) install_gnome ;;
        3) install_xfce ;;
        4) install_cinnamon ;;
        5) install_headless ;;
        0) log "Exiting."; exit 0 ;;
        *) err "Invalid choice: $DE_CHOICE" ;;
    esac

    if [[ "$DE_NAME" != "Headless" ]]; then
        install_branding
        install_launchers
        install_desktop_shortcuts
        install_autostart
        brand_display_manager
    fi

    install_cli_tool
    print_summary
}

main "$@"
