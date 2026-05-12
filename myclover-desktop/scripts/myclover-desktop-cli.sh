#!/usr/bin/env bash
# =============================================================================
# myclover-desktop -- CLI tool to manage MyClover.Tech desktop & services
# Usage: myclover-desktop {status|desktop|headless|switch-de|service-check|launchers}
# =============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}[OK]${NC}    $*"; }
fail() { echo -e "  ${RED}[FAIL]${NC}  $*"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC}  $*"; }
info() { echo -e "  ${CYAN}[INFO]${NC}  $*"; }

# -- Service definitions (name : description : check command) --
declare -A SERVICES=(
    ["netmon"]="NetMon Dashboard|systemctl is-active myclover-netmon"
    ["sentrylog"]="SentryLog (Graylog)|systemctl is-active graylog-server"
    ["wazuh"]="Wazuh Security SIEM|systemctl is-active wazuh-manager"
    ["portainer"]="Portainer Containers|docker ps --filter name=portainer -q"
    ["guacamole"]="Guacamole Remote Access|docker ps --filter name=guacamole -q"
    ["snipeit"]="Snipe-IT Assets|docker ps --filter name=snipeit -q"
    ["rustdesk"]="RustDesk Remote|systemctl is-active rustdesk-server"
    ["wireguard"]="WireGuard VPN|systemctl is-active wg-quick@wg0"
    ["traefik"]="Traefik Proxy|docker ps --filter name=traefik -q"
    ["restic"]="Restic Backup (timer)|systemctl is-active restic-backup.timer"
    ["gitea"]="Gitea Git Server|systemctl is-active gitea"
    ["ollama"]="Ollama AI|systemctl is-active ollama"
)

# =============================================================================
# Commands
# =============================================================================

cmd_status() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  MyClover.Tech System Status${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""

    # Boot target
    local target
    target=$(systemctl get-default 2>/dev/null || echo "unknown")
    if [[ "$target" == "graphical.target" ]]; then
        ok "Boot mode: Desktop (graphical.target)"
    else
        info "Boot mode: Headless (multi-user.target)"
    fi

    # Detect DE
    if [[ -n "${XDG_CURRENT_DESKTOP:-}" ]]; then
        ok "Desktop: $XDG_CURRENT_DESKTOP"
    elif [[ -n "${DESKTOP_SESSION:-}" ]]; then
        ok "Desktop: $DESKTOP_SESSION"
    else
        info "Desktop: not detected (possibly headless or SSH session)"
    fi

    # Display manager
    for dm in sddm gdm3 lightdm; do
        if systemctl is-active --quiet "$dm" 2>/dev/null; then
            ok "Display manager: $dm (running)"
            break
        fi
    done

    echo ""
    echo "  Services:"
    echo "  ---------"
    cmd_service_check_quiet
    echo ""
}

cmd_service_check() {
    echo ""
    echo -e "${CYAN}  MyClover.Tech Service Health${NC}"
    echo "  ----------------------------"
    cmd_service_check_quiet
    echo ""
}

cmd_service_check_quiet() {
    for svc_key in $(echo "${!SERVICES[@]}" | tr ' ' '\n' | sort); do
        IFS='|' read -r desc check_cmd <<< "${SERVICES[$svc_key]}"
        if eval "$check_cmd" &>/dev/null; then
            ok "$desc"
        else
            fail "$desc (not running)"
        fi
    done
}

cmd_desktop() {
    echo ""
    [[ $EUID -eq 0 ]] || { echo "Run as root: sudo myclover-desktop desktop"; exit 1; }
    info "Switching to desktop mode..."
    systemctl set-default graphical.target
    ok "Default target set to graphical.target"
    info "Run 'sudo systemctl isolate graphical.target' to start now, or reboot."
    echo ""
}

cmd_headless() {
    echo ""
    [[ $EUID -eq 0 ]] || { echo "Run as root: sudo myclover-desktop headless"; exit 1; }
    info "Switching to headless mode..."
    systemctl set-default multi-user.target
    ok "Default target set to multi-user.target"
    info "Run 'sudo systemctl isolate multi-user.target' to switch now, or reboot."
    echo ""
}

cmd_switch_de() {
    echo ""
    [[ $EUID -eq 0 ]] || { echo "Run as root: sudo myclover-desktop switch-de"; exit 1; }
    echo -e "${CYAN}  Switch Desktop Environment${NC}"
    echo ""
    echo "  Currently installed:"

    local has_kde=0 has_gnome=0 has_xfce=0 has_cinnamon=0

    dpkg -l | grep -q "kde-plasma-desktop" && { ok "KDE Plasma"; has_kde=1; } || true
    dpkg -l | grep -q "ubuntu-desktop-minimal\|gnome-shell" && { ok "GNOME"; has_gnome=1; } || true
    dpkg -l | grep -q "xfce4" && { ok "XFCE"; has_xfce=1; } || true
    dpkg -l | grep -q "cinnamon-desktop" && { ok "Cinnamon"; has_cinnamon=1; } || true

    echo ""
    echo "  Install another DE:"
    echo "  1) KDE Plasma"
    echo "  2) GNOME"
    echo "  3) XFCE"
    echo "  4) Cinnamon"
    echo "  0) Cancel"
    echo ""
    read -rp "  Choice [0-4]: " choice

    case "$choice" in
        1)
            apt-get install -y kde-plasma-desktop sddm konsole dolphin firefox
            systemctl enable sddm
            ok "KDE Plasma installed. Reboot and select at login."
            ;;
        2)
            apt-get install -y ubuntu-desktop-minimal gdm3 firefox
            systemctl enable gdm3
            ok "GNOME installed. Reboot and select at login."
            ;;
        3)
            apt-get install -y xfce4 xfce4-goodies lightdm firefox
            systemctl enable lightdm
            ok "XFCE installed. Reboot and select at login."
            ;;
        4)
            apt-get install -y cinnamon-desktop-environment lightdm firefox
            systemctl enable lightdm
            ok "Cinnamon installed. Reboot and select at login."
            ;;
        0) info "Cancelled." ;;
        *) fail "Invalid choice." ;;
    esac
    echo ""
}

cmd_launchers() {
    echo ""
    echo -e "${CYAN}  MyClover.Tech Suite Launchers${NC}"
    echo "  ----------------------------"
    for f in /usr/share/applications/myclover-*.desktop; do
        [[ -f "$f" ]] || continue
        local name url
        name=$(grep "^Name=" "$f" | cut -d= -f2)
        url=$(grep "^Exec=" "$f" | sed 's/Exec=xdg-open //')
        info "$name  -->  $url"
    done
    echo ""
}

cmd_help() {
    echo ""
    echo -e "${CYAN}myclover-desktop${NC} -- MyClover.Tech Desktop Manager"
    echo ""
    echo "  Usage: myclover-desktop <command>"
    echo ""
    echo "  Commands:"
    echo "    status         Show current mode, DE, and service health"
    echo "    desktop        Switch boot target to desktop mode"
    echo "    headless       Switch boot target to headless mode"
    echo "    switch-de      Install or switch desktop environment"
    echo "    service-check  Check all MyClover.Tech services"
    echo "    launchers      List installed suite launchers"
    echo "    help           Show this help"
    echo ""
}

# =============================================================================
# Main
# =============================================================================
case "${1:-help}" in
    status)        cmd_status ;;
    desktop)       cmd_desktop ;;
    headless)      cmd_headless ;;
    switch-de)     cmd_switch_de ;;
    service-check) cmd_service_check ;;
    launchers)     cmd_launchers ;;
    help|--help|-h) cmd_help ;;
    *) echo "Unknown command: $1"; cmd_help; exit 1 ;;
esac
