#!/usr/bin/env bash
# paramant-help — complete command reference for ParamantOS

BOLD='\033[1m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; DIM='\033[2m'; RESET='\033[0m'

# Pipe through less -R (keeps ANSI colours, q to quit, arrow keys to scroll)
{
echo -e "
${BOLD}╔══════════════════════════════════════════════════════════════════════╗${RESET}
${BOLD}║                    ParamantOS — Command Reference                    ║${RESET}
${BOLD}╚══════════════════════════════════════════════════════════════════════╝${RESET}

${CYAN}${BOLD}SETUP & INFO${RESET}
  paramant-setup              First-boot wizard (password / hostname / key / SSH)
  paramant-setup --force      Re-run wizard at any time
  paramant-info               System overview (relay, OS, hardware, network)
  paramant-doctor             Automated health check — shows ✓/✗ per component
  paramant-help               This screen  (scroll: arrows / PgUp/PgDn,  quit: q)

${CYAN}${BOLD}RELAY CONTROL${RESET}
  paramant-status             Relay health, version, edition
  paramant-restart            Restart the relay service
  paramant-logs               Live relay log stream (Ctrl-C to stop)
  paramant-logs -n 50         Show last 50 log lines then exit
  paramant-dashboard          Live TUI dashboard — q=quit r=restart l=logs k=keys

${CYAN}${BOLD}API KEYS${RESET}
  paramant-keys               List all API keys
  paramant-key-add            Add a new API key (interactive)
  paramant-key-revoke         Revoke an API key (interactive)

${CYAN}${BOLD}LICENSE${RESET}
  paramant-license            License status, expiry, upgrade info
  cat /etc/paramant/license   Show raw license file
  nano /etc/paramant/license  Edit license key (then: paramant-restart)

${CYAN}${BOLD}NETWORK${RESET}
  paramant-wifi               Interactive WiFi manager
  paramant-ip                 Show IP addresses + relay port status
  paramant-ports              Show firewall rules + listening ports
  paramant-scan               Scan LAN for other Paramant relay nodes

${CYAN}${BOLD}SECURITY${RESET}
  paramant-security           Firewall, SSH, kernel hardening status

${CYAN}${BOLD}SECTORS${RESET}
  paramant-sector-add         Add a new relay sector (health/finance/legal/iot/custom)

${CYAN}${BOLD}DATA & BACKUP${RESET}
  paramant-backup             Backup keys + CT log to /var/lib/paramant-backup
  paramant-restore            Restore from a previous backup (interactive)
  paramant-export             Export audit log to USB drive

${CYAN}${BOLD}SECURITY VERIFICATION (TOFU / fingerprint)${RESET}
  paramant-verify <device>    Fetch + display device fingerprint for out-of-band check
  paramant-verify --list      List all trusted devices with stored fingerprints
  paramant-verify --clear <d> Remove device from trusted list

${CYAN}${BOLD}MAINTENANCE${RESET}
  paramant-cron               Manage systemd timers (backup/watchdog/license-alert)
  paramant-update             Check for updates + show upgrade path

${CYAN}${BOLD}DIAGNOSTICS${RESET}
  paramant-test               Full automated test suite — relay, security, commands, ISO
  paramant-doctor             Targeted health check (relay only)

${CYAN}${BOLD}SYSTEMD — relay management${RESET}
  systemctl status paramant-relay      Service status
  systemctl start  paramant-relay      Start
  systemctl stop   paramant-relay      Stop
  journalctl -u paramant-relay -f      Live logs

${CYAN}${BOLD}WIFI — manual nmcli${RESET}
  nmcli dev wifi list                        Scan for networks
  nmcli dev wifi connect SSID password PASS  Connect
  nmcli con show                             Active connections

${CYAN}${BOLD}HEALTH ENDPOINTS${RESET}
  curl -s http://localhost:3000/health   Main relay
  curl -s http://localhost:3001/health   Health sector
  curl -s http://localhost:3002/health   Finance sector
  curl -s http://localhost:3003/health   Legal sector
  curl -s http://localhost:3004/health   IoT sector

${CYAN}${BOLD}AUTOCOMPLETE${RESET}
  All paramant-* commands support Tab completion.
  Type  paramant-<Tab><Tab>  to list all commands.
  Type  paramant-setup --<Tab>  to see available flags.

${DIM}Questions: privacy@paramant.app   Docs: paramant.app${RESET}
"
} | less -R
